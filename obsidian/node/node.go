// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package node

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	// ErrNodeStopped is returned when the node is stopped
	ErrNodeStopped = errors.New("node not started")
	// ErrNodeRunning is returned when trying to start an already running node
	ErrNodeRunning = errors.New("node already running")
	// ErrServiceUnknown is returned when an unknown service is requested
	ErrServiceUnknown = errors.New("unknown service")
)

// Config represents the configuration of the Obsidian node
type Config struct {
	// Name sets the instance name of the node
	Name string `toml:"-"`
	// Version is the version string of the node
	Version string `toml:"-"`
	// DataDir is the file system folder for the node's data
	DataDir string
	// P2P configuration
	P2P p2p.Config
	// HTTP RPC configuration
	HTTPHost         string `toml:",omitempty"`
	HTTPPort         int    `toml:",omitempty"`
	HTTPCors         []string `toml:",omitempty"`
	HTTPVirtualHosts []string `toml:",omitempty"`
	HTTPModules      []string `toml:",omitempty"`
	HTTPPathPrefix   string   `toml:",omitempty"`
	// WebSocket configuration
	WSHost         string   `toml:",omitempty"`
	WSPort         int      `toml:",omitempty"`
	WSOrigins      []string `toml:",omitempty"`
	WSModules      []string `toml:",omitempty"`
	WSPathPrefix   string   `toml:",omitempty"`
	// IPC configuration
	IPCPath string `toml:",omitempty"`
	// Logger for the node
	Logger log.Logger `toml:"-"`
}

// DefaultConfig returns the default node configuration
func DefaultConfig() Config {
	return Config{
		Name:             "obsidian",
		Version:          "1.0.0",
		DataDir:          DefaultDataDir(),
		HTTPHost:         "localhost",
		HTTPPort:         8545,
		HTTPModules:      []string{"eth", "net", "web3", "obs"},
		HTTPVirtualHosts: []string{"localhost"},
		WSHost:           "localhost",
		WSPort:           8546,
		WSModules:        []string{"eth", "net", "web3", "obs"},
		P2P: p2p.Config{
			MaxPeers:    50,
			ListenAddr:  ":30303",
			NAT:         nil,
		},
	}
}

// DefaultDataDir returns the default data directory
func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".obsidian")
}

// Node represents a full Obsidian node
type Node struct {
	config *Config
	log    log.Logger

	// P2P networking
	server    *p2p.Server
	serverMux sync.RWMutex

	// RPC
	rpcAPIs       []rpc.API
	httpListener  net.Listener
	httpHandler   *rpc.Server
	wsListener    net.Listener
	wsHandler     *rpc.Server
	ipcListener   net.Listener
	ipcHandler    *rpc.Server

	// Lifecycle
	startStopLock sync.Mutex
	state         int // 0 = stopped, 1 = running
	lock          sync.Mutex
	lifecycles    []Lifecycle
	services      map[string]Lifecycle
	closeCh       chan struct{}
}

// Lifecycle represents a service that can be started and stopped
type Lifecycle interface {
	Start() error
	Stop() error
}

// New creates a new Obsidian node
func New(config *Config) (*Node, error) {
	confCopy := *config
	conf := &confCopy

	if conf.DataDir != "" {
		absdir, err := filepath.Abs(conf.DataDir)
		if err != nil {
			return nil, err
		}
		conf.DataDir = absdir

		if err := os.MkdirAll(conf.DataDir, 0700); err != nil {
			return nil, err
		}
	}

	logger := conf.Logger
	if logger == nil {
		logger = log.Root()
	}

	return &Node{
		config:     conf,
		log:        logger,
		services:   make(map[string]Lifecycle),
		closeCh:    make(chan struct{}),
	}, nil
}

// Start starts the node and all registered services
func (n *Node) Start() error {
	n.startStopLock.Lock()
	defer n.startStopLock.Unlock()

	if n.state == 1 {
		return ErrNodeRunning
	}
	n.state = 1

	n.log.Info("Starting Obsidian node", "datadir", n.config.DataDir)

	// Start P2P server
	if err := n.startP2P(); err != nil {
		n.state = 0
		return err
	}

	// Start RPC servers
	if err := n.startRPC(); err != nil {
		n.stopP2P()
		n.state = 0
		return err
	}

	// Start all registered services
	for name, service := range n.services {
		if err := service.Start(); err != nil {
			n.log.Error("Service failed to start", "service", name, "error", err)
			n.stop()
			n.state = 0
			return err
		}
		n.log.Info("Service started", "service", name)
	}

	n.log.Info("Obsidian node started")
	return nil
}

// Stop stops the node and all registered services
func (n *Node) Stop() error {
	n.startStopLock.Lock()
	defer n.startStopLock.Unlock()

	if n.state == 0 {
		return ErrNodeStopped
	}

	n.log.Info("Stopping Obsidian node")
	n.stop()
	n.state = 0

	close(n.closeCh)
	n.closeCh = make(chan struct{})

	n.log.Info("Obsidian node stopped")
	return nil
}

// stop stops all services and networking
func (n *Node) stop() {
	// Stop services in reverse order
	for name, service := range n.services {
		if err := service.Stop(); err != nil {
			n.log.Error("Service failed to stop", "service", name, "error", err)
		}
	}

	n.stopRPC()
	n.stopP2P()
}

// startP2P starts the P2P server
func (n *Node) startP2P() error {
	if n.config.P2P.ListenAddr == "" {
		return nil // P2P disabled
	}

	serverConfig := n.config.P2P
	serverConfig.Name = n.config.Name
	serverConfig.Logger = n.log

	server := &p2p.Server{Config: serverConfig}
	if err := server.Start(); err != nil {
		return err
	}

	n.serverMux.Lock()
	n.server = server
	n.serverMux.Unlock()

	n.log.Info("P2P server started", "self", server.Self())
	return nil
}

// stopP2P stops the P2P server
func (n *Node) stopP2P() {
	n.serverMux.Lock()
	defer n.serverMux.Unlock()

	if n.server != nil {
		n.server.Stop()
		n.server = nil
	}
}

// startRPC starts all RPC endpoints
func (n *Node) startRPC() error {
	// Start HTTP RPC
	if n.config.HTTPHost != "" {
		if err := n.startHTTP(); err != nil {
			return err
		}
	}

	// Start WebSocket RPC
	if n.config.WSHost != "" {
		if err := n.startWS(); err != nil {
			n.stopHTTP()
			return err
		}
	}

	// Start IPC RPC
	if n.config.IPCPath != "" {
		if err := n.startIPC(); err != nil {
			n.stopWS()
			n.stopHTTP()
			return err
		}
	}

	return nil
}

// stopRPC stops all RPC endpoints
func (n *Node) stopRPC() {
	n.stopIPC()
	n.stopWS()
	n.stopHTTP()
}

// startHTTP starts the HTTP RPC server
func (n *Node) startHTTP() error {
	endpoint := fmt.Sprintf("%s:%d", n.config.HTTPHost, n.config.HTTPPort)
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		return err
	}

	handler := rpc.NewServer()
	for _, api := range n.rpcAPIs {
		if containsString(n.config.HTTPModules, api.Namespace) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				listener.Close()
				return err
			}
		}
	}

	n.httpListener = listener
	n.httpHandler = handler

	go handler.ServeListener(listener)
	n.log.Info("HTTP server started", "endpoint", endpoint)
	return nil
}

// stopHTTP stops the HTTP RPC server
func (n *Node) stopHTTP() {
	if n.httpListener != nil {
		n.httpListener.Close()
		n.httpListener = nil
	}
	if n.httpHandler != nil {
		n.httpHandler.Stop()
		n.httpHandler = nil
	}
}

// startWS starts the WebSocket RPC server
func (n *Node) startWS() error {
	endpoint := fmt.Sprintf("%s:%d", n.config.WSHost, n.config.WSPort)
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		return err
	}

	handler := rpc.NewServer()
	for _, api := range n.rpcAPIs {
		if containsString(n.config.WSModules, api.Namespace) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				listener.Close()
				return err
			}
		}
	}

	n.wsListener = listener
	n.wsHandler = handler

	go handler.ServeListener(listener)
	n.log.Info("WebSocket server started", "endpoint", endpoint)
	return nil
}

// stopWS stops the WebSocket RPC server
func (n *Node) stopWS() {
	if n.wsListener != nil {
		n.wsListener.Close()
		n.wsListener = nil
	}
	if n.wsHandler != nil {
		n.wsHandler.Stop()
		n.wsHandler = nil
	}
}

// startIPC starts the IPC RPC server
func (n *Node) startIPC() error {
	ipcPath := n.config.IPCPath
	if ipcPath == "" {
		ipcPath = filepath.Join(n.config.DataDir, "obsidian.ipc")
	}

	// Remove any existing socket file
	os.Remove(ipcPath)

	listener, err := net.Listen("unix", ipcPath)
	if err != nil {
		return err
	}

	handler := rpc.NewServer()
	for _, api := range n.rpcAPIs {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			listener.Close()
			return err
		}
	}

	n.ipcListener = listener
	n.ipcHandler = handler

	go handler.ServeListener(listener)
	n.log.Info("IPC server started", "endpoint", ipcPath)
	return nil
}

// stopIPC stops the IPC RPC server
func (n *Node) stopIPC() {
	if n.ipcListener != nil {
		n.ipcListener.Close()
		n.ipcListener = nil
	}
	if n.ipcHandler != nil {
		n.ipcHandler.Stop()
		n.ipcHandler = nil
	}
}

// RegisterAPIs registers a set of RPC APIs
func (n *Node) RegisterAPIs(apis []rpc.API) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.rpcAPIs = append(n.rpcAPIs, apis...)
}

// RegisterService registers a service
func (n *Node) RegisterService(name string, service Lifecycle) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	if _, exists := n.services[name]; exists {
		return fmt.Errorf("service already registered: %s", name)
	}
	n.services[name] = service
	return nil
}

// Server returns the P2P server
func (n *Node) Server() *p2p.Server {
	n.serverMux.RLock()
	defer n.serverMux.RUnlock()
	return n.server
}

// DataDir returns the data directory
func (n *Node) DataDir() string {
	return n.config.DataDir
}

// ResolvePath resolves a path relative to the data directory
func (n *Node) ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(n.config.DataDir, path)
}

// Wait blocks until the node is stopped
func (n *Node) Wait() {
	<-n.closeCh
}

// containsString checks if a string slice contains a string
func containsString(sl []string, s string) bool {
	for _, item := range sl {
		if item == s {
			return true
		}
	}
	return false
}

// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/log"
)

// Config represents the Obsidian node configuration
type Config struct {
	// Network settings
	Network NetworkConfig `json:"network"`

	// Database settings
	Database DatabaseConfig `json:"database"`

	// RPC settings
	RPC RPCConfig `json:"rpc"`

	// Mining settings
	Mining MiningConfig `json:"mining"`

	// Logging settings
	Logging LoggingConfig `json:"logging"`

	// Performance settings
	Performance PerformanceConfig `json:"performance"`
}

// NetworkConfig contains network-related settings
type NetworkConfig struct {
	Port      int      `json:"port"`      // P2P listening port
	MaxPeers  int      `json:"maxPeers"`  // Maximum peer connections
	BootNodes []string `json:"bootNodes"` // Bootstrap nodes
	NAT       string   `json:"nat"`       // NAT traversal method
	NetworkID uint64   `json:"networkId"` // Network ID
}

// DatabaseConfig contains database settings
type DatabaseConfig struct {
	DataDir                string `json:"dataDir"`    // Data directory
	Cache                  int    `json:"cache"`      // Cache size in MB
	Handles                int    `json:"handles"`    // Number of open file handles
	Sync                   bool   `json:"sync"`       // Synchronous writes
	GarbageCollectInterval int    `json:"gcInterval"` // GC interval in seconds
}

// RPCConfig contains RPC server settings
type RPCConfig struct {
	Enabled bool     `json:"enabled"` // Enable HTTP RPC
	Address string   `json:"address"` // Listen address
	Port    int      `json:"port"`    // Listen port
	CORS    []string `json:"cors"`    // CORS domains
	APIs    []string `json:"apis"`    // Enabled APIs

	WSEnabled bool   `json:"wsEnabled"` // Enable WebSocket RPC
	WSAddress string `json:"wsAddress"` // WebSocket address
	WSPort    int    `json:"wsPort"`    // WebSocket port
}

// MiningConfig contains mining settings
type MiningConfig struct {
	Enabled   bool   `json:"enabled"`   // Enable mining
	Threads   int    `json:"threads"`   // Mining threads
	Coinbase  string `json:"coinbase"`  // Coinbase address
	Etherbase string `json:"etherbase"` // Etherbase address (alternative name)
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string `json:"level"`      // Log level (trace, debug, info, warn, error)
	Format     string `json:"format"`     // Log format (json, text)
	File       string `json:"file"`       // Log file path (empty = stdout)
	MaxSize    int    `json:"maxSize"`    // Max log file size in MB
	MaxBackups int    `json:"maxBackups"` // Max backup files
	MaxAge     int    `json:"maxAge"`     // Max age in days
}

// PerformanceConfig contains performance tuning settings
type PerformanceConfig struct {
	TxPoolSize     int `json:"txPoolSize"`     // Transaction pool size
	BlockCacheSize int `json:"blockCacheSize"` // Block cache size
	TrieCacheSize  int `json:"trieCacheSize"`  // Trie cache size
	MaxBlockSize   int `json:"maxBlockSize"`   // Max block size in bytes
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			Port:      8333,
			MaxPeers:  50,
			BootNodes: []string{},
			NAT:       "any",
			NetworkID: 1,
		},
		Database: DatabaseConfig{
			DataDir:                "~/.obsidian",
			Cache:                  512,
			Handles:                4096,
			Sync:                   false,
			GarbageCollectInterval: 3600,
		},
		RPC: RPCConfig{
			Enabled:   true,
			Address:   "localhost",
			Port:      8545,
			CORS:      []string{"*"},
			APIs:      []string{"eth", "net", "web3", "obs", "personal"},
			WSEnabled: true,
			WSAddress: "localhost",
			WSPort:    8546,
		},
		Mining: MiningConfig{
			Enabled:  false,
			Threads:  0,
			Coinbase: "",
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			File:       "",
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     7,
		},
		Performance: PerformanceConfig{
			TxPoolSize:     10000,
			BlockCacheSize: 256,
			TrieCacheSize:  256,
			MaxBlockSize:   5 * 1024 * 1024, // 5MB
		},
	}
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(content, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// SaveConfig saves configuration to a JSON file
func (c *Config) SaveConfig(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	content, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, content, 0600)
}

// ExpandPath expands ~ to home directory
func ExpandPath(path string) (string, error) {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Network.Port <= 0 || c.Network.Port > 65535 {
		return ErrInvalidPort
	}

	if c.Network.MaxPeers < 0 {
		return ErrInvalidMaxPeers
	}

	if c.Database.Cache < 16 {
		c.Database.Cache = 16 // Minimum cache size
		log.Warn("Cache size too small, using minimum", "cache", 16)
	}

	if c.RPC.Port <= 0 || c.RPC.Port > 65535 {
		return ErrInvalidPort
	}

	if c.Mining.Threads < 0 {
		c.Mining.Threads = 0
	}

	return nil
}

// GetDataDir returns the expanded data directory path
func (c *Config) GetDataDir() (string, error) {
	return ExpandPath(c.Database.DataDir)
}

// GetLogFile returns the expanded log file path
func (c *Config) GetLogFile() (string, error) {
	if c.Logging.File == "" {
		return "", nil
	}
	return ExpandPath(c.Logging.File)
}

// Configuration errors
var (
	ErrInvalidPort     = NewConfigError("invalid port number")
	ErrInvalidMaxPeers = NewConfigError("invalid max peers value")
)

// ConfigError represents a configuration error
type ConfigError struct {
	message string
}

// NewConfigError creates a new config error
func NewConfigError(msg string) *ConfigError {
	return &ConfigError{message: msg}
}

// Error implements the error interface
func (e *ConfigError) Error() string {
	return e.message
}

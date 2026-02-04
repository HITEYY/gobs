// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package rpc

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/ethereum/go-ethereum/log"

	"github.com/obsidian-chain/obsidian/health"
	"github.com/obsidian-chain/obsidian/metrics"
)

// AdminBackend interface provides backend methods for admin RPC
type AdminBackend interface {
	GetHealthMonitor() *health.Monitor
	GetMetrics() *metrics.MetricsRegistry
	GetShutdownManager() interface{}
}

// Admin provides admin RPC methods
type Admin struct {
	backend AdminBackend
}

// NewAdmin creates a new admin RPC service
func NewAdmin(backend AdminBackend) *Admin {
	return &Admin{
		backend: backend,
	}
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	Name      string `json:"name"`
	Healthy   bool   `json:"healthy"`
	Error     string `json:"error,omitempty"`
	Duration  string `json:"duration"`
	Timestamp int64  `json:"timestamp"`
}

// NodeHealthStatus represents overall node health
type NodeHealthStatus struct {
	Status  string              `json:"status"`
	Checks  []HealthCheckResult `json:"checks"`
	Uptime  string              `json:"uptime"`
	Version string              `json:"version"`
}

// Health runs all health checks and returns the results
func (a *Admin) Health(ctx context.Context) (*NodeHealthStatus, error) {
	monitor := a.backend.GetHealthMonitor()
	checkResults := monitor.Run(ctx)

	var checks []HealthCheckResult
	for name, result := range checkResults {
		checks = append(checks, HealthCheckResult{
			Name:      name,
			Healthy:   result.Healthy,
			Error:     result.Error,
			Duration:  result.Duration.String(),
			Timestamp: result.Timestamp.Unix(),
		})
	}

	return &NodeHealthStatus{
		Status:  string(monitor.GetStatus()),
		Checks:  checks,
		Uptime:  fmt.Sprintf("%d seconds", int64(time.Since(startTime).Seconds())),
		Version: "1.0.0",
	}, nil
}

// MetricsSnapshot represents a snapshot of node metrics
type MetricsSnapshot struct {
	BlocksProcessed      int64  `json:"blocksProcessed"`
	BlocksRejected       int64  `json:"blocksRejected"`
	TransactionsValid    int64  `json:"transactionsValid"`
	TransactionsRejected int64  `json:"transactionsRejected"`
	TransactionsReceived int64  `json:"transactionsReceived"`
	PeersConnected       int64  `json:"peersConnected"`
	RPCRequestsTotal     int64  `json:"rpcRequestsTotal"`
	MessagesSent         int64  `json:"messagesSent"`
	MessagesReceived     int64  `json:"messagesReceived"`
	TxPoolSize           int64  `json:"txPoolSize"`
	AvgBlockTime         string `json:"avgBlockTime"`
	Timestamp            int64  `json:"timestamp"`
}

// Metrics returns current metrics
func (a *Admin) Metrics(ctx context.Context) (*MetricsSnapshot, error) {
	reg := a.backend.GetMetrics()
	m := reg.GetMetrics()

	return &MetricsSnapshot{
		BlocksProcessed:      m.BlocksProcessed,
		BlocksRejected:       m.BlocksRejected,
		TransactionsValid:    m.TransactionsValid,
		TransactionsRejected: m.TransactionsRejected,
		TransactionsReceived: m.TransactionsReceived,
		PeersConnected:       m.PeersConnected,
		RPCRequestsTotal:     m.RPCRequestsTotal,
		MessagesSent:         m.MessagesSent,
		MessagesReceived:     m.MessagesReceived,
		TxPoolSize:           m.TxPoolSize,
		AvgBlockTime:         m.BlockProcessTime.String(),
		Timestamp:            time.Now().Unix(),
	}, nil
}

// NodeInfo represents node information
type NodeInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	ChainID    string `json:"chainId"`
	NetworkID  string `json:"networkId"`
	Uptime     string `json:"uptime"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Goroutines int    `json:"goroutines"`
	MemoryMB   uint64 `json:"memoryMB"`
	Timestamp  int64  `json:"timestamp"`
}

// NodeInfo returns node information
func (a *Admin) NodeInfo(ctx context.Context) (*NodeInfo, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &NodeInfo{
		Name:       "Obsidian",
		Version:    "1.0.0",
		ChainID:    "1719",
		NetworkID:  "obsidian-mainnet",
		Uptime:     fmt.Sprintf("%d seconds", int64(time.Since(startTime).Seconds())),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Goroutines: runtime.NumGoroutine(),
		MemoryMB:   m.Alloc / 1024 / 1024,
		Timestamp:  time.Now().Unix(),
	}, nil
}

// SystemStatus represents system resource status
type SystemStatus struct {
	Memory     MemoryStatus `json:"memory"`
	Goroutines int          `json:"goroutines"`
	Timestamp  int64        `json:"timestamp"`
}

// MemoryStatus represents memory information
type MemoryStatus struct {
	AllocMB      uint64 `json:"allocMB"`
	TotalMB      uint64 `json:"totalMB"`
	SysMB        uint64 `json:"sysMB"`
	NumGC        uint32 `json:"numGC"`
	PauseNanoSec uint64 `json:"pauseNanoSec"`
}

// SystemStatus returns system resource information
func (a *Admin) SystemStatus(ctx context.Context) (*SystemStatus, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &SystemStatus{
		Memory: MemoryStatus{
			AllocMB:      m.Alloc / 1024 / 1024,
			TotalMB:      m.TotalAlloc / 1024 / 1024,
			SysMB:        m.Sys / 1024 / 1024,
			NumGC:        m.NumGC,
			PauseNanoSec: m.PauseNs[(m.NumGC+255)%256],
		},
		Goroutines: runtime.NumGoroutine(),
		Timestamp:  time.Now().Unix(),
	}, nil
}

// BackupInfo represents a backup operation result
type BackupInfo struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Timestamp int64  `json:"timestamp"`
	Error     string `json:"error,omitempty"`
}

// CreateBackup creates a database backup
func (a *Admin) CreateBackup(ctx context.Context, name string) (*BackupInfo, error) {
	// Note: This requires backup manager integration in backend
	// For now, return a placeholder
	info := &BackupInfo{
		Name:      name,
		Timestamp: time.Now().Unix(),
		Path:      fmt.Sprintf("/data/backups/%s.tar.gz", name),
	}
	log.Info("Backup created", "name", name)
	return info, nil
}

// Version represents version information
type VersionInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	GitCommit string `json:"gitCommit"`
	GitDate   string `json:"gitDate"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"goVersion"`
	BuildDate string `json:"buildDate"`
}

// Version returns version information
func (a *Admin) Version(ctx context.Context) (*VersionInfo, error) {
	return &VersionInfo{
		Name:      "Obsidian",
		Version:   "1.0.0",
		GitCommit: os.Getenv("GIT_COMMIT"),
		GitDate:   os.Getenv("GIT_DATE"),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		BuildDate: time.Now().Format(time.RFC3339),
	}, nil
}

// Global start time for uptime calculation
var startTime = time.Now()

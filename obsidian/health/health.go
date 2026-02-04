// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package health

import (
	"context"
	"math/big"
	"sync"
	"time"
)

// Status represents the health status of the node
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

// Check represents a single health check
type Check interface {
	Name() string
	Check(ctx context.Context) error
}

// CheckResult represents the result of a health check
type CheckResult struct {
	Name      string        `json:"name"`
	Healthy   bool          `json:"healthy"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// Monitor monitors node health
type Monitor struct {
	mu sync.RWMutex

	checks         map[string]Check
	lastResults    map[string]*CheckResult
	criticalChecks map[string]bool
	degradedChecks map[string]bool

	status Status
}

// New creates a new health monitor
func New() *Monitor {
	return &Monitor{
		checks:         make(map[string]Check),
		lastResults:    make(map[string]*CheckResult),
		criticalChecks: make(map[string]bool),
		degradedChecks: make(map[string]bool),
		status:         StatusHealthy,
	}
}

// Register registers a health check
func (m *Monitor) Register(check Check, critical bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := check.Name()
	m.checks[name] = check
	m.criticalChecks[name] = critical
}

// Run runs all health checks
func (m *Monitor) Run(ctx context.Context) map[string]*CheckResult {
	m.mu.RLock()
	checks := make(map[string]Check, len(m.checks))
	for name, check := range m.checks {
		checks[name] = check
	}
	m.mu.RUnlock()

	results := make(map[string]*CheckResult, len(checks))
	failed := 0
	degraded := 0

	for name, check := range checks {
		start := time.Now()

		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := check.Check(checkCtx)
		cancel()

		result := &CheckResult{
			Name:      name,
			Healthy:   err == nil,
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}

		if err != nil {
			result.Error = err.Error()
			if m.isCritical(name) {
				failed++
			} else {
				degraded++
			}
		}

		results[name] = result
	}

	// Update status
	m.updateStatus(failed, degraded)

	// Store results
	m.mu.Lock()
	m.lastResults = results
	m.mu.Unlock()

	return results
}

// GetStatus returns the current health status
func (m *Monitor) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// GetResults returns the last check results
func (m *Monitor) GetResults() map[string]*CheckResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make(map[string]*CheckResult, len(m.lastResults))
	for k, v := range m.lastResults {
		results[k] = v
	}
	return results
}

func (m *Monitor) isCritical(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.criticalChecks[name]
}

func (m *Monitor) updateStatus(failed, degraded int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if failed > 0 {
		m.status = StatusUnhealthy
	} else if degraded > 0 {
		m.status = StatusDegraded
	} else {
		m.status = StatusHealthy
	}
}

// Common health checks

// BlockchainCheck checks blockchain health
type BlockchainCheck struct {
	CurrentBlock  func() (uint64, error)
	LastBlockTime func() time.Time
}

// Name implements Check
func (c *BlockchainCheck) Name() string {
	return "blockchain"
}

// Check implements Check
func (c *BlockchainCheck) Check(ctx context.Context) error {
	blockNum, err := c.CurrentBlock()
	if err != nil {
		return err
	}

	// Check if blocks are being produced (not stalled)
	lastTime := c.LastBlockTime()
	if lastTime.IsZero() {
		return nil // Genesis block
	}

	age := time.Since(lastTime)
	if age > 5*time.Minute {
		return NewHealthError("no new blocks for 5 minutes")
	}

	if blockNum == 0 {
		return NewHealthError("blockchain not initialized")
	}

	return nil
}

// NetworkCheck checks network health
type NetworkCheck struct {
	PeerCount func() int
	MinPeers  int
}

// Name implements Check
func (c *NetworkCheck) Name() string {
	return "network"
}

// Check implements Check
func (c *NetworkCheck) Check(ctx context.Context) error {
	peers := c.PeerCount()
	if peers < c.MinPeers {
		return NewHealthError("insufficient peers")
	}
	return nil
}

// MemoryCheck checks memory health
type MemoryCheck struct {
	MemUsage func() (uint64, uint64) // (used, total)
	MaxUsage float64                 // percentage
}

// Name implements Check
func (c *MemoryCheck) Name() string {
	return "memory"
}

// Check implements Check
func (c *MemoryCheck) Check(ctx context.Context) error {
	used, total := c.MemUsage()
	if total == 0 {
		return nil
	}

	percent := float64(used) / float64(total) * 100
	if percent > c.MaxUsage {
		return NewHealthError("memory usage too high")
	}
	return nil
}

// DiskCheck checks disk health
type DiskCheck struct {
	DiskUsage func() (uint64, uint64) // (used, total)
	MaxUsage  float64                 // percentage
}

// Name implements Check
func (c *DiskCheck) Name() string {
	return "disk"
}

// Check implements Check
func (c *DiskCheck) Check(ctx context.Context) error {
	used, total := c.DiskUsage()
	if total == 0 {
		return nil
	}

	percent := float64(used) / float64(total) * 100
	if percent > c.MaxUsage {
		return NewHealthError("disk usage too high")
	}
	return nil
}

// TransactionPoolCheck checks transaction pool health
type TransactionPoolCheck struct {
	PoolSize func() int
	MaxSize  int
}

// Name implements Check
func (c *TransactionPoolCheck) Name() string {
	return "txpool"
}

// Check implements Check
func (c *TransactionPoolCheck) Check(ctx context.Context) error {
	size := c.PoolSize()
	if size > c.MaxSize {
		return NewHealthError("transaction pool full")
	}
	return nil
}

// SyncCheck checks synchronization health
type SyncCheck struct {
	IsSynced func() bool
	Progress func() (current, target *big.Int)
}

// Name implements Check
func (c *SyncCheck) Name() string {
	return "sync"
}

// Check implements Check
func (c *SyncCheck) Check(ctx context.Context) error {
	if !c.IsSynced() {
		current, target := c.Progress()
		if target != nil && current != nil {
			return NewHealthError("not synced")
		}
	}
	return nil
}

// HealthError represents a health check error
type HealthError struct {
	message string
}

// NewHealthError creates a new health error
func NewHealthError(msg string) *HealthError {
	return &HealthError{message: msg}
}

// Error implements the error interface
func (e *HealthError) Error() string {
	return e.message
}

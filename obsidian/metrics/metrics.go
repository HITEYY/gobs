// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds all system metrics
type Metrics struct {
	// Block metrics
	BlocksProcessed  int64
	BlocksRejected   int64
	BlockProcessTime time.Duration
	LastBlockTime    time.Time

	// Transaction metrics
	TransactionsReceived int64
	TransactionsValid    int64
	TransactionsRejected int64
	TxPoolSize           int64
	TxPoolCap            int64

	// Network metrics
	PeersConnected   int64
	BytesIn          int64
	BytesOut         int64
	MessagesSent     int64
	MessagesReceived int64

	// RPC metrics
	RPCRequestsTotal   int64
	RPCRequestsActive  int64
	RPCErrors          int64
	RPCLastRequestTime time.Time

	// State metrics
	StateObjects    int64
	StateTrieSize   int64
	AccountsTracked int64

	// Mining metrics
	HashesPerSecond  float64
	MinedBlocks      int64
	DifficultyTarget string

	// System metrics
	MemoryAllocated uint64
	MemoryTotal     uint64
	GoroutinesCount int
	CPUPercent      float64
}

// Counter is an atomic counter
type Counter struct {
	value int64
}

// NewCounter creates a new counter
func NewCounter() *Counter {
	return &Counter{}
}

// Inc increments the counter
func (c *Counter) Inc() {
	atomic.AddInt64(&c.value, 1)
}

// Add adds a value to the counter
func (c *Counter) Add(n int64) {
	atomic.AddInt64(&c.value, n)
}

// Get returns the current value
func (c *Counter) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

// Reset resets the counter
func (c *Counter) Reset() {
	atomic.StoreInt64(&c.value, 0)
}

// Gauge is an atomic gauge
type Gauge struct {
	value int64
}

// NewGauge creates a new gauge
func NewGauge() *Gauge {
	return &Gauge{}
}

// Set sets the gauge value
func (g *Gauge) Set(v int64) {
	atomic.StoreInt64(&g.value, v)
}

// Get returns the current value
func (g *Gauge) Get() int64 {
	return atomic.LoadInt64(&g.value)
}

// Histogram tracks value distributions
type Histogram struct {
	mu     sync.RWMutex
	values []int64
	sum    int64
	count  int64
	min    int64
	max    int64
}

// NewHistogram creates a new histogram
func NewHistogram() *Histogram {
	return &Histogram{
		values: make([]int64, 0, 1000),
		min:    int64(^uint64(0) >> 1),
		max:    0,
	}
}

// Record records a value
func (h *Histogram) Record(v int64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.values = append(h.values, v)
	h.sum += v
	h.count++

	if v < h.min {
		h.min = v
	}
	if v > h.max {
		h.max = v
	}

	// Keep only last 1000 values to limit memory
	if len(h.values) > 1000 {
		h.values = h.values[len(h.values)-1000:]
	}
}

// Mean returns the mean value
func (h *Histogram) Mean() float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.count == 0 {
		return 0
	}
	return float64(h.sum) / float64(h.count)
}

// Min returns the minimum value
func (h *Histogram) Min() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.min
}

// Max returns the maximum value
func (h *Histogram) Max() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.max
}

// Count returns the number of recorded values
func (h *Histogram) Count() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.count
}

// MetricsRegistry holds all metrics
type MetricsRegistry struct {
	mu sync.RWMutex

	BlocksProcessed  *Counter
	BlocksRejected   *Counter
	TxReceived       *Counter
	TxValid          *Counter
	TxRejected       *Counter
	PeersConnected   *Gauge
	RPCRequests      *Counter
	BlockProcessTime *Histogram
	TxPoolSize       *Gauge
	MessagesSent     *Counter
	MessagesReceived *Counter

	startTime   time.Time
	lastMetrics *Metrics
}

// NewMetricsRegistry creates a new metrics registry
func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		BlocksProcessed:  NewCounter(),
		BlocksRejected:   NewCounter(),
		TxReceived:       NewCounter(),
		TxValid:          NewCounter(),
		TxRejected:       NewCounter(),
		PeersConnected:   NewGauge(),
		RPCRequests:      NewCounter(),
		BlockProcessTime: NewHistogram(),
		TxPoolSize:       NewGauge(),
		MessagesSent:     NewCounter(),
		MessagesReceived: NewCounter(),
		startTime:        time.Now(),
		lastMetrics:      &Metrics{},
	}
}

// GetMetrics returns a snapshot of current metrics
func (mr *MetricsRegistry) GetMetrics() *Metrics {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	return &Metrics{
		BlocksProcessed:      mr.BlocksProcessed.Get(),
		BlocksRejected:       mr.BlocksRejected.Get(),
		TransactionsValid:    mr.TxValid.Get(),
		TransactionsRejected: mr.TxRejected.Get(),
		TransactionsReceived: mr.TxReceived.Get(),
		PeersConnected:       mr.PeersConnected.Get(),
		RPCRequestsTotal:     mr.RPCRequests.Get(),
		MessagesSent:         mr.MessagesSent.Get(),
		MessagesReceived:     mr.MessagesReceived.Get(),
		TxPoolSize:           mr.TxPoolSize.Get(),
		BlockProcessTime:     time.Duration(int64(mr.BlockProcessTime.Mean())) * time.Millisecond,
		LastBlockTime:        time.Now(),
	}
}

// Reset resets all metrics
func (mr *MetricsRegistry) Reset() {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	mr.BlocksProcessed.Reset()
	mr.BlocksRejected.Reset()
	mr.TxReceived.Reset()
	mr.TxValid.Reset()
	mr.TxRejected.Reset()
	mr.RPCRequests.Reset()
	mr.MessagesSent.Reset()
	mr.MessagesReceived.Reset()
}

// Global metrics registry
var globalRegistry = NewMetricsRegistry()

// GetGlobalRegistry returns the global metrics registry
func GetGlobalRegistry() *MetricsRegistry {
	return globalRegistry
}

// Convenience functions using global registry

// RecordBlockProcessed records a processed block
func RecordBlockProcessed() {
	globalRegistry.BlocksProcessed.Inc()
}

// RecordBlockRejected records a rejected block
func RecordBlockRejected() {
	globalRegistry.BlocksRejected.Inc()
}

// RecordTransaction records a received transaction
func RecordTransaction() {
	globalRegistry.TxReceived.Inc()
}

// RecordValidTransaction records a valid transaction
func RecordValidTransaction() {
	globalRegistry.TxValid.Inc()
}

// RecordRejectedTransaction records a rejected transaction
func RecordRejectedTransaction() {
	globalRegistry.TxRejected.Inc()
}

// SetPeersConnected sets the number of connected peers
func SetPeersConnected(count int64) {
	globalRegistry.PeersConnected.Set(count)
}

// RecordRPCRequest records an RPC request
func RecordRPCRequest() {
	globalRegistry.RPCRequests.Inc()
}

// SetTxPoolSize sets the transaction pool size
func SetTxPoolSize(size int64) {
	globalRegistry.TxPoolSize.Set(size)
}

// RecordMessageSent records a sent message
func RecordMessageSent() {
	globalRegistry.MessagesSent.Inc()
}

// RecordMessageReceived records a received message
func RecordMessageReceived() {
	globalRegistry.MessagesReceived.Inc()
}

// RecordBlockProcessTime records block processing time
func RecordBlockProcessTime(duration time.Duration) {
	globalRegistry.BlockProcessTime.Record(int64(duration.Milliseconds()))
}

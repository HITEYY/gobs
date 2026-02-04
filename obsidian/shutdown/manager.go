// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package shutdown

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// Manager handles graceful shutdown
type Manager struct {
	mu sync.RWMutex

	// State
	shutting int32 // atomic flag
	done     chan struct{}
	handlers []Handler
	timeout  time.Duration

	// Signal handling
	sigChan chan os.Signal
	stop    chan struct{}
}

// Handler is a shutdown handler
type Handler interface {
	Name() string
	Shutdown(ctx context.Context) error
}

// New creates a new shutdown manager
func New(timeout time.Duration) *Manager {
	return &Manager{
		done:    make(chan struct{}),
		timeout: timeout,
		sigChan: make(chan os.Signal, 1),
		stop:    make(chan struct{}),
	}
}

// Register registers a shutdown handler
func (m *Manager) Register(h Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if atomic.LoadInt32(&m.shutting) != 0 {
		log.Warn("Cannot register handler during shutdown", "handler", h.Name())
		return
	}

	m.handlers = append(m.handlers, h)
	log.Debug("Shutdown handler registered", "handler", h.Name())
}

// IsStopping returns true if shutdown has been initiated
func (m *Manager) IsStopping() bool {
	return atomic.LoadInt32(&m.shutting) != 0
}

// Notify notifies about a shutdown signal
func (m *Manager) Notify(sig os.Signal) {
	select {
	case m.sigChan <- sig:
	default:
	}
}

// Start starts listening for signals
func (m *Manager) Start() {
	go m.run()
}

// run is the main signal handling loop
func (m *Manager) run() {
	signal.Notify(m.sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case sig := <-m.sigChan:
			log.Info("Shutdown signal received", "signal", sig)
			m.doShutdown()
			return
		case <-m.stop:
			return
		}
	}
}

// Shutdown triggers a graceful shutdown
func (m *Manager) Shutdown(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&m.shutting, 0, 1) {
		log.Warn("Shutdown already in progress")
		return nil
	}

	log.Info("Starting graceful shutdown", "timeout", m.timeout)

	// Create a timeout context if none provided
	if ctx == nil || ctx.Done() == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), m.timeout)
		defer cancel()
	}

	return m.executeHandlers(ctx)
}

// doShutdown performs the actual shutdown
func (m *Manager) doShutdown() {
	if !atomic.CompareAndSwapInt32(&m.shutting, 0, 1) {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	_ = m.executeHandlers(ctx)
	close(m.done)
}

// executeHandlers executes all registered handlers
func (m *Manager) executeHandlers(ctx context.Context) error {
	m.mu.RLock()
	handlers := make([]Handler, len(m.handlers))
	copy(handlers, m.handlers)
	m.mu.RUnlock()

	// Execute handlers in reverse order (LIFO)
	for i := len(handlers) - 1; i >= 0; i-- {
		h := handlers[i]
		log.Info("Shutting down", "handler", h.Name())

		select {
		case <-ctx.Done():
			log.Warn("Shutdown timeout, forcing exit", "handler", h.Name())
			return ctx.Err()
		default:
		}

		// Execute with individual timeout
		handlerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := h.Shutdown(handlerCtx)
		cancel()

		if err != nil {
			log.Error("Shutdown error", "handler", h.Name(), "err", err)
		} else {
			log.Info("Shutdown complete", "handler", h.Name())
		}
	}

	return nil
}

// Stop stops the signal listening
func (m *Manager) Stop() {
	close(m.stop)
}

// Wait waits for shutdown to complete
func (m *Manager) Wait() {
	<-m.done
}

// ShutdownableComponent is an interface for components that need graceful shutdown
type ShutdownableComponent interface {
	Shutdown(ctx context.Context) error
}

// SimpleHandler is a simple handler wrapper
type SimpleHandler struct {
	name string
	fn   func(context.Context) error
}

// NewSimpleHandler creates a simple handler
func NewSimpleHandler(name string, fn func(context.Context) error) *SimpleHandler {
	return &SimpleHandler{
		name: name,
		fn:   fn,
	}
}

// Name returns the handler name
func (h *SimpleHandler) Name() string {
	return h.name
}

// Shutdown executes the handler
func (h *SimpleHandler) Shutdown(ctx context.Context) error {
	return h.fn(ctx)
}

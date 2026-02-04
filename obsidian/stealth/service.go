// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package stealth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

var (
	ErrScannerExists   = errors.New("scanner already exists for this address")
	ErrScannerNotFound = errors.New("scanner not found for this address")
	ErrBackendRequired = errors.New("blockchain backend required")
	ErrKeysRequired    = errors.New("view and spend keys required")
)

// StealthService manages multiple stealth address scanners
type StealthService struct {
	mu       sync.RWMutex
	scanners map[common.Address]*Scanner // keyed by spend public key address
	backend  BlockchainBackend

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewStealthService creates a new stealth service
func NewStealthService() *StealthService {
	return &StealthService{
		scanners: make(map[common.Address]*Scanner),
		stopCh:   make(chan struct{}),
	}
}

// SetBackend sets the blockchain backend for scanning
func (s *StealthService) SetBackend(backend BlockchainBackend) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backend = backend
}

// RegisterScanner registers a new scanner for the given keys
func (s *StealthService) RegisterScanner(viewPrivKey, spendPrivKey *ecdsa.PrivateKey) (common.Address, error) {
	if viewPrivKey == nil || spendPrivKey == nil {
		return common.Address{}, ErrKeysRequired
	}

	// Use spend public key address as identifier
	scannerID := PublicKeyToAddress(&spendPrivKey.PublicKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.scanners[scannerID]; exists {
		return scannerID, ErrScannerExists
	}

	scanner := NewScanner(viewPrivKey, spendPrivKey)
	s.scanners[scannerID] = scanner

	log.Info("Stealth scanner registered", "id", scannerID.Hex())
	return scannerID, nil
}

// UnregisterScanner removes a scanner
func (s *StealthService) UnregisterScanner(scannerID common.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.scanners[scannerID]; !exists {
		return ErrScannerNotFound
	}

	delete(s.scanners, scannerID)
	log.Info("Stealth scanner unregistered", "id", scannerID.Hex())
	return nil
}

// GetScanner returns a scanner by ID
func (s *StealthService) GetScanner(scannerID common.Address) (*Scanner, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scanner, exists := s.scanners[scannerID]
	if !exists {
		return nil, ErrScannerNotFound
	}
	return scanner, nil
}

// ListScanners returns all registered scanner IDs
func (s *StealthService) ListScanners() []common.Address {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]common.Address, 0, len(s.scanners))
	for id := range s.scanners {
		ids = append(ids, id)
	}
	return ids
}

// ScanBlocks scans a range of blocks for all registered scanners
func (s *StealthService) ScanBlocks(ctx context.Context, fromBlock, toBlock uint64) (map[common.Address][]*StealthPayment, error) {
	s.mu.RLock()
	backend := s.backend
	scanners := make(map[common.Address]*Scanner, len(s.scanners))
	for id, scanner := range s.scanners {
		scanners[id] = scanner
	}
	s.mu.RUnlock()

	if backend == nil {
		return nil, ErrBackendRequired
	}

	results := make(map[common.Address][]*StealthPayment)

	for blockNum := fromBlock; blockNum <= toBlock; blockNum++ {
		// Get stealth transactions from block
		txs, err := backend.GetStealthTransactions(ctx, blockNum)
		if err != nil {
			log.Warn("Failed to get stealth txs", "block", blockNum, "err", err)
			continue
		}

		if len(txs) == 0 {
			continue
		}

		// Scan with each scanner
		for id, scanner := range scanners {
			payments := scanner.ScanBlock(blockNum, txs)
			if len(payments) > 0 {
				results[id] = append(results[id], payments...)
			}
		}
	}

	return results, nil
}

// ScanSingleBlock scans a single block for all scanners
func (s *StealthService) ScanSingleBlock(ctx context.Context, blockNum uint64) (map[common.Address][]*StealthPayment, error) {
	return s.ScanBlocks(ctx, blockNum, blockNum)
}

// GetPayments returns all payments for a scanner
func (s *StealthService) GetPayments(scannerID common.Address) ([]*StealthPayment, error) {
	scanner, err := s.GetScanner(scannerID)
	if err != nil {
		return nil, err
	}
	return scanner.GetPayments(), nil
}

// GetTotalBalance returns the total balance for a scanner
func (s *StealthService) GetTotalBalance(scannerID common.Address) (string, error) {
	scanner, err := s.GetScanner(scannerID)
	if err != nil {
		return "0", err
	}
	return scanner.TotalBalance().String(), nil
}

// StartAutoScan starts automatic scanning for new blocks
func (s *StealthService) StartAutoScan(ctx context.Context) error {
	s.mu.RLock()
	backend := s.backend
	s.mu.RUnlock()

	if backend == nil {
		return ErrBackendRequired
	}

	s.wg.Add(1)
	go s.autoScanLoop(ctx)
	log.Info("Stealth auto-scan started")
	return nil
}

// Stop stops all scanning
func (s *StealthService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	log.Info("Stealth service stopped")
}

func (s *StealthService) autoScanLoop(ctx context.Context) {
	defer s.wg.Done()

	newBlocks := make(chan uint64, 100)

	// Start block subscription
	go func() {
		s.mu.RLock()
		backend := s.backend
		s.mu.RUnlock()

		if backend != nil {
			_ = backend.SubscribeNewBlocks(ctx, newBlocks)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case blockNum := <-newBlocks:
			results, err := s.ScanSingleBlock(ctx, blockNum)
			if err != nil {
				log.Warn("Auto-scan failed", "block", blockNum, "err", err)
				continue
			}

			// Log any found payments
			for scannerID, payments := range results {
				for _, payment := range payments {
					log.Info("Stealth payment detected",
						"scanner", scannerID.Hex(),
						"tx", payment.TxHash.Hex(),
						"address", payment.StealthAddress.Hex(),
						"amount", payment.Amount,
					)
				}
			}
		}
	}
}

// ScanResult represents the result of scanning for a specific scanner
type ScanResult struct {
	ScannerID   common.Address    `json:"scannerId"`
	Payments    []*StealthPayment `json:"payments"`
	TotalAmount string            `json:"totalAmount"`
	BlocksFrom  uint64            `json:"blocksFrom"`
	BlocksTo    uint64            `json:"blocksTo"`
}

// ScanForPayments is a convenience method that scans blocks and returns results
func (s *StealthService) ScanForPayments(ctx context.Context, scannerID common.Address, fromBlock, toBlock uint64) (*ScanResult, error) {
	scanner, err := s.GetScanner(scannerID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	backend := s.backend
	s.mu.RUnlock()

	if backend == nil {
		return nil, ErrBackendRequired
	}

	var newPayments []*StealthPayment

	for blockNum := fromBlock; blockNum <= toBlock; blockNum++ {
		txs, err := backend.GetStealthTransactions(ctx, blockNum)
		if err != nil {
			continue
		}
		if len(txs) > 0 {
			payments := scanner.ScanBlock(blockNum, txs)
			newPayments = append(newPayments, payments...)
		}
	}

	return &ScanResult{
		ScannerID:   scannerID,
		Payments:    newPayments,
		TotalAmount: scanner.TotalBalance().String(),
		BlocksFrom:  fromBlock,
		BlocksTo:    toBlock,
	}, nil
}

// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package stealth

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Scanner scans the blockchain for stealth payments to the owner
type Scanner struct {
	mu sync.RWMutex

	// Keys for scanning
	viewPrivKey  *ecdsa.PrivateKey
	spendPrivKey *ecdsa.PrivateKey
	spendPubKey  *ecdsa.PublicKey

	// Detected payments
	payments []*StealthPayment

	// Scanning state
	lastScannedBlock uint64
}

// NewScanner creates a new stealth address scanner
func NewScanner(viewPrivKey, spendPrivKey *ecdsa.PrivateKey) *Scanner {
	return &Scanner{
		viewPrivKey:  viewPrivKey,
		spendPrivKey: spendPrivKey,
		spendPubKey:  &spendPrivKey.PublicKey,
		payments:     make([]*StealthPayment, 0),
	}
}

// ScanBlock scans a block for stealth payments
// stealthTxs should be a list of stealth transaction data from the block
func (s *Scanner) ScanBlock(blockNumber uint64, stealthTxs []StealthTxData) []*StealthPayment {
	s.mu.Lock()
	defer s.mu.Unlock()

	var found []*StealthPayment

	for _, tx := range stealthTxs {
		// Quick view tag filter
		if !s.checkViewTag(tx.EphemeralPubKey, tx.ViewTag) {
			continue
		}

		// Full address derivation check
		isOurs, privKey, stealthAddr := s.checkAndDerive(tx.EphemeralPubKey, tx.ToAddress)
		if !isOurs {
			continue
		}

		payment := &StealthPayment{
			TxHash:          tx.TxHash,
			BlockNumber:     blockNumber,
			StealthAddress:  stealthAddr,
			EphemeralPubKey: tx.EphemeralPubKey,
			Amount:          tx.Amount,
			PrivateKey:      privKey,
		}

		found = append(found, payment)
		s.payments = append(s.payments, payment)
	}

	s.lastScannedBlock = blockNumber
	return found
}

// StealthTxData represents the stealth-specific data from a transaction
type StealthTxData struct {
	TxHash          common.Hash
	ToAddress       common.Address
	EphemeralPubKey []byte
	ViewTag         byte
	Amount          string
}

// checkViewTag performs a quick view tag check
func (s *Scanner) checkViewTag(ephemeralPubKey []byte, viewTag byte) bool {
	ephPubKey, err := DecompressPublicKey(ephemeralPubKey)
	if err != nil {
		return false
	}

	sharedSecret := SharedSecret(s.viewPrivKey, ephPubKey)
	computedTag := computeViewTag(sharedSecret)

	return computedTag == viewTag
}

// checkAndDerive checks if we're the recipient and derives the private key
func (s *Scanner) checkAndDerive(ephemeralPubKey []byte, expectedAddr common.Address) (bool, *ecdsa.PrivateKey, common.Address) {
	ephPubKey, err := DecompressPublicKey(ephemeralPubKey)
	if err != nil {
		return false, nil, common.Address{}
	}

	// Compute shared secret
	sharedSecret := SharedSecret(s.viewPrivKey, ephPubKey)

	// Derive stealth public key
	stealthPubKey := DeriveStealthPublicKey(s.spendPubKey, sharedSecret)
	derivedAddr := PublicKeyToAddress(stealthPubKey)

	// Check if address matches
	if derivedAddr != expectedAddr {
		return false, nil, common.Address{}
	}

	// Derive private key
	stealthPrivKey := DeriveStealthPrivateKey(s.spendPrivKey, sharedSecret)

	return true, stealthPrivKey, derivedAddr
}

// computeViewTag computes the view tag from shared secret
func computeViewTag(sharedSecret []byte) byte {
	// Use first byte of keccak256(sharedSecret) as view tag
	hash := keccak256(sharedSecret)
	return hash[0]
}

// keccak256 computes the Keccak-256 hash
func keccak256(data []byte) []byte {
	return crypto.Keccak256(data)
}

// GetPayments returns all detected payments
func (s *Scanner) GetPayments() []*StealthPayment {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*StealthPayment, len(s.payments))
	copy(result, s.payments)
	return result
}

// GetPaymentsByAddress returns payments to a specific stealth address
func (s *Scanner) GetPaymentsByAddress(addr common.Address) []*StealthPayment {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*StealthPayment
	for _, p := range s.payments {
		if p.StealthAddress == addr {
			result = append(result, p)
		}
	}
	return result
}

// LastScannedBlock returns the last scanned block number
func (s *Scanner) LastScannedBlock() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastScannedBlock
}

// TotalBalance calculates the total balance of all detected payments
func (s *Scanner) TotalBalance() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := big.NewInt(0)
	for _, p := range s.payments {
		amount, ok := new(big.Int).SetString(p.Amount, 10)
		if ok {
			total.Add(total, amount)
		}
	}
	return total
}

// BlockScanner provides a higher-level interface for continuous scanning
type BlockScanner struct {
	scanner *Scanner
	backend BlockchainBackend

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// BlockchainBackend is the interface for blockchain data access
type BlockchainBackend interface {
	// GetStealthTransactions returns stealth transactions in a block
	GetStealthTransactions(ctx context.Context, blockNumber uint64) ([]StealthTxData, error)
	// CurrentBlock returns the current block number
	CurrentBlock(ctx context.Context) (uint64, error)
	// SubscribeNewBlocks subscribes to new block events
	SubscribeNewBlocks(ctx context.Context, ch chan<- uint64) error
}

// NewBlockScanner creates a new block scanner
func NewBlockScanner(scanner *Scanner, backend BlockchainBackend) *BlockScanner {
	return &BlockScanner{
		scanner: scanner,
		backend: backend,
		stopCh:  make(chan struct{}),
	}
}

// Start starts continuous scanning
func (bs *BlockScanner) Start(ctx context.Context, startBlock uint64) error {
	bs.wg.Add(1)
	go bs.scanLoop(ctx, startBlock)
	return nil
}

// Stop stops the scanner
func (bs *BlockScanner) Stop() {
	close(bs.stopCh)
	bs.wg.Wait()
}

// scanLoop is the main scanning loop
func (bs *BlockScanner) scanLoop(ctx context.Context, startBlock uint64) {
	defer bs.wg.Done()

	currentBlock := startBlock
	newBlocks := make(chan uint64, 10)

	// Subscribe to new blocks
	go func() { _ = bs.backend.SubscribeNewBlocks(ctx, newBlocks) }()

	for {
		select {
		case <-ctx.Done():
			return
		case <-bs.stopCh:
			return
		case newBlock := <-newBlocks:
			// Scan any missed blocks
			for b := currentBlock; b <= newBlock; b++ {
				txs, err := bs.backend.GetStealthTransactions(ctx, b)
				if err != nil {
					continue
				}
				bs.scanner.ScanBlock(b, txs)
			}
			currentBlock = newBlock + 1
		}
	}
}

// GetLastScannedBlock returns the last scanned block number
func (bs *BlockScanner) GetLastScannedBlock() uint64 {
	return bs.scanner.LastScannedBlock()
}

// GetDetectedPayments returns all payments detected by the scanner
func (bs *BlockScanner) GetDetectedPayments() []*StealthPayment {
	return bs.scanner.GetPayments()
}

// GetTotalBalance returns the total balance of all detected payments
func (bs *BlockScanner) GetTotalBalance() *big.Int {
	return bs.scanner.TotalBalance()
}


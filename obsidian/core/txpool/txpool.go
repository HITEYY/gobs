// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package txpool

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/obsidian-chain/obsidian/core/state"
	obstypes "github.com/obsidian-chain/obsidian/core/types"
)

var (
	// ErrInvalidSender is returned when the transaction contains an invalid signature
	ErrInvalidSender = errors.New("invalid sender")
	// ErrNonceTooLow is returned when a transaction's nonce is lower than expected
	ErrNonceTooLow = errors.New("nonce too low")
	// ErrUnderpriced is returned when a transaction's gas price is below the minimum
	ErrUnderpriced = errors.New("transaction underpriced")
	// ErrTxPoolOverflow is returned when the pool is full
	ErrTxPoolOverflow = errors.New("txpool is full")
	// ErrReplaceUnderpriced is returned when a replacement transaction's gas price is too low
	ErrReplaceUnderpriced = errors.New("replacement transaction underpriced")
	// ErrInsufficientFunds is returned when the sender has insufficient funds
	ErrInsufficientFunds = errors.New("insufficient funds for gas * price + value")
	// ErrGasLimit is returned when the gas limit is too low
	ErrGasLimit = errors.New("exceeds block gas limit")
	// ErrNegativeValue is returned when a transaction has a negative value
	ErrNegativeValue = errors.New("negative value")
	// ErrOversizedData is returned when a transaction's data is too large
	ErrOversizedData = errors.New("oversized data")
	// ErrAlreadyKnown is returned when a transaction is already in the pool
	ErrAlreadyKnown = errors.New("already known")
)

// Config contains the configuration for the transaction pool
type Config struct {
	Journal      string        // Path to the transaction journal file
	Rejournal    time.Duration // Time interval to regenerate the journal
	PriceLimit   uint64        // Minimum gas price to accept
	PriceBump    uint64        // Minimum price bump percentage
	AccountSlots uint64        // Minimum number of executable transaction slots
	GlobalSlots  uint64        // Maximum number of executable transaction slots
	AccountQueue uint64        // Maximum number of non-executable transaction slots
	GlobalQueue  uint64        // Maximum number of non-executable transaction slots
	Lifetime     time.Duration // Maximum duration for non-executable transactions
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		Journal:      "transactions.rlp",
		Rejournal:    time.Hour,
		PriceLimit:   1,
		PriceBump:    10,
		AccountSlots: 16,
		GlobalSlots:  4096,
		AccountQueue: 64,
		GlobalQueue:  1024,
		Lifetime:     3 * time.Hour,
	}
}

// TxStatus represents the status of a transaction in the pool
type TxStatus uint

const (
	TxStatusUnknown TxStatus = iota
	TxStatusQueued
	TxStatusPending
	TxStatusIncluded
)

// BlockChain defines the interface for blockchain interaction
type BlockChain interface {
	CurrentBlock() *obstypes.ObsidianHeader
	GetBlock(hash common.Hash, number uint64) *obstypes.ObsidianBlock
	StateAt(root common.Hash) (state.StateDBInterface, error)
}

// TxPool contains all the pending transactions
type TxPool struct {
	config Config
	chain  BlockChain

	signer obstypes.StealthSigner
	mu     sync.RWMutex

	pending map[common.Address]*txList // All currently processable transactions
	queue   map[common.Address]*txList // Queued but non-processable transactions

	all    *txLookup // All transactions in the pool
	priced *txPricedList

	chainHeadCh chan *obstypes.ObsidianBlock

	reqResetCh      chan *txPoolResetRequest
	reqPromoteCh    chan *accountSet
	queueTxEventCh  chan *obstypes.StealthTransaction
	reorgDoneCh     chan chan struct{}
	reorgShutdownCh chan struct{}

	wg sync.WaitGroup

	gasPrice *big.Int
}

// txPoolResetRequest is used to reset the pool
type txPoolResetRequest struct {
	oldHead, newHead *obstypes.ObsidianHeader
}

// NewTxPool creates a new transaction pool
func NewTxPool(config Config, chain BlockChain, signer obstypes.StealthSigner) *TxPool {
	pool := &TxPool{
		config:          config,
		chain:           chain,
		signer:          signer,
		pending:         make(map[common.Address]*txList),
		queue:           make(map[common.Address]*txList),
		all:             newTxLookup(),
		priced:          newTxPricedList(nil),
		chainHeadCh:     make(chan *obstypes.ObsidianBlock, 10),
		reqResetCh:      make(chan *txPoolResetRequest),
		reqPromoteCh:    make(chan *accountSet),
		queueTxEventCh:  make(chan *obstypes.StealthTransaction),
		reorgDoneCh:     make(chan chan struct{}),
		reorgShutdownCh: make(chan struct{}),
		gasPrice:        big.NewInt(int64(config.PriceLimit)),
	}

	pool.wg.Add(1)
	go pool.loop()

	return pool
}

// loop is the main processing loop
func (pool *TxPool) loop() {
	defer pool.wg.Done()

	var (
		curDone       chan struct{}
		nextDone      = make(chan struct{})
		launchNextRun bool
		reset         *txPoolResetRequest
	)

	for {
		// Launch next background reorg if needed
		if curDone == nil && launchNextRun {
			go pool.runReorg(nextDone, reset, nil, nil)
			curDone, nextDone = nextDone, make(chan struct{})
			launchNextRun = false
			reset = nil
		}

		select {
		case req := <-pool.reqResetCh:
			if reset == nil {
				reset = req
			} else {
				reset.newHead = req.newHead
			}
			launchNextRun = true

		case req := <-pool.reqPromoteCh:
			_ = req
			launchNextRun = true

		case tx := <-pool.queueTxEventCh:
			_ = tx

		case <-curDone:
			curDone = nil

		case <-pool.reorgShutdownCh:
			if curDone != nil {
				<-curDone
			}
			close(nextDone)
			return
		}
	}
}

// runReorg runs the reorg process
func (pool *TxPool) runReorg(done chan struct{}, reset *txPoolResetRequest, dirtyAccounts *accountSet, events map[common.Address]*txSortedMap) {
	defer close(done)

	var (
		promoteAddrs []common.Address
		promoted     []*obstypes.StealthTransaction
	)

	// Placeholder for future promoted transactions logging

	// Reset if requested
	if reset != nil {
		pool.reset(reset.oldHead, reset.newHead)
	}

	// Promote transactions from queue to pending
	if dirtyAccounts != nil {
		promoteAddrs = dirtyAccounts.flatten()
	}
	if promoteAddrs != nil {
		promoted = pool.promoteExecutables(promoteAddrs)
	}

	_ = promoted
}

// reset resets the pool to a new head
func (pool *TxPool) reset(oldHead, newHead *obstypes.ObsidianHeader) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Discard all transactions from old blocks that are not in new chain
	// and reinject valid transactions
}

// promoteExecutables promotes transactions from queue to pending
func (pool *TxPool) promoteExecutables(accounts []common.Address) []*obstypes.StealthTransaction {
	var promoted []*obstypes.StealthTransaction

	for _, addr := range accounts {
		list := pool.queue[addr]
		if list == nil {
			continue
		}

		// Promote all valid transactions
		for _, tx := range list.Flatten() {
			hash := tx.Hash()
			if pool.pending[addr] == nil {
				pool.pending[addr] = newTxList(true)
			}
			pool.pending[addr].Add(tx, pool.config.PriceBump)
			pool.all.Add(tx)
			promoted = append(promoted, tx)
			log.Trace("Promoted queued transaction", "hash", hash)
		}

		// Delete the list if it's empty
		if list.Empty() {
			delete(pool.queue, addr)
		}
	}

	return promoted
}

// Add adds a transaction to the pool
func (pool *TxPool) Add(tx *obstypes.StealthTransaction, local bool) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.add(tx, local)
}

// add adds a transaction to the pool (must be called with lock held)
func (pool *TxPool) add(tx *obstypes.StealthTransaction, local bool) error {
	// Validate basic transaction fields
	if err := tx.ValidateBasic(); err != nil {
		return err
	}

	// Check if already known
	hash := tx.Hash()
	if pool.all.Get(hash) != nil {
		return ErrAlreadyKnown
	}

	// Validate the transaction sender via signature recovery
	from, err := pool.signer.Sender(tx)
	if err != nil {
		return ErrInvalidSender
	}

	// Get current state for balance/nonce checks
	currentHead := pool.chain.CurrentBlock()
	stateDB, err := pool.chain.StateAt(currentHead.Root)
	if err != nil {
		log.Error("Failed to get state for tx validation", "err", err)
		return err
	}

	// Check nonce - must be >= current nonce
	currentNonce := stateDB.GetNonce(from)
	if tx.Nonce() < currentNonce {
		return ErrNonceTooLow
	}

	// Check balance - must have enough for gas * price + value
	balance := stateDB.GetBalance(from)
	gasPrice := tx.GasPrice()
	if gasPrice == nil {
		gasPrice = big.NewInt(0)
	}
	cost := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(tx.Gas()))
	if tx.Value() != nil {
		cost.Add(cost, tx.Value())
	}
	if balance.Cmp(cost) < 0 {
		return ErrInsufficientFunds
	}

	// Check gas limit against block gas limit
	if tx.Gas() > currentHead.GasLimit {
		return ErrGasLimit
	}

	// Check gas price minimum
	if gasPrice.Cmp(pool.gasPrice) < 0 {
		return ErrUnderpriced
	}

	// Check for negative value
	if tx.Value() != nil && tx.Value().Sign() < 0 {
		return ErrNegativeValue
	}

	// Check data size limit (128KB)
	if len(tx.Data()) > 128*1024 {
		return ErrOversizedData
	}

	// If nonce matches current, add to pending directly
	if tx.Nonce() == currentNonce {
		if pool.pending[from] == nil {
			pool.pending[from] = newTxList(true)
		}
		inserted, old := pool.pending[from].Add(tx, pool.config.PriceBump)
		if !inserted {
			return ErrReplaceUnderpriced
		}
		if old != nil {
			pool.all.Remove(old.Hash())
		}
		pool.all.Add(tx)
		log.Debug("Added pending transaction", "hash", hash, "from", from, "nonce", tx.Nonce())
	} else {
		// Add to queue for future processing
		if pool.queue[from] == nil {
			pool.queue[from] = newTxList(false)
		}
		inserted, old := pool.queue[from].Add(tx, pool.config.PriceBump)
		if !inserted {
			return ErrReplaceUnderpriced
		}
		if old != nil {
			pool.all.Remove(old.Hash())
		}
		pool.all.Add(tx)
		log.Debug("Added queued transaction", "hash", hash, "from", from, "nonce", tx.Nonce())
	}

	return nil
}

// Get returns a transaction by hash
func (pool *TxPool) Get(hash common.Hash) *obstypes.StealthTransaction {
	return pool.all.Get(hash)
}

// Pending returns all pending transactions
func (pool *TxPool) Pending(enforceTips bool) map[common.Address][]*obstypes.StealthTransaction {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address][]*obstypes.StealthTransaction)
	for addr, list := range pool.pending {
		txs := list.Flatten()
		if len(txs) > 0 {
			pending[addr] = txs
		}
	}
	return pending
}

// Locals returns all local transactions
func (pool *TxPool) Locals() []common.Address {
	// Currently we don't track locals separately
	return nil
}

// Status returns the status of a transaction
func (pool *TxPool) Status(hash common.Hash) TxStatus {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	if tx := pool.all.Get(hash); tx != nil {
		from, _ := pool.signer.Sender(tx)
		if pool.pending[from] != nil && pool.pending[from].items[tx.Nonce()] != nil {
			return TxStatusPending
		}
		return TxStatusQueued
	}
	return TxStatusUnknown
}

// Stop shuts down the transaction pool
func (pool *TxPool) Stop() {
	close(pool.reorgShutdownCh)
	pool.wg.Wait()
}

// Content returns the current content of the pool
func (pool *TxPool) Content() (map[common.Address][]*obstypes.StealthTransaction, map[common.Address][]*obstypes.StealthTransaction) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address][]*obstypes.StealthTransaction)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	queued := make(map[common.Address][]*obstypes.StealthTransaction)
	for addr, list := range pool.queue {
		queued[addr] = list.Flatten()
	}
	return pending, queued
}

// Stats returns the current pool stats
func (pool *TxPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	var pending, queued int
	for _, list := range pool.pending {
		pending += list.Len()
	}
	for _, list := range pool.queue {
		queued += list.Len()
	}
	return pending, queued
}

// SetGasPrice updates the minimum gas price
func (pool *TxPool) SetGasPrice(price *big.Int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.gasPrice = price
}

// accountSet is a set of accounts
type accountSet struct {
	accounts map[common.Address]struct{}
}

func (as *accountSet) flatten() []common.Address {
	list := make([]common.Address, 0, len(as.accounts))
	for addr := range as.accounts {
		list = append(list, addr)
	}
	return list
}

// txList is a list of transactions sorted by nonce
type txList struct {
	strict bool
	items  map[uint64]*obstypes.StealthTransaction
}

func newTxList(strict bool) *txList {
	return &txList{
		strict: strict,
		items:  make(map[uint64]*obstypes.StealthTransaction),
	}
}

func (l *txList) Add(tx *obstypes.StealthTransaction, priceBump uint64) (bool, *obstypes.StealthTransaction) {
	old := l.items[tx.Nonce()]
	if old != nil {
		// Check if replacement
		threshold := new(big.Int).Mul(old.GasPrice(), big.NewInt(100+int64(priceBump)))
		threshold.Div(threshold, big.NewInt(100))
		if tx.GasPrice().Cmp(threshold) < 0 {
			return false, nil
		}
	}
	l.items[tx.Nonce()] = tx
	return true, old
}

func (l *txList) Flatten() []*obstypes.StealthTransaction {
	txs := make([]*obstypes.StealthTransaction, 0, len(l.items))
	for _, tx := range l.items {
		txs = append(txs, tx)
	}
	return txs
}

func (l *txList) Len() int {
	return len(l.items)
}

func (l *txList) Empty() bool {
	return len(l.items) == 0
}

// txLookup is a lookup table for transactions
type txLookup struct {
	all   map[common.Hash]*obstypes.StealthTransaction
	slots int
	lock  sync.RWMutex
}

func newTxLookup() *txLookup {
	return &txLookup{
		all: make(map[common.Hash]*obstypes.StealthTransaction),
	}
}

func (t *txLookup) Add(tx *obstypes.StealthTransaction) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.all[tx.Hash()] = tx
	t.slots++
}

func (t *txLookup) Get(hash common.Hash) *obstypes.StealthTransaction {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.all[hash]
}

func (t *txLookup) Remove(hash common.Hash) {
	t.lock.Lock()
	defer t.lock.Unlock()
	delete(t.all, hash)
	t.slots--
}

// txPricedList is a list sorted by gas price
type txPricedList struct {
	all *txLookup
}

func newTxPricedList(all *txLookup) *txPricedList {
	return &txPricedList{all: all}
}

// txSortedMap is a nonce-sorted map of transactions
type txSortedMap struct {
}

// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package miner

import (
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/obsidian-chain/obsidian/consensus/obsidianash"
	"github.com/obsidian-chain/obsidian/core/state"
	obstypes "github.com/obsidian-chain/obsidian/core/types"
	"github.com/obsidian-chain/obsidian/params"
)

var (
	// ErrMinerNotRunning is returned when the miner is not running
	ErrMinerNotRunning = errors.New("miner not running")
	// ErrMinerAlreadyRunning is returned when trying to start already running miner
	ErrMinerAlreadyRunning = errors.New("miner already running")
)

// Config is the configuration for the miner
type Config struct {
	Etherbase    common.Address // Address for mining rewards
	ExtraData    []byte         // Block extra data set by the miner
	GasFloor     uint64         // Target gas floor for mined blocks
	GasCeil      uint64         // Target gas ceiling for mined blocks
	GasPrice     *big.Int       // Minimum gas price for mining a transaction
	Recommit     time.Duration  // Interval to recreate mining work
	NewPayload   time.Duration  // Maximum time for new payload building
}

// DefaultConfig returns the default miner configuration
func DefaultConfig() Config {
	return Config{
		GasFloor:   30000000,
		GasCeil:    30000000,
		GasPrice:   big.NewInt(1e9), // 1 Gwei
		Recommit:   3 * time.Second,
		NewPayload: 2 * time.Second,
		ExtraData:  []byte("Obsidian"),
	}
}

// Backend is the interface for the blockchain backend
type Backend interface {
	// Blockchain methods
	CurrentBlock() *obstypes.ObsidianHeader
	GetBlock(hash common.Hash, number uint64) *obstypes.ObsidianBlock
	StateAt(root common.Hash) (state.StateDBInterface, error)

	// Transaction pool methods
	PendingTransactions(enforceTips bool) map[common.Address][]*obstypes.StealthTransaction

	// Block insertion
	InsertBlock(block *obstypes.ObsidianBlock) error

	// Event subscription
	SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription
}

// ChainHeadEvent is sent when a new block is added
type ChainHeadEvent struct {
	Block *obstypes.ObsidianBlock
}

// Miner creates blocks and mines them using PoW
type Miner struct {
	config  *Config
	backend Backend
	engine  *obsidianash.ObsidianAsh

	// Mining state
	running    int32 // atomic
	coinbase   common.Address
	extraData  []byte

	// Work state
	currentWork *Work
	workMu      sync.Mutex

	// Channels
	startCh chan struct{}
	stopCh  chan struct{}
	exitCh  chan struct{}

	// Events
	newWorkCh    chan *Work
	resultCh     chan *obstypes.ObsidianBlock
	chainHeadCh  chan ChainHeadEvent
	chainHeadSub event.Subscription

	// Stats
	hashrate     uint64 // atomic
	minedBlocks  uint64 // atomic

	wg sync.WaitGroup
}

// Work represents a unit of mining work
type Work struct {
	Block      *obstypes.ObsidianBlock
	Header     *obstypes.ObsidianHeader
	Txs        []*obstypes.StealthTransaction
	Receipts   []*Receipt
	State      state.StateDBInterface
	CreatedAt  time.Time
}

// Receipt is a placeholder for transaction receipts
type Receipt struct {
	Status            uint64
	CumulativeGasUsed uint64
	Logs              []Log
	TxHash            common.Hash
	GasUsed           uint64
}

// Log is a placeholder for event logs
type Log struct {
	Address common.Address
	Topics  []common.Hash
	Data    []byte
}

// New creates a new Miner
func New(config *Config, backend Backend, engine *obsidianash.ObsidianAsh) *Miner {
	miner := &Miner{
		config:      config,
		backend:     backend,
		engine:      engine,
		coinbase:    config.Etherbase,
		extraData:   config.ExtraData,
		startCh:     make(chan struct{}),
		stopCh:      make(chan struct{}),
		exitCh:      make(chan struct{}),
		newWorkCh:   make(chan *Work),
		resultCh:    make(chan *obstypes.ObsidianBlock),
		chainHeadCh: make(chan ChainHeadEvent, 10),
	}

	// Subscribe to chain head events
	miner.chainHeadSub = backend.SubscribeChainHeadEvent(miner.chainHeadCh)

	// Start background workers
	miner.wg.Add(2)
	go miner.mainLoop()
	go miner.resultLoop()

	return miner
}

// mainLoop is the main mining loop
func (m *Miner) mainLoop() {
	defer m.wg.Done()
	defer m.chainHeadSub.Unsubscribe()

	ticker := time.NewTicker(m.config.Recommit)
	defer ticker.Stop()

	for {
		select {
		case <-m.startCh:
			log.Info("Miner started")
			m.commit()

		case <-m.stopCh:
			log.Info("Miner stopped")

		case ev := <-m.chainHeadCh:
			if atomic.LoadInt32(&m.running) == 1 {
				log.Debug("New chain head", "number", ev.Block.NumberU64())
				m.commit()
			}

		case <-ticker.C:
			if atomic.LoadInt32(&m.running) == 1 {
				m.commit()
			}

		case <-m.exitCh:
			return
		}
	}
}

// resultLoop handles mining results
func (m *Miner) resultLoop() {
	defer m.wg.Done()

	for {
		select {
		case block := <-m.resultCh:
			if block == nil {
				continue
			}

			// Insert block into chain
			if err := m.backend.InsertBlock(block); err != nil {
				log.Error("Failed to insert mined block", "error", err)
				continue
			}

			log.Info("Successfully mined and inserted block",
				"number", block.NumberU64(),
				"hash", block.Hash().Hex(),
				"txs", len(block.Transactions()),
				"difficulty", block.Difficulty(),
			)

			atomic.AddUint64(&m.minedBlocks, 1)

			// Create new work for next block
			m.commit()

		case <-m.exitCh:
			return
		}
	}
}

// commit creates new work and starts mining
func (m *Miner) commit() {
	m.workMu.Lock()
	defer m.workMu.Unlock()

	parent := m.backend.CurrentBlock()
	if parent == nil {
		log.Error("Current block is nil")
		return
	}

	// Create new block header
	header := &obstypes.ObsidianHeader{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, big.NewInt(1)),
		GasLimit:   m.config.GasCeil,
		Time:       uint64(time.Now().Unix()),
		Coinbase:   m.coinbase,
		Extra:      m.extraData,
	}

	// Calculate difficulty using local calculation
	header.Difficulty = calcDifficulty(header.Time, parent)

	// Get pending transactions
	pending := m.backend.PendingTransactions(true)

	// Create work
	work := &Work{
		Header:    header,
		Txs:       flattenTxs(pending),
		CreatedAt: time.Now(),
	}

	// Start mining in background
	go m.mine(work)
}

// mine performs the actual PoW mining
func (m *Miner) mine(work *Work) {
	if atomic.LoadInt32(&m.running) != 1 {
		return
	}

	// Prepare block for sealing
	block := obstypes.NewBlock(work.Header, work.Txs, nil, nil)

	// Seal the block using our internal sealer
	resultCh := make(chan *obstypes.ObsidianBlock)
	stopCh := make(chan struct{})

	go func() {
		sealedBlock := sealBlock(block, stopCh)
		if sealedBlock != nil {
			resultCh <- sealedBlock
		}
		close(resultCh)
	}()

	select {
	case result := <-resultCh:
		if result != nil {
			m.resultCh <- result
		}
	case <-m.stopCh:
		close(stopCh)
	case <-m.exitCh:
		close(stopCh)
	}
}

// sealBlock performs the PoW sealing
func sealBlock(block *obstypes.ObsidianBlock, stop chan struct{}) *obstypes.ObsidianBlock {
	header := block.Header()
	target := new(big.Int).Div(maxUint256, header.Difficulty)

	var nonce uint64
	for {
		select {
		case <-stop:
			return nil
		default:
			// Compute hash with current nonce
			header.Nonce = obstypes.EncodeNonce(nonce)
			hash := sealHash(header)

			// Check if hash meets target
			if new(big.Int).SetBytes(hash[:]).Cmp(target) <= 0 {
				// Found valid nonce
				header.MixDigest = hash // Simplified - in real impl this would be computed differently
				return block.WithSeal(header)
			}

			nonce++
			if nonce%1000000 == 0 {
				log.Debug("Mining", "nonce", nonce)
			}
		}
	}
}

// sealHash computes the hash for sealing
func sealHash(header *obstypes.ObsidianHeader) common.Hash {
	return header.Hash()
}

var maxUint256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)

// Start starts the mining process
func (m *Miner) Start() error {
	if atomic.LoadInt32(&m.running) == 1 {
		return ErrMinerAlreadyRunning
	}
	atomic.StoreInt32(&m.running, 1)
	m.startCh <- struct{}{}
	return nil
}

// Stop stops the mining process
func (m *Miner) Stop() error {
	if atomic.LoadInt32(&m.running) != 1 {
		return ErrMinerNotRunning
	}
	atomic.StoreInt32(&m.running, 0)
	m.stopCh <- struct{}{}
	return nil
}

// Close shuts down the miner
func (m *Miner) Close() {
	close(m.exitCh)
	m.wg.Wait()
}

// Mining returns whether mining is currently running
func (m *Miner) Mining() bool {
	return atomic.LoadInt32(&m.running) == 1
}

// Hashrate returns the current hashrate
func (m *Miner) Hashrate() uint64 {
	return uint64(m.engine.Hashrate())
}

// SetCoinbase sets the mining reward address
func (m *Miner) SetCoinbase(addr common.Address) {
	m.workMu.Lock()
	defer m.workMu.Unlock()
	m.coinbase = addr
}

// Coinbase returns the current coinbase address
func (m *Miner) Coinbase() common.Address {
	m.workMu.Lock()
	defer m.workMu.Unlock()
	return m.coinbase
}

// SetExtra sets the extra data for mined blocks
func (m *Miner) SetExtra(extra []byte) {
	m.workMu.Lock()
	defer m.workMu.Unlock()
	m.extraData = extra
}

// SetGasPrice sets the minimum gas price for transactions
func (m *Miner) SetGasPrice(price *big.Int) {
	m.workMu.Lock()
	defer m.workMu.Unlock()
	m.config.GasPrice = price
}

// MinedBlocks returns the number of mined blocks
func (m *Miner) MinedBlocks() uint64 {
	return atomic.LoadUint64(&m.minedBlocks)
}

// GetConfig returns the current miner config
func (m *Miner) GetConfig() *Config {
	return m.config
}

// Helper functions

func flattenTxs(pending map[common.Address][]*obstypes.StealthTransaction) []*obstypes.StealthTransaction {
	var txs []*obstypes.StealthTransaction
	for _, accountTxs := range pending {
		txs = append(txs, accountTxs...)
	}
	return txs
}

// CalculateReward calculates the block reward
func CalculateReward(blockNum uint64, config *params.ObsidianashConfig) *big.Int {
	return obsidianash.CalcBlockReward(config, blockNum)
}

// calcDifficulty calculates the difficulty for a new block
func calcDifficulty(time uint64, parent *obstypes.ObsidianHeader) *big.Int {
	// Target block time: 2 seconds
	const targetBlockTime = 2
	const difficultyBoundDivisor = 11
	const minimumDifficulty = 131072

	parentDiff := parent.Difficulty
	if parentDiff == nil {
		parentDiff = big.NewInt(minimumDifficulty)
	}

	// Calculate time difference
	timeDiff := int64(time) - int64(parent.Time)

	// Adjustment based on time difference
	var adjustment *big.Int
	if timeDiff < targetBlockTime {
		// Block was too fast, increase difficulty
		adjustment = new(big.Int).Div(parentDiff, big.NewInt(difficultyBoundDivisor))
	} else if timeDiff > targetBlockTime*2 {
		// Block was too slow, decrease difficulty
		adjustment = new(big.Int).Neg(new(big.Int).Div(parentDiff, big.NewInt(difficultyBoundDivisor)))
	} else {
		// Block time is acceptable, no change
		adjustment = big.NewInt(0)
	}

	// Apply adjustment
	newDiff := new(big.Int).Add(parentDiff, adjustment)

	// Ensure minimum difficulty
	if newDiff.Cmp(big.NewInt(minimumDifficulty)) < 0 {
		newDiff = big.NewInt(minimumDifficulty)
	}

	return newDiff
}

// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package backend

import (
	"context"
	"errors"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/obsidian-chain/obsidian/accounts/keystore"
	"github.com/obsidian-chain/obsidian/backup"
	"github.com/obsidian-chain/obsidian/consensus/obsidianash"
	obsstate "github.com/obsidian-chain/obsidian/core/state"
	"github.com/obsidian-chain/obsidian/core/txpool"
	obstypes "github.com/obsidian-chain/obsidian/core/types"
	"github.com/obsidian-chain/obsidian/health"
	"github.com/obsidian-chain/obsidian/metrics"
	"github.com/obsidian-chain/obsidian/miner"
	"github.com/obsidian-chain/obsidian/params"
	"github.com/obsidian-chain/obsidian/shutdown"
	"github.com/obsidian-chain/obsidian/stealth"
)

var (
	// ErrNotFound is returned when a block or transaction is not found
	ErrNotFound = errors.New("not found")
)

// BlockBroadcaster interface for P2P block broadcasting
type BlockBroadcaster interface {
	BroadcastBlock(block *obstypes.ObsidianBlock)
	PeerCount() int
}

// Backend implements the full Obsidian backend
type Backend struct {
	config *Config

	// Core components
	engine     *obsidianash.ObsidianAsh
	txPool     *txpool.TxPool
	miner      *miner.Miner
	state      *obsstate.StateDB
	keystore   *keystore.KeystoreWrapper
	stealthSvc *stealth.StealthService

	// Blockchain data
	chainMu      sync.RWMutex
	currentBlock *obstypes.ObsidianBlock
	genesisBlock *obstypes.ObsidianBlock
	blocks       map[common.Hash]*obstypes.ObsidianBlock
	blocksByNum  map[uint64]*obstypes.ObsidianBlock

	// Transaction data
	txLookup map[common.Hash]*txLookupEntry

	// P2P
	p2pHandler BlockBroadcaster

	// Events
	chainHeadFeed  event.Feed
	minedBlockFeed event.Feed // For broadcasting mined blocks
	newBlockFeed   event.Feed // For stealth scanning
	scope          event.SubscriptionScope

	// Production features
	shutdownMgr *shutdown.Manager
	metricsReg  *metrics.MetricsRegistry
	healthMon   *health.Monitor
	backupMgr   *backup.Manager

	// Shutdown
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

// Config is the backend configuration
type Config struct {
	ChainID         *big.Int
	DataDir         string
	MinerConfig     miner.Config
	TxPoolConfig    txpool.Config
	ConsensusConfig *params.ObsidianashConfig
	Genesis         *Genesis
}

// Genesis represents the genesis block configuration
type Genesis struct {
	Timestamp  uint64
	ExtraData  []byte
	GasLimit   uint64
	Difficulty *big.Int
	Alloc      map[common.Address]GenesisAccount
}

// GenesisAccount is an account in the genesis state
type GenesisAccount struct {
	Balance *big.Int
	Code    []byte
	Nonce   uint64
	Storage map[common.Hash]common.Hash
}

// txLookupEntry is used to look up transactions
type txLookupEntry struct {
	BlockHash  common.Hash
	BlockIndex uint64
	TxIndex    uint64
}

// DefaultConfig returns the default backend configuration
func DefaultConfig() *Config {
	return &Config{
		ChainID:         big.NewInt(1719),
		MinerConfig:     miner.DefaultConfig(),
		TxPoolConfig:    txpool.DefaultConfig(),
		ConsensusConfig: params.DefaultObsidianashConfig(),
		Genesis: &Genesis{
			GasLimit:   30000000,
			Difficulty: big.NewInt(131072),
			Alloc:      make(map[common.Address]GenesisAccount),
		},
	}
}

// New creates a new Obsidian backend
func New(config *Config) (*Backend, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create consensus engine
	engine := obsidianash.New(config.ConsensusConfig)

	// Create state
	stateDB := obsstate.NewMemoryStateDB()

	// Create keystore
	keystoreDir := filepath.Join(config.DataDir, "keystore")
	ks := keystore.NewKeyStore(keystoreDir)

	// Create stealth service
	stealthSvc := stealth.NewStealthService()

	// Create production components
	shutdownMgr := shutdown.New(30 * time.Second)
	metricsReg := metrics.NewMetricsRegistry()
	healthMon := health.New()
	backupMgr := backup.New(config.DataDir, 5) // Keep last 5 backups

	// Create backend
	b := &Backend{
		config:      config,
		engine:      engine,
		state:       stateDB,
		keystore:    keystore.NewKeystoreWrapper(ks),
		stealthSvc:  stealthSvc,
		blocks:      make(map[common.Hash]*obstypes.ObsidianBlock),
		blocksByNum: make(map[uint64]*obstypes.ObsidianBlock),
		txLookup:    make(map[common.Hash]*txLookupEntry),
		shutdownMgr: shutdownMgr,
		metricsReg:  metricsReg,
		healthMon:   healthMon,
		backupMgr:   backupMgr,
		shutdownCh:  make(chan struct{}),
	}

	// Initialize genesis
	if err := b.initGenesis(config.Genesis); err != nil {
		return nil, err
	}

	// Create transaction pool
	signer := obstypes.NewStealthEIP155Signer(config.ChainID)
	b.txPool = txpool.NewTxPool(config.TxPoolConfig, b, signer)

	// Create miner
	b.miner = miner.New(&config.MinerConfig, b, engine)

	// Register health checks
	b.registerHealthChecks()

	// Register shutdown handlers
	b.registerShutdownHandlers()

	log.Info("Obsidian backend initialized",
		"chainId", config.ChainID,
		"genesis", b.genesisBlock.Hash().Hex(),
	)

	return b, nil
}

// initGenesis initializes the genesis block
func (b *Backend) initGenesis(genesis *Genesis) error {
	// Apply genesis allocations to state
	for addr, account := range genesis.Alloc {
		b.state.CreateAccount(addr)
		if account.Balance != nil {
			b.state.SetBalance(addr, account.Balance)
		}
		if account.Nonce > 0 {
			b.state.SetNonce(addr, account.Nonce)
		}
		if len(account.Code) > 0 {
			b.state.SetCode(addr, account.Code)
		}
		for key, value := range account.Storage {
			b.state.SetState(addr, key, value)
		}
	}

	// Create genesis header
	header := &obstypes.ObsidianHeader{
		Number:     big.NewInt(0),
		Time:       genesis.Timestamp,
		GasLimit:   genesis.GasLimit,
		Difficulty: genesis.Difficulty,
		Extra:      genesis.ExtraData,
		Nonce:      obstypes.EncodeNonce(0),
	}

	// Create genesis block
	b.genesisBlock = obstypes.NewBlock(header, nil, nil, nil)
	b.currentBlock = b.genesisBlock
	b.blocks[b.genesisBlock.Hash()] = b.genesisBlock
	b.blocksByNum[0] = b.genesisBlock

	return nil
}

// Start starts the backend services
func (b *Backend) Start() error {
	log.Info("Starting Obsidian backend")
	return nil
}

// Stop stops the backend services
func (b *Backend) Stop() error {
	log.Info("Stopping Obsidian backend")

	close(b.shutdownCh)
	b.scope.Close()

	b.miner.Close()
	b.txPool.Stop()

	b.wg.Wait()
	return nil
}

// Implement Backend interface for txpool

// CurrentBlock returns the current head block
func (b *Backend) CurrentBlock() *obstypes.ObsidianHeader {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()
	return b.currentBlock.Header()
}

// GetBlock returns a block by hash and number
func (b *Backend) GetBlock(hash common.Hash, number uint64) *obstypes.ObsidianBlock {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()
	return b.blocks[hash]
}

// StateAt returns a state database at a given root
func (b *Backend) StateAt(root common.Hash) (obsstate.StateDBInterface, error) {
	// For simplicity, return current state
	return b.state, nil
}

// Implement Backend interface for miner

// PendingTransactions returns pending transactions
func (b *Backend) PendingTransactions(enforceTips bool) map[common.Address][]*obstypes.StealthTransaction {
	return b.txPool.Pending(enforceTips)
}

// SubscribeChainHeadEvent subscribes to chain head events
func (b *Backend) SubscribeChainHeadEvent(ch chan<- miner.ChainHeadEvent) event.Subscription {
	return b.scope.Track(b.chainHeadFeed.Subscribe(ch))
}

// Implement RPC Backend interface

// BlockByNumber returns a block by number
func (b *Backend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*obstypes.ObsidianBlock, error) {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()

	var blockNum uint64
	switch number {
	case rpc.LatestBlockNumber, rpc.PendingBlockNumber:
		blockNum = b.currentBlock.NumberU64()
	case rpc.EarliestBlockNumber:
		blockNum = 0
	default:
		blockNum = uint64(number)
	}

	block, ok := b.blocksByNum[blockNum]
	if !ok {
		return nil, ErrNotFound
	}
	return block, nil
}

// BlockByHash returns a block by hash
func (b *Backend) BlockByHash(ctx context.Context, hash common.Hash) (*obstypes.ObsidianBlock, error) {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()

	block, ok := b.blocks[hash]
	if !ok {
		return nil, ErrNotFound
	}
	return block, nil
}

// ChainID returns the chain ID
func (b *Backend) ChainID() *big.Int {
	return b.config.ChainID
}

// SendTransaction sends a transaction
func (b *Backend) SendTransaction(ctx context.Context, tx *obstypes.StealthTransaction) (common.Hash, error) {
	if err := b.txPool.Add(tx, true); err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}

// GetTransaction returns a transaction by hash
func (b *Backend) GetTransaction(ctx context.Context, hash common.Hash) (*obstypes.StealthTransaction, common.Hash, uint64, uint64, error) {
	// Check if in pool
	if tx := b.txPool.Get(hash); tx != nil {
		return tx, common.Hash{}, 0, 0, nil
	}

	// Check lookup table
	b.chainMu.RLock()
	entry, ok := b.txLookup[hash]
	b.chainMu.RUnlock()

	if !ok {
		return nil, common.Hash{}, 0, 0, ErrNotFound
	}

	block := b.blocks[entry.BlockHash]
	if block == nil {
		return nil, common.Hash{}, 0, 0, ErrNotFound
	}

	txs := block.Transactions()
	if int(entry.TxIndex) >= len(txs) {
		return nil, common.Hash{}, 0, 0, ErrNotFound
	}

	return txs[entry.TxIndex], entry.BlockHash, entry.BlockIndex, entry.TxIndex, nil
}

// GetTransactionReceipt returns a transaction receipt
func (b *Backend) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	// Simplified - would need full receipt storage
	return nil, ErrNotFound
}

// GetBalance returns the balance of an address
func (b *Backend) GetBalance(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*big.Int, error) {
	return b.state.GetBalance(address), nil
}

// GetCode returns the code at an address
func (b *Backend) GetCode(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	return b.state.GetCode(address), nil
}

// GetNonce returns the nonce of an address
func (b *Backend) GetNonce(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (uint64, error) {
	return b.state.GetNonce(address), nil
}

// Mining returns whether mining is active
func (b *Backend) Mining() bool {
	return b.miner.Mining()
}

// Hashrate returns the current hashrate
func (b *Backend) Hashrate() uint64 {
	return b.miner.Hashrate()
}

// SetCoinbase sets the mining reward address
func (b *Backend) SetCoinbase(address common.Address) error {
	b.miner.SetCoinbase(address)
	return nil
}

// PeerCount returns the number of peers
func (b *Backend) PeerCount() int {
	return 0 // Would need P2P server integration
}

// NetVersion returns the network version
func (b *Backend) NetVersion() uint64 {
	return b.config.ChainID.Uint64()
}

// Syncing returns the sync status
func (b *Backend) Syncing() (interface{}, error) {
	return false, nil
}

// SuggestGasPrice suggests a gas price
func (b *Backend) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return big.NewInt(1e9), nil // 1 Gwei
}

// EstimateGas estimates gas for a call
func (b *Backend) EstimateGas(ctx context.Context, args obstypes.CallArgs) (uint64, error) {
	// Basic gas estimation - 21000 for simple transfers
	// Would be more complex for contract calls
	if args.Data != nil && len(*args.Data) > 0 {
		return 21000 + uint64(len(*args.Data))*68, nil
	}
	return 21000, nil
}

// StartMining starts the miner
func (b *Backend) StartMining() error {
	return b.miner.Start()
}

// StopMining stops the miner
func (b *Backend) StopMining() error {
	return b.miner.Stop()
}

// InsertBlock inserts a new block into the chain
func (b *Backend) InsertBlock(block *obstypes.ObsidianBlock) error {
	b.chainMu.Lock()
	defer b.chainMu.Unlock()

	// Validate block
	if block.ParentHash() != b.currentBlock.Hash() {
		return errors.New("invalid parent hash")
	}

	// Store block
	hash := block.Hash()
	b.blocks[hash] = block
	b.blocksByNum[block.NumberU64()] = block
	b.currentBlock = block

	// Index transactions
	for i, tx := range block.Transactions() {
		b.txLookup[tx.Hash()] = &txLookupEntry{
			BlockHash:  hash,
			BlockIndex: block.NumberU64(),
			TxIndex:    uint64(i),
		}
	}

	// Notify subscribers
	b.chainHeadFeed.Send(miner.ChainHeadEvent{Block: block})

	// Broadcast to peers via P2P handler
	if b.p2pHandler != nil {
		b.p2pHandler.BroadcastBlock(block)
	}

	// Also send to minedBlockFeed for other subscribers
	b.minedBlockFeed.Send(MinedBlockEvent{Block: block})

	// Notify stealth scanners of new block
	b.notifyNewBlock(block.NumberU64())

	log.Info("Block inserted",
		"number", block.NumberU64(),
		"hash", hash.Hex(),
		"txs", len(block.Transactions()),
		"peers", func() int {
			if b.p2pHandler != nil {
				return b.p2pHandler.PeerCount()
			}
			return 0
		}(),
	)

	return nil
}

// MinedBlockEvent is sent when a block is mined and ready to broadcast
type MinedBlockEvent struct {
	Block *obstypes.ObsidianBlock
}

// SubscribeMinedBlockEvent subscribes to mined block events for broadcasting
func (b *Backend) SubscribeMinedBlockEvent(ch chan<- MinedBlockEvent) event.Subscription {
	return b.scope.Track(b.minedBlockFeed.Subscribe(ch))
}

// GetEngine returns the consensus engine
func (b *Backend) GetEngine() *obsidianash.ObsidianAsh {
	return b.engine
}

// GetMiner returns the miner
func (b *Backend) GetMiner() *miner.Miner {
	return b.miner
}

// GetTxPool returns the transaction pool
func (b *Backend) GetTxPool() *txpool.TxPool {
	return b.txPool
}

// GetState returns the state database
func (b *Backend) GetState() *obsstate.StateDB {
	return b.state
}

// SetP2PHandler sets the P2P handler for block broadcasting
func (b *Backend) SetP2PHandler(handler BlockBroadcaster) {
	b.p2pHandler = handler
}

// GenesisHash returns the genesis block hash
func (b *Backend) GenesisHash() common.Hash {
	if b.genesisBlock != nil {
		return b.genesisBlock.Hash()
	}
	return common.Hash{}
}

// GetBlockByHash returns a block by hash
func (b *Backend) GetBlockByHash(hash common.Hash) *obstypes.ObsidianBlock {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()
	return b.blocks[hash]
}

// GetBlockByNumber returns a block by number
func (b *Backend) GetBlockByNumber(number uint64) *obstypes.ObsidianBlock {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()
	return b.blocksByNum[number]
}

// GetTD returns the total difficulty for a block
func (b *Backend) GetTD(hash common.Hash) *big.Int {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()

	block, ok := b.blocks[hash]
	if !ok {
		return nil
	}

	// Calculate total difficulty by summing all difficulties
	td := big.NewInt(0)
	for num := uint64(0); num <= block.NumberU64(); num++ {
		blk := b.blocksByNum[num]
		if blk != nil {
			td.Add(td, blk.Difficulty())
		}
	}
	return td
}

// HasBlock checks if a block exists
func (b *Backend) HasBlock(hash common.Hash) bool {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()
	_, exists := b.blocks[hash]
	return exists
}

// AddRemoteTxs adds transactions from remote peers
func (b *Backend) AddRemoteTxs(txs []*obstypes.StealthTransaction) []error {
	errs := make([]error, len(txs))
	for i, tx := range txs {
		errs[i] = b.txPool.Add(tx, false) // false = remote (not local)
	}
	return errs
}

// PendingTxs returns pending transactions
func (b *Backend) PendingTxs() []*obstypes.StealthTransaction {
	pending := b.txPool.Pending(true)
	var txs []*obstypes.StealthTransaction
	for _, list := range pending {
		txs = append(txs, list...)
	}
	return txs
}

// BroadcastBlock broadcasts a block to peers (implements BlockBroadcaster)
func (b *Backend) BroadcastBlock(block *obstypes.ObsidianBlock) {
	if b.p2pHandler != nil {
		b.p2pHandler.BroadcastBlock(block)
	}
}

// SendRawTransaction sends a raw encoded transaction
func (b *Backend) SendRawTransaction(ctx context.Context, encodedTx []byte) (common.Hash, error) {
	tx := new(obstypes.StealthTransaction)
	if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
		return common.Hash{}, err
	}
	if err := b.txPool.Add(tx, true); err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}

// GetPoolTransactions returns all transactions in the pool
func (b *Backend) GetPoolTransactions() []*obstypes.StealthTransaction {
	pending := b.txPool.Pending(true)
	var txs []*obstypes.StealthTransaction
	for _, list := range pending {
		txs = append(txs, list...)
	}
	return txs
}

// GetPoolTransaction returns a specific transaction from the pool
func (b *Backend) GetPoolTransaction(hash common.Hash) *obstypes.StealthTransaction {
	return b.txPool.Get(hash)
}

// GetStorageAt returns storage value at a given position
func (b *Backend) GetStorageAt(ctx context.Context, address common.Address, key common.Hash, blockNr rpc.BlockNumber) (common.Hash, error) {
	return b.state.GetState(address, key), nil
}

// Call executes a message call
func (b *Backend) Call(ctx context.Context, args obstypes.CallArgs, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	// For now, return empty - full implementation would require EVM execution
	// This is a placeholder for contract calls
	if args.To == nil {
		return nil, errors.New("contract creation not supported in call")
	}

	// Get code at the address
	code := b.state.GetCode(*args.To)
	if len(code) == 0 {
		// If no code, just return empty
		return hexutil.Bytes{}, nil
	}

	// Full EVM execution would go here
	// For now, return empty bytes
	return hexutil.Bytes{}, nil
}

// GetCoinbase returns the current coinbase address
func (b *Backend) GetCoinbase() common.Address {
	return b.miner.Coinbase()
}

// StartMining starts the miner with specified threads
func (b *Backend) StartMiningWithThreads(threads int) error {
	// Thread configuration is not yet implemented
	// Just start the miner
	return b.miner.Start()
}

// StopMiningAsync stops the miner without returning error
func (b *Backend) StopMiningAsync() {
	_ = b.miner.Stop()
}

// GetLogs returns logs matching the filter criteria
func (b *Backend) GetLogs(ctx context.Context, filter obstypes.FilterQuery) ([]*obstypes.Log, error) {
	var logs []*obstypes.Log

	// Determine block range
	var fromBlock, toBlock uint64
	if filter.FromBlock != nil {
		fromBlock = filter.FromBlock.Uint64()
	}
	if filter.ToBlock != nil {
		toBlock = filter.ToBlock.Uint64()
	} else {
		toBlock = b.currentBlock.NumberU64()
	}

	// For now, return empty logs since we don't have full receipt storage
	// Iterate through blocks
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()

	for num := fromBlock; num <= toBlock; num++ {
		block := b.blocksByNum[num]
		if block == nil {
			continue
		}

		// Get receipts for this block (simplified - would need receipt storage)
		// For now, return empty as we don't have full receipt storage
	}

	return logs, nil
}

// GetKeystore returns the keystore backend for account management
func (b *Backend) GetKeystore() interface{} {
	return b.keystore
}

// GetStealthService returns the stealth service
func (b *Backend) GetStealthService() *stealth.StealthService {
	return b.stealthSvc
}

// GetStealthTransactions implements stealth.BlockchainBackend
func (b *Backend) GetStealthTransactions(ctx context.Context, blockNumber uint64) ([]stealth.StealthTxData, error) {
	b.chainMu.RLock()
	block, exists := b.blocksByNum[blockNumber]
	b.chainMu.RUnlock()

	if !exists {
		return nil, ErrNotFound
	}

	var stealthTxs []stealth.StealthTxData
	for _, tx := range block.Transactions() {
		// Check if this is a stealth transaction
		ephemeralPubKey := tx.EphemeralPubKey()
		if len(ephemeralPubKey) == 0 {
			continue
		}

		stealthTxs = append(stealthTxs, stealth.StealthTxData{
			TxHash:          tx.Hash(),
			ToAddress:       *tx.To(),
			EphemeralPubKey: ephemeralPubKey,
			ViewTag:         tx.ViewTag(),
			Amount:          tx.Value().String(),
		})
	}

	return stealthTxs, nil
}

// CurrentBlockNumber returns the current block number (for stealth.BlockchainBackend)
func (b *Backend) CurrentBlockNumber(ctx context.Context) (uint64, error) {
	b.chainMu.RLock()
	defer b.chainMu.RUnlock()

	if b.currentBlock == nil {
		return 0, nil
	}
	return b.currentBlock.NumberU64(), nil
}

// SubscribeNewBlocks implements stealth.BlockchainBackend
func (b *Backend) SubscribeNewBlocks(ctx context.Context, ch chan<- uint64) error {
	sub := b.newBlockFeed.Subscribe(ch)

	go func() {
		select {
		case <-ctx.Done():
			sub.Unsubscribe()
		case <-b.shutdownCh:
			sub.Unsubscribe()
		}
	}()

	return nil
}

// notifyNewBlock notifies subscribers of a new block
func (b *Backend) notifyNewBlock(blockNumber uint64) {
	b.newBlockFeed.Send(blockNumber)
}

// registerHealthChecks registers health checks for the backend
func (b *Backend) registerHealthChecks() {
	// Register blockchain health check
	b.healthMon.Register(&health.BlockchainCheck{
		CurrentBlock: func() (uint64, error) {
			return b.CurrentBlockNumber(context.Background())
		},
		LastBlockTime: func() time.Time {
			b.chainMu.RLock()
			defer b.chainMu.RUnlock()
			if b.currentBlock == nil {
				return time.Time{}
			}
			return time.Unix(int64(b.currentBlock.Time()), 0)
		},
	}, true) // Critical check

	// Register network health check
	b.healthMon.Register(&health.NetworkCheck{
		PeerCount: func() int {
			if b.p2pHandler == nil {
				return 0
			}
			return b.p2pHandler.PeerCount()
		},
		MinPeers: 0, // Allow running with no peers for now
	}, false) // Non-critical

	// Register transaction pool health check
	b.healthMon.Register(&health.TransactionPoolCheck{
		PoolSize: func() int {
			executable, _ := b.txPool.Stats()
			return executable
		},
		MaxSize: int(b.config.TxPoolConfig.GlobalSlots),
	}, false) // Non-critical
}

// registerShutdownHandlers registers graceful shutdown handlers
func (b *Backend) registerShutdownHandlers() {
	// Register miner shutdown
	b.shutdownMgr.Register(shutdown.NewSimpleHandler("miner", func(ctx context.Context) error {
		b.miner.Close()
		return nil
	}))

	// Register transaction pool shutdown
	b.shutdownMgr.Register(shutdown.NewSimpleHandler("txpool", func(ctx context.Context) error {
		b.txPool.Stop()
		return nil
	}))

	// Register event scope shutdown
	b.shutdownMgr.Register(shutdown.NewSimpleHandler("events", func(ctx context.Context) error {
		b.scope.Close()
		return nil
	}))

	// Register backup shutdown handler (creates final backup)
	b.shutdownMgr.Register(shutdown.NewSimpleHandler("backup", func(ctx context.Context) error {
		name := "shutdown-" + time.Now().Format("2006-01-02-150405")
		_, err := b.backupMgr.Create(name)
		if err != nil {
			log.Warn("Failed to create shutdown backup", "err", err)
			return nil // Don't fail shutdown for backup failure
		}
		log.Info("Shutdown backup created", "name", name)
		return nil
	}))
}

// GetShutdownManager returns the shutdown manager for external use
func (b *Backend) GetShutdownManager() *shutdown.Manager {
	return b.shutdownMgr
}

// GetHealthMonitor returns the health monitor for external use
func (b *Backend) GetHealthMonitor() *health.Monitor {
	return b.healthMon
}

// GetMetrics returns the metrics registry for external use
func (b *Backend) GetMetrics() *metrics.MetricsRegistry {
	return b.metricsReg
}

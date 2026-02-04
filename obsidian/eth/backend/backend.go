// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package backend

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/obsidian-chain/obsidian/core"
	"github.com/obsidian-chain/obsidian/core/rawdb"
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
	blockchain *core.BlockChain
	txPool     *txpool.TxPool
	miner      *miner.Miner
	db         *rawdb.Database
	keystore   *keystore.KeystoreWrapper
	stealthSvc *stealth.StealthService

	// P2P
	p2pHandler BlockBroadcaster

	// Events
	minedBlockFeed event.Feed // For broadcasting mined blocks
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

	// Initialize database
	dbPath := filepath.Join(config.DataDir, "chaindata")
	db, err := rawdb.NewDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Create consensus engine
	engine := obsidianash.New(config.ConsensusConfig)

	// Create blockchain
	chainCfg := &core.ChainConfig{
		ChainID: config.ChainID,
	}
	genesis := &core.Genesis{
		GasLimit:   config.Genesis.GasLimit,
		Difficulty: config.Genesis.Difficulty,
		Alloc:      make(map[common.Address]core.GenesisAccount),
	}
	for addr, acc := range config.Genesis.Alloc {
		genesis.Alloc[addr] = core.GenesisAccount{
			Balance: acc.Balance,
			Code:    acc.Code,
			Nonce:   acc.Nonce,
			Storage: acc.Storage,
		}
	}

	blockchain, err := core.NewBlockChain(db, chainCfg, engine, genesis)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create blockchain: %v", err)
	}

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
		blockchain:  blockchain,
		db:          db,
		keystore:    keystore.NewKeystoreWrapper(ks),
		stealthSvc:  stealthSvc,
		shutdownMgr: shutdownMgr,
		metricsReg:  metricsReg,
		healthMon:   healthMon,
		backupMgr:   backupMgr,
		shutdownCh:  make(chan struct{}),
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
		"genesis", b.blockchain.Genesis().Hash().Hex(),
	)

	return b, nil
}

// initGenesis initializes the genesis block
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
	b.blockchain.Stop()
	b.db.Close()

	b.wg.Wait()
	return nil
}

// Implement Backend interface for txpool

// CurrentBlock returns the current head block
func (b *Backend) CurrentBlock() *obstypes.ObsidianHeader {
	return b.blockchain.CurrentHeader()
}

// GetBlock returns a block by hash and number
func (b *Backend) GetBlock(hash common.Hash, number uint64) *obstypes.ObsidianBlock {
	return b.blockchain.GetBlock(hash, number)
}

// StateAt returns a state database at a given root
func (b *Backend) StateAt(root common.Hash) (obsstate.StateDBInterface, error) {
	return b.blockchain.StateAt(root)
}

// Implement Backend interface for miner

// PendingTransactions returns pending transactions
func (b *Backend) PendingTransactions(enforceTips bool) map[common.Address][]*obstypes.StealthTransaction {
	return b.txPool.Pending(enforceTips)
}

// SubscribeChainHeadEvent subscribes to chain head events
func (b *Backend) SubscribeChainHeadEvent(ch chan<- miner.ChainHeadEvent) event.Subscription {
	// Need to bridge core.ChainHeadEvent to miner.ChainHeadEvent
	coreCh := make(chan core.ChainHeadEvent, 10)
	sub := b.blockchain.SubscribeChainHeadEvent(coreCh)

	go func() {
		defer sub.Unsubscribe()
		for {
			select {
			case ev := <-coreCh:
				select {
				case ch <- miner.ChainHeadEvent{Block: ev.Block}:
				case <-b.shutdownCh:
					return
				}
			case <-b.shutdownCh:
				return
			}
		}
	}()

	return sub
}

// Implement RPC Backend interface

// BlockByNumber returns a block by number
func (b *Backend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*obstypes.ObsidianBlock, error) {
	var blockNum uint64
	switch number {
	case rpc.LatestBlockNumber, rpc.PendingBlockNumber:
		return b.blockchain.CurrentBlock(), nil
	case rpc.EarliestBlockNumber:
		blockNum = 0
	default:
		blockNum = uint64(number)
	}

	block := b.blockchain.GetBlockByNumber(blockNum)
	if block == nil {
		return nil, ErrNotFound
	}
	return block, nil
}

// BlockByHash returns a block by hash
func (b *Backend) BlockByHash(ctx context.Context, hash common.Hash) (*obstypes.ObsidianBlock, error) {
	block := b.blockchain.GetBlockByHash(hash)
	if block == nil {
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

	// Check blockchain
	block, blockHash, blockIndex, txIndex := b.blockchain.GetTransaction(hash)
	if block == nil {
		return nil, common.Hash{}, 0, 0, ErrNotFound
	}

	return block, blockHash, blockIndex, txIndex, nil
}

// GetTransactionReceipt returns a transaction receipt
func (b *Backend) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	// Simplified - would need full receipt storage
	return nil, ErrNotFound
}

// GetBalance returns the balance of an address
func (b *Backend) GetBalance(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*big.Int, error) {
	state, err := b.blockchain.State()
	if err != nil {
		return nil, err
	}
	return state.GetBalance(address), nil
}

// GetCode returns the code at an address
func (b *Backend) GetCode(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	state, err := b.blockchain.State()
	if err != nil {
		return nil, err
	}
	return state.GetCode(address), nil
}

// GetNonce returns the nonce of an address
func (b *Backend) GetNonce(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (uint64, error) {
	state, err := b.blockchain.State()
	if err != nil {
		return 0, err
	}
	return state.GetNonce(address), nil
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
	// Let the blockchain core handle the insertion and persistence
	return b.blockchain.InsertBlock(block)
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
	state, _ := b.blockchain.State()
	return state
}

// SetP2PHandler sets the P2P handler for block broadcasting
func (b *Backend) SetP2PHandler(handler BlockBroadcaster) {
	b.p2pHandler = handler
	b.blockchain.SetP2PHandler(handler)
}

// GenesisHash returns the genesis block hash
func (b *Backend) GenesisHash() common.Hash {
	return b.blockchain.Genesis().Hash()
}

// GetBlockByHash returns a block by hash
func (b *Backend) GetBlockByHash(hash common.Hash) *obstypes.ObsidianBlock {
	return b.blockchain.GetBlockByHash(hash)
}

// GetBlockByNumber returns a block by number
func (b *Backend) GetBlockByNumber(number uint64) *obstypes.ObsidianBlock {
	return b.blockchain.GetBlockByNumber(number)
}

// GetTD returns the total difficulty for a block
func (b *Backend) GetTD(hash common.Hash) *big.Int {
	number := rawdb.ReadHeaderNumber(b.db, hash)
	if number == nil {
		return nil
	}
	return b.blockchain.GetTd(hash, *number)
}

// HasBlock checks if a block exists
func (b *Backend) HasBlock(hash common.Hash) bool {
	number := rawdb.ReadHeaderNumber(b.db, hash)
	if number == nil {
		return false
	}
	return b.blockchain.HasBlock(hash, *number)
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
	state, err := b.blockchain.State()
	if err != nil {
		return common.Hash{}, err
	}
	return state.GetState(address, key), nil
}

// Call executes a message call
func (b *Backend) Call(ctx context.Context, args obstypes.CallArgs, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	// For now, return empty - full implementation would require EVM execution
	// This is a placeholder for contract calls
	if args.To == nil {
		return nil, errors.New("contract creation not supported in call")
	}

	// Get state
	state, err := b.blockchain.State()
	if err != nil {
		return nil, err
	}

	// Get code at the address
	code := state.GetCode(*args.To)
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
		toBlock = b.blockchain.CurrentBlock().NumberU64()
	}

	// For now, return empty logs since we don't have full receipt storage
	// Iterate through blocks
	for num := fromBlock; num <= toBlock; num++ {
		block := b.blockchain.GetBlockByNumber(num)
		if block == nil {
			continue
		}
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
	block := b.blockchain.GetBlockByNumber(blockNumber)
	if block == nil {
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
	return b.blockchain.CurrentBlock().NumberU64(), nil
}

// SubscribeNewBlocks implements stealth.BlockchainBackend
func (b *Backend) SubscribeNewBlocks(ctx context.Context, ch chan<- uint64) error {
	// For simplicity, we convert ChainHeadEvent to uint64
	eventCh := make(chan core.ChainHeadEvent, 10)
	sub := b.blockchain.SubscribeChainHeadEvent(eventCh)

	go func() {
		defer sub.Unsubscribe()
		for {
			select {
			case ev := <-eventCh:
				select {
				case ch <- ev.Block.NumberU64():
				case <-ctx.Done():
					return
				case <-b.shutdownCh:
					return
				}
			case <-ctx.Done():
				return
			case <-b.shutdownCh:
				return
			}
		}
	}()

	return nil
}

// registerHealthChecks registers health checks for the backend
func (b *Backend) registerHealthChecks() {
	// Register blockchain health check
	b.healthMon.Register(&health.BlockchainCheck{
		CurrentBlock: func() (uint64, error) {
			return b.CurrentBlockNumber(context.Background())
		},
		LastBlockTime: func() time.Time {
			return b.blockchain.LastBlockTime()
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

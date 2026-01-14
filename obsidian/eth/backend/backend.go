// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package backend

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/obsidian-chain/obsidian/consensus/obsidianash"
	obsstate "github.com/obsidian-chain/obsidian/core/state"
	obstypes "github.com/obsidian-chain/obsidian/core/types"
	"github.com/obsidian-chain/obsidian/core/txpool"
	"github.com/obsidian-chain/obsidian/miner"
	"github.com/obsidian-chain/obsidian/params"
)

var (
	// ErrNotFound is returned when a block or transaction is not found
	ErrNotFound = errors.New("not found")
)

// Backend implements the full Obsidian backend
type Backend struct {
	config *Config

	// Core components
	engine  *obsidianash.ObsidianAsh
	txPool  *txpool.TxPool
	miner   *miner.Miner
	state   *obsstate.StateDB

	// Blockchain data
	chainMu      sync.RWMutex
	currentBlock *obstypes.ObsidianBlock
	genesisBlock *obstypes.ObsidianBlock
	blocks       map[common.Hash]*obstypes.ObsidianBlock
	blocksByNum  map[uint64]*obstypes.ObsidianBlock

	// Transaction data
	txLookup map[common.Hash]*txLookupEntry

	// Events
	chainHeadFeed     event.Feed
	minedBlockFeed    event.Feed  // For broadcasting mined blocks
	scope             event.SubscriptionScope

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

	// Create backend
	b := &Backend{
		config:      config,
		engine:      engine,
		state:       stateDB,
		blocks:      make(map[common.Hash]*obstypes.ObsidianBlock),
		blocksByNum: make(map[uint64]*obstypes.ObsidianBlock),
		txLookup:    make(map[common.Hash]*txLookupEntry),
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

	// Broadcast to peers
	b.minedBlockFeed.Send(MinedBlockEvent{Block: block})

	log.Info("New block inserted and broadcasted",
		"number", block.NumberU64(),
		"hash", hash.Hex(),
		"txs", len(block.Transactions()),
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

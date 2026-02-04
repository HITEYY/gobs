// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package core

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/obsidian-chain/obsidian/consensus/obsidianash"
	"github.com/obsidian-chain/obsidian/core/rawdb"
	obsstate "github.com/obsidian-chain/obsidian/core/state"
	obstypes "github.com/obsidian-chain/obsidian/core/types"
	"github.com/obsidian-chain/obsidian/params"
)

var (
	ErrNoGenesis            = errors.New("genesis not found in chain")
	ErrKnownBlock           = errors.New("block already known")
	ErrUnknownAncestor      = errors.New("unknown ancestor")
	ErrPrunedAncestor       = errors.New("pruned ancestor")
	ErrFutureBlock          = errors.New("block in the future")
	ErrInvalidNumber        = errors.New("invalid block number")
	ErrInvalidTerminalBlock = errors.New("invalid terminal block")
	ErrSideChainReceipts    = errors.New("side chain receipts")
)

// BlockChain represents the canonical chain
type BlockChain struct {
	chainConfig *ChainConfig
	db          *rawdb.Database
	engine      *obsidianash.ObsidianAsh

	// Chain state
	currentBlock     atomic.Pointer[obstypes.ObsidianBlock]
	currentFastBlock atomic.Pointer[obstypes.ObsidianBlock]
	genesisBlock     *obstypes.ObsidianBlock

	// State database
	stateCache *StateCache

	// Block caches
	blockCache    *LRUCache[common.Hash, *obstypes.ObsidianBlock]
	headerCache   *LRUCache[common.Hash, *obstypes.ObsidianHeader]
	tdCache       *LRUCache[common.Hash, *big.Int]
	receiptsCache *LRUCache[common.Hash, obstypes.Receipts]

	// Feeds
	chainHeadFeed event.Feed
	logsFeed      event.Feed
	scope         event.SubscriptionScope

	// Mutex
	chainmu  sync.RWMutex
	insertMu sync.Mutex

	// Running state
	running int32
	quit    chan struct{}
	wg      sync.WaitGroup
}

// ChainConfig holds chain configuration
type ChainConfig struct {
	ChainID        *big.Int
	HomesteadBlock *big.Int
	EIP150Block    *big.Int
	EIP155Block    *big.Int
	EIP158Block    *big.Int
}

// DefaultChainConfig returns the default chain configuration
func DefaultChainConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:        big.NewInt(1719),
		HomesteadBlock: big.NewInt(0),
		EIP150Block:    big.NewInt(0),
		EIP155Block:    big.NewInt(0),
		EIP158Block:    big.NewInt(0),
	}
}

// StateCache caches state databases
type StateCache struct {
	db      *rawdb.Database
	mu      sync.RWMutex
	states  map[common.Hash]*obsstate.StateDB
	maxSize int
}

// NewStateCache creates a new state cache
func NewStateCache(db *rawdb.Database, maxSize int) *StateCache {
	return &StateCache{
		db:      db,
		states:  make(map[common.Hash]*obsstate.StateDB),
		maxSize: maxSize,
	}
}

// OpenState opens or creates a state database at the given root
func (sc *StateCache) OpenState(root common.Hash) (*obsstate.StateDB, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if state, ok := sc.states[root]; ok {
		return state.Copy(), nil
	}

	// Create new state from database
	state, err := obsstate.NewWithDB(root, sc.db)
	if err != nil {
		return nil, err
	}

	// Cache if space available
	if len(sc.states) < sc.maxSize {
		sc.states[root] = state
	}

	return state, nil
}

// LRUCache is a simple LRU cache
type LRUCache[K comparable, V any] struct {
	mu      sync.RWMutex
	items   map[K]V
	keys    []K
	maxSize int
}

// NewLRUCache creates a new LRU cache
func NewLRUCache[K comparable, V any](maxSize int) *LRUCache[K, V] {
	return &LRUCache[K, V]{
		items:   make(map[K]V),
		keys:    make([]K, 0, maxSize),
		maxSize: maxSize,
	}
}

// Get retrieves an item from the cache
func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.items[key]
	return v, ok
}

// Add adds an item to the cache
func (c *LRUCache[K, V]) Add(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.items[key]; ok {
		c.items[key] = value
		return
	}

	if len(c.keys) >= c.maxSize {
		// Evict oldest
		oldest := c.keys[0]
		c.keys = c.keys[1:]
		delete(c.items, oldest)
	}

	c.items[key] = value
	c.keys = append(c.keys, key)
}

// NewBlockChain creates a new blockchain
func NewBlockChain(db *rawdb.Database, config *ChainConfig, engine *obsidianash.ObsidianAsh, genesis *Genesis) (*BlockChain, error) {
	if config == nil {
		config = DefaultChainConfig()
	}

	bc := &BlockChain{
		chainConfig:   config,
		db:            db,
		engine:        engine,
		stateCache:    NewStateCache(db, 128),
		blockCache:    NewLRUCache[common.Hash, *obstypes.ObsidianBlock](256),
		headerCache:   NewLRUCache[common.Hash, *obstypes.ObsidianHeader](512),
		tdCache:       NewLRUCache[common.Hash, *big.Int](256),
		receiptsCache: NewLRUCache[common.Hash, obstypes.Receipts](256),
		quit:          make(chan struct{}),
	}

	// Load or create genesis
	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		if genesis == nil {
			return nil, ErrNoGenesis
		}
		// Write genesis
		genesisBlock, err := bc.WriteGenesis(genesis)
		if err != nil {
			return nil, err
		}
		bc.genesisBlock = genesisBlock
	} else {
		// Load existing genesis
		bc.genesisBlock = bc.GetBlockByHash(genesisHash)
		if bc.genesisBlock == nil {
			return nil, ErrNoGenesis
		}
	}

	// Load current head
	headHash := rawdb.ReadHeadBlockHash(db)
	if headHash == (common.Hash{}) {
		bc.currentBlock.Store(bc.genesisBlock)
		bc.currentFastBlock.Store(bc.genesisBlock)
	} else {
		head := bc.GetBlockByHash(headHash)
		if head == nil {
			log.Warn("Head block missing, resetting to genesis", "hash", headHash)
			bc.currentBlock.Store(bc.genesisBlock)
			bc.currentFastBlock.Store(bc.genesisBlock)
		} else {
			bc.currentBlock.Store(head)
			bc.currentFastBlock.Store(head)
		}
	}

	log.Info("Loaded blockchain",
		"genesis", bc.genesisBlock.Hash().Hex(),
		"head", bc.currentBlock.Load().NumberU64(),
		"td", bc.GetTd(bc.currentBlock.Load().Hash(), bc.currentBlock.Load().NumberU64()),
	)

	return bc, nil
}

// Genesis represents genesis block configuration
type Genesis struct {
	Timestamp  uint64
	ExtraData  []byte
	GasLimit   uint64
	Difficulty *big.Int
	Coinbase   common.Address
	Alloc      map[common.Address]GenesisAccount
}

// GenesisAccount represents an account in genesis state
type GenesisAccount struct {
	Balance *big.Int
	Code    []byte
	Nonce   uint64
	Storage map[common.Hash]common.Hash
}

// WriteGenesis writes the genesis block and state to the database
func (bc *BlockChain) WriteGenesis(genesis *Genesis) (*obstypes.ObsidianBlock, error) {
	// Create state DB
	stateDB := obsstate.NewMemoryStateDB()

	// Apply genesis allocations
	for addr, account := range genesis.Alloc {
		stateDB.CreateAccount(addr)
		if account.Balance != nil {
			stateDB.SetBalance(addr, account.Balance)
		}
		if account.Nonce > 0 {
			stateDB.SetNonce(addr, account.Nonce)
		}
		if len(account.Code) > 0 {
			stateDB.SetCode(addr, account.Code)
		}
		for key, value := range account.Storage {
			stateDB.SetState(addr, key, value)
		}
	}

	// Compute state root
	stateRoot, err := stateDB.Commit(false)
	if err != nil {
		return nil, err
	}

	// Create genesis header
	header := &obstypes.ObsidianHeader{
		ParentHash:  common.Hash{},
		Coinbase:    genesis.Coinbase,
		Root:        stateRoot,
		TxHash:      obstypes.EmptyTxsHash,
		ReceiptHash: obstypes.EmptyReceiptsHash,
		Number:      big.NewInt(0),
		GasLimit:    genesis.GasLimit,
		GasUsed:     0,
		Time:        genesis.Timestamp,
		Extra:       genesis.ExtraData,
		Difficulty:  genesis.Difficulty,
		Nonce:       obstypes.EncodeNonce(66),
	}

	// Create genesis block
	block := obstypes.NewBlock(header, nil, nil, nil)
	hash := block.Hash()

	// Write to database
	rawdb.WriteCanonicalHash(bc.db, hash, 0)
	rawdb.WriteHeaderNumber(bc.db, hash, 0)
	rawdb.WriteHeadBlockHash(bc.db, hash)
	rawdb.WriteHeadHeaderHash(bc.db, hash)

	// Write header
	headerRLP, err := rlp.EncodeToBytes(header)
	if err != nil {
		return nil, err
	}
	rawdb.WriteHeaderRLP(bc.db, hash, 0, headerRLP)

	// Write TD
	rawdb.WriteTd(bc.db, hash, 0, genesis.Difficulty)

	// Write state to database
	if err := bc.writeState(stateDB, stateRoot); err != nil {
		return nil, err
	}

	log.Info("Wrote genesis block",
		"hash", hash.Hex(),
		"stateRoot", stateRoot.Hex(),
		"alloc", len(genesis.Alloc),
	)

	return block, nil
}

// writeState persists the state to the database
func (bc *BlockChain) writeState(state *obsstate.StateDB, root common.Hash) error {
	// Persist all accounts to the database
	return state.CommitToDB(bc.db, root)
}

// CurrentBlock returns the current head block
func (bc *BlockChain) CurrentBlock() *obstypes.ObsidianBlock {
	return bc.currentBlock.Load()
}

// CurrentHeader returns the current head header
func (bc *BlockChain) CurrentHeader() *obstypes.ObsidianHeader {
	return bc.currentBlock.Load().Header()
}

// Genesis returns the genesis block
func (bc *BlockChain) Genesis() *obstypes.ObsidianBlock {
	return bc.genesisBlock
}

// GetBlockByHash retrieves a block by hash
func (bc *BlockChain) GetBlockByHash(hash common.Hash) *obstypes.ObsidianBlock {
	// Check cache
	if block, ok := bc.blockCache.Get(hash); ok {
		return block
	}

	// Load from database
	number := rawdb.ReadHeaderNumber(bc.db, hash)
	if number == nil {
		return nil
	}

	return bc.GetBlock(hash, *number)
}

// GetBlock retrieves a block by hash and number
func (bc *BlockChain) GetBlock(hash common.Hash, number uint64) *obstypes.ObsidianBlock {
	// Check cache
	if block, ok := bc.blockCache.Get(hash); ok {
		return block
	}

	// Load header
	headerRLP := rawdb.ReadHeaderRLP(bc.db, hash, number)
	if headerRLP == nil {
		return nil
	}
	var header obstypes.ObsidianHeader
	if err := rlp.DecodeBytes(headerRLP, &header); err != nil {
		return nil
	}

	// Load body
	bodyRLP := rawdb.ReadBodyRLP(bc.db, hash, number)
	var body obstypes.Body
	if bodyRLP != nil {
		if err := rlp.DecodeBytes(bodyRLP, &body); err != nil {
			log.Error("Failed to decode block body", "err", err)
		}
	}

	block := obstypes.NewBlockWithHeader(&header).WithBody(body.Transactions, body.Uncles)

	// Cache
	bc.blockCache.Add(hash, block)

	return block
}

// GetBlockByNumber retrieves a block by number
func (bc *BlockChain) GetBlockByNumber(number uint64) *obstypes.ObsidianBlock {
	hash := rawdb.ReadCanonicalHash(bc.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return bc.GetBlock(hash, number)
}

// GetHeader retrieves a header by hash and number
func (bc *BlockChain) GetHeader(hash common.Hash, number uint64) *obstypes.ObsidianHeader {
	// Check cache
	if header, ok := bc.headerCache.Get(hash); ok {
		return header
	}

	// Load from database
	headerRLP := rawdb.ReadHeaderRLP(bc.db, hash, number)
	if headerRLP == nil {
		return nil
	}
	var header obstypes.ObsidianHeader
	if err := rlp.DecodeBytes(headerRLP, &header); err != nil {
		return nil
	}

	// Cache
	bc.headerCache.Add(hash, &header)

	return &header
}

// GetHeaderByHash retrieves a header by hash
func (bc *BlockChain) GetHeaderByHash(hash common.Hash) *obstypes.ObsidianHeader {
	number := rawdb.ReadHeaderNumber(bc.db, hash)
	if number == nil {
		return nil
	}
	return bc.GetHeader(hash, *number)
}

// GetHeaderByNumber retrieves a header by number
func (bc *BlockChain) GetHeaderByNumber(number uint64) *obstypes.ObsidianHeader {
	hash := rawdb.ReadCanonicalHash(bc.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return bc.GetHeader(hash, number)
}

// GetTd retrieves the total difficulty for a block
func (bc *BlockChain) GetTd(hash common.Hash, number uint64) *big.Int {
	// Check cache
	if td, ok := bc.tdCache.Get(hash); ok {
		return td
	}

	// Load from database
	td := rawdb.ReadTd(bc.db, hash, number)
	if td == nil {
		return nil
	}

	// Cache
	bc.tdCache.Add(hash, td)

	return td
}

// HasBlock checks if a block exists in the chain
func (bc *BlockChain) HasBlock(hash common.Hash, number uint64) bool {
	if _, ok := bc.blockCache.Get(hash); ok {
		return true
	}
	return rawdb.ReadHeaderRLP(bc.db, hash, number) != nil
}

// State returns the state database for the current head
func (bc *BlockChain) State() (*obsstate.StateDB, error) {
	return bc.StateAt(bc.CurrentBlock().Root())
}

// StateAt returns the state database for a given root
func (bc *BlockChain) StateAt(root common.Hash) (*obsstate.StateDB, error) {
	return bc.stateCache.OpenState(root)
}

// InsertBlock inserts a new block into the chain
func (bc *BlockChain) InsertBlock(block *obstypes.ObsidianBlock) error {
	bc.insertMu.Lock()
	defer bc.insertMu.Unlock()

	return bc.insertBlock(block, true)
}

// insertBlock is the internal block insertion function
func (bc *BlockChain) insertBlock(block *obstypes.ObsidianBlock, validate bool) error {
	// Check if already known
	hash := block.Hash()
	number := block.NumberU64()
	if bc.HasBlock(hash, number) {
		return ErrKnownBlock
	}

	// Validate parent
	parent := bc.GetBlock(block.ParentHash(), number-1)
	if parent == nil {
		return ErrUnknownAncestor
	}

	// Verify header using our own validation
	if validate {
		if err := bc.verifyHeader(block.Header(), parent.Header()); err != nil {
			return fmt.Errorf("header verification failed: %w", err)
		}
	}

	// Get parent state
	parentState, err := bc.StateAt(parent.Root())
	if err != nil {
		return fmt.Errorf("failed to get parent state: %w", err)
	}

	// Execute block transactions
	receipts, logs, usedGas, err := bc.processor(block, parentState)
	if err != nil {
		return fmt.Errorf("block processing failed: %w", err)
	}

	// Verify gas used
	if usedGas != block.GasUsed() {
		return fmt.Errorf("gas used mismatch: got %d, want %d", usedGas, block.GasUsed())
	}

	// Commit state
	stateRoot, err := parentState.Commit(true)
	if err != nil {
		return fmt.Errorf("state commit failed: %w", err)
	}

	// Verify state root
	if stateRoot != block.Root() {
		return fmt.Errorf("state root mismatch: got %s, want %s", stateRoot.Hex(), block.Root().Hex())
	}

	// Persist state
	if err := bc.writeState(parentState, stateRoot); err != nil {
		return fmt.Errorf("state write failed: %w", err)
	}

	// Calculate total difficulty
	parentTd := bc.GetTd(parent.Hash(), parent.NumberU64())
	if parentTd == nil {
		return errors.New("parent total difficulty not found")
	}
	td := new(big.Int).Add(parentTd, block.Difficulty())

	// Write block to database
	bc.writeBlock(block, receipts, td)

	// Update chain head if this is the new canonical chain
	currentTd := bc.GetTd(bc.currentBlock.Load().Hash(), bc.currentBlock.Load().NumberU64())
	if td.Cmp(currentTd) > 0 {
		bc.writeHeadBlock(block)
		bc.chainHeadFeed.Send(ChainHeadEvent{Block: block})
	}

	// Emit logs
	if len(logs) > 0 {
		bc.logsFeed.Send(logs)
	}

	log.Info("Inserted block",
		"number", number,
		"hash", hash.Hex(),
		"txs", len(block.Transactions()),
		"gas", usedGas,
		"td", td,
	)

	return nil
}

// processor executes all transactions in a block
func (bc *BlockChain) processor(block *obstypes.ObsidianBlock, state *obsstate.StateDB) (obstypes.Receipts, []*obstypes.Log, uint64, error) {
	var (
		receipts    obstypes.Receipts
		allLogs     []*obstypes.Log
		usedGas     uint64
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.NumberU64()
		txs         = block.Transactions()
	)

	// Execute each transaction
	for i, tx := range txs {
		state.SetTxContext(tx.Hash(), i)

		receipt, err := bc.applyTransaction(tx, state, header, &usedGas)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("tx %d failed: %w", i, err)
		}

		receipt.BlockHash = blockHash
		receipt.BlockNumber = new(big.Int).SetUint64(blockNumber)
		receipt.TransactionIndex = uint(i)

		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}

	// Apply block reward
	bc.applyBlockReward(header, state)

	return receipts, allLogs, usedGas, nil
}

// applyTransaction executes a single transaction
func (bc *BlockChain) applyTransaction(tx *obstypes.StealthTransaction, state *obsstate.StateDB, header *obstypes.ObsidianHeader, usedGas *uint64) (*obstypes.Receipt, error) {
	// Get sender
	signer := obstypes.NewStealthEIP155Signer(bc.chainConfig.ChainID)
	from, err := signer.Sender(tx)
	if err != nil {
		return nil, fmt.Errorf("invalid sender: %w", err)
	}

	// Validate nonce
	nonce := state.GetNonce(from)
	if tx.Nonce() != nonce {
		return nil, fmt.Errorf("nonce mismatch: got %d, want %d", tx.Nonce(), nonce)
	}

	// Calculate gas cost
	gasPrice := tx.GasPrice()
	if gasPrice == nil {
		gasPrice = big.NewInt(1e9) // Default 1 Gwei
	}
	gasCost := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(tx.Gas()))

	// Check balance for gas + value
	totalCost := new(big.Int).Add(gasCost, tx.Value())
	if state.GetBalance(from).Cmp(totalCost) < 0 {
		return nil, fmt.Errorf("insufficient balance: have %s, need %s", state.GetBalance(from), totalCost)
	}

	// Deduct gas cost
	state.SubBalance(from, gasCost)
	state.SetNonce(from, nonce+1)

	// Execute transaction
	var (
		gas    uint64
		failed = false
		logs   []*obstypes.Log
	)

	to := tx.To()
	if to == nil {
		// Contract creation
		contractAddr := CreateAddress(from, nonce)
		state.CreateAccount(contractAddr)
		state.SetCode(contractAddr, tx.Data())
		state.AddBalance(contractAddr, tx.Value())
		state.SubBalance(from, tx.Value())
		gas = 21000 + uint64(len(tx.Data()))*200 // Simplified gas
	} else {
		// Transfer or contract call
		if len(state.GetCode(*to)) > 0 {
			// Contract call - simplified execution
			gas = 21000 + uint64(len(tx.Data()))*68
			// Note: Full EVM execution would go here
		} else {
			// Simple transfer
			gas = 21000
		}

		// Transfer value
		if tx.Value().Sign() > 0 {
			state.SubBalance(from, tx.Value())
			state.AddBalance(*to, tx.Value())
		}
	}

	// Refund unused gas
	gasUsed := gas
	if gasUsed > tx.Gas() {
		gasUsed = tx.Gas()
	}
	refund := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(tx.Gas()-gasUsed))
	state.AddBalance(from, refund)

	*usedGas += gasUsed

	// Create receipt
	receipt := &obstypes.Receipt{
		Type:              tx.Type(),
		Status:            obstypes.ReceiptStatusSuccessful,
		CumulativeGasUsed: *usedGas,
		Logs:              logs,
		TxHash:            tx.Hash(),
		GasUsed:           gasUsed,
		EffectiveGasPrice: gasPrice,
	}

	if failed {
		receipt.Status = obstypes.ReceiptStatusFailed
	}

	receipt.Bloom = obstypes.CreateBloom(obstypes.Receipts{receipt})

	return receipt, nil
}

// CreateAddress creates a contract address from sender and nonce
func CreateAddress(sender common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{sender, nonce})
	return common.BytesToAddress(crypto.Keccak256(data)[12:])
}

// writeBlock writes a block to the database
func (bc *BlockChain) writeBlock(block *obstypes.ObsidianBlock, receipts obstypes.Receipts, td *big.Int) {
	hash := block.Hash()
	number := block.NumberU64()

	// Write header
	headerRLP, _ := rlp.EncodeToBytes(block.Header())
	rawdb.WriteHeaderRLP(bc.db, hash, number, headerRLP)
	rawdb.WriteHeaderNumber(bc.db, hash, number)

	// Write body
	body := &obstypes.Body{
		Transactions: block.Transactions(),
		Uncles:       block.Uncles(),
	}
	bodyRLP, _ := rlp.EncodeToBytes(body)
	rawdb.WriteBodyRLP(bc.db, hash, number, bodyRLP)

	// Write receipts
	receiptsRLP, _ := rlp.EncodeToBytes(receipts)
	rawdb.WriteReceiptsRLP(bc.db, hash, number, receiptsRLP)

	// Write tx lookup entries
	txHashes := make([]common.Hash, len(block.Transactions()))
	for i, tx := range block.Transactions() {
		txHashes[i] = tx.Hash()
	}
	rawdb.WriteTxLookupEntriesByBlock(bc.db, txHashes, hash, number)

	// Write total difficulty
	rawdb.WriteTd(bc.db, hash, number, td)

	// Cache
	bc.blockCache.Add(hash, block)
	bc.headerCache.Add(hash, block.Header())
	bc.tdCache.Add(hash, td)
	bc.receiptsCache.Add(hash, receipts)
}

// writeHeadBlock updates the head block
func (bc *BlockChain) writeHeadBlock(block *obstypes.ObsidianBlock) {
	hash := block.Hash()
	number := block.NumberU64()

	rawdb.WriteCanonicalHash(bc.db, hash, number)
	rawdb.WriteHeadBlockHash(bc.db, hash)
	rawdb.WriteHeadHeaderHash(bc.db, hash)

	bc.currentBlock.Store(block)
	bc.currentFastBlock.Store(block)
}

// GetReceipts retrieves receipts for a block
func (bc *BlockChain) GetReceipts(hash common.Hash) obstypes.Receipts {
	// Check cache
	if receipts, ok := bc.receiptsCache.Get(hash); ok {
		return receipts
	}

	// Load from database
	number := rawdb.ReadHeaderNumber(bc.db, hash)
	if number == nil {
		return nil
	}

	receiptsRLP := rawdb.ReadReceiptsRLP(bc.db, hash, *number)
	if receiptsRLP == nil {
		return nil
	}

	var receipts obstypes.Receipts
	if err := rlp.DecodeBytes(receiptsRLP, &receipts); err != nil {
		return nil
	}

	// Cache
	bc.receiptsCache.Add(hash, receipts)

	return receipts
}

// SubscribeChainHeadEvent subscribes to chain head events
func (bc *BlockChain) SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription {
	return bc.scope.Track(bc.chainHeadFeed.Subscribe(ch))
}

// SubscribeLogsEvent subscribes to log events
func (bc *BlockChain) SubscribeLogsEvent(ch chan<- []*obstypes.Log) event.Subscription {
	return bc.scope.Track(bc.logsFeed.Subscribe(ch))
}

// Stop stops the blockchain
func (bc *BlockChain) Stop() {
	if !atomic.CompareAndSwapInt32(&bc.running, 0, 1) {
		return
	}

	close(bc.quit)
	bc.scope.Close()
	bc.wg.Wait()

	log.Info("Blockchain stopped")
}

// ChainHeadEvent represents a chain head change
type ChainHeadEvent struct {
	Block *obstypes.ObsidianBlock
}

// Engine returns the consensus engine
func (bc *BlockChain) Engine() *obsidianash.ObsidianAsh {
	return bc.engine
}

// Config returns the chain config
func (bc *BlockChain) Config() *ChainConfig {
	return bc.chainConfig
}

// Database returns the underlying database
func (bc *BlockChain) Database() *rawdb.Database {
	return bc.db
}

// GetVMConfig returns the VM configuration (for compatibility)
func (bc *BlockChain) GetVMConfig() interface{} {
	return nil
}

// Processor returns a state processor (for compatibility)
func (bc *BlockChain) Processor() interface{} {
	return bc
}

// SetHead rewinds the chain to a given block number
func (bc *BlockChain) SetHead(head uint64) error {
	bc.chainmu.Lock()
	defer bc.chainmu.Unlock()

	block := bc.GetBlockByNumber(head)
	if block == nil {
		return fmt.Errorf("block %d not found", head)
	}

	bc.writeHeadBlock(block)

	log.Info("Rewound chain", "number", head, "hash", block.Hash().Hex())
	return nil
}

// Export exports blocks for a range
func (bc *BlockChain) Export(first, last uint64) ([]*obstypes.ObsidianBlock, error) {
	if first > last {
		return nil, errors.New("invalid range")
	}

	blocks := make([]*obstypes.ObsidianBlock, 0, last-first+1)
	for i := first; i <= last; i++ {
		block := bc.GetBlockByNumber(i)
		if block == nil {
			return nil, fmt.Errorf("block %d not found", i)
		}
		blocks = append(blocks, block)
	}

	return blocks, nil
}

// GasLimit returns the gas limit for the current block
func (bc *BlockChain) GasLimit() uint64 {
	return bc.CurrentBlock().GasLimit()
}

// LastBlockTime returns the timestamp of the current block
func (bc *BlockChain) LastBlockTime() time.Time {
	return time.Unix(int64(bc.CurrentBlock().Time()), 0)
}

// verifyHeader validates a block header
func (bc *BlockChain) verifyHeader(header, parent *obstypes.ObsidianHeader) error {
	// Verify timestamp
	if header.Time <= parent.Time {
		return errors.New("timestamp must be after parent")
	}

	// Verify block number
	if header.Number.Uint64() != parent.Number.Uint64()+1 {
		return errors.New("invalid block number")
	}

	// Verify parent hash
	if header.ParentHash != parent.Hash() {
		return errors.New("invalid parent hash")
	}

	// Verify gas limit bounds
	diff := int64(header.GasLimit) - int64(parent.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / 1024
	if uint64(diff) >= limit {
		return errors.New("invalid gas limit")
	}

	// Verify gas used
	if header.GasUsed > header.GasLimit {
		return errors.New("gas used exceeds limit")
	}

	// Verify difficulty
	if header.Difficulty == nil || header.Difficulty.Sign() <= 0 {
		return errors.New("invalid difficulty")
	}

	return nil
}

// applyBlockReward applies the block reward to the coinbase
func (bc *BlockChain) applyBlockReward(header *obstypes.ObsidianHeader, state *obsstate.StateDB) {
	blockNumber := header.Number.Uint64()
	reward := params.CalculateBlockReward(blockNumber)
	state.AddBalance(header.Coinbase, reward)
}

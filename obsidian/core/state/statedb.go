// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package state

import (
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// StateDB is the database for storing account state
type StateDB struct {
	db      Database
	trie    Trie
	objects map[common.Address]*stateObject
	dirty   map[common.Address]struct{}
	lock    sync.RWMutex

	// Journal for reverts
	journal        *journal
	validRevisions []revision
	nextRevisionId int
}

// Database wraps access to tries and contract code
type Database interface {
	// OpenTrie opens the main account trie
	OpenTrie(root common.Hash) (Trie, error)
	// ContractCode retrieves contract code
	ContractCode(codeHash common.Hash) ([]byte, error)
	// ContractCodeSize retrieves contract code size
	ContractCodeSize(codeHash common.Hash) (int, error)
}

// Trie is a merkle patricia trie
type Trie interface {
	// GetKey returns the key stored for a given hash
	GetKey(hash []byte) []byte
	// TryGet returns the value for a given key
	TryGet(key []byte) ([]byte, error)
	// TryUpdate updates a key-value pair
	TryUpdate(key, value []byte) error
	// TryDelete deletes a key
	TryDelete(key []byte) error
	// Hash returns the root hash of the trie
	Hash() common.Hash
	// Commit commits all changes
	Commit(collectLeaf bool) (common.Hash, *NodeSet, error)
}

// NodeSet represents a set of trie nodes
type NodeSet struct {
	Nodes map[string][]byte
}

// stateObject represents an account
type stateObject struct {
	address  common.Address
	data     Account
	code     []byte
	codeHash []byte
	dirty    bool

	// Storage changes
	originStorage  map[common.Hash]common.Hash
	pendingStorage map[common.Hash]common.Hash
	dirtyStorage   map[common.Hash]common.Hash
}

// Account represents an Obsidian account
type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // storage root
	CodeHash []byte
}

// journal records state changes for reversion
type journal struct {
	entries []journalEntry
}

type journalEntry interface {
	revert(*StateDB)
}

type revision struct {
	id           int
	journalIndex int
}

// New creates a new state database
func New(root common.Hash, db Database) (*StateDB, error) {
	tr, err := db.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	return &StateDB{
		db:      db,
		trie:    tr,
		objects: make(map[common.Address]*stateObject),
		dirty:   make(map[common.Address]struct{}),
		journal: &journal{},
	}, nil
}

// NewMemoryStateDB creates an in-memory state database
func NewMemoryStateDB() *StateDB {
	return &StateDB{
		objects: make(map[common.Address]*stateObject),
		dirty:   make(map[common.Address]struct{}),
		journal: &journal{},
	}
}

// GetOrNewStateObject returns the state object for an address, creating one if needed
func (s *StateDB) GetOrNewStateObject(addr common.Address) *stateObject {
	s.lock.Lock()
	defer s.lock.Unlock()

	obj := s.objects[addr]
	if obj == nil {
		obj = &stateObject{
			address: addr,
			data: Account{
				Balance: big.NewInt(0),
			},
			originStorage:  make(map[common.Hash]common.Hash),
			pendingStorage: make(map[common.Hash]common.Hash),
			dirtyStorage:   make(map[common.Hash]common.Hash),
		}
		s.objects[addr] = obj
	}
	return obj
}

// getStateObject returns the state object for an address
func (s *StateDB) getStateObject(addr common.Address) *stateObject {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.objects[addr]
}

// GetBalance returns the balance of an account
func (s *StateDB) GetBalance(addr common.Address) *big.Int {
	obj := s.getStateObject(addr)
	if obj != nil {
		return new(big.Int).Set(obj.data.Balance)
	}
	return big.NewInt(0)
}

// SetBalance sets the balance of an account
func (s *StateDB) SetBalance(addr common.Address, amount *big.Int) {
	obj := s.GetOrNewStateObject(addr)
	obj.data.Balance = new(big.Int).Set(amount)
	obj.dirty = true
	s.dirty[addr] = struct{}{}
}

// AddBalance adds amount to an account's balance
func (s *StateDB) AddBalance(addr common.Address, amount *big.Int) {
	obj := s.GetOrNewStateObject(addr)
	obj.data.Balance = new(big.Int).Add(obj.data.Balance, amount)
	obj.dirty = true
	s.dirty[addr] = struct{}{}
}

// SubBalance subtracts amount from an account's balance
func (s *StateDB) SubBalance(addr common.Address, amount *big.Int) {
	obj := s.GetOrNewStateObject(addr)
	obj.data.Balance = new(big.Int).Sub(obj.data.Balance, amount)
	obj.dirty = true
	s.dirty[addr] = struct{}{}
}

// GetNonce returns the nonce of an account
func (s *StateDB) GetNonce(addr common.Address) uint64 {
	obj := s.getStateObject(addr)
	if obj != nil {
		return obj.data.Nonce
	}
	return 0
}

// SetNonce sets the nonce of an account
func (s *StateDB) SetNonce(addr common.Address, nonce uint64) {
	obj := s.GetOrNewStateObject(addr)
	obj.data.Nonce = nonce
	obj.dirty = true
	s.dirty[addr] = struct{}{}
}

// GetCode returns the code of an account
func (s *StateDB) GetCode(addr common.Address) []byte {
	obj := s.getStateObject(addr)
	if obj != nil {
		return obj.code
	}
	return nil
}

// SetCode sets the code of an account
func (s *StateDB) SetCode(addr common.Address, code []byte) {
	obj := s.GetOrNewStateObject(addr)
	obj.code = code
	obj.codeHash = crypto.Keccak256(code)
	obj.data.CodeHash = obj.codeHash
	obj.dirty = true
	s.dirty[addr] = struct{}{}
}

// GetCodeHash returns the code hash of an account
func (s *StateDB) GetCodeHash(addr common.Address) common.Hash {
	obj := s.getStateObject(addr)
	if obj != nil && len(obj.codeHash) > 0 {
		return common.BytesToHash(obj.codeHash)
	}
	return common.Hash{}
}

// GetCodeSize returns the code size of an account
func (s *StateDB) GetCodeSize(addr common.Address) int {
	obj := s.getStateObject(addr)
	if obj != nil {
		return len(obj.code)
	}
	return 0
}

// GetState returns the value of a storage key
func (s *StateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	obj := s.getStateObject(addr)
	if obj != nil {
		if val, ok := obj.dirtyStorage[key]; ok {
			return val
		}
		if val, ok := obj.pendingStorage[key]; ok {
			return val
		}
		if val, ok := obj.originStorage[key]; ok {
			return val
		}
	}
	return common.Hash{}
}

// SetState sets the value of a storage key
func (s *StateDB) SetState(addr common.Address, key, value common.Hash) {
	obj := s.GetOrNewStateObject(addr)
	obj.dirtyStorage[key] = value
	obj.dirty = true
	s.dirty[addr] = struct{}{}
}

// Exist returns whether an account exists
func (s *StateDB) Exist(addr common.Address) bool {
	return s.getStateObject(addr) != nil
}

// Empty returns whether an account is empty
func (s *StateDB) Empty(addr common.Address) bool {
	obj := s.getStateObject(addr)
	if obj == nil {
		return true
	}
	return obj.data.Nonce == 0 && obj.data.Balance.Sign() == 0 && len(obj.code) == 0
}

// CreateAccount creates a new account
func (s *StateDB) CreateAccount(addr common.Address) {
	s.GetOrNewStateObject(addr)
}

// Snapshot creates a snapshot for later reversion
func (s *StateDB) Snapshot() int {
	id := s.nextRevisionId
	s.nextRevisionId++
	s.validRevisions = append(s.validRevisions, revision{id: id, journalIndex: len(s.journal.entries)})
	return id
}

// RevertToSnapshot reverts to a previous snapshot
func (s *StateDB) RevertToSnapshot(revid int) {
	// Find the snapshot index
	idx := -1
	for i := len(s.validRevisions) - 1; i >= 0; i-- {
		if s.validRevisions[i].id == revid {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}

	// Revert journal entries
	snapshot := s.validRevisions[idx]
	for i := len(s.journal.entries) - 1; i >= snapshot.journalIndex; i-- {
		s.journal.entries[i].revert(s)
	}
	s.journal.entries = s.journal.entries[:snapshot.journalIndex]
	s.validRevisions = s.validRevisions[:idx]
}

// Finalise finalizes the state
func (s *StateDB) Finalise(deleteEmptyObjects bool) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for addr := range s.dirty {
		obj := s.objects[addr]
		if obj == nil {
			continue
		}

		// Move dirty storage to pending
		for key, value := range obj.dirtyStorage {
			obj.pendingStorage[key] = value
		}
		obj.dirtyStorage = make(map[common.Hash]common.Hash)

		if deleteEmptyObjects && s.emptyObject(obj) {
			delete(s.objects, addr)
		}
	}
	s.dirty = make(map[common.Address]struct{})
}

func (s *StateDB) emptyObject(obj *stateObject) bool {
	return obj.data.Nonce == 0 && obj.data.Balance.Sign() == 0 && len(obj.code) == 0
}

// IntermediateRoot computes the state root
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) common.Hash {
	s.Finalise(deleteEmptyObjects)
	// In a full implementation, this would update the trie and return its root
	return common.Hash{}
}

// Commit commits the state changes
func (s *StateDB) Commit(deleteEmptyObjects bool) (common.Hash, error) {
	root := s.IntermediateRoot(deleteEmptyObjects)
	// In a full implementation, this would persist changes to disk
	return root, nil
}

// Copy creates a deep copy of the state
func (s *StateDB) Copy() *StateDB {
	s.lock.RLock()
	defer s.lock.RUnlock()

	state := &StateDB{
		db:      s.db,
		trie:    s.trie,
		objects: make(map[common.Address]*stateObject),
		dirty:   make(map[common.Address]struct{}),
		journal: &journal{},
	}

	for addr, obj := range s.objects {
		newObj := &stateObject{
			address:        obj.address,
			data:           obj.data,
			code:           obj.code,
			codeHash:       obj.codeHash,
			originStorage:  make(map[common.Hash]common.Hash),
			pendingStorage: make(map[common.Hash]common.Hash),
			dirtyStorage:   make(map[common.Hash]common.Hash),
		}
		newObj.data.Balance = new(big.Int).Set(obj.data.Balance)
		for k, v := range obj.originStorage {
			newObj.originStorage[k] = v
		}
		for k, v := range obj.pendingStorage {
			newObj.pendingStorage[k] = v
		}
		for k, v := range obj.dirtyStorage {
			newObj.dirtyStorage[k] = v
		}
		state.objects[addr] = newObj
	}

	for addr := range s.dirty {
		state.dirty[addr] = struct{}{}
	}

	return state
}

// GetLogs returns all logs
func (s *StateDB) GetLogs(hash common.Hash, blockNumber uint64, blockHash common.Hash) []*Log {
	return nil // TODO: implement
}

// Log represents a log entry
type Log struct {
	Address     common.Address
	Topics      []common.Hash
	Data        []byte
	BlockNumber uint64
	TxHash      common.Hash
	TxIndex     uint
	BlockHash   common.Hash
	Index       uint
}

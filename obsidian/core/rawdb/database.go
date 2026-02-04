// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package rawdb

import (
	"encoding/binary"
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	// Database key prefixes
	headerPrefix       = []byte("h") // headerPrefix + num (uint64 big endian) + hash -> header
	headerHashSuffix   = []byte("n") // headerPrefix + num (uint64 big endian) + headerHashSuffix -> hash
	headerNumberPrefix = []byte("H") // headerNumberPrefix + hash -> num (uint64 big endian)

	blockBodyPrefix     = []byte("b") // blockBodyPrefix + num (uint64 big endian) + hash -> block body
	blockReceiptsPrefix = []byte("r") // blockReceiptsPrefix + num (uint64 big endian) + hash -> block receipts

	txLookupPrefix = []byte("l") // txLookupPrefix + hash -> transaction lookup entry

	codePrefix = []byte("c") // codePrefix + code hash -> contract code

	headHeaderKey = []byte("LastHeader")
	headBlockKey  = []byte("LastBlock")

	// Account state keys (for flat state)
	accountPrefix = []byte("a") // accountPrefix + address hash -> account data
	storagePrefix = []byte("o") // storagePrefix + address hash + key hash -> storage value

	// Total difficulty
	tdSuffix = []byte("t") // headerPrefix + num + hash + tdSuffix -> total difficulty
)

var (
	ErrNotFound = errors.New("not found")
)

// Database wraps access to LevelDB
type Database struct {
	db   *leveldb.DB
	path string
	mu   sync.RWMutex
}

// NewDatabase creates a new database instance
func NewDatabase(path string) (*Database, error) {
	opts := &opt.Options{
		OpenFilesCacheCapacity: 256,
		BlockCacheCapacity:     256 * opt.MiB,
		WriteBuffer:            128 * opt.MiB,
		Filter:                 filter.NewBloomFilter(10),
	}

	db, err := leveldb.OpenFile(path, opts)
	if err != nil {
		return nil, err
	}

	log.Info("Opened database", "path", path)
	return &Database{
		db:   db,
		path: path,
	}, nil
}

// Close closes the database
func (d *Database) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.db.Close()
}

// Put writes a key-value pair to the database
func (d *Database) Put(key, value []byte) error {
	return d.db.Put(key, value, nil)
}

// Get retrieves a value by key
func (d *Database) Get(key []byte) ([]byte, error) {
	value, err := d.db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, ErrNotFound
	}
	return value, err
}

// Has checks if a key exists
func (d *Database) Has(key []byte) (bool, error) {
	return d.db.Has(key, nil)
}

// Delete removes a key
func (d *Database) Delete(key []byte) error {
	return d.db.Delete(key, nil)
}

// NewIterator creates a new iterator
func (d *Database) NewIterator(prefix []byte, start []byte) interface{} {
	return d.db.NewIterator(util.BytesPrefix(prefix), nil)
}

// NewBatch creates a new write batch
func (d *Database) NewBatch() *Batch {
	return &Batch{
		db:    d.db,
		batch: new(leveldb.Batch),
	}
}

// Batch represents a batch of writes
type Batch struct {
	db    *leveldb.DB
	batch *leveldb.Batch
	size  int
}

// Put adds a put operation to the batch
func (b *Batch) Put(key, value []byte) error {
	b.batch.Put(key, value)
	b.size += len(key) + len(value)
	return nil
}

// Delete adds a delete operation to the batch
func (b *Batch) Delete(key []byte) error {
	b.batch.Delete(key)
	b.size += len(key)
	return nil
}

// ValueSize returns the size of data in the batch
func (b *Batch) ValueSize() int {
	return b.size
}

// Write commits the batch to the database
func (b *Batch) Write() error {
	return b.db.Write(b.batch, nil)
}

// Reset resets the batch
func (b *Batch) Reset() {
	b.batch.Reset()
	b.size = 0
}

// Helper functions for key encoding

// encodeBlockNumber encodes a block number as big-endian uint64
func encodeBlockNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

// headerKey returns the header key for a given number and hash
func headerKey(number uint64, hash common.Hash) []byte {
	return append(append(headerPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// headerHashKey returns the hash lookup key for a block number
func headerHashKey(number uint64) []byte {
	return append(append(headerPrefix, encodeBlockNumber(number)...), headerHashSuffix...)
}

// headerNumberKey returns the number lookup key for a header hash
func headerNumberKey(hash common.Hash) []byte {
	return append(headerNumberPrefix, hash.Bytes()...)
}

// blockBodyKey returns the block body key
func blockBodyKey(number uint64, hash common.Hash) []byte {
	return append(append(blockBodyPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// blockReceiptsKey returns the receipts key
func blockReceiptsKey(number uint64, hash common.Hash) []byte {
	return append(append(blockReceiptsPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// txLookupKey returns the transaction lookup key
func txLookupKey(hash common.Hash) []byte {
	return append(txLookupPrefix, hash.Bytes()...)
}

// codeKey returns the code storage key
func codeKey(codeHash common.Hash) []byte {
	return append(codePrefix, codeHash.Bytes()...)
}

// accountKey returns the account storage key
func accountKey(addressHash common.Hash) []byte {
	return append(accountPrefix, addressHash.Bytes()...)
}

// storageKey returns the storage key
func storageKey(addressHash, keyHash common.Hash) []byte {
	return append(append(storagePrefix, addressHash.Bytes()...), keyHash.Bytes()...)
}

// tdKey returns the total difficulty key
func tdKey(number uint64, hash common.Hash) []byte {
	return append(append(append(headerPrefix, encodeBlockNumber(number)...), hash.Bytes()...), tdSuffix...)
}

// Header/Block storage functions

// ReadHeaderRLP retrieves a header in RLP encoding
func ReadHeaderRLP(db *Database, hash common.Hash, number uint64) rlp.RawValue {
	data, err := db.Get(headerKey(number, hash))
	if err != nil {
		return nil
	}
	return data
}

// WriteHeaderRLP stores a header in RLP encoding
func WriteHeaderRLP(db *Database, hash common.Hash, number uint64, rlp rlp.RawValue) {
	key := headerKey(number, hash)
	if err := db.Put(key, rlp); err != nil {
		log.Crit("Failed to store header", "err", err)
	}
}

// ReadCanonicalHash retrieves the canonical block hash for a number
func ReadCanonicalHash(db *Database, number uint64) common.Hash {
	data, err := db.Get(headerHashKey(number))
	if err != nil {
		return common.Hash{}
	}
	return common.BytesToHash(data)
}

// WriteCanonicalHash stores the canonical block hash for a number
func WriteCanonicalHash(db *Database, hash common.Hash, number uint64) {
	if err := db.Put(headerHashKey(number), hash.Bytes()); err != nil {
		log.Crit("Failed to store number to hash mapping", "err", err)
	}
}

// ReadHeaderNumber retrieves the block number for a header hash
func ReadHeaderNumber(db *Database, hash common.Hash) *uint64 {
	data, err := db.Get(headerNumberKey(hash))
	if err != nil {
		return nil
	}
	number := binary.BigEndian.Uint64(data)
	return &number
}

// WriteHeaderNumber stores the hash to number mapping
func WriteHeaderNumber(db *Database, hash common.Hash, number uint64) {
	if err := db.Put(headerNumberKey(hash), encodeBlockNumber(number)); err != nil {
		log.Crit("Failed to store hash to number mapping", "err", err)
	}
}

// ReadBodyRLP retrieves the block body in RLP encoding
func ReadBodyRLP(db *Database, hash common.Hash, number uint64) rlp.RawValue {
	data, err := db.Get(blockBodyKey(number, hash))
	if err != nil {
		return nil
	}
	return data
}

// WriteBodyRLP stores the block body in RLP encoding
func WriteBodyRLP(db *Database, hash common.Hash, number uint64, rlp rlp.RawValue) {
	if err := db.Put(blockBodyKey(number, hash), rlp); err != nil {
		log.Crit("Failed to store block body", "err", err)
	}
}

// ReadReceiptsRLP retrieves all receipts in RLP encoding
func ReadReceiptsRLP(db *Database, hash common.Hash, number uint64) rlp.RawValue {
	data, err := db.Get(blockReceiptsKey(number, hash))
	if err != nil {
		return nil
	}
	return data
}

// WriteReceiptsRLP stores the receipts in RLP encoding
func WriteReceiptsRLP(db *Database, hash common.Hash, number uint64, rlp rlp.RawValue) {
	if err := db.Put(blockReceiptsKey(number, hash), rlp); err != nil {
		log.Crit("Failed to store block receipts", "err", err)
	}
}

// TxLookupEntry represents a transaction lookup entry
type TxLookupEntry struct {
	BlockHash  common.Hash
	BlockIndex uint64
	TxIndex    uint64
}

// ReadTxLookupEntry retrieves a transaction's lookup entry
func ReadTxLookupEntry(db *Database, hash common.Hash) *TxLookupEntry {
	data, err := db.Get(txLookupKey(hash))
	if err != nil {
		return nil
	}
	var entry TxLookupEntry
	if err := rlp.DecodeBytes(data, &entry); err != nil {
		return nil
	}
	return &entry
}

// WriteTxLookupEntry stores a transaction's lookup entry
func WriteTxLookupEntry(db *Database, hash common.Hash, entry *TxLookupEntry) {
	data, err := rlp.EncodeToBytes(entry)
	if err != nil {
		log.Crit("Failed to encode tx lookup entry", "err", err)
	}
	if err := db.Put(txLookupKey(hash), data); err != nil {
		log.Crit("Failed to store tx lookup entry", "err", err)
	}
}

// WriteTxLookupEntriesByBlock stores tx lookup entries for all transactions in a block
func WriteTxLookupEntriesByBlock(db *Database, txHashes []common.Hash, blockHash common.Hash, blockNumber uint64) {
	batch := db.NewBatch()
	for i, txHash := range txHashes {
		entry := &TxLookupEntry{
			BlockHash:  blockHash,
			BlockIndex: blockNumber,
			TxIndex:    uint64(i),
		}
		data, _ := rlp.EncodeToBytes(entry)
		_ = batch.Put(txLookupKey(txHash), data)
	}
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write tx lookup entries", "err", err)
	}
}

// ReadCode retrieves contract code
func ReadCode(db *Database, codeHash common.Hash) []byte {
	data, err := db.Get(codeKey(codeHash))
	if err != nil {
		return nil
	}
	return data
}

// WriteCode stores contract code
func WriteCode(db *Database, codeHash common.Hash, code []byte) {
	if err := db.Put(codeKey(codeHash), code); err != nil {
		log.Crit("Failed to store contract code", "err", err)
	}
}

// Head block accessors

// ReadHeadHeaderHash retrieves the head header hash
func ReadHeadHeaderHash(db *Database) common.Hash {
	data, err := db.Get(headHeaderKey)
	if err != nil {
		return common.Hash{}
	}
	return common.BytesToHash(data)
}

// WriteHeadHeaderHash stores the head header hash
func WriteHeadHeaderHash(db *Database, hash common.Hash) {
	if err := db.Put(headHeaderKey, hash.Bytes()); err != nil {
		log.Crit("Failed to store head header hash", "err", err)
	}
}

// ReadHeadBlockHash retrieves the head block hash
func ReadHeadBlockHash(db *Database) common.Hash {
	data, err := db.Get(headBlockKey)
	if err != nil {
		return common.Hash{}
	}
	return common.BytesToHash(data)
}

// WriteHeadBlockHash stores the head block hash
func WriteHeadBlockHash(db *Database, hash common.Hash) {
	if err := db.Put(headBlockKey, hash.Bytes()); err != nil {
		log.Crit("Failed to store head block hash", "err", err)
	}
}

// ReadTd retrieves the total difficulty for a block
func ReadTd(db *Database, hash common.Hash, number uint64) *big.Int {
	data, err := db.Get(tdKey(number, hash))
	if err != nil {
		return nil
	}
	td := new(big.Int)
	if err := rlp.DecodeBytes(data, td); err != nil {
		return nil
	}
	return td
}

// WriteTd stores the total difficulty for a block
func WriteTd(db *Database, hash common.Hash, number uint64, td *big.Int) {
	data, err := rlp.EncodeToBytes(td)
	if err != nil {
		log.Crit("Failed to encode total difficulty", "err", err)
	}
	if err := db.Put(tdKey(number, hash), data); err != nil {
		log.Crit("Failed to store total difficulty", "err", err)
	}
}

// Account state accessors (flat state storage)

// ReadAccountData retrieves the encoded account data
func ReadAccountData(db *Database, addressHash common.Hash) []byte {
	data, err := db.Get(accountKey(addressHash))
	if err != nil {
		return nil
	}
	return data
}

// WriteAccountData stores the encoded account data
func WriteAccountData(db *Database, addressHash common.Hash, data []byte) {
	if err := db.Put(accountKey(addressHash), data); err != nil {
		log.Crit("Failed to store account data", "err", err)
	}
}

// DeleteAccountData removes account data
func DeleteAccountData(db *Database, addressHash common.Hash) {
	if err := db.Delete(accountKey(addressHash)); err != nil {
		log.Crit("Failed to delete account data", "err", err)
	}
}

// ReadStorageData retrieves storage data
func ReadStorageData(db *Database, addressHash, keyHash common.Hash) []byte {
	data, err := db.Get(storageKey(addressHash, keyHash))
	if err != nil {
		return nil
	}
	return data
}

// WriteStorageData stores storage data
func WriteStorageData(db *Database, addressHash, keyHash common.Hash, value []byte) {
	if err := db.Put(storageKey(addressHash, keyHash), value); err != nil {
		log.Crit("Failed to store storage data", "err", err)
	}
}

// DeleteStorageData removes storage data
func DeleteStorageData(db *Database, addressHash, keyHash common.Hash) {
	if err := db.Delete(storageKey(addressHash, keyHash)); err != nil {
		log.Crit("Failed to delete storage data", "err", err)
	}
}

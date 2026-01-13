// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package types

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// ObsidianHeader represents a block header in the Obsidian blockchain
type ObsidianHeader struct {
	ParentHash  common.Hash    `json:"parentHash"`
	UncleHash   common.Hash    `json:"sha3Uncles"`
	Coinbase    common.Address `json:"miner"`
	Root        common.Hash    `json:"stateRoot"`
	TxHash      common.Hash    `json:"transactionsRoot"`
	ReceiptHash common.Hash    `json:"receiptsRoot"`
	Bloom       types.Bloom    `json:"logsBloom"`
	Difficulty  *big.Int       `json:"difficulty"`
	Number      *big.Int       `json:"number"`
	GasLimit    uint64         `json:"gasLimit"`
	GasUsed     uint64         `json:"gasUsed"`
	Time        uint64         `json:"timestamp"`
	Extra       []byte         `json:"extraData"`
	MixDigest   common.Hash    `json:"mixHash"`
	Nonce       BlockNonce     `json:"nonce"`

	// EIP-1559 fields (optional)
	BaseFee *big.Int `json:"baseFeePerGas" rlp:"optional"`

	// EIP-4895 fields (optional)
	WithdrawalsHash *common.Hash `json:"withdrawalsRoot" rlp:"optional"`

	// EIP-4844 fields (optional)
	BlobGasUsed   *uint64 `json:"blobGasUsed" rlp:"optional"`
	ExcessBlobGas *uint64 `json:"excessBlobGas" rlp:"optional"`

	// EIP-4788 fields (optional)
	ParentBeaconRoot *common.Hash `json:"parentBeaconBlockRoot" rlp:"optional"`
}

// BlockNonce is a 64-bit hash used as PoW nonce
type BlockNonce [8]byte

// EncodeNonce converts a uint64 to BlockNonce
func EncodeNonce(i uint64) BlockNonce {
	var n BlockNonce
	binary.BigEndian.PutUint64(n[:], i)
	return n
}

// Uint64 returns the nonce as uint64
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:])
}

// Hash returns the block hash
func (h *ObsidianHeader) Hash() common.Hash {
	return rlpHash(h)
}

// Size returns the approximate memory used by the header
func (h *ObsidianHeader) Size() uint64 {
	c := writeCounter(0)
	rlp.Encode(&c, h)
	return uint64(c)
}

// SanityCheck performs a sanity check on the header
func (h *ObsidianHeader) SanityCheck() error {
	if h.Number == nil {
		return errMissingNumber
	}
	if h.Difficulty == nil {
		return errMissingDifficulty
	}
	if len(h.Extra) > 32 {
		return errExtraDataTooLong
	}
	return nil
}

// ObsidianBlock represents a complete block in the Obsidian blockchain
type ObsidianBlock struct {
	header       *ObsidianHeader
	uncles       []*ObsidianHeader
	transactions []*StealthTransaction
	withdrawals  types.Withdrawals

	// caches
	hash atomic.Value
	size atomic.Value

	// TD is used by package core to store total difficulty
	td *big.Int

	// ReceivedAt and ReceivedFrom track block arrival
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

// NewBlock creates a new block
func NewBlock(header *ObsidianHeader, txs []*StealthTransaction, uncles []*ObsidianHeader, receipts []*types.Receipt) *ObsidianBlock {
	b := &ObsidianBlock{
		header: CopyHeader(header),
		td:     new(big.Int),
	}

	if len(txs) == 0 {
		b.header.TxHash = types.EmptyTxsHash
	} else {
		b.header.TxHash = DeriveSha(StealthTransactions(txs))
		b.transactions = make([]*StealthTransaction, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = types.EmptyReceiptsHash
	} else {
		b.header.ReceiptHash = types.DeriveSha(types.Receipts(receipts), trie.NewStackTrie(nil))
		b.header.Bloom = types.MergeBloom(types.Receipts(receipts))
	}

	if len(uncles) == 0 {
		b.header.UncleHash = types.EmptyUncleHash
	} else {
		b.header.UncleHash = CalcUncleHash(uncles)
		b.uncles = make([]*ObsidianHeader, len(uncles))
		for i := range uncles {
			b.uncles[i] = CopyHeader(uncles[i])
		}
	}

	return b
}

// DeriveSha computes the Merkle root of a list of items
func DeriveSha(list StealthTransactions) common.Hash {
	hasher := trie.NewStackTrie(nil)
	var buf bytes.Buffer
	for i := 0; i < list.Len(); i++ {
		buf.Reset()
		list.EncodeIndex(i, &buf)
		hasher.Update(rlp.AppendUint64(nil, uint64(i)), buf.Bytes())
	}
	return hasher.Hash()
}

// NewBlockWithHeader creates a block with the given header data
func NewBlockWithHeader(header *ObsidianHeader) *ObsidianBlock {
	return &ObsidianBlock{header: CopyHeader(header)}
}

// CopyHeader creates a deep copy of a header
func CopyHeader(h *ObsidianHeader) *ObsidianHeader {
	cpy := *h
	if cpy.Difficulty = new(big.Int); h.Difficulty != nil {
		cpy.Difficulty.Set(h.Difficulty)
	}
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if h.BaseFee != nil {
		cpy.BaseFee = new(big.Int).Set(h.BaseFee)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	return &cpy
}

// CalcUncleHash calculates the uncle hash
func CalcUncleHash(uncles []*ObsidianHeader) common.Hash {
	if len(uncles) == 0 {
		return types.EmptyUncleHash
	}
	return rlpHash(uncles)
}

// Header returns the block header
func (b *ObsidianBlock) Header() *ObsidianHeader {
	return CopyHeader(b.header)
}

// Body returns the block body
func (b *ObsidianBlock) Body() *ObsidianBody {
	return &ObsidianBody{b.transactions, b.uncles, b.withdrawals}
}

// Transactions returns the block transactions
func (b *ObsidianBlock) Transactions() []*StealthTransaction {
	return b.transactions
}

// Transaction returns the transaction at the given index
func (b *ObsidianBlock) Transaction(hash common.Hash) *StealthTransaction {
	for _, tx := range b.transactions {
		if tx.Hash() == hash {
			return tx
		}
	}
	return nil
}

// Uncles returns the block uncles
func (b *ObsidianBlock) Uncles() []*ObsidianHeader {
	return b.uncles
}

// Withdrawals returns the block withdrawals
func (b *ObsidianBlock) Withdrawals() types.Withdrawals {
	return b.withdrawals
}

// Number returns the block number
func (b *ObsidianBlock) Number() *big.Int {
	return new(big.Int).Set(b.header.Number)
}

// GasLimit returns the gas limit
func (b *ObsidianBlock) GasLimit() uint64 {
	return b.header.GasLimit
}

// GasUsed returns the gas used
func (b *ObsidianBlock) GasUsed() uint64 {
	return b.header.GasUsed
}

// Difficulty returns the difficulty
func (b *ObsidianBlock) Difficulty() *big.Int {
	return new(big.Int).Set(b.header.Difficulty)
}

// Time returns the timestamp
func (b *ObsidianBlock) Time() uint64 {
	return b.header.Time
}

// NumberU64 returns the block number as uint64
func (b *ObsidianBlock) NumberU64() uint64 {
	return b.header.Number.Uint64()
}

// MixDigest returns the mix digest
func (b *ObsidianBlock) MixDigest() common.Hash {
	return b.header.MixDigest
}

// Nonce returns the nonce
func (b *ObsidianBlock) Nonce() uint64 {
	return b.header.Nonce.Uint64()
}

// Bloom returns the bloom filter
func (b *ObsidianBlock) Bloom() types.Bloom {
	return b.header.Bloom
}

// Coinbase returns the coinbase address
func (b *ObsidianBlock) Coinbase() common.Address {
	return b.header.Coinbase
}

// Root returns the state root
func (b *ObsidianBlock) Root() common.Hash {
	return b.header.Root
}

// ParentHash returns the parent hash
func (b *ObsidianBlock) ParentHash() common.Hash {
	return b.header.ParentHash
}

// TxHash returns the transaction hash
func (b *ObsidianBlock) TxHash() common.Hash {
	return b.header.TxHash
}

// ReceiptHash returns the receipt hash
func (b *ObsidianBlock) ReceiptHash() common.Hash {
	return b.header.ReceiptHash
}

// UncleHash returns the uncle hash
func (b *ObsidianBlock) UncleHash() common.Hash {
	return b.header.UncleHash
}

// Extra returns the extra data
func (b *ObsidianBlock) Extra() []byte {
	return common.CopyBytes(b.header.Extra)
}

// BaseFee returns the base fee
func (b *ObsidianBlock) BaseFee() *big.Int {
	if b.header.BaseFee == nil {
		return nil
	}
	return new(big.Int).Set(b.header.BaseFee)
}

// Hash returns the keccak256 hash of the block
func (b *ObsidianBlock) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := b.header.Hash()
	b.hash.Store(v)
	return v
}

// Size returns the approximate size of the block
func (b *ObsidianBlock) Size() uint64 {
	if size := b.size.Load(); size != nil {
		return size.(uint64)
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	size := uint64(c)
	b.size.Store(size)
	return size
}

// WithSeal returns a new block with the sealed header
func (b *ObsidianBlock) WithSeal(header *ObsidianHeader) *ObsidianBlock {
	cpy := *header

	return &ObsidianBlock{
		header:       &cpy,
		transactions: b.transactions,
		uncles:       b.uncles,
		withdrawals:  b.withdrawals,
	}
}

// WithBody returns a new block with the given body
func (b *ObsidianBlock) WithBody(transactions []*StealthTransaction, uncles []*ObsidianHeader) *ObsidianBlock {
	block := &ObsidianBlock{
		header:       CopyHeader(b.header),
		transactions: make([]*StealthTransaction, len(transactions)),
		uncles:       make([]*ObsidianHeader, len(uncles)),
	}
	copy(block.transactions, transactions)
	for i := range uncles {
		block.uncles[i] = CopyHeader(uncles[i])
	}
	return block
}

// ObsidianBody represents a block body
type ObsidianBody struct {
	Transactions []*StealthTransaction
	Uncles       []*ObsidianHeader
	Withdrawals  types.Withdrawals
}

// StealthTransactions implements types.DerivableList for stealth transactions
type StealthTransactions []*StealthTransaction

// Len returns the number of transactions
func (s StealthTransactions) Len() int { return len(s) }

// EncodeIndex encodes the i-th transaction to the buffer
func (s StealthTransactions) EncodeIndex(i int, w *bytes.Buffer) {
	rlp.Encode(w, s[i])
}

// Errors
var (
	errMissingNumber     = &headerError{"missing number"}
	errMissingDifficulty = &headerError{"missing difficulty"}
	errExtraDataTooLong  = &headerError{"extra data too long"}
)

type headerError struct {
	msg string
}

func (e *headerError) Error() string { return e.msg }

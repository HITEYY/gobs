// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint64(0)
	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint64(1)
)

// Receipt represents the results of a transaction.
type Receipt struct {
	// Consensus fields
	Type              uint8  `json:"type,omitempty"`
	PostState         []byte `json:"root"`
	Status            uint64 `json:"status"`
	CumulativeGasUsed uint64 `json:"cumulativeGasUsed" gencodec:"required"`
	Bloom             Bloom  `json:"logsBloom"         gencodec:"required"`
	Logs              []*Log `json:"logs"              gencodec:"required"`

	// Implementation fields
	TxHash            common.Hash    `json:"transactionHash" gencodec:"required"`
	ContractAddress   common.Address `json:"contractAddress"`
	GasUsed           uint64         `json:"gasUsed" gencodec:"required"`
	EffectiveGasPrice *big.Int       `json:"effectiveGasPrice"`

	// Inclusion information
	BlockHash        common.Hash `json:"blockHash,omitempty"`
	BlockNumber      *big.Int    `json:"blockNumber,omitempty"`
	TransactionIndex uint        `json:"transactionIndex"`
}

// Receipts is a wrapper around a Receipt array to implement DerivableList.
type Receipts []*Receipt

// Len returns the number of receipts in this list.
func (rs Receipts) Len() int { return len(rs) }

// EncodeIndex encodes the i'th receipt to w.
func (rs Receipts) EncodeIndex(i int, w *bytes.Buffer) {
	r := rs[i]
	data := &receiptRLP{r.PostState, r.Status, r.CumulativeGasUsed, r.Bloom, r.Logs}
	if r.Type == LegacyTxType {
		_ = rlp.Encode(w, data)
	} else {
		w.WriteByte(r.Type)
		_ = rlp.Encode(w, data)
	}
}

// receiptRLP is the consensus encoding of a receipt.
type receiptRLP struct {
	PostStateOrStatus []byte
	Status            uint64
	CumulativeGasUsed uint64
	Bloom             Bloom
	Logs              []*Log
}

// NewReceipt creates a new receipt
func NewReceipt(root []byte, failed bool, cumulativeGasUsed uint64) *Receipt {
	r := &Receipt{
		Type:              LegacyTxType,
		PostState:         common.CopyBytes(root),
		CumulativeGasUsed: cumulativeGasUsed,
	}
	if failed {
		r.Status = ReceiptStatusFailed
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

// EncodeRLP implements rlp.Encoder
func (r *Receipt) EncodeRLP(w *rlp.EncoderBuffer) error {
	data := &receiptRLP{r.statusEncoding(), r.Status, r.CumulativeGasUsed, r.Bloom, r.Logs}
	if r.Type == LegacyTxType {
		return rlp.Encode(w, data)
	}
	buf := w.List()
	w.WriteBytes([]byte{r.Type})
	_ = rlp.Encode(w, data)
	w.ListEnd(buf)
	return nil
}

// DecodeRLP implements rlp.Decoder
func (r *Receipt) DecodeRLP(s *rlp.Stream) error {
	kind, _, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		// Legacy receipt
		var dec receiptRLP
		if err := s.Decode(&dec); err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(dec)
	default:
		// Typed receipt
		b, err := s.Bytes()
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return rlp.EOL
		}
		r.Type = b[0]
		var dec receiptRLP
		if err := rlp.DecodeBytes(b[1:], &dec); err != nil {
			return err
		}
		return r.setFromRLP(dec)
	}
}

func (r *Receipt) setFromRLP(data receiptRLP) error {
	r.CumulativeGasUsed = data.CumulativeGasUsed
	r.Bloom = data.Bloom
	r.Logs = data.Logs
	return r.setStatus(data.PostStateOrStatus, data.Status)
}

func (r *Receipt) setStatus(postStateOrStatus []byte, status uint64) error {
	if len(postStateOrStatus) > 0 {
		r.PostState = postStateOrStatus
	} else {
		r.Status = status
	}
	return nil
}

func (r *Receipt) statusEncoding() []byte {
	if len(r.PostState) == 0 {
		if r.Status == ReceiptStatusFailed {
			return []byte{}
		}
		return []byte{0x01}
	}
	return r.PostState
}

// Size returns the approximate memory used by all internal contents
func (r *Receipt) Size() uint64 {
	size := uint64(len(r.PostState))
	size += 8 // CumulativeGasUsed
	size += uint64(len(r.Bloom))
	size += uint64(len(r.TxHash))
	size += uint64(len(r.ContractAddress))
	size += 8 // GasUsed
	size += uint64(len(r.BlockHash))
	for _, log := range r.Logs {
		size += log.Size()
	}
	return size
}

// DeriveFields fills the receipts with their computed fields based on consensus
// data and contextual infos like containing block and transactions.
func (rs Receipts) DeriveFields(hash common.Hash, number uint64, baseFee *big.Int, txs []*StealthTransaction) error {
	logIndex := uint(0)
	for i := 0; i < len(rs); i++ {
		rs[i].Type = txs[i].Type()
		rs[i].TxHash = txs[i].Hash()
		rs[i].BlockHash = hash
		rs[i].BlockNumber = new(big.Int).SetUint64(number)
		rs[i].TransactionIndex = uint(i)

		// Effective gas price
		if txs[i].GasPrice() != nil {
			rs[i].EffectiveGasPrice = txs[i].GasPrice()
		} else if baseFee != nil && txs[i].GasFeeCap() != nil && txs[i].GasTipCap() != nil {
			tip := new(big.Int).Sub(txs[i].GasFeeCap(), baseFee)
			if tip.Cmp(txs[i].GasTipCap()) > 0 {
				tip = txs[i].GasTipCap()
			}
			rs[i].EffectiveGasPrice = new(big.Int).Add(baseFee, tip)
		}

		// Gas used
		if i == 0 {
			rs[i].GasUsed = rs[i].CumulativeGasUsed
		} else {
			rs[i].GasUsed = rs[i].CumulativeGasUsed - rs[i-1].CumulativeGasUsed
		}

		// Logs
		for j := 0; j < len(rs[i].Logs); j++ {
			rs[i].Logs[j].BlockHash = hash
			rs[i].Logs[j].BlockNumber = number
			rs[i].Logs[j].TxHash = rs[i].TxHash
			rs[i].Logs[j].TxIndex = uint(i)
			rs[i].Logs[j].Index = logIndex
			logIndex++
		}
	}
	return nil
}

// Log represents a contract log event.
type Log struct {
	// Consensus fields
	Address common.Address `json:"address" gencodec:"required"`
	Topics  []common.Hash  `json:"topics" gencodec:"required"`
	Data    []byte         `json:"data" gencodec:"required"`

	// Derived fields
	BlockNumber uint64      `json:"blockNumber"`
	TxHash      common.Hash `json:"transactionHash" gencodec:"required"`
	TxIndex     uint        `json:"transactionIndex"`
	BlockHash   common.Hash `json:"blockHash"`
	Index       uint        `json:"logIndex"`

	// Removed is true if this log was reverted due to a chain reorganisation.
	Removed bool `json:"removed"`
}

// Size returns the approximate memory used by all internal contents
func (l *Log) Size() uint64 {
	return uint64(len(l.Address) + len(l.Data) + len(l.Topics)*32 + 64)
}

// LogForStorage is a wrapper around Log for RLP encoding
type LogForStorage Log

// EncodeRLP implements rlp.Encoder
func (l *LogForStorage) EncodeRLP(w *rlp.EncoderBuffer) error {
	return rlp.Encode(w, []interface{}{l.Address, l.Topics, l.Data})
}

// DecodeRLP implements rlp.Decoder
func (l *LogForStorage) DecodeRLP(s *rlp.Stream) error {
	var dec struct {
		Address common.Address
		Topics  []common.Hash
		Data    []byte
	}
	if err := s.Decode(&dec); err != nil {
		return err
	}
	l.Address = dec.Address
	l.Topics = dec.Topics
	l.Data = dec.Data
	return nil
}

// Bloom represents a 2048 bit bloom filter.
type Bloom [256]byte

// BytesToBloom converts a byte slice to a bloom filter.
func BytesToBloom(b []byte) Bloom {
	var bloom Bloom
	bloom.SetBytes(b)
	return bloom
}

// SetBytes sets the content of b to the given bytes.
func (b *Bloom) SetBytes(d []byte) {
	if len(d) > len(b) {
		d = d[len(d)-len(b):]
	}
	copy(b[len(b)-len(d):], d)
}

// Add adds topics to the bloom filter.
func (b *Bloom) Add(topics []byte) {
	b.add(topics, make([]byte, 6))
}

func (b *Bloom) add(topics []byte, buf []byte) {
	i1, v1, i2, v2, i3, v3 := bloomValues(topics, buf)
	b[i1] |= v1
	b[i2] |= v2
	b[i3] |= v3
}

// Test returns true if the bloom filter matches the given topics.
func (b Bloom) Test(topics []byte) bool {
	i1, v1, i2, v2, i3, v3 := bloomValues(topics, make([]byte, 6))
	return b[i1]&v1 == v1 &&
		b[i2]&v2 == v2 &&
		b[i3]&v3 == v3
}

// Bytes returns the bloom filter as a byte slice.
func (b Bloom) Bytes() []byte {
	return b[:]
}

// bloomValues calculates the bit positions for bloom filter.
func bloomValues(data []byte, hashbuf []byte) (uint, byte, uint, byte, uint, byte) {
	sha := crypto.NewKeccakState()
	sha.Write(data)
	_, _ = sha.Read(hashbuf)
	// The actual bits to flip
	v1 := byte(1 << (hashbuf[1] & 0x7))
	v2 := byte(1 << (hashbuf[3] & 0x7))
	v3 := byte(1 << (hashbuf[5] & 0x7))
	// The bit locations
	i1 := 256 - uint((uint16(hashbuf[0])<<8|uint16(hashbuf[1]))&2047)/8 - 1
	i2 := 256 - uint((uint16(hashbuf[2])<<8|uint16(hashbuf[3]))&2047)/8 - 1
	i3 := 256 - uint((uint16(hashbuf[4])<<8|uint16(hashbuf[5]))&2047)/8 - 1
	return i1, v1, i2, v2, i3, v3
}

// CreateBloom creates a bloom filter from a set of receipts.
func CreateBloom(receipts Receipts) Bloom {
	var bin Bloom
	for _, receipt := range receipts {
		for _, log := range receipt.Logs {
			bin.Add(log.Address.Bytes())
			for _, topic := range log.Topics {
				bin.Add(topic.Bytes())
			}
		}
	}
	return bin
}

// LogsBloom creates a bloom filter from logs.
func LogsBloom(logs []*Log) []byte {
	var bin Bloom
	for _, log := range logs {
		bin.Add(log.Address.Bytes())
		for _, topic := range log.Topics {
			bin.Add(topic.Bytes())
		}
	}
	return bin[:]
}

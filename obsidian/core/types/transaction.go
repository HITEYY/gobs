// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package types

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// LegacyTxType is the type identifier for legacy transactions
	LegacyTxType = 0x00
	// AccessListTxType is the type identifier for EIP-2930 transactions
	AccessListTxType = 0x01
	// DynamicFeeTxType is the type identifier for EIP-1559 transactions
	DynamicFeeTxType = 0x02
	// StealthTxType is the type identifier for Obsidian stealth transactions
	StealthTxType = 0x10
)

var (
	// ErrInvalidStealthTx is returned when stealth transaction validation fails
	ErrInvalidStealthTx = errors.New("invalid stealth transaction")
	// ErrMissingEphemeralKey is returned when ephemeral key is missing
	ErrMissingEphemeralKey = errors.New("missing ephemeral public key")
	// ErrInvalidViewTag is returned when view tag doesn't match
	ErrInvalidViewTag = errors.New("invalid view tag")
)

// StealthTxData represents a stealth transaction
type StealthTxData struct {
	ChainID    *big.Int
	Nonce      uint64
	GasPrice   *big.Int // nil for dynamic fee tx
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList types.AccessList

	// Stealth-specific fields
	EphemeralPubKey []byte // 33 bytes compressed public key
	ViewTag         byte   // 1 byte view tag for fast scanning

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

// StealthTransaction wraps a stealth transaction with caching
type StealthTransaction struct {
	inner StealthTxData

	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

// NewStealthTransaction creates a new stealth transaction
func NewStealthTransaction(
	nonce uint64,
	to common.Address,
	amount *big.Int,
	gasLimit uint64,
	gasPrice *big.Int,
	data []byte,
	ephemeralPubKey []byte,
	viewTag byte,
) *StealthTransaction {
	return &StealthTransaction{
		inner: StealthTxData{
			Nonce:           nonce,
			GasPrice:        gasPrice,
			Gas:             gasLimit,
			To:              &to,
			Value:           amount,
			Data:            data,
			EphemeralPubKey: ephemeralPubKey,
			ViewTag:         viewTag,
		},
	}
}

// NewStealthContractCreation creates a new stealth contract creation transaction
func NewStealthContractCreation(
	nonce uint64,
	amount *big.Int,
	gasLimit uint64,
	gasPrice *big.Int,
	data []byte,
	ephemeralPubKey []byte,
	viewTag byte,
) *StealthTransaction {
	return &StealthTransaction{
		inner: StealthTxData{
			Nonce:           nonce,
			GasPrice:        gasPrice,
			Gas:             gasLimit,
			To:              nil,
			Value:           amount,
			Data:            data,
			EphemeralPubKey: ephemeralPubKey,
			ViewTag:         viewTag,
		},
	}
}

// Type returns the transaction type
func (tx *StealthTransaction) Type() uint8 {
	return StealthTxType
}

// ChainId returns the chain ID of the transaction
func (tx *StealthTransaction) ChainId() *big.Int {
	return tx.inner.ChainID
}

// Data returns the input data of the transaction
func (tx *StealthTransaction) Data() []byte {
	return tx.inner.Data
}

// AccessList returns the access list of the transaction
func (tx *StealthTransaction) AccessList() types.AccessList {
	return tx.inner.AccessList
}

// Gas returns the gas limit of the transaction
func (tx *StealthTransaction) Gas() uint64 {
	return tx.inner.Gas
}

// GasPrice returns the gas price of the transaction
func (tx *StealthTransaction) GasPrice() *big.Int {
	return tx.inner.GasPrice
}

// GasTipCap returns the gas tip cap
func (tx *StealthTransaction) GasTipCap() *big.Int {
	return tx.inner.GasTipCap
}

// GasFeeCap returns the gas fee cap
func (tx *StealthTransaction) GasFeeCap() *big.Int {
	return tx.inner.GasFeeCap
}

// Value returns the value of the transaction
func (tx *StealthTransaction) Value() *big.Int {
	return tx.inner.Value
}

// Nonce returns the nonce of the transaction
func (tx *StealthTransaction) Nonce() uint64 {
	return tx.inner.Nonce
}

// To returns the recipient address
func (tx *StealthTransaction) To() *common.Address {
	return tx.inner.To
}

// EphemeralPubKey returns the ephemeral public key
func (tx *StealthTransaction) EphemeralPubKey() []byte {
	return tx.inner.EphemeralPubKey
}

// ViewTag returns the view tag
func (tx *StealthTransaction) ViewTag() byte {
	return tx.inner.ViewTag
}

// RawSignatureValues returns the raw signature values
func (tx *StealthTransaction) RawSignatureValues() (v, r, s *big.Int) {
	return tx.inner.V, tx.inner.R, tx.inner.S
}

// Hash returns the hash of the transaction
func (tx *StealthTransaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	h := rlpHash(tx)
	tx.hash.Store(h)
	return h
}

// Size returns the encoded size of the transaction
func (tx *StealthTransaction) Size() uint64 {
	if size := tx.size.Load(); size != nil {
		return size.(uint64)
	}
	c := writeCounter(0)
	rlp.Encode(&c, tx)
	size := uint64(c)
	tx.size.Store(size)
	return size
}

// WithSignature returns a new transaction with the given signature
func (tx *StealthTransaction) WithSignature(signer StealthSigner, sig []byte) (*StealthTransaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := &StealthTransaction{inner: tx.inner}
	cpy.inner.R, cpy.inner.S, cpy.inner.V = r, s, v
	return cpy, nil
}

// EncodeRLP encodes the transaction to RLP
func (tx *StealthTransaction) EncodeRLP(w *rlp.EncoderBuffer) error {
	buf := w.List()
	w.WriteUint64(uint64(StealthTxType))
	if err := rlp.Encode(w, &tx.inner); err != nil {
		return err
	}
	w.ListEnd(buf)
	return nil
}

// DecodeRLP decodes the transaction from RLP
func (tx *StealthTransaction) DecodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return err
	}
	var txType uint64
	if err := s.Decode(&txType); err != nil {
		return err
	}
	if txType != StealthTxType {
		return ErrInvalidStealthTx
	}
	if err := s.Decode(&tx.inner); err != nil {
		return err
	}
	return s.ListEnd()
}

// ValidateBasic performs basic validation
func (tx *StealthTransaction) ValidateBasic() error {
	if len(tx.inner.EphemeralPubKey) != 33 {
		return ErrMissingEphemeralKey
	}
	if tx.inner.Value == nil || tx.inner.Value.Sign() < 0 {
		return errors.New("invalid value")
	}
	if tx.inner.Gas == 0 {
		return errors.New("gas is zero")
	}
	return nil
}

// StealthSigner provides signing functionality for stealth transactions
type StealthSigner interface {
	// Sender returns the sender address of the transaction
	Sender(tx *StealthTransaction) (common.Address, error)
	// SignatureValues returns r, s, v values from a signature
	SignatureValues(tx *StealthTransaction, sig []byte) (r, s, v *big.Int, err error)
	// Hash returns the hash to be signed
	Hash(tx *StealthTransaction) common.Hash
	// Equal checks if two signers are equal
	Equal(StealthSigner) bool
}

// StealthEIP155Signer implements EIP-155 signing for stealth transactions
type StealthEIP155Signer struct {
	chainId, chainIdMul *big.Int
}

// NewStealthEIP155Signer creates a new EIP-155 signer for stealth transactions
func NewStealthEIP155Signer(chainId *big.Int) StealthEIP155Signer {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return StealthEIP155Signer{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

// Equal checks if two signers are equal
func (s StealthEIP155Signer) Equal(other StealthSigner) bool {
	o, ok := other.(StealthEIP155Signer)
	if !ok {
		return false
	}
	return s.chainId.Cmp(o.chainId) == 0
}

// Sender returns the sender address
func (s StealthEIP155Signer) Sender(tx *StealthTransaction) (common.Address, error) {
	V, R, S := tx.RawSignatureValues()
	if V == nil || R == nil || S == nil {
		return common.Address{}, errors.New("missing signature")
	}

	// Derive the V value for recovery
	V = new(big.Int).Sub(V, s.chainIdMul)
	V.Sub(V, big.NewInt(8))

	return recoverPlain(s.Hash(tx), R, S, V, true)
}

// SignatureValues returns signature values
func (s StealthEIP155Signer) SignatureValues(tx *StealthTransaction, sig []byte) (R, S, V *big.Int, err error) {
	if len(sig) != crypto.SignatureLength {
		return nil, nil, nil, errors.New("invalid signature length")
	}
	R = new(big.Int).SetBytes(sig[:32])
	S = new(big.Int).SetBytes(sig[32:64])
	V = big.NewInt(int64(sig[64] + 35))
	V.Add(V, s.chainIdMul)
	return R, S, V, nil
}

// Hash returns the hash to be signed
func (s StealthEIP155Signer) Hash(tx *StealthTransaction) common.Hash {
	return rlpHash([]interface{}{
		tx.inner.Nonce,
		tx.inner.GasPrice,
		tx.inner.Gas,
		tx.inner.To,
		tx.inner.Value,
		tx.inner.Data,
		tx.inner.EphemeralPubKey,
		tx.inner.ViewTag,
		s.chainId, uint(0), uint(0),
	})
}

// SignStealthTx signs a stealth transaction with the given private key
func SignStealthTx(tx *StealthTransaction, s StealthSigner, prv *ecdsa.PrivateKey) (*StealthTransaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

// Helper functions

type writeCounter uint64

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := crypto.NewKeccakState()
	rlp.Encode(hw, x)
	hw.Read(h[:])
	return h
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int, homestead bool) (common.Address, error) {
	if Vb.BitLen() > 8 {
		return common.Address{}, errors.New("invalid signature")
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, homestead) {
		return common.Address{}, errors.New("invalid signature")
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

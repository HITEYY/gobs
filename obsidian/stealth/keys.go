// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

// Package stealth implements the Stealth Address protocol for Obsidian.
// Stealth addresses allow senders to create unique, one-time addresses for recipients,
// hiding the recipient's identity while maintaining EVM compatibility.
package stealth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// ErrInvalidKey is returned when a key is invalid
	ErrInvalidKey = errors.New("invalid stealth key")
	// ErrInvalidViewKey is returned when a view key is invalid
	ErrInvalidViewKey = errors.New("invalid view key")
	// ErrInvalidSpendKey is returned when a spend key is invalid
	ErrInvalidSpendKey = errors.New("invalid spend key")
)

// StealthKeyPair contains both the spend key and view key for stealth addresses
type StealthKeyPair struct {
	// SpendKey is used to spend funds sent to stealth addresses
	SpendPrivateKey *ecdsa.PrivateKey
	SpendPublicKey  *ecdsa.PublicKey

	// ViewKey is used to scan the blockchain for incoming payments
	ViewPrivateKey *ecdsa.PrivateKey
	ViewPublicKey  *ecdsa.PublicKey
}

// StealthMetaAddress is the public information shared with senders
// Senders use this to create stealth addresses
type StealthMetaAddress struct {
	// SpendPubKey is the recipient's spend public key
	SpendPubKey []byte
	// ViewPubKey is the recipient's view public key
	ViewPubKey []byte
}

// GenerateStealthKeyPair generates a new stealth key pair
func GenerateStealthKeyPair() (*StealthKeyPair, error) {
	// Generate spend key
	spendPriv, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Generate view key
	viewPriv, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &StealthKeyPair{
		SpendPrivateKey: spendPriv,
		SpendPublicKey:  &spendPriv.PublicKey,
		ViewPrivateKey:  viewPriv,
		ViewPublicKey:   &viewPriv.PublicKey,
	}, nil
}

// FromPrivateKeys creates a StealthKeyPair from existing private keys
func FromPrivateKeys(spendPrivHex, viewPrivHex string) (*StealthKeyPair, error) {
	spendPriv, err := crypto.HexToECDSA(spendPrivHex)
	if err != nil {
		return nil, ErrInvalidSpendKey
	}

	viewPriv, err := crypto.HexToECDSA(viewPrivHex)
	if err != nil {
		return nil, ErrInvalidViewKey
	}

	return &StealthKeyPair{
		SpendPrivateKey: spendPriv,
		SpendPublicKey:  &spendPriv.PublicKey,
		ViewPrivateKey:  viewPriv,
		ViewPublicKey:   &viewPriv.PublicKey,
	}, nil
}

// MetaAddress returns the stealth meta-address (public keys) for sharing
func (kp *StealthKeyPair) MetaAddress() *StealthMetaAddress {
	return &StealthMetaAddress{
		SpendPubKey: crypto.CompressPubkey(kp.SpendPublicKey),
		ViewPubKey:  crypto.CompressPubkey(kp.ViewPublicKey),
	}
}

// String returns the hex-encoded meta-address string
// Format: "st:obs:<spendPubKey><viewPubKey>"
func (m *StealthMetaAddress) String() string {
	return "st:obs:" + common.Bytes2Hex(m.SpendPubKey) + common.Bytes2Hex(m.ViewPubKey)
}

// ParseMetaAddress parses a stealth meta-address string
func ParseMetaAddress(s string) (*StealthMetaAddress, error) {
	if len(s) < 7 || s[:7] != "st:obs:" {
		return nil, errors.New("invalid stealth meta-address format")
	}

	data := common.FromHex(s[7:])
	if len(data) != 66 { // 33 bytes spend + 33 bytes view
		return nil, errors.New("invalid stealth meta-address length")
	}

	return &StealthMetaAddress{
		SpendPubKey: data[:33],
		ViewPubKey:  data[33:],
	}, nil
}

// PublicKeyToAddress converts a public key to an Ethereum address
func PublicKeyToAddress(pubKey *ecdsa.PublicKey) common.Address {
	return crypto.PubkeyToAddress(*pubKey)
}

// CompressPublicKey compresses an ECDSA public key
func CompressPublicKey(pubKey *ecdsa.PublicKey) []byte {
	return crypto.CompressPubkey(pubKey)
}

// DecompressPublicKey decompresses a 33-byte compressed public key
func DecompressPublicKey(compressed []byte) (*ecdsa.PublicKey, error) {
	return crypto.DecompressPubkey(compressed)
}

// SharedSecret computes the ECDH shared secret between a private key and public key
func SharedSecret(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) []byte {
	// Compute the shared point: privKey * pubKey
	x, _ := crypto.S256().ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())

	// Hash the x-coordinate to get the shared secret
	return crypto.Keccak256(x.Bytes())
}

// DeriveStealthPrivateKey derives the private key for a stealth address
// This is used by the recipient to derive the key to spend funds
func DeriveStealthPrivateKey(spendPrivKey *ecdsa.PrivateKey, sharedSecret []byte) *ecdsa.PrivateKey {
	// stealthPrivKey = spendPrivKey + hash(sharedSecret)
	secretScalar := new(big.Int).SetBytes(sharedSecret)
	stealthScalar := new(big.Int).Add(spendPrivKey.D, secretScalar)
	stealthScalar.Mod(stealthScalar, crypto.S256().Params().N)

	stealthPrivKey := new(ecdsa.PrivateKey)
	stealthPrivKey.D = stealthScalar
	stealthPrivKey.PublicKey.Curve = crypto.S256()
	stealthPrivKey.PublicKey.X, stealthPrivKey.PublicKey.Y = crypto.S256().ScalarBaseMult(stealthScalar.Bytes())

	return stealthPrivKey
}

// DeriveStealthPublicKey derives the public key for a stealth address
// This is used by the sender to create the stealth address
func DeriveStealthPublicKey(spendPubKey *ecdsa.PublicKey, sharedSecret []byte) *ecdsa.PublicKey {
	// stealthPubKey = spendPubKey + hash(sharedSecret) * G
	secretScalar := new(big.Int).SetBytes(sharedSecret)

	// Compute hash(sharedSecret) * G
	gx, gy := crypto.S256().ScalarBaseMult(secretScalar.Bytes())

	// Add to spend public key
	stealthX, stealthY := crypto.S256().Add(spendPubKey.X, spendPubKey.Y, gx, gy)

	return &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     stealthX,
		Y:     stealthY,
	}
}

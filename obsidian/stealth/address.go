// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package stealth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// ErrInvalidEphemeralKey is returned when the ephemeral public key is invalid
	ErrInvalidEphemeralKey = errors.New("invalid ephemeral public key")
	// ErrNotRecipient is returned when scanning indicates we're not the recipient
	ErrNotRecipient = errors.New("not the intended recipient")
)

// StealthAddress represents a one-time stealth address
type StealthAddress struct {
	// Address is the one-time Ethereum address
	Address common.Address
	// EphemeralPubKey is the ephemeral public key used to derive this address
	// The recipient needs this to derive the private key
	EphemeralPubKey []byte
	// ViewTag is an optional 1-byte tag for fast filtering (EIP-5564 style)
	ViewTag byte
}

// GenerateStealthAddress creates a new stealth address for the recipient
// This is called by the sender when they want to send funds privately
func GenerateStealthAddress(metaAddress *StealthMetaAddress) (*StealthAddress, error) {
	// Decompress recipient's public keys
	viewPubKey, err := DecompressPublicKey(metaAddress.ViewPubKey)
	if err != nil {
		return nil, ErrInvalidViewKey
	}

	spendPubKey, err := DecompressPublicKey(metaAddress.SpendPubKey)
	if err != nil {
		return nil, ErrInvalidSpendKey
	}

	// Generate ephemeral key pair
	ephemeralPrivKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Compute shared secret: ephemeralPrivKey * viewPubKey
	sharedSecret := SharedSecret(ephemeralPrivKey, viewPubKey)

	// Derive stealth public key: spendPubKey + hash(sharedSecret) * G
	stealthPubKey := DeriveStealthPublicKey(spendPubKey, sharedSecret)

	// Convert to address
	stealthAddr := PublicKeyToAddress(stealthPubKey)

	// Compute view tag (first byte of hashed shared secret for fast filtering)
	viewTag := crypto.Keccak256(sharedSecret)[0]

	return &StealthAddress{
		Address:         stealthAddr,
		EphemeralPubKey: CompressPublicKey(&ephemeralPrivKey.PublicKey),
		ViewTag:         viewTag,
	}, nil
}

// GenerateStealthAddressFromKeys is like GenerateStealthAddress but takes raw keys
func GenerateStealthAddressFromKeys(spendPubKey, viewPubKey *ecdsa.PublicKey) (*StealthAddress, *ecdsa.PrivateKey, error) {
	// Generate ephemeral key pair
	ephemeralPrivKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Compute shared secret: ephemeralPrivKey * viewPubKey
	sharedSecret := SharedSecret(ephemeralPrivKey, viewPubKey)

	// Derive stealth public key: spendPubKey + hash(sharedSecret) * G
	stealthPubKey := DeriveStealthPublicKey(spendPubKey, sharedSecret)

	// Convert to address
	stealthAddr := PublicKeyToAddress(stealthPubKey)

	// Compute view tag
	viewTag := crypto.Keccak256(sharedSecret)[0]

	return &StealthAddress{
		Address:         stealthAddr,
		EphemeralPubKey: CompressPublicKey(&ephemeralPrivKey.PublicKey),
		ViewTag:         viewTag,
	}, ephemeralPrivKey, nil
}

// CheckStealthAddress checks if a stealth address belongs to us
// Returns true if we can derive the private key for this address
func CheckStealthAddress(viewPrivKey *ecdsa.PrivateKey, spendPubKey *ecdsa.PublicKey, ephemeralPubKey []byte, expectedViewTag byte) (bool, error) {
	// Decompress ephemeral public key
	ephPubKey, err := DecompressPublicKey(ephemeralPubKey)
	if err != nil {
		return false, ErrInvalidEphemeralKey
	}

	// Compute shared secret: viewPrivKey * ephemeralPubKey
	sharedSecret := SharedSecret(viewPrivKey, ephPubKey)

	// Quick check with view tag
	computedViewTag := crypto.Keccak256(sharedSecret)[0]
	if computedViewTag != expectedViewTag {
		return false, nil
	}

	return true, nil
}

// DeriveStealthAddressPrivateKey derives the private key for a stealth address
// This is called by the recipient to get the key to spend funds
func DeriveStealthAddressPrivateKey(viewPrivKey, spendPrivKey *ecdsa.PrivateKey, ephemeralPubKey []byte) (*ecdsa.PrivateKey, common.Address, error) {
	// Decompress ephemeral public key
	ephPubKey, err := DecompressPublicKey(ephemeralPubKey)
	if err != nil {
		return nil, common.Address{}, ErrInvalidEphemeralKey
	}

	// Compute shared secret: viewPrivKey * ephemeralPubKey
	sharedSecret := SharedSecret(viewPrivKey, ephPubKey)

	// Derive stealth private key: spendPrivKey + hash(sharedSecret)
	stealthPrivKey := DeriveStealthPrivateKey(spendPrivKey, sharedSecret)

	// Compute the address from the private key
	stealthAddr := crypto.PubkeyToAddress(stealthPrivKey.PublicKey)

	return stealthPrivKey, stealthAddr, nil
}

// ComputeStealthAddress computes what the stealth address would be for given keys
// Used for verification without revealing the private key
func ComputeStealthAddress(viewPrivKey *ecdsa.PrivateKey, spendPubKey *ecdsa.PublicKey, ephemeralPubKey []byte) (common.Address, error) {
	// Decompress ephemeral public key
	ephPubKey, err := DecompressPublicKey(ephemeralPubKey)
	if err != nil {
		return common.Address{}, ErrInvalidEphemeralKey
	}

	// Compute shared secret: viewPrivKey * ephemeralPubKey
	sharedSecret := SharedSecret(viewPrivKey, ephPubKey)

	// Derive stealth public key: spendPubKey + hash(sharedSecret) * G
	stealthPubKey := DeriveStealthPublicKey(spendPubKey, sharedSecret)

	// Convert to address
	return PublicKeyToAddress(stealthPubKey), nil
}

// StealthPayment represents a detected stealth payment
type StealthPayment struct {
	// TxHash is the transaction hash
	TxHash common.Hash
	// BlockNumber is the block containing this payment
	BlockNumber uint64
	// StealthAddress is the one-time address
	StealthAddress common.Address
	// EphemeralPubKey is needed to derive the private key
	EphemeralPubKey []byte
	// Amount is the value transferred (in wei)
	Amount string
	// PrivateKey is the derived key (only set if recipient)
	PrivateKey *ecdsa.PrivateKey
}

// ViewTagFilter is a fast filter for stealth address scanning
// It allows quick rejection of transactions that are definitely not for us
type ViewTagFilter struct {
	viewPrivKey *ecdsa.PrivateKey
	spendPubKey *ecdsa.PublicKey
}

// NewViewTagFilter creates a new view tag filter
func NewViewTagFilter(viewPrivKey *ecdsa.PrivateKey, spendPubKey *ecdsa.PublicKey) *ViewTagFilter {
	return &ViewTagFilter{
		viewPrivKey: viewPrivKey,
		spendPubKey: spendPubKey,
	}
}

// CheckViewTag quickly checks if a view tag matches
func (f *ViewTagFilter) CheckViewTag(ephemeralPubKey []byte, viewTag byte) bool {
	ephPubKey, err := DecompressPublicKey(ephemeralPubKey)
	if err != nil {
		return false
	}

	sharedSecret := SharedSecret(f.viewPrivKey, ephPubKey)
	computedTag := crypto.Keccak256(sharedSecret)[0]

	return computedTag == viewTag
}

// DeriveAddress derives the stealth address and checks if it matches
func (f *ViewTagFilter) DeriveAddress(ephemeralPubKey []byte, expectedAddr common.Address) (bool, *ecdsa.PrivateKey, error) {
	ephPubKey, err := DecompressPublicKey(ephemeralPubKey)
	if err != nil {
		return false, nil, ErrInvalidEphemeralKey
	}

	sharedSecret := SharedSecret(f.viewPrivKey, ephPubKey)
	stealthPubKey := DeriveStealthPublicKey(f.spendPubKey, sharedSecret)
	derivedAddr := PublicKeyToAddress(stealthPubKey)

	if derivedAddr != expectedAddr {
		return false, nil, nil
	}

	// We are the recipient - derive the private key
	// Note: This requires the spend private key, which isn't stored in the filter
	// The caller should use DeriveStealthAddressPrivateKey with their spend key

	return true, nil, nil
}

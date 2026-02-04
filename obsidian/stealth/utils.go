// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package stealth

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// SharedSecretPoint computes the ECDH shared point between a private key and public key
func SharedSecretPoint(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) (*big.Int, *big.Int) {
	return crypto.S256().ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
}

// SharedSecretBytes computes the ECDH shared secret bytes (Keccak256 of X coordinate)
func SharedSecretBytes(x, y *big.Int) []byte {
	return crypto.Keccak256(x.Bytes())
}

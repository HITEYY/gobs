// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
)

const (
	// Standard scrypt parameters
	scryptN     = 262144 // 2^18
	scryptR     = 8
	scryptP     = 1
	scryptDKLen = 32

	// Light scrypt parameters (for faster testing)
	lightScryptN = 4096 // 2^12
	lightScryptR = 8
	lightScryptP = 6

	// Key file version
	keyFileVersion = 3
)

var (
	ErrDecryptFailed = errors.New("could not decrypt key with given password")
	ErrMACMismatch   = errors.New("MAC verification failed")
)

// EncryptKey encrypts a key with a password using scrypt and AES-128-CTR
func EncryptKey(key *Key, password string) (*encryptedKeyJSON, error) {
	// Generate random salt
	salt, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	// Derive key using scrypt
	derivedKey, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return nil, err
	}

	// First half of derived key is encryption key
	encryptKey := derivedKey[:16]

	// Generate random IV
	iv, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}

	// Encrypt private key
	privateKeyBytes := crypto.FromECDSA(key.PrivateKey)
	cipherText, err := aesCTRXOR(encryptKey, privateKeyBytes, iv)
	if err != nil {
		return nil, err
	}

	// Generate MAC: Keccak256(derivedKey[16:32] + cipherText)
	mac := crypto.Keccak256(derivedKey[16:32], cipherText)

	// Create encrypted key JSON
	encryptedKeyJSON := &encryptedKeyJSON{
		Address: hex.EncodeToString(key.Address[:]),
		ID:      key.ID.String(),
		Version: keyFileVersion,
		Crypto: cryptoJSON{
			Cipher: "aes-128-ctr",
			CipherParams: cipherparamsJSON{
				IV: hex.EncodeToString(iv),
			},
			CipherText: hex.EncodeToString(cipherText),
			KDF:        "scrypt",
			KDFParams: map[string]interface{}{
				"dklen": scryptDKLen,
				"n":     scryptN,
				"p":     scryptP,
				"r":     scryptR,
				"salt":  hex.EncodeToString(salt),
			},
			MAC: hex.EncodeToString(mac),
		},
	}

	return encryptedKeyJSON, nil
}

// DecryptKey decrypts an encrypted key JSON with a password
func DecryptKey(encryptedKey *encryptedKeyJSON, password string) (*Key, error) {
	if encryptedKey.Version != keyFileVersion {
		return nil, fmt.Errorf("unsupported key file version: %d", encryptedKey.Version)
	}

	if encryptedKey.Crypto.Cipher != "aes-128-ctr" {
		return nil, fmt.Errorf("unsupported cipher: %s", encryptedKey.Crypto.Cipher)
	}

	if encryptedKey.Crypto.KDF != "scrypt" {
		return nil, fmt.Errorf("unsupported KDF: %s", encryptedKey.Crypto.KDF)
	}

	// Extract KDF params
	kdfParams := encryptedKey.Crypto.KDFParams
	salt, err := hex.DecodeString(kdfParams["salt"].(string))
	if err != nil {
		return nil, err
	}

	n := int(kdfParams["n"].(float64))
	r := int(kdfParams["r"].(float64))
	p := int(kdfParams["p"].(float64))
	dklen := int(kdfParams["dklen"].(float64))

	// Derive key using scrypt
	derivedKey, err := scrypt.Key([]byte(password), salt, n, r, p, dklen)
	if err != nil {
		return nil, err
	}

	// Verify MAC
	cipherText, err := hex.DecodeString(encryptedKey.Crypto.CipherText)
	if err != nil {
		return nil, err
	}

	mac, err := hex.DecodeString(encryptedKey.Crypto.MAC)
	if err != nil {
		return nil, err
	}

	calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
	if !equalBytes(mac, calculatedMAC) {
		return nil, ErrMACMismatch
	}

	// Decrypt private key
	iv, err := hex.DecodeString(encryptedKey.Crypto.CipherParams.IV)
	if err != nil {
		return nil, err
	}

	encryptKey := derivedKey[:16]
	privateKeyBytes, err := aesCTRXOR(encryptKey, cipherText, iv)
	if err != nil {
		return nil, err
	}

	// Parse private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	// Parse UUID
	id, err := uuid.Parse(encryptedKey.ID)
	if err != nil {
		return nil, err
	}

	// Parse address
	address := common.HexToAddress(encryptedKey.Address)

	// Verify address matches
	derivedAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	if derivedAddress != address {
		return nil, errors.New("address mismatch")
	}

	return &Key{
		ID:         id,
		Address:    address,
		PrivateKey: privateKey,
	}, nil
}

// aesCTRXOR performs AES-128-CTR encryption/decryption
func aesCTRXOR(key, input, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	output := make([]byte, len(input))
	stream.XORKeyStream(output, input)

	return output, nil
}

// equalBytes performs constant-time byte comparison
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// HashPassword hashes a password using SHA256
func HashPassword(password string) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	return h.Sum(nil)
}

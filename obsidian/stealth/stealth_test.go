// Copyright 2024 The Obsidian Authors
// This file is part of Obsidian.

package stealth

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestGenerateStealthKeyPair(t *testing.T) {
	keyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate stealth key pair: %v", err)
	}

	if keyPair.SpendPrivateKey == nil {
		t.Fatal("Spend private key is nil")
	}
	if keyPair.ViewPrivateKey == nil {
		t.Fatal("View private key is nil")
	}
	if keyPair.SpendPublicKey == nil {
		t.Fatal("Spend public key is nil")
	}
	if keyPair.ViewPublicKey == nil {
		t.Fatal("View public key is nil")
	}
}

func TestMetaAddress(t *testing.T) {
	keyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	metaAddr := keyPair.MetaAddress()

	// Check meta address format
	if len(metaAddr.SpendPubKey) != 33 {
		t.Errorf("Spend public key should be 33 bytes (compressed), got %d", len(metaAddr.SpendPubKey))
	}
	if len(metaAddr.ViewPubKey) != 33 {
		t.Errorf("View public key should be 33 bytes (compressed), got %d", len(metaAddr.ViewPubKey))
	}

	// Check string format
	str := metaAddr.String()
	if len(str) < 10 || str[:7] != "st:obs:" {
		t.Errorf("Invalid meta address format: %s", str)
	}
}

func TestParseMetaAddress(t *testing.T) {
	keyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	metaAddr := keyPair.MetaAddress()
	metaAddrStr := metaAddr.String()

	// Parse the meta address
	parsed, err := ParseMetaAddress(metaAddrStr)
	if err != nil {
		t.Fatalf("Failed to parse meta address: %v", err)
	}

	// Compare
	if string(parsed.SpendPubKey) != string(metaAddr.SpendPubKey) {
		t.Error("Spend public keys don't match")
	}
	if string(parsed.ViewPubKey) != string(metaAddr.ViewPubKey) {
		t.Error("View public keys don't match")
	}
}

func TestGenerateStealthAddress(t *testing.T) {
	// Generate recipient's key pair
	recipientKeyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	metaAddr := recipientKeyPair.MetaAddress()

	// Generate stealth address (as sender would do)
	stealthAddr, err := GenerateStealthAddress(metaAddr)
	if err != nil {
		t.Fatalf("Failed to generate stealth address: %v", err)
	}

	// Verify stealth address components
	if stealthAddr.Address == (common.Address{}) {
		t.Error("Stealth address is empty")
	}
	if len(stealthAddr.EphemeralPubKey) != 33 {
		t.Errorf("Ephemeral public key should be 33 bytes, got %d", len(stealthAddr.EphemeralPubKey))
	}
}

func TestCheckStealthAddress(t *testing.T) {
	// Generate recipient's key pair
	recipientKeyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	metaAddr := recipientKeyPair.MetaAddress()

	// Generate stealth address (as sender would do)
	stealthAddr, err := GenerateStealthAddress(metaAddr)
	if err != nil {
		t.Fatalf("Failed to generate stealth address: %v", err)
	}

	// Check if recipient can identify this stealth address as theirs
	isOurs, err := CheckStealthAddress(
		recipientKeyPair.ViewPrivateKey,
		recipientKeyPair.SpendPublicKey,
		stealthAddr.EphemeralPubKey,
		stealthAddr.ViewTag,
	)
	if err != nil {
		t.Fatalf("Failed to check stealth address: %v", err)
	}
	if !isOurs {
		t.Error("Recipient should be able to identify their stealth address")
	}
}

func TestDeriveStealthPrivateKey(t *testing.T) {
	// Generate recipient's key pair
	recipientKeyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	metaAddr := recipientKeyPair.MetaAddress()

	// Generate stealth address (as sender would do)
	stealthAddr, err := GenerateStealthAddress(metaAddr)
	if err != nil {
		t.Fatalf("Failed to generate stealth address: %v", err)
	}

	// Derive the private key to spend from this stealth address
	privKey, derivedAddr, err := DeriveStealthAddressPrivateKey(
		recipientKeyPair.ViewPrivateKey,
		recipientKeyPair.SpendPrivateKey,
		stealthAddr.EphemeralPubKey,
	)
	if err != nil {
		t.Fatalf("Failed to derive stealth private key: %v", err)
	}

	if privKey == nil {
		t.Fatal("Derived private key is nil")
	}

	// Verify that the derived address matches the stealth address
	if derivedAddr != stealthAddr.Address {
		t.Errorf("Derived address %s doesn't match stealth address %s",
			derivedAddr.Hex(), stealthAddr.Address.Hex())
	}
}

func TestViewTagFiltering(t *testing.T) {
	// Generate recipient's key pair
	recipientKeyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	metaAddr := recipientKeyPair.MetaAddress()

	// Create filter
	filter := NewViewTagFilter(recipientKeyPair.ViewPrivateKey, recipientKeyPair.SpendPublicKey)

	// Generate multiple stealth addresses and check view tag filtering
	matchCount := 0
	totalTests := 100

	for i := 0; i < totalTests; i++ {
		stealthAddr, err := GenerateStealthAddress(metaAddr)
		if err != nil {
			t.Fatalf("Failed to generate stealth address: %v", err)
		}

		// Quick filter should pass for our addresses
		if filter.CheckViewTag(stealthAddr.EphemeralPubKey, stealthAddr.ViewTag) {
			// Full verification
			isOurs, err := CheckStealthAddress(
				recipientKeyPair.ViewPrivateKey,
				recipientKeyPair.SpendPublicKey,
				stealthAddr.EphemeralPubKey,
				stealthAddr.ViewTag,
			)
			if err != nil {
				t.Fatalf("Failed to check stealth address: %v", err)
			}
			if isOurs {
				matchCount++
			}
		}
	}

	// All generated addresses should be identified as ours
	if matchCount != totalTests {
		t.Errorf("Expected all %d addresses to match, got %d", totalTests, matchCount)
	}
}

func TestWrongRecipientCannotIdentify(t *testing.T) {
	// Generate two different key pairs
	recipientKeyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	wrongKeyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate wrong key pair: %v", err)
	}

	metaAddr := recipientKeyPair.MetaAddress()

	// Generate stealth address for the correct recipient
	stealthAddr, err := GenerateStealthAddress(metaAddr)
	if err != nil {
		t.Fatalf("Failed to generate stealth address: %v", err)
	}

	// Wrong recipient should NOT be able to identify this address as theirs
	// The view tag check should fail
	isWrongOurs, err := CheckStealthAddress(
		wrongKeyPair.ViewPrivateKey,
		wrongKeyPair.SpendPublicKey,
		stealthAddr.EphemeralPubKey,
		stealthAddr.ViewTag,
	)
	if err != nil {
		t.Fatalf("Failed to check stealth address: %v", err)
	}
	if isWrongOurs {
		t.Error("Wrong recipient should NOT be able to identify this stealth address")
	}
}

func TestComputeStealthAddress(t *testing.T) {
	// Generate recipient's key pair
	recipientKeyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	metaAddr := recipientKeyPair.MetaAddress()

	// Generate stealth address (as sender would do)
	stealthAddr, err := GenerateStealthAddress(metaAddr)
	if err != nil {
		t.Fatalf("Failed to generate stealth address: %v", err)
	}

	// Compute the stealth address (as recipient would do to verify)
	computedAddr, err := ComputeStealthAddress(
		recipientKeyPair.ViewPrivateKey,
		recipientKeyPair.SpendPublicKey,
		stealthAddr.EphemeralPubKey,
	)
	if err != nil {
		t.Fatalf("Failed to compute stealth address: %v", err)
	}

	// The computed address should match
	if computedAddr != stealthAddr.Address {
		t.Errorf("Computed address %s doesn't match stealth address %s",
			computedAddr.Hex(), stealthAddr.Address.Hex())
	}
}

func TestMultipleStealthAddressesAreDifferent(t *testing.T) {
	// Generate recipient's key pair
	recipientKeyPair, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient key pair: %v", err)
	}

	metaAddr := recipientKeyPair.MetaAddress()

	// Generate multiple stealth addresses
	addresses := make(map[common.Address]bool)
	numAddresses := 50

	for i := 0; i < numAddresses; i++ {
		stealthAddr, err := GenerateStealthAddress(metaAddr)
		if err != nil {
			t.Fatalf("Failed to generate stealth address: %v", err)
		}

		if addresses[stealthAddr.Address] {
			t.Errorf("Duplicate stealth address generated: %s", stealthAddr.Address.Hex())
		}
		addresses[stealthAddr.Address] = true
	}

	if len(addresses) != numAddresses {
		t.Errorf("Expected %d unique addresses, got %d", numAddresses, len(addresses))
	}
}

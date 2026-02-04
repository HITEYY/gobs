// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package params

import (
	"fmt"
	"math/big"
	"time"
)

// Version information
const (
	VersionMajor = 1       // Major version component
	VersionMinor = 0       // Minor version component
	VersionPatch = 0       // Patch version component
	VersionMeta  = "alpha" // Version metadata
)

// Version holds the textual version string
var Version = func() string {
	return fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionPatch)
}()

// VersionWithMeta holds the textual version string including metadata
var VersionWithMeta = func() string {
	v := Version
	if VersionMeta != "" {
		v += "-" + VersionMeta
	}
	return v
}()

// Obsidian Protocol Constants
const (
	// BlockTime is the target time between blocks (2 seconds)
	BlockTime = 2 * time.Second

	// BlockTimeSeconds is BlockTime in seconds for difficulty calculation
	BlockTimeSeconds = 2

	// HalvingInterval is the number of blocks between halvings (~2 years at 2s blocks)
	// 2 years = 2 * 365.25 * 24 * 60 * 60 / 2 = 31,536,000 blocks
	HalvingInterval uint64 = 31_536_000

	// ChromaticPhaseBlocks is the transition period for smooth halving (10% of halving interval)
	// This creates a gradual reduction in rewards approaching and after each halving
	ChromaticPhaseBlocks uint64 = 3_153_600

	// MaxHalvings is the maximum number of halvings before rewards become negligible
	MaxHalvings = 64

	// StealthTxType is the transaction type for stealth address transactions
	StealthTxType = 0x10

	// StealthRegistryAddress is the precompile address for stealth address registry
	StealthRegistryAddress = 0x0B
)

var (
	// InitialBlockReward is the mining reward for the first epoch (50 OBS)
	InitialBlockReward = new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))

	// MaxSupply is the maximum total supply of OBS tokens (500 million)
	MaxSupply = new(big.Int).Mul(big.NewInt(500_000_000), big.NewInt(1e18))

	// MinimumDifficulty is the minimum difficulty for PoW
	MinimumDifficulty = big.NewInt(131072)

	// DifficultyBoundDivisor is the divisor for difficulty adjustment
	DifficultyBoundDivisor = big.NewInt(2048)

	// AllowedFutureBlockTime is the maximum time from now a block can have
	AllowedFutureBlockTime = 3 * time.Second
)

// NetworkID constants
const (
	ObsidianMainnetNetworkID = 1719 // 0x6B7
	ObsidianTestnetNetworkID = 1720 // 0x6B8
)

// Genesis block constants
const (
	GenesisGasLimit   uint64 = 30_000_000
	GenesisDifficulty uint64 = 131072
)

// P2P Network constants
const (
	// DefaultP2PPort is the default port for P2P connections
	DefaultP2PPort = 8333
)

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes for mainnet
var MainnetBootnodes = []string{
	"enode://0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000@140.238.7.194:8333",
	"enode://0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000@217.142.151.122:8333",
	"enode://0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000@157.151.219.199:8333",
	"enode://0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000@129.154.52.54:8333",
	"enode://0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000@152.69.229.203:8333",
}

// MainnetStaticNodes are the static nodes to always connect to
var MainnetStaticNodes = []string{
	"140.238.7.194:8333",
	"217.142.151.122:8333",
	"157.151.219.199:8333",
	"129.154.52.54:8333",
	"152.69.229.203:8333",
}

// CalculateBlockReward returns the block reward for a given block number
func CalculateBlockReward(blockNum uint64) *big.Int {
	config := DefaultObsidianashConfig()

	// Calculate current epoch (number of halvings)
	epoch := blockNum / config.HalvingInterval

	// Cap at maximum halvings
	if epoch > MaxHalvings {
		return big.NewInt(0)
	}

	// Base reward after standard halving
	reward := new(big.Int).Set(config.InitialReward)
	reward.Rsh(reward, uint(epoch)) // Divide by 2^epoch

	return reward
}

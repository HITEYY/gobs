// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package params

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

// ObsidianashConfig is the consensus engine config for Obsidian PoW
type ObsidianashConfig struct {
	// BlockTime is the target block time in seconds (default: 5)
	BlockTime uint64 `json:"blockTime,omitempty"`

	// InitialReward is the initial block reward in wei (default: 50 OBS)
	InitialReward *big.Int `json:"initialReward,omitempty"`

	// HalvingInterval is blocks between halvings (default: ~2 years)
	HalvingInterval uint64 `json:"halvingInterval,omitempty"`

	// ChromaticPhase is the smooth halving transition period in blocks
	ChromaticPhase uint64 `json:"chromaticPhase,omitempty"`

	// MaxSupply is the maximum total supply (default: 500M OBS)
	MaxSupply *big.Int `json:"maxSupply,omitempty"`
}

// String implements the stringer interface
func (c *ObsidianashConfig) String() string {
	return fmt.Sprintf("obsidianash(blockTime: %ds, halving: %d blocks)", c.BlockTime, c.HalvingInterval)
}

// DefaultObsidianashConfig returns the default Obsidian PoW config
func DefaultObsidianashConfig() *ObsidianashConfig {
	return &ObsidianashConfig{
		BlockTime:       BlockTimeSeconds,
		InitialReward:   new(big.Int).Set(InitialBlockReward),
		HalvingInterval: HalvingInterval,
		ChromaticPhase:  ChromaticPhaseBlocks,
		MaxSupply:       new(big.Int).Set(MaxSupply),
	}
}

// Helper function to create uint64 pointer
func newUint64(val uint64) *uint64 { return &val }

// ObsidianMainnetChainConfig is the chain config for Obsidian mainnet
var ObsidianMainnetChainConfig = &params.ChainConfig{
	ChainID: big.NewInt(ObsidianMainnetNetworkID),

	// Enable all EIPs from genesis (block 0)
	HomesteadBlock:      big.NewInt(0),
	DAOForkBlock:        nil,
	DAOForkSupport:      false,
	EIP150Block:         big.NewInt(0),
	EIP155Block:         big.NewInt(0),
	EIP158Block:         big.NewInt(0),
	ByzantiumBlock:      big.NewInt(0),
	ConstantinopleBlock: big.NewInt(0),
	PetersburgBlock:     big.NewInt(0),
	IstanbulBlock:       big.NewInt(0),
	MuirGlacierBlock:    big.NewInt(0),
	BerlinBlock:         big.NewInt(0),
	LondonBlock:         big.NewInt(0),
	ArrowGlacierBlock:   nil,
	GrayGlacierBlock:    nil,

	// No PoS transition - Obsidian stays on PoW
	TerminalTotalDifficulty: nil,
	MergeNetsplitBlock:      nil,

	// Enable post-merge features from genesis time 0
	ShanghaiTime: newUint64(0),
	CancunTime:   newUint64(0),
	PragueTime:   nil, // Enable later if needed

	// Use Ethash as base - we'll override with ObsidianAsh
	Ethash: new(params.EthashConfig),
}

// ObsidianTestnetChainConfig is the chain config for Obsidian testnet
var ObsidianTestnetChainConfig = &params.ChainConfig{
	ChainID: big.NewInt(ObsidianTestnetNetworkID),

	// Enable all EIPs from genesis
	HomesteadBlock:      big.NewInt(0),
	DAOForkBlock:        nil,
	DAOForkSupport:      false,
	EIP150Block:         big.NewInt(0),
	EIP155Block:         big.NewInt(0),
	EIP158Block:         big.NewInt(0),
	ByzantiumBlock:      big.NewInt(0),
	ConstantinopleBlock: big.NewInt(0),
	PetersburgBlock:     big.NewInt(0),
	IstanbulBlock:       big.NewInt(0),
	MuirGlacierBlock:    big.NewInt(0),
	BerlinBlock:         big.NewInt(0),
	LondonBlock:         big.NewInt(0),
	ArrowGlacierBlock:   nil,
	GrayGlacierBlock:    nil,

	// No PoS transition
	TerminalTotalDifficulty: nil,

	// Enable post-merge features from genesis
	ShanghaiTime: newUint64(0),
	CancunTime:   newUint64(0),

	Ethash: new(params.EthashConfig),
}

// ObsidianGenesisHash will be set after genesis is created
var ObsidianGenesisHash common.Hash

// ObsidianashConfigByChainID returns the ObsidianashConfig for a given chain ID
func ObsidianashConfigByChainID(chainID *big.Int) *ObsidianashConfig {
	if chainID == nil {
		return DefaultObsidianashConfig()
	}

	switch chainID.Uint64() {
	case ObsidianMainnetNetworkID, ObsidianTestnetNetworkID:
		return DefaultObsidianashConfig()
	default:
		return DefaultObsidianashConfig()
	}
}

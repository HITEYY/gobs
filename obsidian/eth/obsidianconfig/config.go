// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package obsidianconfig

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/obsidian-chain/obsidian/params"
)

// FullnodeConfig contains the configuration options for a full Obsidian node
type FullnodeConfig struct {
	// Protocol options
	NetworkId uint64 // Network ID to use for selecting peers
	Genesis   *params.ObsidianashConfig

	// Sync mode settings
	SyncMode downloader.SyncMode

	// Database options
	DatabaseHandles int
	DatabaseCache   int
	DatabaseFreezer string

	// Mining options
	Miner MinerConfig

	// Transaction pool options
	TxPool legacypool.Config

	// Gas price oracle options
	GPO gasprice.Config

	// Enable recording of SHA3/keccak preimages
	EnablePreimageRecording bool

	// RPC options
	RPCGasCap   uint64
	RPCTxFeeCap float64

	// State settings
	TrieTimeout  time.Duration
	TrieCleanup  bool
	SnapshotMode bool

	// Misc settings
	NoPruning  bool
	NoPrefetch bool
}

// MinerConfig contains the configuration options for the miner
type MinerConfig struct {
	Etherbase    common.Address `toml:",omitempty"` // Public address for block mining rewards
	ExtraData    []byte         `toml:",omitempty"` // Block extra data set by the miner
	GasFloor     uint64         // Target gas floor for mined blocks
	GasCeil      uint64         // Target gas ceiling for mined blocks
	GasPrice     *big.Int       // Minimum gas price for mining a transaction
	Recommit     time.Duration  // The time interval for miner to re-create mining work
	NewPayload   time.Duration  // The maximum time for miner to wait for new payload to build
	PendingFeeRecipient common.Address `toml:",omitempty"` // Address to receive pending fees
}

// DefaultConfig returns the default configuration for an Obsidian node
func DefaultConfig() *FullnodeConfig {
	return &FullnodeConfig{
		NetworkId:       params.ObsidianMainnetChainConfig.ChainID.Uint64(),
		SyncMode:        downloader.SnapSync,
		DatabaseHandles: 512,
		DatabaseCache:   256,
		TrieTimeout:     60 * time.Minute,
		Miner:           DefaultMinerConfig(),
		TxPool:          DefaultTxPoolConfig(),
		GPO:             DefaultGasPriceConfig(),
		RPCGasCap:       50000000, // 50M gas
		RPCTxFeeCap:     1,        // 1 OBS
	}
}

// DefaultMinerConfig returns the default configuration for the miner
func DefaultMinerConfig() MinerConfig {
	return MinerConfig{
		GasFloor:   30000000,
		GasCeil:    30000000,
		GasPrice:   big.NewInt(1e9), // 1 Gwei
		Recommit:   3 * time.Second,
		NewPayload: 2 * time.Second,
		ExtraData:  []byte("Obsidian"),
	}
}

// DefaultTxPoolConfig returns the default configuration for the transaction pool
func DefaultTxPoolConfig() legacypool.Config {
	return legacypool.Config{
		Journal:   "transactions.rlp",
		Rejournal: time.Hour,
		PriceLimit: 1,
		PriceBump:  10,
		AccountSlots: 16,
		GlobalSlots:  4096 + 1024,
		AccountQueue: 64,
		GlobalQueue:  1024,
		Lifetime:     3 * time.Hour,
	}
}

// DefaultGasPriceConfig returns the default gas price oracle configuration
func DefaultGasPriceConfig() gasprice.Config {
	return gasprice.Config{
		Blocks:           20,
		Percentile:       60,
		MaxHeaderHistory: 1024,
		MaxBlockHistory:  1024,
		MaxPrice:         gasprice.DefaultMaxPrice,
		IgnorePrice:      gasprice.DefaultIgnorePrice,
	}
}

// MinerConfigCopy returns a copy of the miner config
func (m *MinerConfig) Copy() *MinerConfig {
	cpy := *m
	if m.GasPrice != nil {
		cpy.GasPrice = new(big.Int).Set(m.GasPrice)
	}
	if len(m.ExtraData) > 0 {
		cpy.ExtraData = make([]byte, len(m.ExtraData))
		copy(cpy.ExtraData, m.ExtraData)
	}
	return &cpy
}

// TestnetConfig returns the configuration for testnet
func TestnetConfig() *FullnodeConfig {
	cfg := DefaultConfig()
	cfg.NetworkId = params.ObsidianTestnetChainConfig.ChainID.Uint64()
	cfg.Miner.GasPrice = big.NewInt(1) // Lower gas price for testnet
	return cfg
}

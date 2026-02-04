// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package rpc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	obstypes "github.com/obsidian-chain/obsidian/core/types"
	"github.com/obsidian-chain/obsidian/params"
	"github.com/obsidian-chain/obsidian/stealth"
)

// Common errors
var (
	ErrNotFound     = errors.New("not found")
	ErrInvalidTx    = errors.New("invalid transaction")
	ErrTxPoolFull   = errors.New("transaction pool full")
	ErrUnknownBlock = errors.New("unknown block")
)

// Backend interface defines the methods needed by the RPC API
type Backend interface {
	// Blockchain methods
	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*obstypes.ObsidianBlock, error)
	BlockByHash(ctx context.Context, hash common.Hash) (*obstypes.ObsidianBlock, error)
	CurrentBlock() *obstypes.ObsidianHeader
	ChainID() *big.Int
	GetTD(hash common.Hash) *big.Int

	// Transaction methods
	SendTransaction(ctx context.Context, tx *obstypes.StealthTransaction) (common.Hash, error)
	SendRawTransaction(ctx context.Context, encodedTx []byte) (common.Hash, error)
	GetTransaction(ctx context.Context, hash common.Hash) (*obstypes.StealthTransaction, common.Hash, uint64, uint64, error)
	GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error)
	GetPoolTransactions() []*obstypes.StealthTransaction
	GetPoolTransaction(hash common.Hash) *obstypes.StealthTransaction

	// Account methods
	GetBalance(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*big.Int, error)
	GetCode(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (hexutil.Bytes, error)
	GetNonce(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (uint64, error)
	GetStorageAt(ctx context.Context, address common.Address, key common.Hash, blockNr rpc.BlockNumber) (common.Hash, error)

	// Call methods
	Call(ctx context.Context, args CallArgs, blockNr rpc.BlockNumber) (hexutil.Bytes, error)

	// Mining methods
	Mining() bool
	Hashrate() uint64
	SetCoinbase(address common.Address) error
	GetCoinbase() common.Address
	StartMiningWithThreads(threads int) error
	StopMiningAsync()

	// Network methods
	PeerCount() int
	NetVersion() uint64
	Syncing() (interface{}, error)

	// Gas methods
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	EstimateGas(ctx context.Context, args CallArgs) (uint64, error)

	// Log methods
	GetLogs(ctx context.Context, filter obstypes.FilterQuery) ([]*obstypes.Log, error)
}

// CallArgs is an alias for the shared CallArgs type
type CallArgs = obstypes.CallArgs

// PublicEthereumAPI provides Ethereum-compatible RPC methods
type PublicEthereumAPI struct {
	b Backend
}

// NewPublicEthereumAPI creates a new Ethereum RPC API
func NewPublicEthereumAPI(b Backend) *PublicEthereumAPI {
	return &PublicEthereumAPI{b: b}
}

// ChainId returns the chain ID
func (api *PublicEthereumAPI) ChainId() *hexutil.Big {
	return (*hexutil.Big)(api.b.ChainID())
}

// BlockNumber returns the current block number
func (api *PublicEthereumAPI) BlockNumber() hexutil.Uint64 {
	header := api.b.CurrentBlock()
	return hexutil.Uint64(header.Number.Uint64())
}

// GetBalance returns the balance of an address
func (api *PublicEthereumAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	blockNr, _ := blockNrOrHash.Number()
	balance, err := api.b.GetBalance(ctx, address, blockNr)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Big)(balance), nil
}

// GetBlockByNumber returns the block by number
func (api *PublicEthereumAPI) GetBlockByNumber(ctx context.Context, number rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	block, err := api.b.BlockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	return RPCMarshalBlock(block, true, fullTx), nil
}

// GetBlockByHash returns the block by hash
func (api *PublicEthereumAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block, err := api.b.BlockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	return RPCMarshalBlock(block, true, fullTx), nil
}

// GetTransactionByHash returns transaction by hash
func (api *PublicEthereumAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	tx, blockHash, blockNumber, index, err := api.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, nil
	}
	return RPCMarshalTransaction(tx, blockHash, blockNumber, index), nil
}

// GetTransactionReceipt returns the transaction receipt
func (api *PublicEthereumAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	return api.b.GetTransactionReceipt(ctx, hash)
}

// GetTransactionCount returns the nonce
func (api *PublicEthereumAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	blockNr, _ := blockNrOrHash.Number()
	nonce, err := api.b.GetNonce(ctx, address, blockNr)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Uint64)(&nonce), nil
}

// GetCode returns the code at an address
func (api *PublicEthereumAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	blockNr, _ := blockNrOrHash.Number()
	return api.b.GetCode(ctx, address, blockNr)
}

// GasPrice returns the current gas price
func (api *PublicEthereumAPI) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	price, err := api.b.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Big)(price), nil
}

// EstimateGas estimates the gas needed
func (api *PublicEthereumAPI) EstimateGas(ctx context.Context, args CallArgs) (hexutil.Uint64, error) {
	gas, err := api.b.EstimateGas(ctx, args)
	if err != nil {
		return 0, err
	}
	return hexutil.Uint64(gas), nil
}

// SendRawTransaction sends a raw transaction
func (api *PublicEthereumAPI) SendRawTransaction(ctx context.Context, encodedTx hexutil.Bytes) (common.Hash, error) {
	// Decode the transaction
	tx := new(obstypes.StealthTransaction)
	if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
		return common.Hash{}, fmt.Errorf("invalid transaction: %v", err)
	}

	// Send to backend
	return api.b.SendRawTransaction(ctx, encodedTx)
}

// Call executes a contract call
func (api *PublicEthereumAPI) Call(ctx context.Context, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	blockNr, _ := blockNrOrHash.Number()
	return api.b.Call(ctx, args, blockNr)
}

// GetStorageAt returns storage at a specific position
func (api *PublicEthereumAPI) GetStorageAt(ctx context.Context, address common.Address, key string, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	blockNr, _ := blockNrOrHash.Number()
	storageKey := common.HexToHash(key)
	result, err := api.b.GetStorageAt(ctx, address, storageKey, blockNr)
	if err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

// GetLogs returns logs matching the filter
func (api *PublicEthereumAPI) GetLogs(ctx context.Context, args obstypes.FilterQuery) ([]*obstypes.Log, error) {
	return api.b.GetLogs(ctx, args)
}

// GetBlockTransactionCountByNumber returns transaction count by block number
func (api *PublicEthereumAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*hexutil.Uint, error) {
	block, err := api.b.BlockByNumber(ctx, blockNr)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	count := hexutil.Uint(len(block.Transactions()))
	return &count, nil
}

// GetBlockTransactionCountByHash returns transaction count by block hash
func (api *PublicEthereumAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) (*hexutil.Uint, error) {
	block, err := api.b.BlockByHash(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	count := hexutil.Uint(len(block.Transactions()))
	return &count, nil
}

// GetTransactionByBlockNumberAndIndex returns transaction by block number and index
func (api *PublicEthereumAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := api.b.BlockByNumber(ctx, blockNr)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	txs := block.Transactions()
	if int(index) >= len(txs) {
		return nil, nil
	}
	return RPCMarshalTransaction(txs[index], block.Hash(), block.NumberU64(), uint64(index)), nil
}

// GetTransactionByBlockHashAndIndex returns transaction by block hash and index
func (api *PublicEthereumAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := api.b.BlockByHash(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	txs := block.Transactions()
	if int(index) >= len(txs) {
		return nil, nil
	}
	return RPCMarshalTransaction(txs[index], block.Hash(), block.NumberU64(), uint64(index)), nil
}

// GetUncleByBlockNumberAndIndex returns uncle by block number and index
func (api *PublicEthereumAPI) GetUncleByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := api.b.BlockByNumber(ctx, blockNr)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	uncles := block.Uncles()
	if int(index) >= len(uncles) {
		return nil, nil
	}
	// Create a block from uncle header for marshaling
	uncleBlock := obstypes.NewBlockWithHeader(uncles[index])
	return RPCMarshalBlock(uncleBlock, false, false), nil
}

// GetUncleCountByBlockNumber returns uncle count by block number
func (api *PublicEthereumAPI) GetUncleCountByBlockNumber(ctx context.Context, blockNr rpc.BlockNumber) (*hexutil.Uint, error) {
	block, err := api.b.BlockByNumber(ctx, blockNr)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	count := hexutil.Uint(len(block.Uncles()))
	return &count, nil
}

// Accounts returns list of accounts (empty for now, requires keystore)
func (api *PublicEthereumAPI) Accounts() []common.Address {
	return []common.Address{}
}

// ProtocolVersion returns the protocol version
func (api *PublicEthereumAPI) ProtocolVersion() hexutil.Uint {
	return hexutil.Uint(1) // Obsidian protocol version 1
}

// Mining returns whether mining is active
func (api *PublicEthereumAPI) Mining() bool {
	return api.b.Mining()
}

// Hashrate returns the current hashrate
func (api *PublicEthereumAPI) Hashrate() hexutil.Uint64 {
	return hexutil.Uint64(api.b.Hashrate())
}

// Coinbase returns the coinbase address
func (api *PublicEthereumAPI) Coinbase() common.Address {
	return api.b.GetCoinbase()
}

// Syncing returns syncing status
func (api *PublicEthereumAPI) Syncing() (interface{}, error) {
	return api.b.Syncing()
}

// PublicNetAPI provides network-related RPC methods
type PublicNetAPI struct {
	b Backend
}

// NewPublicNetAPI creates a new network RPC API
func NewPublicNetAPI(b Backend) *PublicNetAPI {
	return &PublicNetAPI{b: b}
}

// Version returns the network version
func (api *PublicNetAPI) Version() string {
	return fmt.Sprintf("%d", api.b.NetVersion())
}

// PeerCount returns the number of peers
func (api *PublicNetAPI) PeerCount() hexutil.Uint {
	return hexutil.Uint(api.b.PeerCount())
}

// Listening returns whether the node is listening
func (api *PublicNetAPI) Listening() bool {
	return true
}

// PublicWeb3API provides web3-related RPC methods
type PublicWeb3API struct{}

// NewPublicWeb3API creates a new web3 RPC API
func NewPublicWeb3API() *PublicWeb3API {
	return &PublicWeb3API{}
}

// ClientVersion returns the client version
func (api *PublicWeb3API) ClientVersion() string {
	return "Obsidian/v1.0.0/go"
}

// Sha3 returns the Keccak-256 hash
func (api *PublicWeb3API) Sha3(input hexutil.Bytes) hexutil.Bytes {
	return crypto.Keccak256(input)
}

// PublicObsidianAPI provides Obsidian-specific RPC methods
type PublicObsidianAPI struct {
	b Backend
}

// NewPublicObsidianAPI creates a new Obsidian RPC API
func NewPublicObsidianAPI(b Backend) *PublicObsidianAPI {
	return &PublicObsidianAPI{b: b}
}

// GenerateStealthKeyPair generates a new stealth key pair
func (api *PublicObsidianAPI) GenerateStealthKeyPair() (map[string]string, error) {
	keyPair, err := stealth.GenerateStealthKeyPair()
	if err != nil {
		return nil, err
	}

	metaAddr := keyPair.MetaAddress()

	return map[string]string{
		"spendPrivateKey": hex.EncodeToString(keyPair.SpendPrivateKey.D.Bytes()),
		"viewPrivateKey":  hex.EncodeToString(keyPair.ViewPrivateKey.D.Bytes()),
		"metaAddress":     metaAddr.String(),
		"spendPublicKey":  hex.EncodeToString(metaAddr.SpendPubKey),
		"viewPublicKey":   hex.EncodeToString(metaAddr.ViewPubKey),
	}, nil
}

// GenerateStealthAddress generates a stealth address for a recipient
func (api *PublicObsidianAPI) GenerateStealthAddress(metaAddressStr string) (map[string]string, error) {
	metaAddr, err := stealth.ParseMetaAddress(metaAddressStr)
	if err != nil {
		return nil, fmt.Errorf("invalid meta address: %v", err)
	}

	stealthAddr, err := stealth.GenerateStealthAddress(metaAddr)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"stealthAddress":  stealthAddr.Address.Hex(),
		"ephemeralPubKey": hex.EncodeToString(stealthAddr.EphemeralPubKey),
		"viewTag":         fmt.Sprintf("0x%02x", stealthAddr.ViewTag),
	}, nil
}

// CheckStealthAddress checks if a stealth address belongs to a given view key
func (api *PublicObsidianAPI) CheckStealthAddress(args struct {
	Address         string `json:"address"`
	EphemeralPubKey string `json:"ephemeralPubKey"`
	ViewTag         string `json:"viewTag"`
	ViewPrivateKey  string `json:"viewPrivateKey"`
	SpendPublicKey  string `json:"spendPublicKey"`
}) (bool, error) {
	// Parse ephemeral public key
	ephemeralPubKeyHex := args.EphemeralPubKey
	if len(ephemeralPubKeyHex) >= 2 && ephemeralPubKeyHex[:2] == "0x" {
		ephemeralPubKeyHex = ephemeralPubKeyHex[2:]
	}
	ephemeralPubKey, err := hex.DecodeString(ephemeralPubKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid ephemeral public key: %v", err)
	}

	// Parse view tag
	var viewTag uint8
	if len(args.ViewTag) > 0 {
		viewTagHex := args.ViewTag
		if len(viewTagHex) >= 2 && viewTagHex[:2] == "0x" {
			viewTagHex = viewTagHex[2:]
		}
		viewTagBytes, err := hex.DecodeString(viewTagHex)
		if err != nil || len(viewTagBytes) != 1 {
			return false, fmt.Errorf("invalid view tag")
		}
		viewTag = viewTagBytes[0]
	}

	// Parse view private key
	viewKeyHex := args.ViewPrivateKey
	if len(viewKeyHex) >= 2 && viewKeyHex[:2] == "0x" {
		viewKeyHex = viewKeyHex[2:]
	}
	viewKeyBytes, err := hex.DecodeString(viewKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid view private key: %v", err)
	}
	viewPrivKey, err := crypto.ToECDSA(viewKeyBytes)
	if err != nil {
		return false, fmt.Errorf("invalid view private key: %v", err)
	}

	// Parse spend public key
	spendPubKeyHex := args.SpendPublicKey
	if len(spendPubKeyHex) >= 2 && spendPubKeyHex[:2] == "0x" {
		spendPubKeyHex = spendPubKeyHex[2:]
	}
	spendPubKeyBytes, err := hex.DecodeString(spendPubKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid spend public key: %v", err)
	}
	spendPubKey, err := stealth.DecompressPublicKey(spendPubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("invalid spend public key: %v", err)
	}

	// Check ownership using the stealth package
	return stealth.CheckStealthAddress(viewPrivKey, spendPubKey, ephemeralPubKey, viewTag)
}

// GetBlockReward returns the block reward for a given block number
func (api *PublicObsidianAPI) GetBlockReward(blockNum uint64) (*hexutil.Big, error) {
	reward := params.CalculateBlockReward(blockNum)
	return (*hexutil.Big)(reward), nil
}

// GetHalvingInfo returns information about halving schedule
func (api *PublicObsidianAPI) GetHalvingInfo() map[string]interface{} {
	currentBlock := api.b.CurrentBlock()
	currentNum := currentBlock.Number.Uint64()
	currentReward := params.CalculateBlockReward(currentNum)

	currentEpoch := currentNum / params.HalvingInterval
	blocksUntilHalving := params.HalvingInterval - (currentNum % params.HalvingInterval)
	nextHalvingBlock := currentNum + blocksUntilHalving

	return map[string]interface{}{
		"currentBlock":       currentNum,
		"currentReward":      (*hexutil.Big)(currentReward),
		"currentEpoch":       currentEpoch,
		"halvingInterval":    params.HalvingInterval,
		"blocksUntilHalving": blocksUntilHalving,
		"nextHalvingBlock":   nextHalvingBlock,
		"maxHalvings":        params.MaxHalvings,
	}
}

// GetProtocolInfo returns protocol information
func (api *PublicObsidianAPI) GetProtocolInfo() map[string]interface{} {
	return map[string]interface{}{
		"version":           params.Version,
		"versionWithMeta":   params.VersionWithMeta,
		"networkID":         api.b.NetVersion(),
		"chainID":           api.b.ChainID().String(),
		"blockTime":         params.BlockTimeSeconds,
		"initialReward":     (*hexutil.Big)(params.InitialBlockReward),
		"maxSupply":         (*hexutil.Big)(params.MaxSupply),
		"minimumDifficulty": (*hexutil.Big)(params.MinimumDifficulty),
	}
}

// ScanStealthTransactions scans for stealth transactions belonging to a view key
func (api *PublicObsidianAPI) ScanStealthTransactions(args struct {
	ViewPrivateKey string `json:"viewPrivateKey"`
	SpendPublicKey string `json:"spendPublicKey"`
	FromBlock      uint64 `json:"fromBlock"`
	ToBlock        uint64 `json:"toBlock"`
}) ([]map[string]interface{}, error) {
	// Parse view private key
	viewKeyHex := args.ViewPrivateKey
	if len(viewKeyHex) >= 2 && viewKeyHex[:2] == "0x" {
		viewKeyHex = viewKeyHex[2:]
	}
	viewKeyBytes, err := hex.DecodeString(viewKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid view private key: %v", err)
	}
	viewPrivKey, err := crypto.ToECDSA(viewKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid view private key: %v", err)
	}

	// Parse spend public key
	spendPubKeyHex := args.SpendPublicKey
	if len(spendPubKeyHex) >= 2 && spendPubKeyHex[:2] == "0x" {
		spendPubKeyHex = spendPubKeyHex[2:]
	}
	spendPubKeyBytes, err := hex.DecodeString(spendPubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid spend public key: %v", err)
	}
	spendPubKey, err := stealth.DecompressPublicKey(spendPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid spend public key: %v", err)
	}

	results := make([]map[string]interface{}, 0)

	// Scan blocks
	for num := args.FromBlock; num <= args.ToBlock; num++ {
		block, err := api.b.BlockByNumber(context.Background(), rpc.BlockNumber(num))
		if err != nil || block == nil {
			continue
		}

		for _, tx := range block.Transactions() {
			if tx.Type() != obstypes.StealthTxType {
				continue
			}

			if tx.To() == nil {
				continue
			}

			isMine, err := stealth.CheckStealthAddress(viewPrivKey, spendPubKey, tx.EphemeralPubKey(), tx.ViewTag())
			if err != nil {
				continue
			}

			if isMine {
				results = append(results, map[string]interface{}{
					"txHash":          tx.Hash().Hex(),
					"blockNumber":     num,
					"to":              tx.To().Hex(),
					"value":           (*hexutil.Big)(tx.Value()),
					"viewTag":         fmt.Sprintf("0x%02x", tx.ViewTag()),
					"ephemeralPubKey": hexutil.Bytes(tx.EphemeralPubKey()),
				})
			}
		}
	}

	return results, nil
}

// DeriveStealthPrivateKey derives the private key for a stealth address
func (api *PublicObsidianAPI) DeriveStealthPrivateKey(args struct {
	ViewPrivateKey  string `json:"viewPrivateKey"`
	SpendPrivateKey string `json:"spendPrivateKey"`
	EphemeralPubKey string `json:"ephemeralPubKey"`
}) (map[string]interface{}, error) {
	// Parse view private key
	viewKeyHex := args.ViewPrivateKey
	if len(viewKeyHex) >= 2 && viewKeyHex[:2] == "0x" {
		viewKeyHex = viewKeyHex[2:]
	}
	viewKeyBytes, err := hex.DecodeString(viewKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid view private key: %v", err)
	}
	viewPrivKey, err := crypto.ToECDSA(viewKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid view private key: %v", err)
	}

	// Parse spend private key
	spendKeyHex := args.SpendPrivateKey
	if len(spendKeyHex) >= 2 && spendKeyHex[:2] == "0x" {
		spendKeyHex = spendKeyHex[2:]
	}
	spendKeyBytes, err := hex.DecodeString(spendKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid spend private key: %v", err)
	}
	spendPrivKey, err := crypto.ToECDSA(spendKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid spend private key: %v", err)
	}

	// Parse ephemeral public key
	ephPubKeyHex := args.EphemeralPubKey
	if len(ephPubKeyHex) >= 2 && ephPubKeyHex[:2] == "0x" {
		ephPubKeyHex = ephPubKeyHex[2:]
	}
	ephPubKey, err := hex.DecodeString(ephPubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %v", err)
	}

	// Derive the stealth private key
	stealthPrivKey, stealthAddr, err := stealth.DeriveStealthAddressPrivateKey(viewPrivKey, spendPrivKey, ephPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive stealth private key: %v", err)
	}

	// Export the private key as hex
	stealthPrivKeyBytes := crypto.FromECDSA(stealthPrivKey)

	return map[string]interface{}{
		"address":    stealthAddr.Hex(),
		"privateKey": hexutil.Bytes(stealthPrivKeyBytes).String(),
	}, nil
}

// ComputeStealthAddress computes the stealth address for verification
func (api *PublicObsidianAPI) ComputeStealthAddress(args struct {
	ViewPrivateKey  string `json:"viewPrivateKey"`
	SpendPublicKey  string `json:"spendPublicKey"`
	EphemeralPubKey string `json:"ephemeralPubKey"`
}) (common.Address, error) {
	// Parse view private key
	viewKeyHex := args.ViewPrivateKey
	if len(viewKeyHex) >= 2 && viewKeyHex[:2] == "0x" {
		viewKeyHex = viewKeyHex[2:]
	}
	viewKeyBytes, err := hex.DecodeString(viewKeyHex)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid view private key: %v", err)
	}
	viewPrivKey, err := crypto.ToECDSA(viewKeyBytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid view private key: %v", err)
	}

	// Parse spend public key
	spendPubKeyHex := args.SpendPublicKey
	if len(spendPubKeyHex) >= 2 && spendPubKeyHex[:2] == "0x" {
		spendPubKeyHex = spendPubKeyHex[2:]
	}
	spendPubKeyBytes, err := hex.DecodeString(spendPubKeyHex)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid spend public key: %v", err)
	}
	spendPubKey, err := stealth.DecompressPublicKey(spendPubKeyBytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid spend public key: %v", err)
	}

	// Parse ephemeral public key
	ephPubKeyHex := args.EphemeralPubKey
	if len(ephPubKeyHex) >= 2 && ephPubKeyHex[:2] == "0x" {
		ephPubKeyHex = ephPubKeyHex[2:]
	}
	ephPubKey, err := hex.DecodeString(ephPubKeyHex)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid ephemeral public key: %v", err)
	}

	// Compute the stealth address
	return stealth.ComputeStealthAddress(viewPrivKey, spendPubKey, ephPubKey)
}

// GetStealthBalance gets the balance at a stealth address
func (api *PublicObsidianAPI) GetStealthBalance(ctx context.Context, args struct {
	ViewPrivateKey  string `json:"viewPrivateKey"`
	SpendPublicKey  string `json:"spendPublicKey"`
	EphemeralPubKey string `json:"ephemeralPubKey"`
}) (*hexutil.Big, error) {
	// Parse view private key
	viewKeyHex := args.ViewPrivateKey
	if len(viewKeyHex) >= 2 && viewKeyHex[:2] == "0x" {
		viewKeyHex = viewKeyHex[2:]
	}
	viewKeyBytes, err := hex.DecodeString(viewKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid view private key: %v", err)
	}
	viewPrivKey, err := crypto.ToECDSA(viewKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid view private key: %v", err)
	}

	// Parse spend public key
	spendPubKeyHex := args.SpendPublicKey
	if len(spendPubKeyHex) >= 2 && spendPubKeyHex[:2] == "0x" {
		spendPubKeyHex = spendPubKeyHex[2:]
	}
	spendPubKeyBytes, err := hex.DecodeString(spendPubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid spend public key: %v", err)
	}
	spendPubKey, err := stealth.DecompressPublicKey(spendPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid spend public key: %v", err)
	}

	// Parse ephemeral public key
	ephPubKeyHex := args.EphemeralPubKey
	if len(ephPubKeyHex) >= 2 && ephPubKeyHex[:2] == "0x" {
		ephPubKeyHex = ephPubKeyHex[2:]
	}
	ephPubKey, err := hex.DecodeString(ephPubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %v", err)
	}

	// Compute the stealth address
	stealthAddr, err := stealth.ComputeStealthAddress(viewPrivKey, spendPubKey, ephPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute stealth address: %v", err)
	}

	// Get balance
	balance, err := api.b.GetBalance(ctx, stealthAddr, rpc.LatestBlockNumber)
	if err != nil {
		return nil, err
	}

	return (*hexutil.Big)(balance), nil
}

// GetFeeEstimate returns gas price estimates for different priority levels
func (api *PublicObsidianAPI) GetFeeEstimate(ctx context.Context) map[string]interface{} {
	gasPrice, _ := api.b.SuggestGasPrice(ctx)
	if gasPrice == nil {
		gasPrice = big.NewInt(1e9) // 1 Gwei default
	}

	// Calculate different priority levels
	slow := new(big.Int).Set(gasPrice)
	average := new(big.Int).Mul(gasPrice, big.NewInt(12))
	average.Div(average, big.NewInt(10)) // 1.2x
	fast := new(big.Int).Mul(gasPrice, big.NewInt(15))
	fast.Div(fast, big.NewInt(10))                       // 1.5x
	instant := new(big.Int).Mul(gasPrice, big.NewInt(2)) // 2x

	return map[string]interface{}{
		"slow": map[string]interface{}{
			"gasPrice":             (*hexutil.Big)(slow),
			"estimatedBlocks":      30,
			"estimatedTimeSeconds": 360, // ~6 minutes
		},
		"average": map[string]interface{}{
			"gasPrice":             (*hexutil.Big)(average),
			"estimatedBlocks":      10,
			"estimatedTimeSeconds": 120, // ~2 minutes
		},
		"fast": map[string]interface{}{
			"gasPrice":             (*hexutil.Big)(fast),
			"estimatedBlocks":      3,
			"estimatedTimeSeconds": 36, // ~36 seconds
		},
		"instant": map[string]interface{}{
			"gasPrice":             (*hexutil.Big)(instant),
			"estimatedBlocks":      1,
			"estimatedTimeSeconds": 12, // next block
		},
		"baseFee": (*hexutil.Big)(gasPrice),
	}
}

// EstimateGas estimates gas for a transaction
func (api *PublicObsidianAPI) EstimateTransactionFee(ctx context.Context, args struct {
	GasLimit uint64 `json:"gasLimit"`
	Priority string `json:"priority"` // "slow", "average", "fast", "instant"
}) map[string]interface{} {
	gasLimit := args.GasLimit
	if gasLimit == 0 {
		gasLimit = 21000 // Default gas for simple transfer
	}

	estimate := api.GetFeeEstimate(ctx)
	priority := args.Priority
	if priority == "" {
		priority = "average"
	}

	var feeData map[string]interface{}
	switch priority {
	case "slow":
		feeData = estimate["slow"].(map[string]interface{})
	case "fast":
		feeData = estimate["fast"].(map[string]interface{})
	case "instant":
		feeData = estimate["instant"].(map[string]interface{})
	default:
		feeData = estimate["average"].(map[string]interface{})
	}

	gasPrice := feeData["gasPrice"].(*hexutil.Big)
	totalFee := new(big.Int).Mul(gasPrice.ToInt(), new(big.Int).SetUint64(gasLimit))

	return map[string]interface{}{
		"gasLimit":        gasLimit,
		"gasPrice":        gasPrice,
		"totalFee":        (*hexutil.Big)(totalFee),
		"priority":        priority,
		"estimatedBlocks": feeData["estimatedBlocks"],
	}
}

// GetNetworkInfo returns network-specific information
func (api *PublicObsidianAPI) GetNetworkInfo() map[string]interface{} {
	return map[string]interface{}{
		"chainId":     api.b.ChainID().String(),
		"networkName": "Obsidian Mainnet",
		"token": map[string]string{
			"name":     "Obsidian",
			"symbol":   "OBS",
			"decimals": "18",
		},
		"features": []string{
			"stealth_addresses",
			"pow_consensus",
			"chromatic_halving",
			"fee_estimation",
		},
	}
}

// PrivateMinerAPI provides miner-related RPC methods
type PrivateMinerAPI struct {
	b Backend
}

// NewPrivateMinerAPI creates a new miner RPC API
func NewPrivateMinerAPI(b Backend) *PrivateMinerAPI {
	return &PrivateMinerAPI{b: b}
}

// SetEtherbase sets the coinbase address
func (api *PrivateMinerAPI) SetEtherbase(address common.Address) bool {
	err := api.b.SetCoinbase(address)
	return err == nil
}

// SetCoinbase is an alias for SetEtherbase
func (api *PrivateMinerAPI) SetCoinbase(address common.Address) bool {
	return api.SetEtherbase(address)
}

// Start starts mining
func (api *PrivateMinerAPI) Start(threads *int) error {
	t := 1
	if threads != nil {
		t = *threads
	}
	return api.b.StartMiningWithThreads(t)
}

// Stop stops mining
func (api *PrivateMinerAPI) Stop() {
	api.b.StopMiningAsync()
}

// GetHashrate returns the hashrate
func (api *PrivateMinerAPI) GetHashrate() hexutil.Uint64 {
	return hexutil.Uint64(api.b.Hashrate())
}

// RPCMarshalBlock converts a block to RPC representation
func RPCMarshalBlock(block *obstypes.ObsidianBlock, inclTx, fullTx bool) map[string]interface{} {
	header := block.Header()
	fields := map[string]interface{}{
		"number":           (*hexutil.Big)(header.Number),
		"hash":             block.Hash(),
		"parentHash":       header.ParentHash,
		"nonce":            hexutil.Uint64(header.Nonce.Uint64()),
		"mixHash":          header.MixDigest,
		"sha3Uncles":       header.UncleHash,
		"logsBloom":        header.Bloom,
		"stateRoot":        header.Root,
		"miner":            header.Coinbase,
		"difficulty":       (*hexutil.Big)(header.Difficulty),
		"extraData":        hexutil.Bytes(header.Extra),
		"size":             hexutil.Uint64(block.Size()),
		"gasLimit":         hexutil.Uint64(header.GasLimit),
		"gasUsed":          hexutil.Uint64(header.GasUsed),
		"timestamp":        hexutil.Uint64(header.Time),
		"transactionsRoot": header.TxHash,
		"receiptsRoot":     header.ReceiptHash,
	}

	if header.BaseFee != nil {
		fields["baseFeePerGas"] = (*hexutil.Big)(header.BaseFee)
	}

	if inclTx {
		txs := block.Transactions()
		if fullTx {
			formatTxs := make([]interface{}, len(txs))
			for i, tx := range txs {
				formatTxs[i] = RPCMarshalTransaction(tx, block.Hash(), block.NumberU64(), uint64(i))
			}
			fields["transactions"] = formatTxs
		} else {
			hashes := make([]common.Hash, len(txs))
			for i, tx := range txs {
				hashes[i] = tx.Hash()
			}
			fields["transactions"] = hashes
		}
	}

	uncles := block.Uncles()
	uncleHashes := make([]common.Hash, len(uncles))
	for i, uncle := range uncles {
		uncleHashes[i] = uncle.Hash()
	}
	fields["uncles"] = uncleHashes

	return fields
}

// RPCMarshalTransaction converts a transaction to RPC representation
func RPCMarshalTransaction(tx *obstypes.StealthTransaction, blockHash common.Hash, blockNumber, index uint64) map[string]interface{} {
	// Recover sender address
	from := common.Address{}
	signer := obstypes.NewStealthEIP155Signer(tx.ChainId())
	if sender, err := signer.Sender(tx); err == nil {
		from = sender
	}

	to := tx.To()

	fields := map[string]interface{}{
		"hash":     tx.Hash(),
		"type":     hexutil.Uint64(tx.Type()),
		"from":     from,
		"nonce":    hexutil.Uint64(tx.Nonce()),
		"gas":      hexutil.Uint64(tx.Gas()),
		"gasPrice": (*hexutil.Big)(tx.GasPrice()),
		"value":    (*hexutil.Big)(tx.Value()),
		"input":    hexutil.Bytes(tx.Data()),
	}

	// Add block-related fields if in a block
	if blockHash != (common.Hash{}) {
		fields["blockHash"] = blockHash
		fields["blockNumber"] = hexutil.Uint64(blockNumber)
		fields["transactionIndex"] = hexutil.Uint64(index)
	} else {
		fields["blockHash"] = nil
		fields["blockNumber"] = nil
		fields["transactionIndex"] = nil
	}

	// Add 'to' field (nil for contract creation)
	if to != nil {
		fields["to"] = to
	} else {
		fields["to"] = nil
	}

	// Add stealth-specific fields
	if tx.Type() == obstypes.StealthTxType {
		fields["ephemeralPubKey"] = hexutil.Bytes(tx.EphemeralPubKey())
		fields["viewTag"] = hexutil.Uint(tx.ViewTag())
	}

	v, r, s := tx.RawSignatureValues()
	fields["v"] = (*hexutil.Big)(v)
	fields["r"] = (*hexutil.Big)(r)
	fields["s"] = (*hexutil.Big)(s)

	// Add chain ID
	if chainID := tx.ChainId(); chainID != nil {
		fields["chainId"] = (*hexutil.Big)(chainID)
	}

	return fields
}

// GetAPIs returns all available APIs
func GetAPIs(b Backend) []rpc.API {
	apis := []rpc.API{
		{
			Namespace: "eth",
			Service:   NewPublicEthereumAPI(b),
		},
		{
			Namespace: "net",
			Service:   NewPublicNetAPI(b),
		},
		{
			Namespace: "web3",
			Service:   NewPublicWeb3API(),
		},
		{
			Namespace: "obs",
			Service:   NewPublicObsidianAPI(b),
		},
		{
			Namespace: "miner",
			Service:   NewPrivateMinerAPI(b),
		},
	}

	// Add personal API if the backend supports it
	if pb, ok := b.(PersonalBackend); ok {
		apis = append(apis, rpc.API{
			Namespace: "personal",
			Service:   NewPrivateAccountAPI(pb),
		})
	}

	// Add admin API if the backend supports it
	if ab, ok := b.(AdminBackend); ok {
		apis = append(apis, rpc.API{
			Namespace: "admin",
			Service:   NewAdmin(ab),
		})
	}

	return apis
}

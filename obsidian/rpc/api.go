// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package rpc

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	obstypes "github.com/obsidian-chain/obsidian/core/types"
	"github.com/obsidian-chain/obsidian/stealth"
)

// Backend interface defines the methods needed by the RPC API
type Backend interface {
	// Blockchain methods
	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*obstypes.ObsidianBlock, error)
	BlockByHash(ctx context.Context, hash common.Hash) (*obstypes.ObsidianBlock, error)
	CurrentBlock() *obstypes.ObsidianHeader
	ChainID() *big.Int

	// Transaction methods
	SendTransaction(ctx context.Context, tx *obstypes.StealthTransaction) (common.Hash, error)
	GetTransaction(ctx context.Context, hash common.Hash) (*obstypes.StealthTransaction, common.Hash, uint64, uint64, error)
	GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error)

	// Account methods
	GetBalance(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*big.Int, error)
	GetCode(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (hexutil.Bytes, error)
	GetNonce(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (uint64, error)

	// Mining methods
	Mining() bool
	Hashrate() uint64
	SetCoinbase(address common.Address) error

	// Network methods
	PeerCount() int
	NetVersion() uint64
	Syncing() (interface{}, error)

	// Gas methods
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	EstimateGas(ctx context.Context, args CallArgs) (uint64, error)
}

// CallArgs represents the arguments to a call
type CallArgs struct {
	From     *common.Address `json:"from"`
	To       *common.Address `json:"to"`
	Gas      *hexutil.Uint64 `json:"gas"`
	GasPrice *hexutil.Big    `json:"gasPrice"`
	Value    *hexutil.Big    `json:"value"`
	Data     *hexutil.Bytes  `json:"data"`
}

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
	// Decode and send transaction
	// This is simplified - in production would decode RLP
	return common.Hash{}, fmt.Errorf("not implemented")
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
	// This would return the configured coinbase
	return common.Address{}
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
	return common.BytesToHash(input).Bytes()
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
		"stealthAddress":   stealthAddr.Address.Hex(),
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
	// Parse inputs and check ownership
	// This is simplified - would need full implementation
	return false, fmt.Errorf("not implemented")
}

// GetBlockReward returns the block reward for a given block number
func (api *PublicObsidianAPI) GetBlockReward(blockNum uint64) (string, error) {
	// Import consensus package and calculate reward
	return "", fmt.Errorf("not implemented")
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
	from := common.Address{} // Would need to recover sender
	to := tx.To()

	fields := map[string]interface{}{
		"blockHash":        blockHash,
		"blockNumber":      hexutil.Uint64(blockNumber),
		"transactionIndex": hexutil.Uint64(index),
		"hash":             tx.Hash(),
		"type":             hexutil.Uint64(tx.Type()),
		"from":             from,
		"to":               to,
		"nonce":            hexutil.Uint64(tx.Nonce()),
		"gas":              hexutil.Uint64(tx.Gas()),
		"gasPrice":         (*hexutil.Big)(tx.GasPrice()),
		"value":            (*hexutil.Big)(tx.Value()),
		"input":            hexutil.Bytes(tx.Data()),
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

	return fields
}

// GetAPIs returns all available APIs
func GetAPIs(b Backend) []rpc.API {
	return []rpc.API{
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
}

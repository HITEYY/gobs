// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package obsidianash

import (
	"errors"
	"fmt"
	"hash"
	"math/big"
	"runtime"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"

	obsparams "github.com/obsidian-chain/obsidian/params"
)

// ObsidianAsh protocol constants
const (
	maxUncles                     = 2  // Maximum uncles per block
	allowedFutureBlockTimeSeconds = 3  // Max seconds from now for future blocks
)

// Errors
var (
	errOlderBlockTime    = errors.New("timestamp older than parent")
	errTooManyUncles     = errors.New("too many uncles")
	errDuplicateUncle    = errors.New("duplicate uncle")
	errUncleIsAncestor   = errors.New("uncle is ancestor")
	errDanglingUncle     = errors.New("uncle's parent is not ancestor")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidMixDigest  = errors.New("invalid mix digest")
	errInvalidPoW        = errors.New("invalid proof-of-work")
)

// ObsidianAsh is the PoW consensus engine for Obsidian
type ObsidianAsh struct {
	config *obsparams.ObsidianashConfig

	// Mining related
	threads  int
	update   chan struct{}
	hashrate *hashrate

	// Testing hooks
	fakeFail  *uint64
	fakeDelay *time.Duration
	fakeFull  bool
}

// New creates a new ObsidianAsh consensus engine
func New(config *obsparams.ObsidianashConfig) *ObsidianAsh {
	if config == nil {
		config = obsparams.DefaultObsidianashConfig()
	}
	return &ObsidianAsh{
		config:   config,
		threads:  runtime.NumCPU(),
		update:   make(chan struct{}),
		hashrate: newHashrate(),
	}
}

// NewFaker creates a fake consensus engine for testing
func NewFaker() *ObsidianAsh {
	return &ObsidianAsh{
		config:   obsparams.DefaultObsidianashConfig(),
		fakeFull: false,
	}
}

// NewFullFaker creates a full fake consensus engine
func NewFullFaker() *ObsidianAsh {
	return &ObsidianAsh{
		config:   obsparams.DefaultObsidianashConfig(),
		fakeFull: true,
	}
}

// Author returns the coinbase address (miner) of the block
func (o *ObsidianAsh) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks if a header conforms to consensus rules
func (o *ObsidianAsh) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Short circuit if already known
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return o.verifyHeader(chain, header, parent, false, time.Now().Unix())
}

// VerifyHeaders verifies a batch of headers concurrently
func (o *ObsidianAsh) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	if o.fakeFull || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for i := 0; i < len(headers); i++ {
			results <- nil
		}
		return abort, results
	}

	abort := make(chan struct{})
	results := make(chan error, len(headers))
	unixNow := time.Now().Unix()

	go func() {
		for i, header := range headers {
			var parent *types.Header
			if i == 0 {
				parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
			} else if headers[i-1].Hash() == headers[i].ParentHash {
				parent = headers[i-1]
			}

			var err error
			if parent == nil {
				err = consensus.ErrUnknownAncestor
			} else {
				err = o.verifyHeader(chain, header, parent, false, unixNow)
			}

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()

	return abort, results
}

// verifyHeader performs the actual header verification
func (o *ObsidianAsh) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header, uncle bool, unixNow int64) error {
	// Verify fake delay if set
	if o.fakeDelay != nil {
		time.Sleep(*o.fakeDelay)
	}
	// Fail if set to fail at specific block
	if o.fakeFail != nil && *o.fakeFail == header.Number.Uint64() {
		return errInvalidPoW
	}
	// Accept everything in full fake mode
	if o.fakeFull {
		return nil
	}

	// Ensure time ordering
	if header.Time <= parent.Time {
		return errOlderBlockTime
	}

	// Verify future block time limit
	if !uncle && header.Time > uint64(unixNow+allowedFutureBlockTimeSeconds) {
		return consensus.ErrFutureBlock
	}

	// Verify difficulty
	expected := o.CalcDifficulty(chain, header.Time, parent)
	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, expected)
	}

	// Verify gas limit
	if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
		return err
	}

	// Verify gas usage
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, limit %d", header.GasUsed, header.GasLimit)
	}

	// Verify EIP-1559 base fee
	if chain.Config().IsLondon(header.Number) {
		expectedBaseFee := eip1559.CalcBaseFee(chain.Config(), parent)
		if header.BaseFee == nil {
			return errors.New("missing baseFee")
		}
		if header.BaseFee.Cmp(expectedBaseFee) != 0 {
			return fmt.Errorf("invalid baseFee: have %v, want %v", header.BaseFee, expectedBaseFee)
		}
	}

	// Verify extra data length (max 32 bytes)
	if len(header.Extra) > 32 {
		return fmt.Errorf("extra data too long: %d > 32", len(header.Extra))
	}

	return nil
}

// VerifyUncles verifies uncle blocks
func (o *ObsidianAsh) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if o.fakeFull {
		return nil
	}

	// Verify uncle count
	if len(block.Uncles()) > maxUncles {
		return errTooManyUncles
	}
	if len(block.Uncles()) == 0 {
		return nil
	}

	// Gather uncles and verify
	uncles, ancestors := mapset.NewSet[common.Hash](), make(map[common.Hash]*types.Header)
	number, parent := block.NumberU64()-1, block.ParentHash()

	for i := 0; i < 7; i++ {
		ancestorHeader := chain.GetHeader(parent, number)
		if ancestorHeader == nil {
			break
		}
		ancestors[parent] = ancestorHeader
		if ancestorHeader.ParentHash != (common.Hash{}) {
			parent, number = ancestorHeader.ParentHash, number-1
		} else {
			break
		}
	}
	ancestors[block.Hash()] = block.Header()
	uncles.Add(block.Hash())

	for _, ancestor := range ancestors {
		for _, uncle := range chain.GetBlock(ancestor.Hash(), ancestor.Number.Uint64()).Uncles() {
			uncles.Add(uncle.Hash())
		}
	}

	for _, uncle := range block.Uncles() {
		hash := uncle.Hash()
		if uncles.Contains(hash) {
			return errDuplicateUncle
		}
		uncles.Add(hash)

		if ancestors[hash] != nil {
			return errUncleIsAncestor
		}
		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == block.ParentHash() {
			return errDanglingUncle
		}
		if err := o.verifyHeader(chain, uncle, ancestors[uncle.ParentHash], true, time.Now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

// Prepare initializes consensus fields of a block header
func (o *ObsidianAsh) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = o.CalcDifficulty(chain, header.Time, parent)
	return nil
}

// Finalize runs post-transaction state modifications (block rewards)
func (o *ObsidianAsh) Finalize(chain consensus.ChainHeaderReader, header *types.Header, stateDB vm.StateDB, body *types.Body) {
	// Apply block rewards
	accumulateRewards(o.config, stateDB, header, body.Uncles)
}

// FinalizeAndAssemble runs state modifications and assembles the final block
func (o *ObsidianAsh) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, stateDB *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	// Handle withdrawals if enabled (Obsidian doesn't use this for PoW, but keep for compatibility)
	if len(body.Withdrawals) > 0 {
		return nil, errors.New("obsidian does not support withdrawals")
	}

	// Apply block rewards
	accumulateRewards(o.config, stateDB, header, body.Uncles)

	// Finalize state
	header.Root = stateDB.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Assemble and return the block
	return types.NewBlock(header, body, receipts, trie.NewStackTrie(nil)), nil
}

// accumulateRewards calculates and distributes mining rewards
func accumulateRewards(config *obsparams.ObsidianashConfig, stateDB vm.StateDB, header *types.Header, uncles []*types.Header) {
	// Calculate block reward with chromatic halving
	blockReward := CalcBlockReward(config, header.Number.Uint64())

	// Convert to uint256
	reward, _ := uint256.FromBig(blockReward)
	r := new(uint256.Int)
	hNum, _ := uint256.FromBig(header.Number)

	// Reward uncles
	for _, uncle := range uncles {
		uNum, _ := uint256.FromBig(uncle.Number)
		r.AddUint64(uNum, 8)
		r.Sub(r, hNum)
		r.Mul(r, reward)
		r.Rsh(r, 3) // uncle reward = 7/8 * block_reward
		stateDB.AddBalance(uncle.Coinbase, r, tracing.BalanceIncreaseRewardMineUncle)

		// Add uncle inclusion bonus (1/32 of block reward)
		r.Rsh(reward, 5)
		reward.Add(reward, r)
	}

	// Reward miner
	stateDB.AddBalance(header.Coinbase, reward, tracing.BalanceIncreaseRewardMineBlock)
}

// SealHash returns the hash of a block prior to sealing
func (o *ObsidianAsh) SealHash(header *types.Header) common.Hash {
	hasher := sha3.NewLegacyKeccak256()
	encodeHeader(hasher, header)
	var hash common.Hash
	hasher.Sum(hash[:0])
	return hash
}

// encodeHeader encodes a header for hashing (excluding mixDigest and nonce)
func encodeHeader(hasher hash.Hash, header *types.Header) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	rlp.Encode(hasher, enc)
}

// CalcDifficulty calculates the difficulty for a new block
func (o *ObsidianAsh) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return CalcDifficulty(time, parent)
}

// Close shuts down the consensus engine
func (o *ObsidianAsh) Close() error {
	return nil
}

// SetThreads sets the number of mining threads
func (o *ObsidianAsh) SetThreads(threads int) {
	o.threads = threads
	select {
	case o.update <- struct{}{}:
	default:
	}
}

// Threads returns the current mining thread count
func (o *ObsidianAsh) Threads() int {
	return o.threads
}

// Hashrate returns the current mining hashrate
func (o *ObsidianAsh) Hashrate() float64 {
	if o.hashrate != nil {
		return o.hashrate.rate()
	}
	return 0
}

// APIs returns RPC APIs exposed by the consensus engine
func (o *ObsidianAsh) APIs(chain consensus.ChainHeaderReader) []interface{} {
	return nil
}

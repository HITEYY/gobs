// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package obsidianash

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"math"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"golang.org/x/crypto/sha3"
)

var (
	errNoMiningWork = errors.New("no mining work available")
)

// hashrate tracks the mining hashrate
type hashrate struct {
	mu      sync.RWMutex
	counts  []uint64
	times   []time.Time
	current float64
}

func newHashrate() *hashrate {
	return &hashrate{
		counts: make([]uint64, 0, 64),
		times:  make([]time.Time, 0, 64),
	}
}

func (h *hashrate) add(count uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	h.counts = append(h.counts, count)
	h.times = append(h.times, now)

	// Keep only last 64 entries
	if len(h.counts) > 64 {
		h.counts = h.counts[1:]
		h.times = h.times[1:]
	}

	// Calculate rate
	if len(h.counts) > 1 {
		elapsed := h.times[len(h.times)-1].Sub(h.times[0]).Seconds()
		if elapsed > 0 {
			var total uint64
			for _, c := range h.counts {
				total += c
			}
			h.current = float64(total) / elapsed
		}
	}
}

func (h *hashrate) rate() float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current
}

// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the PoW difficulty requirements.
func (o *ObsidianAsh) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	// Reject sealing in fake mode (for testing without actual mining)
	if o.fakeFull {
		return errors.New("sealing not supported in fake mode")
	}

	// Create a copy of the header
	header := block.Header()

	// Sealing the genesis block is not supported
	if header.Number.Uint64() == 0 {
		return errors.New("cannot seal genesis block")
	}

	// Calculate the target from difficulty
	target := new(big.Int).Div(two256, header.Difficulty)

	// Generate random starting nonce
	var seed uint64
	if err := binary.Read(crand.Reader, binary.BigEndian, &seed); err != nil {
		seed = uint64(rand.Int63())
	}

	// Start mining threads
	threads := o.threads
	if threads <= 0 {
		threads = 1
	}

	var (
		pend   sync.WaitGroup
		found  = make(chan uint64, 1)
		abort  = make(chan struct{})
		locals = make(chan uint64)
	)

	// Start mining goroutines
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			o.mine(block, id, nonce, target, abort, found, locals)
		}(i, seed+uint64(i))
	}

	// Hashrate tracking goroutine
	go func() {
		var count uint64
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if o.hashrate != nil {
					o.hashrate.add(count)
				}
				count = 0
			case local := <-locals:
				count += local
			case <-abort:
				return
			}
		}
	}()

	// Wait for a solution or abort
	go func() {
		var result *types.Block
		select {
		case <-stop:
			// Stop signal received
			close(abort)
		case nonce := <-found:
			// Solution found, assemble block
			header := block.Header()
			header.Nonce = types.EncodeNonce(nonce)
			header.MixDigest = o.computeMixDigest(header, nonce)

			result = block.WithSeal(header)
		}
		// Wait for all miners to exit
		close(abort)
		pend.Wait()

		// Send result
		if result != nil {
			select {
			case results <- result:
			default:
			}
		}
	}()

	return nil
}

// mine is the actual PoW miner that searches for a nonce
func (o *ObsidianAsh) mine(block *types.Block, id int, startNonce uint64, target *big.Int, abort chan struct{}, found chan uint64, locals chan uint64) {
	header := block.Header()
	var (
		nonce  = startNonce
		hasher = sha3.NewLegacyKeccak256()
	)

	// Mining loop
	for {
		select {
		case <-abort:
			return
		default:
			// Compute hash
			hash := computePoWHash(hasher, header, nonce)

			// Check if hash meets difficulty target
			if new(big.Int).SetBytes(hash[:]).Cmp(target) <= 0 {
				// Found a valid nonce
				select {
				case found <- nonce:
				case <-abort:
				}
				return
			}

			nonce++

			// Report hashrate periodically
			if nonce%1000 == 0 {
				select {
				case locals <- 1000:
				default:
				}
			}
		}
	}
}

// computePoWHash computes the proof-of-work hash
func computePoWHash(hasher hash.Hash, header *types.Header, nonce uint64) common.Hash {
	hasher.Reset()

	// Encode header (without nonce and mix digest)
	encodeHeader(hasher, header)

	// Add nonce
	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], nonce)
	hasher.Write(nonceBytes[:])

	// Compute hash
	var hash common.Hash
	hasher.Sum(hash[:0])
	return hash
}

// computeMixDigest computes the mix digest for the sealed block
func (o *ObsidianAsh) computeMixDigest(header *types.Header, nonce uint64) common.Hash {
	hasher := sha3.NewLegacyKeccak256()

	// Simple mix digest computation
	encodeHeader(hasher, header)

	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], nonce)
	hasher.Write(nonceBytes[:])

	var mix common.Hash
	hasher.Sum(mix[:0])

	// XOR with nonce for variation
	for i := 0; i < 8; i++ {
		mix[i] ^= nonceBytes[i]
	}

	return mix
}

// two256 is 2^256
var two256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))

// VerifySeal checks whether the block satisfies the PoW difficulty requirement
func (o *ObsidianAsh) VerifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Skip verification in fake mode
	if o.fakeFull {
		return nil
	}

	// Check for fake fail at specific block
	if o.fakeFail != nil && *o.fakeFail == header.Number.Uint64() {
		return errInvalidPoW
	}

	// Verify difficulty is positive
	if header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}

	// Compute target
	target := new(big.Int).Div(two256, header.Difficulty)

	// Compute hash with nonce
	hasher := sha3.NewLegacyKeccak256()
	hash := computePoWHash(hasher, header, header.Nonce.Uint64())

	// Verify hash is below target
	if new(big.Int).SetBytes(hash[:]).Cmp(target) > 0 {
		return errInvalidPoW
	}

	return nil
}

// MineBlock is a convenience function that mines a block synchronously
func (o *ObsidianAsh) MineBlock(chain consensus.ChainHeaderReader, block *types.Block) (*types.Block, error) {
	results := make(chan *types.Block)
	stop := make(chan struct{})

	if err := o.Seal(chain, block, results, stop); err != nil {
		return nil, err
	}

	select {
	case result := <-results:
		return result, nil
	case <-time.After(time.Minute * 5):
		close(stop)
		return nil, errors.New("mining timeout")
	}
}

// randomNonce generates a random starting nonce
func randomNonce() uint64 {
	return rand.Uint64()&math.MaxInt64 + rand.Uint64()&math.MaxInt64
}

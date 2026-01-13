// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package obsidianash

import (
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// Difficulty adjustment constants for 5-second block time
const (
	// targetBlockTime is the target time between blocks in seconds
	targetBlockTime = 5

	// difficultyBoundDivisor is the bound divisor (2048)
	// Right-shift by 11 is equivalent to dividing by 2048
	difficultyBoundDivisor = 11

	// minimumDifficulty is the minimum difficulty
	minimumDifficulty = 131072

	// maxAdjustment caps the difficulty adjustment factor
	maxAdjustment = 99
)

// CalcDifficulty calculates the difficulty for a new block based on
// the target 5-second block time.
//
// Algorithm:
//
//	if blockTime < targetBlockTime:
//	    difficulty = parentDiff + parentDiff / 2048 * (targetBlockTime - blockTime) / targetBlockTime
//	else:
//	    difficulty = parentDiff - parentDiff / 2048 * min((blockTime - targetBlockTime) / targetBlockTime, 99)
//
// This ensures faster blocks increase difficulty and slower blocks decrease it,
// targeting 5-second average block times.
func CalcDifficulty(time uint64, parent *types.Header) *big.Int {
	parentDiff, _ := uint256.FromBig(parent.Difficulty)
	blockTime := time - parent.Time

	// Calculate adjustment step: parentDiff / 2048
	adjust := parentDiff.Clone()
	adjust.Rsh(adjust, difficultyBoundDivisor)

	if blockTime < targetBlockTime {
		// Block was too fast - increase difficulty
		// adjustment = (targetBlockTime - blockTime)
		increase := targetBlockTime - blockTime
		if increase > targetBlockTime {
			increase = targetBlockTime
		}

		factor := new(uint256.Int).SetUint64(increase)
		factor.Mul(adjust, factor)
		parentDiff.Add(parentDiff, factor)
	} else {
		// Block was too slow - decrease difficulty
		// adjustment = min((blockTime - targetBlockTime), maxAdjustment)
		decrease := blockTime - targetBlockTime
		if decrease > maxAdjustment {
			decrease = maxAdjustment
		}

		factor := new(uint256.Int).SetUint64(decrease)
		factor.Mul(adjust, factor)

		// Ensure we don't go below minimum
		if parentDiff.Cmp(factor) > 0 {
			parentDiff.Sub(parentDiff, factor)
		} else {
			parentDiff.SetUint64(minimumDifficulty)
		}
	}

	// Enforce minimum difficulty
	if parentDiff.LtUint64(minimumDifficulty) {
		parentDiff.SetUint64(minimumDifficulty)
	}

	return parentDiff.ToBig()
}

// CalcDifficultySimple is a simpler difficulty adjustment for genesis
func CalcDifficultySimple(time uint64, parent *types.Header) *big.Int {
	parentDiff, _ := uint256.FromBig(parent.Difficulty)
	blockTime := time - parent.Time

	// Simple adjustment: +/- 1/2048 based on block time vs target
	adjust := parentDiff.Clone()
	adjust.Rsh(adjust, difficultyBoundDivisor)

	if blockTime < targetBlockTime {
		parentDiff.Add(parentDiff, adjust)
	} else if blockTime > targetBlockTime {
		if parentDiff.Cmp(adjust) > 0 {
			parentDiff.Sub(parentDiff, adjust)
		} else {
			parentDiff.SetUint64(minimumDifficulty)
		}
	}

	if parentDiff.LtUint64(minimumDifficulty) {
		parentDiff.SetUint64(minimumDifficulty)
	}

	return parentDiff.ToBig()
}

// VerifyDifficulty checks if the difficulty of a header is valid
func VerifyDifficulty(header *types.Header, parent *types.Header) error {
	expected := CalcDifficulty(header.Time, parent)
	if expected.Cmp(header.Difficulty) != 0 {
		return errInvalidDifficulty
	}
	return nil
}

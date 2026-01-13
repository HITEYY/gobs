// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package obsidianash

import (
	"math/big"

	"github.com/obsidian-chain/obsidian/params"
)

// CalcBlockReward calculates the block reward for a given block number
// using the chromatic halving algorithm.
//
// Chromatic Halving:
// Instead of instant halving, the reward smoothly transitions over a
// "chromatic phase" period before and after each halving point.
//
// Standard halving would be: reward = initialReward >> epoch
// Chromatic halving adds a gradual transition that starts 10% before
// the halving and completes 10% after the halving, creating a smooth curve.
func CalcBlockReward(config *params.ObsidianashConfig, blockNum uint64) *big.Int {
	if config == nil {
		config = params.DefaultObsidianashConfig()
	}

	halvingInterval := config.HalvingInterval
	chromaticPhase := config.ChromaticPhase
	initialReward := config.InitialReward
	maxSupply := config.MaxSupply

	// Calculate current epoch (number of halvings)
	epoch := blockNum / halvingInterval

	// Cap at maximum halvings to prevent reward going to zero too fast
	if epoch > params.MaxHalvings {
		return big.NewInt(0)
	}

	// Base reward after standard halving
	baseReward := new(big.Int).Set(initialReward)
	baseReward.Rsh(baseReward, uint(epoch)) // Divide by 2^epoch

	// Calculate position within halving cycle
	positionInCycle := blockNum % halvingInterval

	// Chromatic phase adjustment
	reward := chromaticAdjustment(baseReward, positionInCycle, halvingInterval, chromaticPhase)

	// Check against max supply (simplified - in practice would need total supply tracking)
	if reward.Cmp(maxSupply) > 0 {
		return big.NewInt(0)
	}

	return reward
}

// chromaticAdjustment applies the smooth transition curve
func chromaticAdjustment(baseReward *big.Int, position, interval, phase uint64) *big.Int {
	// Before chromatic phase starts - full reward
	if position < interval-phase {
		return baseReward
	}

	// Calculate progress through chromatic phase (0.0 to 1.0)
	distanceToHalving := interval - position
	progress := float64(phase-distanceToHalving) / float64(phase)

	// Apply smooth reduction: reward * (1 - progress * 0.5)
	// At start of chromatic phase: 100% of base reward
	// At halving point: 50% of base reward (which equals the post-halving reward)
	reduction := progress * 0.5

	// Calculate adjusted reward
	// reward = baseReward * (1 - reduction)
	multiplier := 1.0 - reduction

	// Convert to big.Int calculation to maintain precision
	// multiplier is between 0.5 and 1.0, so we use 1000 as precision base
	precisionBase := big.NewInt(1000)
	multiplierBig := big.NewInt(int64(multiplier * 1000))

	result := new(big.Int).Mul(baseReward, multiplierBig)
	result.Div(result, precisionBase)

	return result
}

// CalcTotalSupplyAtBlock calculates the theoretical total supply at a given block
// This is useful for verifying the max supply cap won't be exceeded
func CalcTotalSupplyAtBlock(config *params.ObsidianashConfig, blockNum uint64) *big.Int {
	if config == nil {
		config = params.DefaultObsidianashConfig()
	}

	halvingInterval := config.HalvingInterval
	initialReward := config.InitialReward

	totalSupply := big.NewInt(0)
	currentReward := new(big.Int).Set(initialReward)

	// Sum up rewards for each epoch
	for epoch := uint64(0); epoch <= blockNum/halvingInterval; epoch++ {
		blocksInEpoch := halvingInterval
		if epoch == blockNum/halvingInterval {
			// Partial epoch
			blocksInEpoch = blockNum % halvingInterval
		}

		epochReward := new(big.Int).Mul(currentReward, big.NewInt(int64(blocksInEpoch)))
		totalSupply.Add(totalSupply, epochReward)

		// Halve for next epoch
		currentReward.Rsh(currentReward, 1)
	}

	return totalSupply
}

// EstimateBlocksToMaxSupply estimates how many blocks until max supply is reached
func EstimateBlocksToMaxSupply(config *params.ObsidianashConfig) uint64 {
	if config == nil {
		config = params.DefaultObsidianashConfig()
	}

	// With halving every 2 years:
	// Year 0-2: 50 OBS/block * 12,614,400 blocks = 630,720,000 OBS
	// Year 2-4: 25 OBS/block * 12,614,400 blocks = 315,360,000 OBS
	// Year 4-6: 12.5 OBS/block * 12,614,400 blocks = 157,680,000 OBS
	// ...
	// Total after infinite time approaches: 2 * initial_supply_per_epoch = 1,261,440,000 OBS
	//
	// With max supply of 500M OBS, we'll hit it before the first halving completes
	// 500,000,000 / 50 = 10,000,000 blocks (approximately)

	maxSupply := config.MaxSupply
	initialReward := config.InitialReward
	halvingInterval := config.HalvingInterval

	totalSupply := big.NewInt(0)
	currentReward := new(big.Int).Set(initialReward)
	blocks := uint64(0)

	for epoch := uint64(0); epoch < params.MaxHalvings; epoch++ {
		epochReward := new(big.Int).Mul(currentReward, big.NewInt(int64(halvingInterval)))

		if new(big.Int).Add(totalSupply, epochReward).Cmp(maxSupply) >= 0 {
			// Max supply will be reached in this epoch
			remaining := new(big.Int).Sub(maxSupply, totalSupply)
			blocksNeeded := new(big.Int).Div(remaining, currentReward)
			blocks += blocksNeeded.Uint64()
			break
		}

		totalSupply.Add(totalSupply, epochReward)
		blocks += halvingInterval
		currentReward.Rsh(currentReward, 1)
	}

	return blocks
}

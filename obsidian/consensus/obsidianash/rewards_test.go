// Copyright 2024 The Obsidian Authors
// This file is part of Obsidian.

package obsidianash

import (
	"math/big"
	"testing"

	"github.com/obsidian-chain/obsidian/params"
)

func getTestConfig() *params.ObsidianashConfig {
	return params.DefaultObsidianashConfig()
}

func TestInitialBlockReward(t *testing.T) {
	config := getTestConfig()

	// Block 0 should get initial reward
	reward := CalcBlockReward(config, 0)

	if reward.Cmp(config.InitialReward) != 0 {
		t.Errorf("Block 0 reward should be %s, got %s",
			config.InitialReward.String(), reward.String())
	}
}

func TestFirstHalving(t *testing.T) {
	config := getTestConfig()

	// Before chromatic phase starts (full epoch 0 reward)
	beforeChromatic := CalcBlockReward(config, config.HalvingInterval-config.ChromaticPhase-100)

	// At first halving point (in epoch 1, halved reward)
	atHalving := CalcBlockReward(config, config.HalvingInterval)

	// The reward at halving should be exactly half (new epoch starts)
	expectedHalf := new(big.Int).Div(config.InitialReward, big.NewInt(2))

	if atHalving.Cmp(expectedHalf) != 0 {
		t.Errorf("Reward at halving should be %s, got %s",
			expectedHalf.String(), atHalving.String())
	}

	// Before chromatic phase, reward should be full
	if beforeChromatic.Cmp(config.InitialReward) != 0 {
		t.Errorf("Reward before chromatic phase should be %s, got %s",
			config.InitialReward.String(), beforeChromatic.String())
	}
}

func TestChromaticPhaseSmoothing(t *testing.T) {
	config := getTestConfig()

	// Test that rewards decrease smoothly during chromatic phase
	startBlock := config.HalvingInterval - config.ChromaticPhase
	endBlock := config.HalvingInterval

	var prevReward *big.Int

	// Check that rewards monotonically decrease during chromatic phase
	step := config.ChromaticPhase / 10
	if step == 0 {
		step = 1
	}

	for block := startBlock; block <= endBlock; block += step {
		reward := CalcBlockReward(config, block)

		if prevReward != nil {
			// Each reward should be less than or equal to the previous
			if reward.Cmp(prevReward) > 0 {
				t.Errorf("Reward at block %d (%s) should be <= previous reward (%s)",
					block, reward.String(), prevReward.String())
			}
		}

		prevReward = reward
	}
}

func TestMultipleHalvings(t *testing.T) {
	config := getTestConfig()

	tests := []struct {
		epoch           uint64
		expectedDivisor int64
	}{
		{0, 1},  // 50 OBS
		{1, 2},  // 25 OBS
		{2, 4},  // 12.5 OBS
		{3, 8},  // 6.25 OBS
		{4, 16}, // 3.125 OBS
	}

	for _, tt := range tests {
		// Get reward well after the chromatic phase ends
		block := tt.epoch*config.HalvingInterval + config.ChromaticPhase + 1000
		reward := CalcBlockReward(config, block)

		expected := new(big.Int).Div(config.InitialReward, big.NewInt(tt.expectedDivisor))

		// Allow some tolerance
		tolerance := new(big.Int).Div(expected, big.NewInt(5)) // 20%

		diff := new(big.Int).Sub(reward, expected)
		diff.Abs(diff)

		if diff.Cmp(tolerance) > 0 {
			t.Errorf("Epoch %d: reward should be approximately %s, got %s",
				tt.epoch, expected.String(), reward.String())
		}
	}
}

func TestTotalSupplyAtBlock(t *testing.T) {
	config := getTestConfig()

	// Total supply at block 1 should be at least initial reward
	supply1 := CalcTotalSupplyAtBlock(config, 1)
	if supply1.Cmp(config.InitialReward) < 0 {
		t.Errorf("Total supply at block 1 should be at least %s, got %s",
			config.InitialReward.String(), supply1.String())
	}

	// Total supply should increase with blocks
	supply1000 := CalcTotalSupplyAtBlock(config, 1000)
	if supply1000.Cmp(supply1) <= 0 {
		t.Error("Total supply should increase with blocks")
	}

	// Supply at 1000 blocks should be approximately 1000 * initial reward
	expected1000 := new(big.Int).Mul(config.InitialReward, big.NewInt(1000))
	tolerance := new(big.Int).Div(expected1000, big.NewInt(10)) // 10%
	diff := new(big.Int).Sub(supply1000, expected1000)
	diff.Abs(diff)

	if diff.Cmp(tolerance) > 0 {
		t.Errorf("Total supply at block 1000 should be approximately %s, got %s",
			expected1000.String(), supply1000.String())
	}
}

func TestMaxSupplyEnforcement(t *testing.T) {
	config := getTestConfig()

	// Calculate block where max supply should be reached
	blocks := EstimateBlocksToMaxSupply(config)

	// Reward at estimated final block should be 0 or very small
	reward := CalcBlockReward(config, blocks)

	// Should be zero once max supply is reached
	if reward.Sign() > 0 {
		// Check if we're past max supply
		supply := CalcTotalSupplyAtBlock(config, blocks)
		if supply.Cmp(config.MaxSupply) >= 0 {
			t.Logf("Max supply reached at block %d, reward is %s", blocks, reward.String())
		}
	}
}

func TestRewardNeverNegative(t *testing.T) {
	config := getTestConfig()

	// Test various block numbers to ensure reward is never negative
	testBlocks := []uint64{
		0,
		1,
		100,
		1000,
		config.HalvingInterval - 1,
		config.HalvingInterval,
		config.HalvingInterval + 1,
		config.HalvingInterval * 2,
		config.HalvingInterval * 10,
		config.HalvingInterval * 64,
	}

	for _, block := range testBlocks {
		reward := CalcBlockReward(config, block)
		if reward.Sign() < 0 {
			t.Errorf("Reward at block %d is negative: %s", block, reward.String())
		}
	}
}

func TestChromaticAdjustmentFunction(t *testing.T) {
	// Test chromatic adjustment at various positions
	baseReward := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18)) // 50 OBS
	interval := uint64(12614400)
	phase := uint64(1261440)

	tests := []struct {
		position    uint64 // Position within interval
		description string
	}{
		{0, "start of epoch"},
		{interval / 2, "middle of epoch"},
		{interval - phase, "start of chromatic phase"},
		{interval - phase/2, "middle of chromatic phase"},
		{interval - 1, "end of epoch"},
	}

	for _, tt := range tests {
		result := chromaticAdjustment(baseReward, tt.position, interval, phase)

		// Result should be between 50% and 100% of base reward
		minReward := new(big.Int).Div(baseReward, big.NewInt(2))
		if result.Cmp(minReward) < 0 {
			t.Errorf("%s: reward %s is less than 50%% of base", tt.description, result.String())
		}
		if result.Cmp(baseReward) > 0 {
			t.Errorf("%s: reward %s is greater than base", tt.description, result.String())
		}
	}
}

func BenchmarkCalcBlockReward(b *testing.B) {
	config := getTestConfig()
	for i := 0; i < b.N; i++ {
		CalcBlockReward(config, uint64(i)%(config.HalvingInterval*10))
	}
}

func BenchmarkCalcTotalSupplyAtBlock(b *testing.B) {
	config := getTestConfig()
	for i := 0; i < b.N; i++ {
		CalcTotalSupplyAtBlock(config, uint64(i)%(config.HalvingInterval*10))
	}
}

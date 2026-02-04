// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package feeestimator

import (
	"math/big"
	"sort"
	"sync"
)

// FeeEstimator provides gas price estimation
type FeeEstimator struct {
	mu sync.RWMutex

	// Historical gas prices from recent blocks
	history    []*big.Int
	maxHistory int

	// Configuration
	minGasPrice *big.Int
	maxGasPrice *big.Int

	// Current recommendations
	slow    *big.Int // ~60 blocks confirmation
	average *big.Int // ~20 blocks confirmation
	fast    *big.Int // ~5 blocks confirmation
	instant *big.Int // next block
}

// New creates a new fee estimator
func New(minGasPrice, maxGasPrice *big.Int) *FeeEstimator {
	if minGasPrice == nil {
		minGasPrice = big.NewInt(1e9) // 1 Gwei
	}
	if maxGasPrice == nil {
		maxGasPrice = big.NewInt(500e9) // 500 Gwei
	}

	return &FeeEstimator{
		history:     make([]*big.Int, 0, 200),
		maxHistory:  200,
		minGasPrice: minGasPrice,
		maxGasPrice: maxGasPrice,
		slow:        new(big.Int).Set(minGasPrice),
		average:     new(big.Int).Mul(minGasPrice, big.NewInt(2)),
		fast:        new(big.Int).Mul(minGasPrice, big.NewInt(5)),
		instant:     new(big.Int).Mul(minGasPrice, big.NewInt(10)),
	}
}

// Estimate represents a gas price estimate
type Estimate struct {
	Slow    *big.Int `json:"slow"`    // Low priority
	Average *big.Int `json:"average"` // Medium priority
	Fast    *big.Int `json:"fast"`    // High priority
	Instant *big.Int `json:"instant"` // Highest priority
	BaseFee *big.Int `json:"baseFee"` // Current base fee
}

// AddSample adds a gas price sample from a mined transaction
func (e *FeeEstimator) AddSample(gasPrice *big.Int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Add to history
	e.history = append(e.history, new(big.Int).Set(gasPrice))

	// Trim history if needed
	if len(e.history) > e.maxHistory {
		e.history = e.history[len(e.history)-e.maxHistory:]
	}

	// Recalculate estimates
	e.recalculate()
}

// AddBlockSamples adds all gas prices from a block
func (e *FeeEstimator) AddBlockSamples(gasPrices []*big.Int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, gp := range gasPrices {
		e.history = append(e.history, new(big.Int).Set(gp))
	}

	// Trim history
	if len(e.history) > e.maxHistory {
		e.history = e.history[len(e.history)-e.maxHistory:]
	}

	e.recalculate()
}

// recalculate updates the fee estimates based on history
func (e *FeeEstimator) recalculate() {
	if len(e.history) < 5 {
		// Not enough data, use defaults
		return
	}

	// Sort prices
	sorted := make([]*big.Int, len(e.history))
	copy(sorted, e.history)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Cmp(sorted[j]) < 0
	})

	n := len(sorted)

	// Calculate percentiles
	// Slow: 25th percentile
	slowIdx := n * 25 / 100
	e.slow = sorted[slowIdx]

	// Average: 50th percentile (median)
	avgIdx := n * 50 / 100
	e.average = sorted[avgIdx]

	// Fast: 75th percentile
	fastIdx := n * 75 / 100
	e.fast = sorted[fastIdx]

	// Instant: 95th percentile
	instantIdx := n * 95 / 100
	if instantIdx >= n {
		instantIdx = n - 1
	}
	e.instant = sorted[instantIdx]

	// Apply bounds
	e.slow = e.clamp(e.slow)
	e.average = e.clamp(e.average)
	e.fast = e.clamp(e.fast)
	e.instant = e.clamp(e.instant)
}

// clamp applies min/max bounds to a gas price
func (e *FeeEstimator) clamp(price *big.Int) *big.Int {
	if price.Cmp(e.minGasPrice) < 0 {
		return new(big.Int).Set(e.minGasPrice)
	}
	if price.Cmp(e.maxGasPrice) > 0 {
		return new(big.Int).Set(e.maxGasPrice)
	}
	return new(big.Int).Set(price)
}

// GetEstimate returns current fee estimates
func (e *FeeEstimator) GetEstimate() *Estimate {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return &Estimate{
		Slow:    new(big.Int).Set(e.slow),
		Average: new(big.Int).Set(e.average),
		Fast:    new(big.Int).Set(e.fast),
		Instant: new(big.Int).Set(e.instant),
		BaseFee: new(big.Int).Set(e.slow), // Use slow as base fee estimate
	}
}

// SuggestGasPrice returns a suggested gas price
func (e *FeeEstimator) SuggestGasPrice() *big.Int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return new(big.Int).Set(e.average)
}

// SuggestGasTipCap returns a suggested tip for EIP-1559 transactions
func (e *FeeEstimator) SuggestGasTipCap() *big.Int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Tip is the difference between average and slow
	tip := new(big.Int).Sub(e.average, e.slow)
	if tip.Sign() < 0 {
		return big.NewInt(1e9) // 1 Gwei minimum
	}
	return tip
}

// EstimateConfirmationTime estimates blocks to confirmation for a gas price
func (e *FeeEstimator) EstimateConfirmationTime(gasPrice *big.Int) int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Estimate based on how the gas price compares to our buckets
	if gasPrice.Cmp(e.instant) >= 0 {
		return 1 // Next block
	}
	if gasPrice.Cmp(e.fast) >= 0 {
		return 3 // ~3 blocks
	}
	if gasPrice.Cmp(e.average) >= 0 {
		return 10 // ~10 blocks
	}
	if gasPrice.Cmp(e.slow) >= 0 {
		return 30 // ~30 blocks
	}
	return 100 // Very slow, 100+ blocks
}

// Reset clears the history and resets to defaults
func (e *FeeEstimator) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.history = make([]*big.Int, 0, e.maxHistory)
	e.slow = new(big.Int).Set(e.minGasPrice)
	e.average = new(big.Int).Mul(e.minGasPrice, big.NewInt(2))
	e.fast = new(big.Int).Mul(e.minGasPrice, big.NewInt(5))
	e.instant = new(big.Int).Mul(e.minGasPrice, big.NewInt(10))
}

// GetHistorySize returns the number of samples in history
func (e *FeeEstimator) GetHistorySize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.history)
}

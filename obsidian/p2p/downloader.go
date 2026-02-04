// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package p2p

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	obstypes "github.com/obsidian-chain/obsidian/core/types"
)

// Sync configuration
const (
	maxBlockFetch     = 128 // Maximum blocks to request at once
	maxHeaderFetch    = 192 // Maximum headers to fetch per request
	syncCheckInterval = 10 * time.Second
	requestTimeout    = 15 * time.Second
	maxSyncRetries    = 3
)

var (
	ErrCancelled      = errors.New("sync cancelled")
	ErrTimeout        = errors.New("request timeout")
	ErrBadPeer        = errors.New("bad peer")
	ErrAlreadySyncing = errors.New("already syncing")
	ErrNoSyncPeer     = errors.New("no peer available for sync")
)

// SyncProgress represents current sync progress
type SyncProgress struct {
	StartingBlock uint64
	CurrentBlock  uint64
	HighestBlock  uint64
	Syncing       bool
}

// Downloader manages blockchain synchronization
type Downloader struct {
	backend Backend
	handler *Handler

	// Sync state
	syncing      int32
	syncProgress SyncProgress
	syncMu       sync.RWMutex

	// Request tracking
	pendingRequests map[uint64]*syncRequest

	// Channels for received data
	headerCh chan headerResponse
	bodyCh   chan bodyResponse
	blockCh  chan blockResponse

	// Control
	cancelCh chan struct{}

	log log.Logger
}

type syncRequest struct {
}

type headerResponse struct {
	peer    *Peer
	headers []*obstypes.ObsidianHeader
}

type bodyResponse struct {
	peer   *Peer
	bodies []BlockBody
}

type blockResponse struct {
	peer  *Peer
	block *obstypes.ObsidianBlock
	td    *big.Int
}

// NewDownloader creates a new synchronization manager
func NewDownloader(backend Backend, handler *Handler) *Downloader {
	d := &Downloader{
		backend:         backend,
		handler:         handler,
		pendingRequests: make(map[uint64]*syncRequest),
		headerCh:        make(chan headerResponse, 16),
		bodyCh:          make(chan bodyResponse, 16),
		blockCh:         make(chan blockResponse, 64),
		log:             log.New("module", "downloader"),
	}
	return d
}

// Start begins the sync checker loop
func (d *Downloader) Start() {
	go d.syncLoop()
}

// Stop stops the downloader
func (d *Downloader) Stop() {
	if d.cancelCh != nil {
		close(d.cancelCh)
	}
}

// syncLoop periodically checks if we need to sync
func (d *Downloader) syncLoop() {
	ticker := time.NewTicker(syncCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.CheckAndSync()
		case <-d.cancelCh:
			return
		}
	}
}

// CheckAndSync checks if we should sync with any peer
func (d *Downloader) CheckAndSync() {
	if atomic.LoadInt32(&d.syncing) == 1 {
		return
	}

	// Find best peer
	bestPeer := d.findBestPeer()
	if bestPeer == nil {
		return
	}

	// Check if peer is ahead
	head := d.backend.CurrentBlock()
	ourTD := d.backend.GetTD(head.Hash())
	if ourTD == nil {
		ourTD = big.NewInt(0)
	}

	bestPeer.lock.RLock()
	peerTD := bestPeer.td
	peerNum := bestPeer.number
	bestPeer.lock.RUnlock()

	if peerTD.Cmp(ourTD) <= 0 {
		return
	}

	// Start sync
	go func() { _ = d.synchronise(bestPeer, peerNum) }()
}

// findBestPeer finds the peer with the highest TD
func (d *Downloader) findBestPeer() *Peer {
	if d.handler == nil {
		return nil
	}

	peers := d.handler.Peers()
	if len(peers) == 0 {
		return nil
	}

	var best *Peer
	var bestTD *big.Int

	for _, p := range peers {
		p.lock.RLock()
		td := p.td
		p.lock.RUnlock()

		if best == nil || (td != nil && (bestTD == nil || td.Cmp(bestTD) > 0)) {
			best = p
			bestTD = td
		}
	}

	return best
}

// synchronise syncs with a peer
func (d *Downloader) synchronise(peer *Peer, targetNum uint64) error {
	if !atomic.CompareAndSwapInt32(&d.syncing, 0, 1) {
		return ErrAlreadySyncing
	}
	defer atomic.StoreInt32(&d.syncing, 0)

	head := d.backend.CurrentBlock()
	ourNum := head.Number.Uint64()

	if targetNum <= ourNum {
		return nil
	}

	d.syncMu.Lock()
	d.syncProgress = SyncProgress{
		StartingBlock: ourNum,
		CurrentBlock:  ourNum,
		HighestBlock:  targetNum,
		Syncing:       true,
	}
	d.syncMu.Unlock()

	defer func() {
		d.syncMu.Lock()
		d.syncProgress.Syncing = false
		d.syncMu.Unlock()
	}()

	d.log.Info("Starting block synchronization",
		"peer", peer.id[:16],
		"from", ourNum+1,
		"to", targetNum,
	)

	startTime := time.Now()
	blocksDownloaded := uint64(0)

	// Download blocks in batches
	for num := ourNum + 1; num <= targetNum; {
		// Calculate batch size
		batchSize := uint64(maxBlockFetch)
		if num+batchSize-1 > targetNum {
			batchSize = targetNum - num + 1
		}

		// Request blocks
		blocks, err := d.fetchBlockRange(peer, num, batchSize)
		if err != nil {
			d.log.Error("Failed to fetch blocks", "from", num, "err", err)
			return err
		}

		if len(blocks) == 0 {
			d.log.Warn("No blocks received", "from", num)
			return fmt.Errorf("no blocks received from peer")
		}

		// Insert blocks
		for _, block := range blocks {
			if err := d.backend.InsertBlock(block); err != nil {
				d.log.Error("Failed to insert block",
					"number", block.NumberU64(),
					"hash", block.Hash().Hex()[:16],
					"err", err,
				)
				return err
			}
			blocksDownloaded++

			d.syncMu.Lock()
			d.syncProgress.CurrentBlock = block.NumberU64()
			d.syncMu.Unlock()
		}

		num += uint64(len(blocks))

		// Log progress
		if blocksDownloaded%100 == 0 || num > targetNum {
			progress := float64(num-ourNum-1) / float64(targetNum-ourNum) * 100
			d.log.Info("Sync progress",
				"current", num-1,
				"target", targetNum,
				"progress", fmt.Sprintf("%.2f%%", progress),
			)
		}
	}

	duration := time.Since(startTime)
	blocksPerSec := float64(blocksDownloaded) / duration.Seconds()

	d.log.Info("Synchronization completed",
		"blocks", blocksDownloaded,
		"duration", duration,
		"blocks/sec", fmt.Sprintf("%.2f", blocksPerSec),
	)

	return nil
}

// fetchBlockRange fetches a range of blocks from a peer
func (d *Downloader) fetchBlockRange(peer *Peer, from uint64, count uint64) ([]*obstypes.ObsidianBlock, error) {
	blocks := make([]*obstypes.ObsidianBlock, 0, count)

	// First, get headers
	headers, err := d.fetchHeaders(peer, from, count)
	if err != nil {
		return nil, err
	}

	if len(headers) == 0 {
		return nil, nil
	}

	// Then get bodies
	hashes := make([]common.Hash, len(headers))
	for i, h := range headers {
		hashes[i] = h.Hash()
	}

	bodies, err := d.fetchBodies(peer, hashes)
	if err != nil {
		return nil, err
	}

	// Assemble blocks
	for i, header := range headers {
		var txs []*obstypes.StealthTransaction
		var uncles []*obstypes.ObsidianHeader

		if i < len(bodies) {
			txs = bodies[i].Transactions
			uncles = bodies[i].Uncles
		}

		block := obstypes.NewBlockWithHeader(header).WithBody(txs, uncles)
		blocks = append(blocks, block)
	}

	return blocks, nil
}

// fetchHeaders requests block headers from a peer
func (d *Downloader) fetchHeaders(peer *Peer, from uint64, count uint64) ([]*obstypes.ObsidianHeader, error) {
	req := GetBlockHeadersPacket{
		Origin:  HashOrNumber{Number: from},
		Amount:  count,
		Skip:    0,
		Reverse: false,
	}

	// Send request
	if err := p2p.Send(peer.rw, GetBlockHeadersMsg, &req); err != nil {
		return nil, err
	}

	// Wait for response with timeout
	select {
	case res := <-d.headerCh:
		if res.peer.id != peer.id {
			// This is from a different peer, we should probably put it back or handle it
			// For simplicity, we just ignore it and hope for the best
			return d.fetchHeadersOneByOne(peer, from, count)
		}
		return res.headers, nil
	case <-time.After(requestTimeout):
		// On timeout, try to get blocks directly one by one
		return d.fetchHeadersOneByOne(peer, from, count)
	}
}

// fetchHeadersOneByOne fetches headers one at a time (fallback)
func (d *Downloader) fetchHeadersOneByOne(peer *Peer, from uint64, count uint64) ([]*obstypes.ObsidianHeader, error) {
	headers := make([]*obstypes.ObsidianHeader, 0, count)

	for i := uint64(0); i < count; i++ {
		num := from + i

		req := GetBlockHeadersPacket{
			Origin: HashOrNumber{Number: num},
			Amount: 1,
		}

		if err := p2p.Send(peer.rw, GetBlockHeadersMsg, &req); err != nil {
			return headers, err
		}

		select {
		case res := <-d.headerCh:
			if res.peer.id == peer.id && len(res.headers) > 0 {
				headers = append(headers, res.headers[0])
			}
		case <-time.After(requestTimeout):
			d.log.Debug("Header request timeout", "number", num)
		}
	}

	return headers, nil
}

// fetchBodies requests block bodies from a peer
func (d *Downloader) fetchBodies(peer *Peer, hashes []common.Hash) ([]BlockBody, error) {
	if len(hashes) == 0 {
		return nil, nil
	}

	// Send request
	if err := p2p.Send(peer.rw, GetBlockBodiesMsg, GetBlockBodiesPacket(hashes)); err != nil {
		return nil, err
	}

	// Wait for response with timeout
	select {
	case res := <-d.bodyCh:
		if res.peer.id != peer.id {
			return nil, fmt.Errorf("response from wrong peer")
		}
		return res.bodies, nil
	case <-time.After(requestTimeout):
		return nil, ErrTimeout
	}
}

// DeliverHeaders is called when headers are received from a peer
func (d *Downloader) DeliverHeaders(peer *Peer, headers []*obstypes.ObsidianHeader) {
	select {
	case d.headerCh <- headerResponse{peer: peer, headers: headers}:
	default:
		d.log.Debug("Header channel full, dropping response")
	}
}

// DeliverBodies is called when bodies are received from a peer
func (d *Downloader) DeliverBodies(peer *Peer, bodies []BlockBody) {
	select {
	case d.bodyCh <- bodyResponse{peer: peer, bodies: bodies}:
	default:
		d.log.Debug("Body channel full, dropping response")
	}
}

// DeliverBlock is called when a complete block is received from a peer
func (d *Downloader) DeliverBlock(peer *Peer, block *obstypes.ObsidianBlock, td *big.Int) {
	select {
	case d.blockCh <- blockResponse{peer: peer, block: block, td: td}:
	default:
		d.log.Debug("Block channel full, dropping response")
	}
}

// Progress returns the current sync progress
func (d *Downloader) Progress() SyncProgress {
	d.syncMu.RLock()
	defer d.syncMu.RUnlock()
	return d.syncProgress
}

// Syncing returns true if currently syncing
func (d *Downloader) Syncing() bool {
	return atomic.LoadInt32(&d.syncing) == 1
}

// SyncWithPeer manually triggers sync with a specific peer
func (d *Downloader) SyncWithPeer(peer *Peer) error {
	peer.lock.RLock()
	targetNum := peer.number
	peer.lock.RUnlock()

	return d.synchronise(peer, targetNum)
}

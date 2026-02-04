// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package p2p

import (
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

const (
	// ProtocolName is the name of the Obsidian protocol
	ProtocolName = "obs"
	// ProtocolVersion is the version of the protocol
	ProtocolVersion = 1
	// ProtocolLength is the number of message types
	ProtocolLength = 20

	// Timeouts
	handshakeTimeout = 5 * time.Second
	syncTimeout      = 30 * time.Second
)

// Message codes
const (
	StatusMsg             = 0x00
	NewBlockHashesMsg     = 0x01
	TransactionsMsg       = 0x02
	GetBlockHeadersMsg    = 0x03
	BlockHeadersMsg       = 0x04
	GetBlockBodiesMsg     = 0x05
	BlockBodiesMsg        = 0x06
	NewBlockMsg           = 0x07
	GetNodeDataMsg        = 0x08
	NodeDataMsg           = 0x09
	GetReceiptsMsg        = 0x0a
	ReceiptsMsg           = 0x0b
	NewPooledTxHashesMsg  = 0x0c
	GetPooledTxMsg        = 0x0d
	PooledTransactionsMsg = 0x0e
	PingMsg               = 0x0f
	PongMsg               = 0x10
	GetBlockByNumberMsg   = 0x11
	GetBlockByHashMsg     = 0x12
)

// StatusPacket is the network status packet
type StatusPacket struct {
	ProtocolVersion uint32
	NetworkID       uint64
	TD              *big.Int // Total difficulty
	HeadHash        common.Hash
	HeadNumber      uint64
	GenesisHash     common.Hash
}

// NewBlockHashesPacket is the block hash announcement packet
type NewBlockHashesPacket []BlockHashNumber

// BlockHashNumber pairs a hash with a number
type BlockHashNumber struct {
	Hash   common.Hash
	Number uint64
}

// NewBlockPacket is the new block propagation packet
type NewBlockPacket struct {
	Block *obstypes.ObsidianBlock
	TD    *big.Int
}

// GetBlockHeadersPacket is the request for block headers
type GetBlockHeadersPacket struct {
	Origin  HashOrNumber
	Amount  uint64
	Skip    uint64
	Reverse bool
}

// HashOrNumber is either a hash or a number
type HashOrNumber struct {
	Hash   common.Hash
	Number uint64
}

// BlockHeadersPacket is the response with block headers
type BlockHeadersPacket []*obstypes.ObsidianHeader

// GetBlockBodiesPacket is the request for block bodies
type GetBlockBodiesPacket []common.Hash

// BlockBodiesPacket is the response with block bodies
type BlockBodiesPacket []BlockBody

// BlockBody represents a block body
type BlockBody struct {
	Transactions []*obstypes.StealthTransaction
	Uncles       []*obstypes.ObsidianHeader
}

// TransactionsPacket is a batch of transactions
type TransactionsPacket []*obstypes.StealthTransaction

// Backend interface for blockchain operations
type Backend interface {
	// Chain information
	CurrentBlock() *obstypes.ObsidianHeader
	GetBlockByHash(hash common.Hash) *obstypes.ObsidianBlock
	GetBlockByNumber(number uint64) *obstypes.ObsidianBlock
	GetTD(hash common.Hash) *big.Int
	GenesisHash() common.Hash
	ChainID() *big.Int

	// Block operations
	InsertBlock(block *obstypes.ObsidianBlock) error
	HasBlock(hash common.Hash) bool

	// Transaction pool
	AddRemoteTxs(txs []*obstypes.StealthTransaction) []error
	PendingTxs() []*obstypes.StealthTransaction
}

// Handler manages P2P protocol connections and message handling
type Handler struct {
	networkID   uint64
	genesisHash common.Hash
	backend     Backend

	// Peer management
	peers     map[string]*Peer
	peersMu   sync.RWMutex
	maxPeers  int
	peerCount int32

	// Synchronization
	syncing      int32
	synchronizer *Synchronizer
	downloader   *Downloader

	// Pending blocks (blocks waiting for parent to arrive)
	pendingBlocks   map[common.Hash]*obstypes.ObsidianBlock // parentHash -> block
	pendingBlocksMu sync.RWMutex

	// Channels
	quitCh          chan struct{}
	blockAnnounceCh chan *obstypes.ObsidianBlock

	// Stats
	blocksReceived uint64
	blocksSent     uint64
	txsReceived    uint64
	txsSent        uint64
}

// Peer represents a connected peer
type Peer struct {
	*p2p.Peer
	rw      p2p.MsgReadWriter
	id      string
	version uint32

	// Peer state
	head   common.Hash
	td     *big.Int
	number uint64
	lock   sync.RWMutex

	// Known blocks/txs (to avoid re-sending)
	knownBlocks *knownCache
	knownTxs    *knownCache

	// Queues
	queuedBlocks chan *obstypes.ObsidianBlock
	queuedTxs    chan []*obstypes.StealthTransaction

	term chan struct{}
}

// knownCache tracks known hashes
type knownCache struct {
	cache map[common.Hash]struct{}
	mu    sync.RWMutex
	max   int
}

func newKnownCache(max int) *knownCache {
	return &knownCache{
		cache: make(map[common.Hash]struct{}),
		max:   max,
	}
}

func (k *knownCache) Add(hash common.Hash) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.cache) >= k.max {
		// Remove random entry
		for h := range k.cache {
			delete(k.cache, h)
			break
		}
	}
	k.cache[hash] = struct{}{}
}

func (k *knownCache) Has(hash common.Hash) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.cache[hash]
	return ok
}

// NewHandler creates a new P2P handler
func NewHandler(networkID uint64, backend Backend) *Handler {
	h := &Handler{
		networkID:       networkID,
		backend:         backend,
		genesisHash:     backend.GenesisHash(),
		peers:           make(map[string]*Peer),
		maxPeers:        50,
		pendingBlocks:   make(map[common.Hash]*obstypes.ObsidianBlock),
		quitCh:          make(chan struct{}),
		blockAnnounceCh: make(chan *obstypes.ObsidianBlock, 10),
	}
	h.downloader = NewDownloader(backend, h)
	return h
}

// SetBackend sets the backend (for delayed initialization)
func (h *Handler) SetBackend(backend Backend) {
	h.backend = backend
	h.genesisHash = backend.GenesisHash()
}

// SetSynchronizer sets the blockchain synchronizer
func (h *Handler) SetSynchronizer(sync *Synchronizer) {
	// Synchronizer is deprecated in favor of Downloader
	h.synchronizer = sync
}

// StartSync starts the blockchain synchronizer
func (h *Handler) StartSync() error {
	if h.downloader != nil {
		h.downloader.Start()
		return nil
	}
	if h.synchronizer == nil {
		h.synchronizer = NewSynchronizer(h.backend, h)
	}
	return h.synchronizer.Start()
}

// StopSync stops the blockchain synchronizer
func (h *Handler) StopSync() {
	if h.downloader != nil {
		h.downloader.Stop()
	}
	if h.synchronizer != nil {
		h.synchronizer.Stop()
	}
}

// SyncProgress returns the current sync progress
func (h *Handler) SyncProgress() (start, current, target uint64, syncing bool) {
	if h.downloader != nil {
		p := h.downloader.Progress()
		return p.StartingBlock, p.CurrentBlock, p.HighestBlock, p.Syncing
	}
	if h.synchronizer != nil {
		return h.synchronizer.Progress()
	}
	head := h.backend.CurrentBlock()
	return head.Number.Uint64(), head.Number.Uint64(), head.Number.Uint64(), false
}

// Protocol returns the P2P protocol descriptor
func (h *Handler) Protocol() p2p.Protocol {
	return p2p.Protocol{
		Name:    ProtocolName,
		Version: ProtocolVersion,
		Length:  ProtocolLength,
		Run:     h.runPeer,
		NodeInfo: func() interface{} {
			return h.NodeInfo()
		},
	}
}

// NodeInfo returns information about this node
func (h *Handler) NodeInfo() interface{} {
	head := h.backend.CurrentBlock()
	return map[string]interface{}{
		"network":    h.networkID,
		"genesis":    h.genesisHash.Hex(),
		"head":       head.Hash().Hex(),
		"headNumber": head.Number.Uint64(),
	}
}

// PeerInfo returns information about a peer
func (h *Handler) PeerInfo(id string) interface{} {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()
	if p, ok := h.peers[id]; ok {
		p.lock.RLock()
		defer p.lock.RUnlock()
		return map[string]interface{}{
			"version": p.version,
			"head":    p.head.Hex(),
			"number":  p.number,
		}
	}
	return nil
}

// runPeer handles a new peer connection
func (h *Handler) runPeer(p *p2p.Peer, rw p2p.MsgReadWriter) error {
	peer := &Peer{
		Peer:         p,
		rw:           rw,
		id:           p.ID().String(),
		knownBlocks:  newKnownCache(1024),
		knownTxs:     newKnownCache(4096),
		queuedBlocks: make(chan *obstypes.ObsidianBlock, 4),
		queuedTxs:    make(chan []*obstypes.StealthTransaction, 4),
		term:         make(chan struct{}),
		td:           big.NewInt(0),
	}

	// Perform handshake
	if err := h.handshake(peer); err != nil {
		log.Debug("Handshake failed", "peer", peer.id[:16], "err", err)
		return err
	}

	// Register peer
	if err := h.registerPeer(peer); err != nil {
		log.Debug("Peer registration failed", "peer", peer.id[:16], "err", err)
		return err
	}

	defer h.unregisterPeer(peer.id)

	// Start peer goroutines
	go h.broadcastLoop(peer)

	// Handle messages
	return h.handlePeer(peer)
}

// handshake performs the protocol handshake
func (h *Handler) handshake(p *Peer) error {
	// Get our status
	head := h.backend.CurrentBlock()
	td := h.backend.GetTD(head.Hash())
	if td == nil {
		td = big.NewInt(0)
	}

	ourStatus := StatusPacket{
		ProtocolVersion: ProtocolVersion,
		NetworkID:       h.networkID,
		TD:              td,
		HeadHash:        head.Hash(),
		HeadNumber:      head.Number.Uint64(),
		GenesisHash:     h.genesisHash,
	}

	// Send our status
	errc := make(chan error, 2)
	var peerStatus StatusPacket

	go func() {
		errc <- p2p.Send(p.rw, StatusMsg, &ourStatus)
	}()

	go func() {
		msg, err := p.rw.ReadMsg()
		if err != nil {
			errc <- err
			return
		}
		if msg.Code != StatusMsg {
			errc <- fmt.Errorf("expected status msg, got %d", msg.Code)
			return
		}
		if err := msg.Decode(&peerStatus); err != nil {
			errc <- fmt.Errorf("decode error: %v", err)
			return
		}
		errc <- nil
	}()

	// Wait for both operations
	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()

	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				return err
			}
		case <-timeout.C:
			return fmt.Errorf("handshake timeout")
		}
	}

	// Validate peer status
	if peerStatus.NetworkID != h.networkID {
		return fmt.Errorf("network mismatch: %d vs %d", peerStatus.NetworkID, h.networkID)
	}
	if peerStatus.GenesisHash != h.genesisHash {
		return fmt.Errorf("genesis mismatch: %s vs %s", peerStatus.GenesisHash.Hex()[:16], h.genesisHash.Hex()[:16])
	}

	// Update peer state
	p.version = peerStatus.ProtocolVersion
	p.head = peerStatus.HeadHash
	p.td = peerStatus.TD
	p.number = peerStatus.HeadNumber

	log.Info("Peer handshake completed",
		"peer", p.id[:16],
		"head", p.number,
		"td", p.td,
	)

	return nil
}

// registerPeer adds a peer to the handler
func (h *Handler) registerPeer(p *Peer) error {
	h.peersMu.Lock()
	defer h.peersMu.Unlock()

	if len(h.peers) >= h.maxPeers {
		return fmt.Errorf("too many peers (%d)", len(h.peers))
	}
	if _, exists := h.peers[p.id]; exists {
		return fmt.Errorf("peer already registered")
	}

	h.peers[p.id] = p
	atomic.AddInt32(&h.peerCount, 1)

	log.Info("Peer registered",
		"peer", p.id[:16],
		"name", p.Name(),
		"total", len(h.peers),
	)

	// Trigger sync if peer has higher TD
	if h.downloader != nil {
		go h.downloader.CheckAndSync()
	} else {
		go h.checkSync(p)
	}

	return nil
}

// unregisterPeer removes a peer from the handler
func (h *Handler) unregisterPeer(id string) {
	h.peersMu.Lock()
	defer h.peersMu.Unlock()

	if p, ok := h.peers[id]; ok {
		close(p.term)
		delete(h.peers, id)
		atomic.AddInt32(&h.peerCount, -1)
		log.Info("Peer unregistered", "peer", id[:16], "total", len(h.peers))
	}
}

// handlePeer handles messages from a peer
func (h *Handler) handlePeer(p *Peer) error {
	for {
		msg, err := p.rw.ReadMsg()
		if err != nil {
			return err
		}

		if msg.Size > 10*1024*1024 { // 10MB max message size
			return fmt.Errorf("message too large: %d", msg.Size)
		}

		switch msg.Code {
		case StatusMsg:
			// Already handled in handshake
			_ = msg.Discard()

		case NewBlockHashesMsg:
			if err := h.handleNewBlockHashes(p, msg); err != nil {
				return err
			}

		case TransactionsMsg:
			if err := h.handleTransactions(p, msg); err != nil {
				return err
			}

		case GetBlockHeadersMsg:
			if err := h.handleGetBlockHeaders(p, msg); err != nil {
				return err
			}

		case BlockHeadersMsg:
			if err := h.handleBlockHeaders(p, msg); err != nil {
				return err
			}

		case GetBlockBodiesMsg:
			if err := h.handleGetBlockBodies(p, msg); err != nil {
				return err
			}

		case BlockBodiesMsg:
			if err := h.handleBlockBodies(p, msg); err != nil {
				return err
			}

		case NewBlockMsg:
			if err := h.handleNewBlock(p, msg); err != nil {
				return err
			}

		case GetBlockByNumberMsg:
			if err := h.handleGetBlockByNumber(p, msg); err != nil {
				return err
			}

		case GetBlockByHashMsg:
			if err := h.handleGetBlockByHash(p, msg); err != nil {
				return err
			}

		case PingMsg:
			if err := p2p.Send(p.rw, PongMsg, nil); err != nil {
				return err
			}

		case PongMsg:
			// Ignore pong

		default:
			log.Debug("Unknown message", "code", msg.Code)
			_ = msg.Discard()
		}
	}
}

// handleNewBlockHashes handles new block hash announcements
func (h *Handler) handleNewBlockHashes(p *Peer, msg p2p.Msg) error {
	var announces NewBlockHashesPacket
	if err := msg.Decode(&announces); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	for _, announce := range announces {
		p.knownBlocks.Add(announce.Hash)

		if !h.backend.HasBlock(announce.Hash) {
			log.Debug("New block hash announced",
				"peer", p.id[:16],
				"number", announce.Number,
				"hash", announce.Hash.Hex()[:16],
			)
			// Request the block
			go h.requestBlock(p, announce.Hash)
		}
	}
	return nil
}

// handleTransactions handles incoming transactions
func (h *Handler) handleTransactions(p *Peer, msg p2p.Msg) error {
	var txs TransactionsPacket
	if err := msg.Decode(&txs); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	for _, tx := range txs {
		p.knownTxs.Add(tx.Hash())
	}

	errs := h.backend.AddRemoteTxs(txs)
	for i, err := range errs {
		if err != nil {
			log.Debug("Failed to add transaction", "hash", txs[i].Hash().Hex()[:16], "err", err)
		}
	}

	atomic.AddUint64(&h.txsReceived, uint64(len(txs)))
	log.Debug("Received transactions", "peer", p.id[:16], "count", len(txs))
	return nil
}

// handleGetBlockHeaders handles block header requests
func (h *Handler) handleGetBlockHeaders(p *Peer, msg p2p.Msg) error {
	var query GetBlockHeadersPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	headers := make(BlockHeadersPacket, 0, query.Amount)

	var origin uint64
	if query.Origin.Hash != (common.Hash{}) {
		block := h.backend.GetBlockByHash(query.Origin.Hash)
		if block != nil {
			origin = block.NumberU64()
		}
	} else {
		origin = query.Origin.Number
	}

	for i := uint64(0); i < query.Amount; i++ {
		var num uint64
		if query.Reverse {
			if origin < i*(query.Skip+1) {
				break
			}
			num = origin - i*(query.Skip+1)
		} else {
			num = origin + i*(query.Skip+1)
		}

		block := h.backend.GetBlockByNumber(num)
		if block == nil {
			break
		}
		headers = append(headers, block.Header())
	}

	return p2p.Send(p.rw, BlockHeadersMsg, headers)
}

// handleBlockHeaders handles block header responses
func (h *Handler) handleBlockHeaders(p *Peer, msg p2p.Msg) error {
	var headers BlockHeadersPacket
	if err := msg.Decode(&headers); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	log.Debug("Received block headers", "peer", p.id[:16], "count", len(headers))
	if h.downloader != nil {
		h.downloader.DeliverHeaders(p, headers)
	}
	return nil
}

// handleGetBlockBodies handles block body requests
func (h *Handler) handleGetBlockBodies(p *Peer, msg p2p.Msg) error {
	var hashes GetBlockBodiesPacket
	if err := msg.Decode(&hashes); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	bodies := make(BlockBodiesPacket, 0, len(hashes))
	for _, hash := range hashes {
		block := h.backend.GetBlockByHash(hash)
		if block != nil {
			bodies = append(bodies, BlockBody{
				Transactions: block.Transactions(),
				Uncles:       block.Uncles(),
			})
		}
	}

	return p2p.Send(p.rw, BlockBodiesMsg, bodies)
}

// handleBlockBodies handles block body responses
func (h *Handler) handleBlockBodies(p *Peer, msg p2p.Msg) error {
	var bodies BlockBodiesPacket
	if err := msg.Decode(&bodies); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	log.Debug("Received block bodies", "peer", p.id[:16], "count", len(bodies))
	if h.downloader != nil {
		h.downloader.DeliverBodies(p, bodies)
	}
	return nil
}

// handleNewBlock handles new block propagation
func (h *Handler) handleNewBlock(p *Peer, msg p2p.Msg) error {
	var packet NewBlockPacket
	if err := msg.Decode(&packet); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	block := packet.Block
	hash := block.Hash()

	p.knownBlocks.Add(hash)

	// Update peer's head
	p.lock.Lock()
	if packet.TD != nil && (p.td == nil || packet.TD.Cmp(p.td) > 0) {
		p.head = hash
		p.td = packet.TD
		p.number = block.NumberU64()
	}
	p.lock.Unlock()

	// Deliver to synchronizer if syncing
	if h.synchronizer != nil && h.synchronizer.Syncing() {
		h.synchronizer.DeliverBlock(block)
		atomic.AddUint64(&h.blocksReceived, 1)
		return nil
	}

	// Check if we already have this block
	if h.backend.HasBlock(hash) {
		log.Debug("Already have block", "number", block.NumberU64(), "hash", hash.Hex()[:16])
		return nil
	}

	log.Info("Received new block",
		"peer", p.id[:16],
		"number", block.NumberU64(),
		"hash", hash.Hex()[:16],
		"txs", len(block.Transactions()),
	)

	// Check if we have the parent block
	parentHash := block.ParentHash()
	if !h.backend.HasBlock(parentHash) {
		// Store in pending blocks (keyed by parent hash)
		h.pendingBlocksMu.Lock()
		h.pendingBlocks[parentHash] = block
		pendingCount := len(h.pendingBlocks)
		h.pendingBlocksMu.Unlock()

		// We're missing parent block(s), need to sync
		ourHead := h.backend.CurrentBlock()
		ourNum := ourHead.Number.Uint64()
		blockNum := block.NumberU64()

		log.Info("Missing parent block, stored in pending",
			"our_head", ourNum,
			"received_block", blockNum,
			"parent_hash", parentHash.Hex()[:16],
			"pending_count", pendingCount,
		)

		// Request missing blocks from peer (only if we're behind)
		if blockNum > ourNum+1 {
			go h.syncMissingBlocks(p, ourNum+1, blockNum-1)
		}
		return nil
	}

	// Insert block and process any pending children
	if err := h.insertBlockAndChildren(block); err != nil {
		log.Warn("Failed to insert received block", "err", err)
		return nil // Don't disconnect, just log
	}

	atomic.AddUint64(&h.blocksReceived, 1)

	// Propagate to other peers
	h.BroadcastBlock(block)

	return nil
}

// handleGetBlockByNumber handles block by number requests
func (h *Handler) handleGetBlockByNumber(p *Peer, msg p2p.Msg) error {
	var number uint64
	if err := msg.Decode(&number); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	block := h.backend.GetBlockByNumber(number)
	if block == nil {
		return nil
	}

	td := h.backend.GetTD(block.Hash())
	if td == nil {
		td = big.NewInt(0)
	}

	return p2p.Send(p.rw, NewBlockMsg, &NewBlockPacket{Block: block, TD: td})
}

// handleGetBlockByHash handles block by hash requests
func (h *Handler) handleGetBlockByHash(p *Peer, msg p2p.Msg) error {
	var hash common.Hash
	if err := msg.Decode(&hash); err != nil {
		return fmt.Errorf("decode error: %v", err)
	}

	block := h.backend.GetBlockByHash(hash)
	if block == nil {
		return nil
	}

	td := h.backend.GetTD(block.Hash())
	if td == nil {
		td = big.NewInt(0)
	}

	return p2p.Send(p.rw, NewBlockMsg, &NewBlockPacket{Block: block, TD: td})
}

// requestBlock requests a block from a peer
func (h *Handler) requestBlock(p *Peer, hash common.Hash) {
	if err := p2p.Send(p.rw, GetBlockByHashMsg, hash); err != nil {
		log.Debug("Failed to request block", "peer", p.id[:16], "err", err)
	}
}

// broadcastLoop broadcasts blocks and transactions to a peer
func (h *Handler) broadcastLoop(p *Peer) {
	for {
		select {
		case block := <-p.queuedBlocks:
			if err := h.sendNewBlock(p, block); err != nil {
				log.Debug("Failed to send block", "peer", p.id[:16], "err", err)
				return
			}

		case txs := <-p.queuedTxs:
			if err := h.sendTransactions(p, txs); err != nil {
				log.Debug("Failed to send transactions", "peer", p.id[:16], "err", err)
				return
			}

		case <-p.term:
			return
		}
	}
}

// sendNewBlock sends a new block to a peer
func (h *Handler) sendNewBlock(p *Peer, block *obstypes.ObsidianBlock) error {
	td := h.backend.GetTD(block.Hash())
	if td == nil {
		td = block.Difficulty()
	}

	p.knownBlocks.Add(block.Hash())
	atomic.AddUint64(&h.blocksSent, 1)

	return p2p.Send(p.rw, NewBlockMsg, &NewBlockPacket{Block: block, TD: td})
}

// sendTransactions sends transactions to a peer
func (h *Handler) sendTransactions(p *Peer, txs []*obstypes.StealthTransaction) error {
	for _, tx := range txs {
		p.knownTxs.Add(tx.Hash())
	}
	atomic.AddUint64(&h.txsSent, uint64(len(txs)))
	return p2p.Send(p.rw, TransactionsMsg, TransactionsPacket(txs))
}

// BroadcastBlock sends a block to all connected peers
func (h *Handler) BroadcastBlock(block *obstypes.ObsidianBlock) {
	hash := block.Hash()
	totalPeers := h.PeerCount()

	h.peersMu.RLock()
	peers := make([]*Peer, 0, len(h.peers))
	for _, p := range h.peers {
		if !p.knownBlocks.Has(hash) {
			peers = append(peers, p)
		}
	}
	h.peersMu.RUnlock()

	if totalPeers == 0 {
		log.Debug("No peers connected, skipping broadcast",
			"number", block.NumberU64(),
			"hash", hash.Hex()[:16],
		)
		return
	}

	if len(peers) == 0 {
		log.Debug("All peers already know this block",
			"number", block.NumberU64(),
			"hash", hash.Hex()[:16],
			"total_peers", totalPeers,
		)
		return
	}

	// Broadcast to all peers that don't know this block
	var sent int
	for _, p := range peers {
		// Send directly instead of queuing for immediate delivery
		go func(peer *Peer) {
			if err := h.sendNewBlock(peer, block); err != nil {
				log.Debug("Failed to broadcast block to peer",
					"peer", peer.id[:16],
					"block", block.NumberU64(),
					"err", err,
				)
			}
		}(p)
		sent++
	}

	log.Info("Block broadcast initiated",
		"number", block.NumberU64(),
		"hash", hash.Hex()[:16],
		"peers", sent,
		"total_peers", totalPeers,
	)
}

// BroadcastTxs sends transactions to all connected peers
func (h *Handler) BroadcastTxs(txs []*obstypes.StealthTransaction) {
	if len(txs) == 0 {
		return
	}

	h.peersMu.RLock()
	defer h.peersMu.RUnlock()

	for _, p := range h.peers {
		// Filter out known transactions
		unknown := make([]*obstypes.StealthTransaction, 0, len(txs))
		for _, tx := range txs {
			if !p.knownTxs.Has(tx.Hash()) {
				unknown = append(unknown, tx)
			}
		}

		if len(unknown) > 0 {
			select {
			case p.queuedTxs <- unknown:
			default:
				log.Debug("Dropping tx broadcast", "peer", p.id[:16])
			}
		}
	}
}

// checkSync checks if we need to sync with a peer
func (h *Handler) checkSync(p *Peer) {
	// Use the synchronizer if available
	if h.synchronizer != nil {
		// Synchronizer handles its own sync checks
		return
	}

	// Fallback: basic sync logic
	if !atomic.CompareAndSwapInt32(&h.syncing, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&h.syncing, 0)

	head := h.backend.CurrentBlock()
	ourTD := h.backend.GetTD(head.Hash())
	if ourTD == nil {
		ourTD = big.NewInt(0)
	}

	p.lock.RLock()
	peerTD := p.td
	peerNum := p.number
	p.lock.RUnlock()

	if peerTD == nil || peerTD.Cmp(ourTD) <= 0 {
		return
	}

	log.Info("Starting sync with peer",
		"peer", p.id[:16],
		"ourHead", head.Number.Uint64(),
		"peerHead", peerNum,
	)

	// Request blocks we're missing
	for num := head.Number.Uint64() + 1; num <= peerNum; num++ {
		if err := p2p.Send(p.rw, GetBlockByNumberMsg, num); err != nil {
			log.Error("Failed to request block", "number", num, "err", err)
			break
		}
		time.Sleep(100 * time.Millisecond) // Rate limit
	}
}

// syncMissingBlocks requests missing blocks from a peer to fill gaps in our chain
func (h *Handler) syncMissingBlocks(p *Peer, fromNum, toNum uint64) {
	// Use synchronizer if available
	if h.synchronizer != nil {
		log.Info("Triggering synchronizer for missing blocks",
			"peer", p.id[:16],
			"from", fromNum,
			"to", toNum,
		)
		_ = h.synchronizer.Start()
		return
	}

	// Fallback: request blocks directly
	log.Info("Requesting missing blocks",
		"peer", p.id[:16],
		"from", fromNum,
		"to", toNum,
	)

	for num := fromNum; num <= toNum; num++ {
		if err := p2p.Send(p.rw, GetBlockByNumberMsg, num); err != nil {
			log.Error("Failed to request block", "number", num, "err", err)
			return
		}
		// Wait a bit for response before requesting next
		time.Sleep(50 * time.Millisecond)
	}
}

// insertBlockAndChildren inserts a block and any pending child blocks
func (h *Handler) insertBlockAndChildren(block *obstypes.ObsidianBlock) error {
	// Insert the block
	if err := h.backend.InsertBlock(block); err != nil {
		return err
	}

	log.Info("Block inserted successfully",
		"number", block.NumberU64(),
		"hash", block.Hash().Hex()[:16],
	)

	// Check if any pending blocks are waiting for this block as parent
	blockHash := block.Hash()
	for {
		h.pendingBlocksMu.Lock()
		child, exists := h.pendingBlocks[blockHash]
		if exists {
			delete(h.pendingBlocks, blockHash)
		}
		h.pendingBlocksMu.Unlock()

		if !exists {
			break
		}

		// Insert the child block
		if err := h.backend.InsertBlock(child); err != nil {
			log.Warn("Failed to insert pending child block",
				"number", child.NumberU64(),
				"hash", child.Hash().Hex()[:16],
				"err", err,
			)
			break
		}

		log.Info("Pending block inserted",
			"number", child.NumberU64(),
			"hash", child.Hash().Hex()[:16],
		)

		atomic.AddUint64(&h.blocksReceived, 1)

		// Broadcast the child block too
		h.BroadcastBlock(child)

		// Continue with the next child
		blockHash = child.Hash()
	}

	return nil
}

// PeerCount returns the number of connected peers
func (h *Handler) PeerCount() int {
	return int(atomic.LoadInt32(&h.peerCount))
}

// Peers returns all connected peers
func (h *Handler) Peers() []*Peer {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()

	peers := make([]*Peer, 0, len(h.peers))
	for _, p := range h.peers {
		peers = append(peers, p)
	}
	return peers
}

// Stats returns P2P statistics
func (h *Handler) Stats() map[string]interface{} {
	return map[string]interface{}{
		"peers":          h.PeerCount(),
		"blocksReceived": atomic.LoadUint64(&h.blocksReceived),
		"blocksSent":     atomic.LoadUint64(&h.blocksSent),
		"txsReceived":    atomic.LoadUint64(&h.txsReceived),
		"txsSent":        atomic.LoadUint64(&h.txsSent),
	}
}

// Stop stops the handler
func (h *Handler) Stop() {
	close(h.quitCh)

	h.peersMu.Lock()
	for _, p := range h.peers {
		p.Disconnect(p2p.DiscQuitting)
	}
	h.peersMu.Unlock()
}

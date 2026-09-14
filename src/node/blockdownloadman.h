// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_H

#include <blockencodings.h>
#include <kernel/cs_main.h>
#include <net.h>
#include <uint256.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

class CBlockIndex;
class ChainstateManager;
class CTxMemPool;

namespace node {
class BlockDownloadManagerImpl;

/** Default time during which a peer must stall block download progress before being disconnected.
 * The actual timeout is increased temporarily if peers are disconnected for hitting the timeout */
inline constexpr auto BLOCK_STALLING_TIMEOUT_DEFAULT{2s};
/** Maximum timeout for stalling block download. */
inline constexpr auto BLOCK_STALLING_TIMEOUT_MAX{64s};
/** Number of blocks that can be requested at any given time from a single peer. */
inline constexpr int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and pruning harder). We'll probably
 *  want to make this a per-peer adaptive value at some point. */
inline constexpr unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Minimum blocks required to signal NODE_NETWORK_LIMITED */
inline constexpr unsigned int NODE_NETWORK_LIMITED_MIN_BLOCKS = 288;
/** Maximum number of outstanding CMPCTBLOCK requests for the same block. */
inline constexpr unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;

struct BlockDownloadOptions {
    /** Reference to ChainstateManager for chain state access and LookupBlockIndex. */
    ChainstateManager& m_chainman;
};

/** Peer capabilities read by the caller when scheduling downloads. */
struct BlockDownloadPeerInfo {
    bool m_can_serve_witnesses;
    bool m_is_limited_peer;
};

/**
 * Class responsible for tracking block download state: which blocks are
 * in-flight, which peers are downloading from, request scheduling, stalling
 * detection, and source tracking.
 *
 * Chain-dependent operations require the caller to hold cs_main. They do not
 * acquire it or invoke caller-supplied callbacks. The atomic tip-update and
 * stalling-timeout accessors may be used without cs_main.
 *
 * Connection preferences remain in PeerManager. Peer capabilities are passed
 * to scheduling calls, so feature negotiation does not require cs_main.
 * No references or pointers into the manager's mutable state are exposed.
 */
class BlockDownloadManager {
    const std::unique_ptr<BlockDownloadManagerImpl> m_impl;

public:
    explicit BlockDownloadManager(const BlockDownloadOptions& options);
    ~BlockDownloadManager();

    /** Register a new peer for block download tracking. The peer must not already be registered. */
    void ConnectedPeer(NodeId nodeid, bool is_inbound) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Clean up all block download state for a disconnected peer. */
    void DisconnectedPeer(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Have we requested this block from any peer? */
    bool IsBlockRequested(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Have we requested this block from an outbound peer? */
    bool IsBlockRequestedFromOutbound(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Remove this block from our tracked requested blocks.
     *  If from_peer is specified, only remove the block if it is in flight from that peer. */
    void RemoveBlockRequest(const uint256& hash, std::optional<NodeId> from_peer) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Mark a block as in flight. Returns false if already requested from this peer. */
    bool BlockRequested(NodeId nodeid, const CBlockIndex& block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Check whether the tip might be stale based on last update time and in-flight state.
     *  nPowTargetSpacing is used to determine the staleness threshold. */
    bool TipMayBeStale(std::chrono::seconds now, int64_t n_pow_target_spacing) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Record that the tip was updated. */
    void SetLastTipUpdate(std::chrono::seconds time);

    /** Get the last tip update time. */
    std::chrono::seconds GetLastTipUpdate() const;

    /** Check whether the last unknown block a peer advertised is not yet known. */
    void ProcessBlockAvailability(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Update tracking information about which blocks a peer is assumed to have. */
    void UpdateBlockAvailability(NodeId nodeid, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Calculate which blocks to download from a given peer, given our current tip.
     *  Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks.
     *  Sets nodeStaller to a stalling peer NodeId if applicable, or -1. */
    void FindNextBlocksToDownload(NodeId nodeid, const BlockDownloadPeerInfo& info, unsigned int count,
                                  std::vector<const CBlockIndex*>& vBlocks,
                                  NodeId& nodeStaller) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Request blocks for the background chainstate, if one is in use. */
    void TryDownloadingHistoricalBlocks(NodeId nodeid, const BlockDownloadPeerInfo& info, unsigned int count,
                                        std::vector<const CBlockIndex*>& vBlocks,
                                        const CBlockIndex* from_tip,
                                        const CBlockIndex* target_block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the best known block for a peer (or nullptr). */
    const CBlockIndex* GetBestKnownBlock(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the best header we have sent a peer (or nullptr). */
    const CBlockIndex* GetBestHeaderSent(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Set the best header we have sent a peer. */
    void SetBestHeaderSent(NodeId nodeid, const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the last common block with a peer (or nullptr). */
    const CBlockIndex* GetLastCommonBlock(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get whether we have started syncing headers with this peer. */
    bool GetSyncStarted(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Mark that we've started syncing headers with this peer, incrementing the global counter. */
    void SetSyncStarted(NodeId nodeid, bool started) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the global number of peers with sync started. */
    int GetNumSyncStarted() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the stalling timeout for blocks. */
    std::chrono::seconds GetBlockStallingTimeout() const;

    /** Atomically compare-and-exchange the stalling timeout.
     *  Returns true on success (value was expected, now set to desired). */
    bool CompareExchangeBlockStallingTimeout(std::chrono::seconds& expected, std::chrono::seconds desired);

    /** Get the number of peers we are downloading blocks from. */
    int GetPeersDownloadingFrom() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Whether blocks are in flight from any peer. */
    bool HasBlocksInFlight() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get total number of blocks in flight (across all hashes and peers). */
    size_t GetTotalBlocksInFlight() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the number of outstanding block requests from a peer. */
    size_t GetNumBlocksInFlight(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Snapshot the heights of a peer's outstanding block requests, in request order. */
    std::vector<int> GetRequestedBlockHeights(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Return the first outstanding block hash, if any. */
    std::optional<uint256> GetFirstBlockInFlight(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the downloading-since time for a peer. */
    std::chrono::microseconds GetDownloadingSince(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the stalling-since time for a peer. */
    std::chrono::microseconds GetStallingSince(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Set the stalling-since time for a peer. */
    void SetStallingSince(NodeId nodeid, std::chrono::microseconds time) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Pause scheduling from a peer until the given time, as used for manual peers. */
    void PauseDownload(NodeId nodeid, std::chrono::microseconds until) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    std::chrono::microseconds GetDownloadPausedUntil(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get block source information for a given block hash. */
    std::optional<std::pair<NodeId, bool>> GetBlockSource(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Record the source of a received block. */
    void SetBlockSource(const uint256& hash, NodeId nodeid, bool punish_on_invalid) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Remove a block source entry. */
    void EraseBlockSource(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the count of blocks in flight matching a hash. */
    size_t CountBlocksInFlight(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Check that peer and request tracking is empty after all peers disconnect.
     *  Block sources may remain until asynchronous validation completes. */
    void CheckIsEmpty() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Check whether a peer has a particular header. */
    bool PeerHasHeader(NodeId nodeid, const CBlockIndex* pindex) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Result of looking up in-flight block information. */
    struct BlockInFlightInfo {
        /** How many peers have this block in flight. */
        size_t already_in_flight{0};
        /** Whether the first entry (if any) is from the specified peer. */
        bool first_in_flight{false};
        /** Whether the specified peer has this block in flight. */
        bool requested_from_peer{false};
        bool has_partial_block{false};
        /** A previous reconstruction attempt consumed the partial block's header. */
        bool partial_block_failed{false};
    };

    /** Find detailed in-flight information for a block hash + specific peer. */
    BlockInFlightInfo FindBlockInFlight(const uint256& hash, NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    struct CompactBlockResult {
        ReadStatus status;
        std::vector<uint16_t> missing_transactions;
    };

    /** Track and initialize a compact block, returning nullopt for a duplicate announcement.
     *  Leaves the request in flight on failure; the caller decides whether to retry or remove it. */
    std::optional<CompactBlockResult> InitCompactBlock(NodeId nodeid, const CBlockIndex& block,
        const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<Wtxid, CTransactionRef>>& extra_txns,
        CTxMemPool& mempool) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Reconstruct a requested compact block. Requires an initialized, unconsumed partial block. */
    ReadStatus FillBlock(NodeId nodeid, const BlockTransactions& transactions, CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};
} // namespace node
#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_H

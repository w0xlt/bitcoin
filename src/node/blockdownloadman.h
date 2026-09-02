// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_H

#include <arith_uint256.h>
#include <net.h>
#include <uint256.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

class PartiallyDownloadedBlock;

namespace node {
class BlockDownloadManagerImpl;

/** Maximum number of parallel requests for one block. Parallel requests are
 * used by compact-block download. */
static constexpr size_t MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK{3};
/** Default time before a peer stalling block download is disconnected. */
static constexpr std::chrono::seconds DEFAULT_BLOCK_STALLING_TIMEOUT{2};

/** Validation-derived identity copied before crossing into request tracking. */
struct BlockDownloadBlock {
    uint256 m_hash;
    int m_height;
    arith_uint256 m_chain_work;

    friend bool operator==(const BlockDownloadBlock&, const BlockDownloadBlock&) = default;
};

/** Connection properties needed to maintain request invariants. */
struct BlockDownloadConnectionInfo {
    const bool m_is_inbound;
    bool m_preferred_download{false};
    bool m_can_serve_witness{false};
    bool m_limited_peer{false};
};

enum class BlockRequestStatus {
    NEW,
    ALREADY_REQUESTED,
    UPGRADED_TO_COMPACT,
    DUPLICATE_COMPACT,
    PEER_NOT_FOUND,
    MAX_REQUESTS_REACHED,
};

/** Result of atomically reserving an externally selected block request. */
struct BlockRequestReservation {
    BlockRequestStatus m_status;
    /** Number of requests for this hash immediately before the operation. */
    size_t m_requests_before;
    /** Whether this peer's request was (or would be) first for this hash. */
    bool m_first_in_flight;
    /** Resulting compact reconstruction state, if any.
     *
     * This shared pointer only extends object lifetime. It does not synchronize
     * PartiallyDownloadedBlock mutation; callers must retain single-user
     * mutation semantics.
     */
    std::shared_ptr<PartiallyDownloadedBlock> m_partial_block;
};

/** Result of atomically inspecting and removing matching requests. */
struct BlockRequestRemoval {
    size_t m_requests_before{0};
    size_t m_removed{0};
};

/** Owned information about requests for a hash, relative to one peer. */
struct BlockInFlightInfo {
    size_t m_request_count{0};
    std::optional<NodeId> m_first_peer;
    bool m_requested_from_peer{false};
    bool m_first_in_flight{true};
    /** Copied lifetime ownership; does not authorize concurrent mutation. */
    std::shared_ptr<PartiallyDownloadedBlock> m_partial_block;
};

/** Owned copy of one peer's block-download bookkeeping. */
struct PeerBlockDownloadSnapshot {
    std::vector<BlockDownloadBlock> m_blocks;
    std::chrono::microseconds m_downloading_since{0};
    std::chrono::microseconds m_stalling_since{0};
    bool m_is_inbound{false};
    bool m_preferred_download{false};
    bool m_can_serve_witness{false};
    bool m_limited_peer{false};
    bool m_sync_started{false};
    uint64_t m_generation{0};
    /** Global values copied under the same lock as this peer's state. */
    size_t m_total_requests{0};
    int m_peers_downloading_from{0};
    int m_num_preferred_download_peers{0};
    int m_num_sync_started{0};
};

/**
 * Owned copy of global block-download bookkeeping. All fields are copied at
 * the same manager-mutex linearization point.
 */
struct BlockDownloadGlobalSnapshot {
    size_t m_total_requests{0};
    int m_peers_downloading_from{0};
    int m_num_preferred_download_peers{0};
    int m_num_sync_started{0};
    uint64_t m_in_flight_generation{0};
    std::chrono::seconds m_last_tip_update{0};
    std::chrono::seconds m_block_stalling_timeout{DEFAULT_BLOCK_STALLING_TIMEOUT};
};

/** Owned block source attribution. */
struct BlockSource {
    NodeId m_peer;
    bool m_punish_on_invalid;

    friend bool operator==(const BlockSource&, const BlockSource&) = default;
};

/**
 * Internally synchronized owner of chain-independent block-download bookkeeping.
 *
 * The manager owns peer connection capabilities, request queues, source
 * attribution, compact reconstruction lifetime, counters, and timers. It
 * deliberately has no chain, validation, mempool, availability, or scheduling
 * dependency.
 */
class BlockDownloadManager {
    const std::unique_ptr<BlockDownloadManagerImpl> m_impl;

public:
    BlockDownloadManager();
    ~BlockDownloadManager();

    BlockDownloadManager(const BlockDownloadManager&) = delete;
    BlockDownloadManager& operator=(const BlockDownloadManager&) = delete;

    /** Register or atomically update a peer without resetting its active state. */
    void ConnectedPeer(NodeId peer, const BlockDownloadConnectionInfo& info);
    /** Remove a peer and all bookkeeping owned by it. */
    void DisconnectedPeer(NodeId peer);

    /**
     * Atomically reserve a request. A non-null proposed_partial requests
     * compact reconstruction or upgrades an existing full-block request.
     */
    BlockRequestReservation ReserveBlockRequest(
        NodeId peer,
        const BlockDownloadBlock& block,
        std::chrono::microseconds now,
        std::shared_ptr<PartiallyDownloadedBlock> proposed_partial = {});

    /** Remove requests for hash, optionally restricted to one peer. */
    BlockRequestRemoval RemoveBlockRequest(
        const uint256& hash,
        std::optional<NodeId> from_peer,
        std::chrono::microseconds now);

    bool IsBlockRequested(const uint256& hash) const;
    bool IsBlockRequestedFromOutbound(const uint256& hash) const;
    BlockInFlightInfo GetBlockInFlightInfo(const uint256& hash, NodeId peer) const;
    std::optional<PeerBlockDownloadSnapshot> GetPeerSnapshot(NodeId peer) const;
    BlockDownloadGlobalSnapshot GetGlobalSnapshot() const;

    /** Match the historical count(hash) == total-request-count query atomically. */
    bool AllRequestsAreFor(const uint256& hash) const;

    /** Start stalling only if the peer is not already marked as stalling. */
    bool StartStalling(NodeId peer, std::chrono::microseconds since);
    /** Clear a peer's stalling timer, returning whether it was set. */
    bool ClearStalling(NodeId peer);

    /** Start headers synchronization, keeping the peer flag and count together. */
    bool StartSync(NodeId peer);
    /** Stop headers synchronization, keeping the peer flag and count together. */
    bool ClearSync(NodeId peer);

    /** Record the first connected source for a block hash. */
    bool RecordBlockSource(const uint256& hash, NodeId peer, bool punish_on_invalid);
    std::optional<BlockSource> ConsumeBlockSource(const uint256& hash);
    bool EraseBlockSource(const uint256& hash);

    /** Initialize if needed and query the independent stale-tip state. */
    bool TipMayBeStale(std::chrono::seconds now, std::chrono::seconds stale_after);
    void UpdatedBlockTip(std::chrono::seconds now);
    /** Increase the timeout once if it still equals expected. */
    std::optional<std::chrono::seconds> TryIncreaseBlockStallingTimeout(std::chrono::seconds expected);
    /** Decrease the timeout once if it still equals expected. */
    std::optional<std::chrono::seconds> TryDecreaseBlockStallingTimeout(std::chrono::seconds expected);

    /** Test/debug consistency checks that expose no container identity. */
    bool CheckConsistency() const;
    void CheckIsEmpty() const;
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_H

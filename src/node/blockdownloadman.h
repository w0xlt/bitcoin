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
#include <memory>
#include <optional>
#include <vector>

class PartiallyDownloadedBlock;

namespace node {
class BlockDownloadManagerImpl;

/** Maximum number of parallel requests for one block. Parallel requests are
 * used by compact-block download. */
static constexpr size_t MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK{3};

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

/** Owned copy of one peer's request queue and queue-coupled timing state. */
struct PeerBlockRequestInfo {
    std::vector<BlockDownloadBlock> m_blocks;
    std::chrono::microseconds m_downloading_since{0};
    std::chrono::microseconds m_stalling_since{0};
    /** Global count copied under the same lock as this peer's queue. */
    int m_peers_downloading_from{0};
};

/** Owned summary of global request state. */
struct BlockRequestSummary {
    size_t m_total_requests{0};
    int m_peers_downloading_from{0};
};

/**
 * Internally synchronized owner of the block request/in-flight lifecycle.
 *
 * The manager owns peer request queues, the global hash index, compact
 * reconstruction lifetime, and queue-coupled timers. It deliberately has no
 * chain, validation, mempool, availability, or scheduling dependency.
 */
class BlockDownloadManager {
    const std::unique_ptr<BlockDownloadManagerImpl> m_impl;

public:
    BlockDownloadManager();
    ~BlockDownloadManager();

    BlockDownloadManager(const BlockDownloadManager&) = delete;
    BlockDownloadManager& operator=(const BlockDownloadManager&) = delete;

    /** Register a peer. Re-registering the same connection is idempotent. */
    void ConnectedPeer(NodeId peer, const BlockDownloadConnectionInfo& info);
    /** Remove a peer and all requests owned by it. */
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
    std::optional<PeerBlockRequestInfo> GetPeerRequestInfo(NodeId peer) const;
    BlockRequestSummary GetRequestSummary() const;

    /** Match the historical count(hash) == total-request-count query atomically. */
    bool AllRequestsAreFor(const uint256& hash) const;

    /** Start stalling only if the peer is not already marked as stalling. */
    bool StartStalling(NodeId peer, std::chrono::microseconds since);
    /** Clear a peer's stalling timer, returning whether it was set. */
    bool ClearStalling(NodeId peer);

    /** Test/debug consistency checks that expose no container identity. */
    bool CheckConsistency() const;
    void CheckIsEmpty() const;
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_H

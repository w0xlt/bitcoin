// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H

#include <node/blockdownloadman.h>

#include <sync.h>

#include <chrono>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <optional>

namespace node {

class BlockDownloadManagerImpl {
private:
    /**
     * Lock order: callers may enter the manager while holding cs_main. Code
     * holding m_mutex must not acquire cs_main, mempool or peer locks, log,
     * invoke callbacks/providers, or send messages.
     */
    mutable Mutex m_mutex;

    struct QueuedBlock {
        BlockDownloadBlock m_block;
        std::shared_ptr<PartiallyDownloadedBlock> m_partial_block;
    };

    struct PeerRequestState {
        BlockDownloadConnectionInfo m_connection_info;
        std::list<QueuedBlock> m_requests;
        std::chrono::microseconds m_downloading_since{0};
        std::chrono::microseconds m_stalling_since{0};
        bool m_sync_started{false};
        uint64_t m_generation{0};

        PeerRequestState(const BlockDownloadConnectionInfo& info, uint64_t generation)
            : m_connection_info{info}, m_generation{generation}
        {
        }
    };

    using QueueIterator = std::list<QueuedBlock>::iterator;
    struct IndexedRequest {
        NodeId m_peer;
        QueueIterator m_queue_it;
    };
    using RequestIndex = std::multimap<uint256, IndexedRequest>;

    /** Per-peer queues and their coupled timers. */
    std::map<NodeId, PeerRequestState> m_peer_states GUARDED_BY(m_mutex);
    /** Hash index into m_peer_states queues. Equivalent keys retain insertion order. */
    RequestIndex m_requests_by_hash GUARDED_BY(m_mutex);
    /** Number of peers whose request queue is non-empty. */
    int m_peers_downloading_from GUARDED_BY(m_mutex){0};
    /** Number of peers selected as preferred download peers. */
    int m_num_preferred_download_peers GUARDED_BY(m_mutex){0};
    /** Number of peers with headers synchronization started. */
    int m_num_sync_started GUARDED_BY(m_mutex){0};
    /** First-writer block source attribution. */
    std::map<uint256, BlockSource> m_block_sources GUARDED_BY(m_mutex);
    /** Monotonic source for unique peer-state generations. */
    uint64_t m_next_peer_generation GUARDED_BY(m_mutex){0};
    /** Monotonic generation for the global in-flight request set. */
    uint64_t m_in_flight_generation GUARDED_BY(m_mutex){0};

    /** Timing state included in the manager's coherent global snapshots. */
    std::chrono::seconds m_last_tip_update GUARDED_BY(m_mutex){0};
    std::chrono::seconds m_block_stalling_timeout GUARDED_BY(m_mutex){DEFAULT_BLOCK_STALLING_TIMEOUT};

    BlockInFlightInfo GetBlockInFlightInfoLocked(const uint256& hash, NodeId peer) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void BumpPeerGenerationLocked(PeerRequestState& state) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool CheckConsistencyLocked() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    BlockDownloadManagerImpl() = default;

    void ConnectedPeer(NodeId peer, const BlockDownloadConnectionInfo& info) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void DisconnectedPeer(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    BlockRequestReservation ReserveBlockRequest(
        NodeId peer,
        const BlockDownloadBlock& block,
        std::chrono::microseconds now,
        std::shared_ptr<PartiallyDownloadedBlock> proposed_partial) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    BlockRequestRemoval RemoveBlockRequest(
        const uint256& hash,
        std::optional<NodeId> from_peer,
        std::chrono::microseconds now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool IsBlockRequested(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool IsBlockRequestedFromOutbound(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    BlockInFlightInfo GetBlockInFlightInfo(const uint256& hash, NodeId peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::optional<PeerBlockDownloadSnapshot> GetPeerSnapshot(NodeId peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    BlockDownloadGlobalSnapshot GetGlobalSnapshot() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool AllRequestsAreFor(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool StartStalling(NodeId peer, std::chrono::microseconds since) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool ClearStalling(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool StartSync(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool ClearSync(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool RecordBlockSource(const uint256& hash, NodeId peer, bool punish_on_invalid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::optional<BlockSource> ConsumeBlockSource(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool EraseBlockSource(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool TipMayBeStale(std::chrono::seconds now, std::chrono::seconds stale_after) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void UpdatedBlockTip(std::chrono::seconds now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::optional<std::chrono::seconds> TryIncreaseBlockStallingTimeout(std::chrono::seconds expected) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::optional<std::chrono::seconds> TryDecreaseBlockStallingTimeout(std::chrono::seconds expected) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool CheckConsistency() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void CheckIsEmpty() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H

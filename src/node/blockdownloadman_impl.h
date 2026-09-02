// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H

#include <node/blockdownloadman.h>

#include <sync.h>

#include <chrono>
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

        explicit PeerRequestState(const BlockDownloadConnectionInfo& info)
            : m_connection_info{info}
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

    BlockInFlightInfo GetBlockInFlightInfoLocked(const uint256& hash, NodeId peer) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
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
    std::optional<PeerBlockRequestInfo> GetPeerRequestInfo(NodeId peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    BlockRequestSummary GetRequestSummary() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool AllRequestsAreFor(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool StartStalling(NodeId peer, std::chrono::microseconds since) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool ClearStalling(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool CheckConsistency() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void CheckIsEmpty() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H

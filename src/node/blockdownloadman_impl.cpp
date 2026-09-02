// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/blockdownloadman_impl.h>

#include <util/check.h>

#include <algorithm>
#include <iterator>
#include <set>
#include <utility>

namespace node {

BlockDownloadManager::BlockDownloadManager()
    : m_impl{std::make_unique<BlockDownloadManagerImpl>()}
{
}

BlockDownloadManager::~BlockDownloadManager() = default;

void BlockDownloadManager::ConnectedPeer(NodeId peer, const BlockDownloadConnectionInfo& info)
{
    m_impl->ConnectedPeer(peer, info);
}

void BlockDownloadManager::DisconnectedPeer(NodeId peer)
{
    m_impl->DisconnectedPeer(peer);
}

BlockRequestReservation BlockDownloadManager::ReserveBlockRequest(
    NodeId peer,
    const BlockDownloadBlock& block,
    std::chrono::microseconds now,
    std::shared_ptr<PartiallyDownloadedBlock> proposed_partial)
{
    return m_impl->ReserveBlockRequest(peer, block, now, std::move(proposed_partial));
}

BlockRequestRemoval BlockDownloadManager::RemoveBlockRequest(
    const uint256& hash,
    std::optional<NodeId> from_peer,
    std::chrono::microseconds now)
{
    return m_impl->RemoveBlockRequest(hash, from_peer, now);
}

bool BlockDownloadManager::IsBlockRequested(const uint256& hash) const
{
    return m_impl->IsBlockRequested(hash);
}

bool BlockDownloadManager::IsBlockRequestedFromOutbound(const uint256& hash) const
{
    return m_impl->IsBlockRequestedFromOutbound(hash);
}

BlockInFlightInfo BlockDownloadManager::GetBlockInFlightInfo(const uint256& hash, NodeId peer) const
{
    return m_impl->GetBlockInFlightInfo(hash, peer);
}

std::optional<PeerBlockRequestInfo> BlockDownloadManager::GetPeerRequestInfo(NodeId peer) const
{
    return m_impl->GetPeerRequestInfo(peer);
}

BlockRequestSummary BlockDownloadManager::GetRequestSummary() const
{
    return m_impl->GetRequestSummary();
}

bool BlockDownloadManager::AllRequestsAreFor(const uint256& hash) const
{
    return m_impl->AllRequestsAreFor(hash);
}

bool BlockDownloadManager::StartStalling(NodeId peer, std::chrono::microseconds since)
{
    return m_impl->StartStalling(peer, since);
}

bool BlockDownloadManager::ClearStalling(NodeId peer)
{
    return m_impl->ClearStalling(peer);
}

bool BlockDownloadManager::CheckConsistency() const
{
    return m_impl->CheckConsistency();
}

void BlockDownloadManager::CheckIsEmpty() const
{
    m_impl->CheckIsEmpty();
}

void BlockDownloadManagerImpl::ConnectedPeer(NodeId peer, const BlockDownloadConnectionInfo& info)
{
    LOCK(m_mutex);
    auto [it, inserted]{m_peer_states.try_emplace(peer, info)};
    if (!inserted) Assume(it->second.m_connection_info.m_is_inbound == info.m_is_inbound);
}

void BlockDownloadManagerImpl::DisconnectedPeer(NodeId peer)
{
    LOCK(m_mutex);
    const auto peer_it{m_peer_states.find(peer)};
    if (peer_it == m_peer_states.end()) return;

    auto& state{peer_it->second};
    for (auto queue_it{state.m_requests.begin()}; queue_it != state.m_requests.end(); ++queue_it) {
        auto range{m_requests_by_hash.equal_range(queue_it->m_block.m_hash)};
        for (auto index_it{range.first}; index_it != range.second;) {
            if (index_it->second.m_peer == peer) {
                index_it = m_requests_by_hash.erase(index_it);
            } else {
                ++index_it;
            }
        }
    }
    if (!state.m_requests.empty()) {
        --m_peers_downloading_from;
        Assume(m_peers_downloading_from >= 0);
    }
    m_peer_states.erase(peer_it);
}

BlockInFlightInfo BlockDownloadManagerImpl::GetBlockInFlightInfoLocked(const uint256& hash, NodeId peer) const
{
    BlockInFlightInfo result;
    const auto range{m_requests_by_hash.equal_range(hash)};
    result.m_request_count = std::distance(range.first, range.second);
    if (range.first != range.second) result.m_first_peer = range.first->second.m_peer;
    result.m_first_in_flight = result.m_request_count == 0 || result.m_first_peer == peer;

    for (auto it{range.first}; it != range.second; ++it) {
        if (it->second.m_peer != peer) continue;
        result.m_requested_from_peer = true;
        result.m_partial_block = it->second.m_queue_it->m_partial_block;
        break;
    }
    return result;
}

BlockRequestReservation BlockDownloadManagerImpl::ReserveBlockRequest(
    NodeId peer,
    const BlockDownloadBlock& block,
    std::chrono::microseconds now,
    std::shared_ptr<PartiallyDownloadedBlock> proposed_partial)
{
    LOCK(m_mutex);

    const BlockInFlightInfo before{GetBlockInFlightInfoLocked(block.m_hash, peer)};
    BlockRequestReservation result{
        .m_status = BlockRequestStatus::NEW,
        .m_requests_before = before.m_request_count,
        .m_first_in_flight = before.m_first_in_flight,
        .m_partial_block = before.m_partial_block,
    };

    const auto peer_it{m_peer_states.find(peer)};
    if (peer_it == m_peer_states.end()) {
        result.m_status = BlockRequestStatus::PEER_NOT_FOUND;
        return result;
    }

    if (before.m_requested_from_peer) {
        if (!proposed_partial) {
            result.m_status = BlockRequestStatus::ALREADY_REQUESTED;
            return result;
        }
        if (before.m_partial_block) {
            result.m_status = BlockRequestStatus::DUPLICATE_COMPACT;
            return result;
        }

        const auto range{m_requests_by_hash.equal_range(block.m_hash)};
        for (auto it{range.first}; it != range.second; ++it) {
            if (it->second.m_peer == peer) {
                it->second.m_queue_it->m_partial_block = std::move(proposed_partial);
                result.m_partial_block = it->second.m_queue_it->m_partial_block;
                result.m_status = BlockRequestStatus::UPGRADED_TO_COMPACT;
                return result;
            }
        }
        Assume(false);
        result.m_status = BlockRequestStatus::ALREADY_REQUESTED;
        return result;
    }

    if (before.m_request_count >= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK) {
        result.m_status = BlockRequestStatus::MAX_REQUESTS_REACHED;
        return result;
    }

    auto& state{peer_it->second};
    state.m_requests.push_back({block, std::move(proposed_partial)});
    const auto queue_it{std::prev(state.m_requests.end())};
    if (state.m_requests.size() == 1) {
        state.m_downloading_since = now;
        ++m_peers_downloading_from;
    }
    m_requests_by_hash.emplace(block.m_hash, IndexedRequest{peer, queue_it});
    result.m_partial_block = queue_it->m_partial_block;
    return result;
}

BlockRequestRemoval BlockDownloadManagerImpl::RemoveBlockRequest(
    const uint256& hash,
    std::optional<NodeId> from_peer,
    std::chrono::microseconds now)
{
    LOCK(m_mutex);
    const auto initial_range{m_requests_by_hash.equal_range(hash)};
    const size_t request_count{static_cast<size_t>(std::distance(initial_range.first, initial_range.second))};
    Assume(request_count <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    BlockRequestRemoval result{.m_requests_before = request_count};
    auto range{initial_range};
    while (range.first != range.second) {
        const NodeId peer{range.first->second.m_peer};
        const auto queue_it{range.first->second.m_queue_it};
        if (from_peer && *from_peer != peer) {
            ++range.first;
            continue;
        }

        auto peer_it{m_peer_states.find(peer)};
        Assume(peer_it != m_peer_states.end());
        auto& state{peer_it->second};
        if (state.m_requests.begin() == queue_it) {
            state.m_downloading_since = std::max(state.m_downloading_since, now);
        }
        state.m_requests.erase(queue_it);
        if (state.m_requests.empty()) {
            --m_peers_downloading_from;
            Assume(m_peers_downloading_from >= 0);
        }
        state.m_stalling_since = std::chrono::microseconds{0};
        range.first = m_requests_by_hash.erase(range.first);
        ++result.m_removed;
    }
    return result;
}

bool BlockDownloadManagerImpl::IsBlockRequested(const uint256& hash) const
{
    LOCK(m_mutex);
    return m_requests_by_hash.contains(hash);
}

bool BlockDownloadManagerImpl::IsBlockRequestedFromOutbound(const uint256& hash) const
{
    LOCK(m_mutex);
    const auto range{m_requests_by_hash.equal_range(hash)};
    for (auto it{range.first}; it != range.second; ++it) {
        const auto peer_it{m_peer_states.find(it->second.m_peer)};
        if (peer_it != m_peer_states.end() && !peer_it->second.m_connection_info.m_is_inbound) return true;
    }
    return false;
}

BlockInFlightInfo BlockDownloadManagerImpl::GetBlockInFlightInfo(const uint256& hash, NodeId peer) const
{
    LOCK(m_mutex);
    return GetBlockInFlightInfoLocked(hash, peer);
}

std::optional<PeerBlockRequestInfo> BlockDownloadManagerImpl::GetPeerRequestInfo(NodeId peer) const
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end()) return std::nullopt;

    PeerBlockRequestInfo result;
    result.m_blocks.reserve(it->second.m_requests.size());
    for (const auto& queued : it->second.m_requests) result.m_blocks.push_back(queued.m_block);
    result.m_downloading_since = it->second.m_downloading_since;
    result.m_stalling_since = it->second.m_stalling_since;
    result.m_peers_downloading_from = m_peers_downloading_from;
    return result;
}

BlockRequestSummary BlockDownloadManagerImpl::GetRequestSummary() const
{
    LOCK(m_mutex);
    return {m_requests_by_hash.size(), m_peers_downloading_from};
}

bool BlockDownloadManagerImpl::AllRequestsAreFor(const uint256& hash) const
{
    LOCK(m_mutex);
    return m_requests_by_hash.count(hash) == m_requests_by_hash.size();
}

bool BlockDownloadManagerImpl::StartStalling(NodeId peer, std::chrono::microseconds since)
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end() || it->second.m_stalling_since != std::chrono::microseconds{0}) {
        return false;
    }
    it->second.m_stalling_since = since;
    return true;
}

bool BlockDownloadManagerImpl::ClearStalling(NodeId peer)
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end() || it->second.m_stalling_since == std::chrono::microseconds{0}) return false;
    it->second.m_stalling_since = std::chrono::microseconds{0};
    return true;
}

bool BlockDownloadManagerImpl::CheckConsistencyLocked() const
{
    size_t queue_size{0};
    int peers_downloading{0};
    std::set<std::pair<uint256, NodeId>> unique_requests;

    for (const auto& [peer, state] : m_peer_states) {
        queue_size += state.m_requests.size();
        peers_downloading += !state.m_requests.empty();
        for (auto queue_it{state.m_requests.begin()}; queue_it != state.m_requests.end(); ++queue_it) {
            if (!unique_requests.emplace(queue_it->m_block.m_hash, peer).second) return false;
            const auto range{m_requests_by_hash.equal_range(queue_it->m_block.m_hash)};
            size_t matches{0};
            for (auto index_it{range.first}; index_it != range.second; ++index_it) {
                if (index_it->second.m_peer == peer && index_it->second.m_queue_it == queue_it) ++matches;
            }
            if (matches != 1) return false;
        }
    }
    if (queue_size != m_requests_by_hash.size() || peers_downloading != m_peers_downloading_from) return false;

    for (auto it{m_requests_by_hash.begin()}; it != m_requests_by_hash.end();) {
        const auto range{m_requests_by_hash.equal_range(it->first)};
        if (static_cast<size_t>(std::distance(range.first, range.second)) > MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK) return false;
        for (auto index_it{range.first}; index_it != range.second; ++index_it) {
            const auto peer_it{m_peer_states.find(index_it->second.m_peer)};
            if (peer_it == m_peer_states.end() || index_it->second.m_queue_it->m_block.m_hash != it->first) return false;
        }
        it = range.second;
    }
    return true;
}

bool BlockDownloadManagerImpl::CheckConsistency() const
{
    LOCK(m_mutex);
    return CheckConsistencyLocked();
}

void BlockDownloadManagerImpl::CheckIsEmpty() const
{
    LOCK(m_mutex);
    Assume(CheckConsistencyLocked());
    Assume(m_peer_states.empty());
    Assume(m_requests_by_hash.empty());
    Assume(m_peers_downloading_from == 0);
}

} // namespace node

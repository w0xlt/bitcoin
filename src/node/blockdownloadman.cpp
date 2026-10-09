// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockdownloadman.h>

#include <blockencodings.h>
#include <chain.h>
#include <util/check.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <iterator>

namespace node {
BlockDownloadPeer::~BlockDownloadPeer() = default;

void BlockDownloadManager::DisconnectedPeer(BlockDownloadPeer& peer)
{
    for (const QueuedBlock& entry : peer.m_blocks_in_flight) {
        auto range = mapBlocksInFlight.equal_range(entry.pindex->GetBlockHash());
        while (range.first != range.second) {
            auto [owner, list_it] = range.first->second;
            if (owner != &peer) {
                range.first++;
            } else {
                range.first = mapBlocksInFlight.erase(range.first);
            }
        }
    }
    m_peers_downloading_from.m_value -= (!peer.m_blocks_in_flight.empty());
    assert(m_peers_downloading_from.m_value >= 0);
    peer.m_blocks_in_flight.clear();
    peer.m_disconnected = true;
}

void BlockDownloadManager::CheckIsEmpty() const
{
    assert(mapBlocksInFlight.empty());
    assert(m_peers_downloading_from.m_value == 0);
}

bool BlockDownloadManager::IsBlockRequestedFromOutbound(const uint256& hash) const
{
    for (auto range = mapBlocksInFlight.equal_range(hash); range.first != range.second; range.first++) {
        auto [owner, block_it] = range.first->second;
        if (!owner->m_is_inbound) return true;
    }

    return false;
}

BlockDownloadPeer* BlockDownloadManager::FirstRequestedFrom(const uint256& hash) const
{
    const auto it{mapBlocksInFlight.lower_bound(hash)};
    return it == mapBlocksInFlight.end() || it->first != hash ? nullptr : it->second.first;
}

void BlockDownloadManager::RemoveBlockRequest(const uint256& hash, const BlockDownloadPeer* from_peer)
{
    auto range = mapBlocksInFlight.equal_range(hash);
    if (range.first == range.second) {
        // Block was not requested from any peer
        return;
    }

    // We should not have requested too many of this block
    Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    while (range.first != range.second) {
        const auto& [owner, list_it]{range.first->second};

        if (from_peer && from_peer != owner) {
            range.first++;
            continue;
        }

        auto& state{*owner};

        if (state.m_blocks_in_flight.begin() == list_it) {
            // First block on the queue was received, update the start download time for the next one
            state.m_downloading_since = std::max(state.m_downloading_since, GetTime<std::chrono::microseconds>());
        }
        state.m_blocks_in_flight.erase(list_it);

        if (state.m_blocks_in_flight.empty()) {
            // Last validated block on the queue for this peer was received.
            m_peers_downloading_from.m_value--;
        }
        state.m_stalling_since = 0us;

        range.first = mapBlocksInFlight.erase(range.first);
    }
}

bool BlockDownloadManager::AddRequest(BlockDownloadPeer& peer, const CBlockIndex& block, QueuedBlock** compact, CTxMemPool* mempool)
{
    const uint256& hash{block.GetBlockHash()};

    auto& state{peer};
    assert(!state.m_disconnected);

    // A compact block request creates a partial block, which needs the mempool.
    Assume(!compact || mempool);

    Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    // Short-circuit most stuff in case it is from the same node
    for (auto range = mapBlocksInFlight.equal_range(hash); range.first != range.second; range.first++) {
        if (range.first->second.first == &peer) {
            if (compact) {
                *compact = &*range.first->second.second;
            }
            return false;
        }
    }

    // Make sure it's not being fetched already from same peer.
    RemoveBlockRequest(hash, &peer);

    std::list<QueuedBlock>::iterator it = state.m_blocks_in_flight.insert(state.m_blocks_in_flight.end(),
            {&block, std::unique_ptr<PartiallyDownloadedBlock>(compact ? new PartiallyDownloadedBlock(mempool) : nullptr)});
    if (state.m_blocks_in_flight.size() == 1) {
        // We're starting a block download (batch) from this peer.
        state.m_downloading_since = GetTime<std::chrono::microseconds>();
        m_peers_downloading_from.m_value++;
    }
    mapBlocksInFlight.insert(std::make_pair(hash, std::make_pair(&peer, it)));
    if (compact) {
        *compact = &*it;
    }
    return true;
}

BlockDownloadManager::CompactRequest BlockDownloadManager::RequestCompactBlock(BlockDownloadPeer& peer, const CBlockIndex& block, CTxMemPool& mempool)
{
    QueuedBlock* request{nullptr};
    if (AddRequest(peer, block, &request, &mempool)) return CompactRequest::ADDED;
    if (request->partialBlock) return CompactRequest::ALREADY_COMPACT;
    request->partialBlock.reset(new PartiallyDownloadedBlock(&mempool));
    return CompactRequest::MADE_COMPACT;
}

void BlockDownloadManager::GetMissingTransactions(const QueuedBlock& request, size_t tx_count, std::vector<uint16_t>& indexes) const
{
    for (size_t i = 0; i < tx_count; i++) {
        if (!request.partialBlock->IsTxAvailable(i))
            indexes.push_back(i);
    }
}

BlockInFlightInfo BlockDownloadManager::FindBlockInFlight(const uint256& hash, const BlockDownloadPeer& peer)
{
    BlockInFlightInfo info;
    const auto [first, last]{mapBlocksInFlight.equal_range(hash)};
    info.already_in_flight = std::distance(first, last);
    // Multimap ensures ordering of outstanding requests. It's either empty or first in line.
    info.first_in_flight = first == last || first->second.first == &peer;
    // A peer has at most one request per block.
    const auto it{std::find_if(first, last, [&](const auto& entry) { return entry.second.first == &peer; })};
    if (it != last) {
        info.requested_from_peer = true;
        if (it->second.second->partialBlock) info.compact_request = &*it->second.second;
    }
    return info;
}

std::vector<int> BlockDownloadManager::BlocksInFlightHeights(const BlockDownloadPeer& peer) const
{
    std::vector<int> heights;
    for (const QueuedBlock& queue : peer.m_blocks_in_flight) {
        heights.push_back(queue.pindex->nHeight);
    }
    return heights;
}

void BlockDownloadManager::PauseBlockDownload(BlockDownloadPeer& peer, std::chrono::microseconds until)
{
    peer.m_block_download_paused_until = until;
    while (!peer.m_blocks_in_flight.empty()) {
        RemoveBlockRequest(peer.m_blocks_in_flight.front().pindex->GetBlockHash(), &peer);
    }
}

std::optional<std::pair<NodeId, bool>> BlockDownloadManager::TakeBlockSource(const uint256& hash)
{
    const auto it{mapBlockSource.find(hash)};
    if (it == mapBlockSource.end()) return std::nullopt;
    const auto source{it->second};
    mapBlockSource.erase(it);
    return source;
}
} // namespace node

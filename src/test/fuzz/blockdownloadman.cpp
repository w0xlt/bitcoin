// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <blockencodings.h>
#include <node/blockdownloadman.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace {

constexpr size_t NUM_PEERS{6};
constexpr size_t NUM_BLOCKS{8};

struct MirrorRequest {
    node::BlockDownloadBlock block;
    std::shared_ptr<PartiallyDownloadedBlock> partial;
};

struct PeerMirror {
    bool registered{false};
    bool inbound{false};
    std::vector<MirrorRequest> requests;
    std::chrono::microseconds downloading_since{0};
    std::chrono::microseconds stalling_since{0};
};

struct IndexedMirrorRequest {
    uint256 hash;
    NodeId peer;
};

FUZZ_TARGET(blockdownloadman)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    node::BlockDownloadManager manager;
    std::array<PeerMirror, NUM_PEERS> peers;
    std::vector<IndexedMirrorRequest> index;
    std::array<node::BlockDownloadBlock, NUM_BLOCKS> blocks;
    for (size_t i{0}; i < blocks.size(); ++i) {
        blocks[i] = {
            .m_hash = ArithToUint256(arith_uint256{i + 1}),
            .m_height = static_cast<int>(i),
            .m_chain_work = arith_uint256{(i + 1) * 100},
        };
    }

    auto random_peer = [&] {
        return provider.ConsumeIntegralInRange<NodeId>(0, NUM_PEERS - 1);
    };
    auto random_block = [&]() -> const node::BlockDownloadBlock& {
        return blocks[provider.ConsumeIntegralInRange<size_t>(0, blocks.size() - 1)];
    };
    auto random_time = [&] {
        return std::chrono::microseconds{provider.ConsumeIntegral<uint32_t>()};
    };
    auto find_request = [&](NodeId peer, const uint256& hash) {
        auto& requests{peers[peer].requests};
        return std::find_if(requests.begin(), requests.end(), [&](const MirrorRequest& request) {
            return request.block.m_hash == hash;
        });
    };
    auto count_hash = [&](const uint256& hash) {
        return static_cast<size_t>(std::count_if(index.begin(), index.end(), [&](const IndexedMirrorRequest& request) {
            return request.hash == hash;
        }));
    };

    LIMITED_WHILE(provider.ConsumeBool(), 500) {
        const NodeId peer{random_peer()};
        const auto& block{random_block()};
        const auto now{random_time()};
        switch (provider.ConsumeIntegralInRange<unsigned>(0, 7)) {
        case 0: {
            const bool inbound{peers[peer].registered ? peers[peer].inbound : provider.ConsumeBool()};
            manager.ConnectedPeer(peer, {.m_is_inbound = inbound});
            peers[peer].registered = true;
            peers[peer].inbound = inbound;
            break;
        }
        case 1: {
            manager.DisconnectedPeer(peer);
            index.erase(std::remove_if(index.begin(), index.end(), [&](const IndexedMirrorRequest& request) {
                return request.peer == peer;
            }), index.end());
            peers[peer] = {};
            break;
        }
        case 2: {
            const bool compact{provider.ConsumeBool()};
            auto proposed{compact ? std::make_shared<PartiallyDownloadedBlock>(nullptr) : nullptr};
            auto proposed_copy{proposed};
            const size_t count_before{count_hash(block.m_hash)};
            const auto first_it{std::find_if(index.begin(), index.end(), [&](const IndexedMirrorRequest& request) {
                return request.hash == block.m_hash;
            })};
            const bool first{count_before == 0 || first_it->peer == peer};
            const auto request_it{find_request(peer, block.m_hash)};

            const auto result{manager.ReserveBlockRequest(peer, block, now, std::move(proposed))};
            Assert(result.m_requests_before == count_before);
            Assert(result.m_first_in_flight == first);
            if (!peers[peer].registered) {
                Assert(result.m_status == node::BlockRequestStatus::PEER_NOT_FOUND);
            } else if (request_it != peers[peer].requests.end()) {
                if (!compact) {
                    Assert(result.m_status == node::BlockRequestStatus::ALREADY_REQUESTED);
                } else if (request_it->partial) {
                    Assert(result.m_status == node::BlockRequestStatus::DUPLICATE_COMPACT);
                    Assert(result.m_partial_block == request_it->partial);
                } else {
                    Assert(result.m_status == node::BlockRequestStatus::UPGRADED_TO_COMPACT);
                    request_it->partial = std::move(proposed_copy);
                    Assert(result.m_partial_block == request_it->partial);
                }
            } else if (count_before >= node::MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK) {
                Assert(result.m_status == node::BlockRequestStatus::MAX_REQUESTS_REACHED);
            } else {
                Assert(result.m_status == node::BlockRequestStatus::NEW);
                if (peers[peer].requests.empty()) peers[peer].downloading_since = now;
                peers[peer].requests.push_back({block, std::move(proposed_copy)});
                index.push_back({block.m_hash, peer});
            }
            break;
        }
        case 3: {
            std::optional<NodeId> from_peer;
            if (provider.ConsumeBool()) from_peer = peer;
            const size_t count_before{count_hash(block.m_hash)};
            size_t removed{0};
            for (auto it{index.begin()}; it != index.end();) {
                if (it->hash != block.m_hash || (from_peer && it->peer != *from_peer)) {
                    ++it;
                    continue;
                }
                auto& mirror{peers[it->peer]};
                const auto queue_it{find_request(it->peer, block.m_hash)};
                Assert(queue_it != mirror.requests.end());
                if (queue_it == mirror.requests.begin()) {
                    mirror.downloading_since = std::max(mirror.downloading_since, now);
                }
                mirror.requests.erase(queue_it);
                mirror.stalling_since = std::chrono::microseconds{0};
                it = index.erase(it);
                ++removed;
            }
            const auto result{manager.RemoveBlockRequest(block.m_hash, from_peer, now)};
            Assert(result.m_requests_before == count_before);
            Assert(result.m_removed == removed);
            break;
        }
        case 4: {
            const bool expected{peers[peer].registered && peers[peer].stalling_since == std::chrono::microseconds{0}};
            Assert(manager.StartStalling(peer, now) == expected);
            if (expected) peers[peer].stalling_since = now;
            break;
        }
        case 5: {
            const bool expected{peers[peer].registered && peers[peer].stalling_since != std::chrono::microseconds{0}};
            Assert(manager.ClearStalling(peer) == expected);
            if (expected) peers[peer].stalling_since = std::chrono::microseconds{0};
            break;
        }
        case 6: {
            const auto info{manager.GetBlockInFlightInfo(block.m_hash, peer)};
            Assert(info.m_request_count == count_hash(block.m_hash));
            Assert(info.m_requested_from_peer == (find_request(peer, block.m_hash) != peers[peer].requests.end()));
            if (info.m_first_peer) Assert(info.m_request_count != 0);
            if (info.m_partial_block) Assert(info.m_requested_from_peer);
            break;
        }
        case 7:
            (void)manager.GetRequestSummary();
            break;
        }

        size_t total{0};
        int downloading_peers{0};
        for (NodeId id{0}; id < static_cast<NodeId>(NUM_PEERS); ++id) {
            const auto actual{manager.GetPeerRequestInfo(id)};
            if (!peers[id].registered) {
                Assert(!actual);
                continue;
            }
            Assert(actual);
            Assert(actual->m_blocks.size() == peers[id].requests.size());
            for (size_t pos{0}; pos < actual->m_blocks.size(); ++pos) {
                Assert(actual->m_blocks[pos] == peers[id].requests[pos].block);
            }
            Assert(actual->m_downloading_since == peers[id].downloading_since);
            Assert(actual->m_stalling_since == peers[id].stalling_since);
            total += peers[id].requests.size();
            downloading_peers += !peers[id].requests.empty();
        }
        const auto summary{manager.GetRequestSummary()};
        Assert(summary.m_total_requests == total);
        Assert(summary.m_total_requests == index.size());
        Assert(summary.m_peers_downloading_from == downloading_peers);
        Assert(manager.CheckConsistency());

        for (const auto& candidate : blocks) {
            bool outbound{false};
            for (const auto& request : index) {
                if (request.hash == candidate.m_hash && !peers[request.peer].inbound) outbound = true;
            }
            Assert(manager.IsBlockRequested(candidate.m_hash) == (count_hash(candidate.m_hash) != 0));
            Assert(manager.IsBlockRequestedFromOutbound(candidate.m_hash) == outbound);
        }
    }

    for (NodeId peer{0}; peer < static_cast<NodeId>(NUM_PEERS); ++peer) manager.DisconnectedPeer(peer);
    manager.CheckIsEmpty();
}

} // namespace

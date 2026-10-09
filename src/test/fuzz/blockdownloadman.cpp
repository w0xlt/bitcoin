// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <blockencodings.h>
#include <chain.h>
#include <node/blockdownloadman.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <list>
#include <map>
#include <optional>
#include <utility>
#include <vector>

using node::BlockDownloadCounter;
using node::BlockDownloadManager;
using node::BlockDownloadPeer;
using node::QueuedBlock;

namespace {
const TestingSetup* g_setup;

constexpr size_t NUM_PEERS{8};
constexpr size_t NUM_BLOCKS{16};
/** Block index entries for requests. The manager only reads their hash and height. */
std::array<uint256, NUM_BLOCKS> g_hashes;
std::array<CBlockIndex, NUM_BLOCKS> g_blocks;

void initialize_blockdownloadman()
{
    static const auto testing_setup{MakeNoLogFileContext<const TestingSetup>()};
    g_setup = testing_setup.get();
    for (size_t i{0}; i < NUM_BLOCKS; ++i) {
        g_hashes[i] = ArithToUint256(arith_uint256{i + 1});
        g_blocks[i].phashBlock = &g_hashes[i];
        g_blocks[i].nHeight = static_cast<int>(i + 1);
    }
}

/** What the manager and the peers are expected to hold. */
struct Model {
    struct Peer {
        Peer(NodeId id_in, bool inbound_in) : id{id_in}, inbound{inbound_in} {}
        NodeId id;
        bool inbound;
        bool disconnected{false};
        /** Requested blocks, oldest first, and whether each has a partial block. */
        std::vector<std::pair<size_t, bool>> requests;
        std::chrono::microseconds downloading_since{0us};
        std::chrono::microseconds stalling_since{0us};
        std::chrono::microseconds paused_until{0us};
    };
    /** Per slot, the peer using it, if any. */
    std::array<std::optional<Peer>, NUM_PEERS> peers;
    /** Per block, the slots it is in flight from, oldest request first. */
    std::array<std::vector<size_t>, NUM_BLOCKS> requesters;
    std::map<uint256, std::pair<NodeId, bool>> sources;

    void Remove(size_t block, std::optional<size_t> from_slot, std::chrono::microseconds now)
    {
        auto& order{requesters[block]};
        for (auto it{order.begin()}; it != order.end();) {
            if (from_slot && *it != *from_slot) {
                ++it;
                continue;
            }
            auto& peer{*peers[*it]};
            const auto pos{std::ranges::find_if(peer.requests, [&](const auto& r) { return r.first == block; })};
            if (pos == peer.requests.begin()) peer.downloading_since = std::max(peer.downloading_since, now);
            peer.requests.erase(pos);
            peer.stalling_since = 0us;
            it = order.erase(it);
        }
    }

    bool HasRequest(size_t block, size_t slot) const
    {
        return std::ranges::find(requesters[block], slot) != requesters[block].end();
    }
};
} // namespace

FUZZ_TARGET(blockdownloadman, .init = initialize_blockdownloadman)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider)};
    CTxMemPool* const mempool{g_setup->m_node.mempool.get()};

    BlockDownloadCounter downloading_from;
    BlockDownloadManager bdm{downloading_from};
    // Like a Peer, a BlockDownloadPeer may outlive its disconnection.
    std::array<std::optional<BlockDownloadPeer>, NUM_PEERS> peers;
    Model model;
    NodeId next_id{0};
    auto now{[] { return GetTime<std::chrono::microseconds>(); }};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        const size_t slot{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, NUM_PEERS - 1)};
        const size_t block{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, NUM_BLOCKS - 1)};
        auto& mpeer{model.peers[slot]};
        const bool connected{mpeer && !mpeer->disconnected};

        CallOneOf(
            fuzzed_data_provider,
            [&] {
                if (mpeer) return;
                const bool inbound{fuzzed_data_provider.ConsumeBool()};
                peers[slot].emplace(next_id, inbound);
                mpeer.emplace(next_id, inbound);
                ++next_id;
            },
            [&] {
                if (!connected) return;
                bdm.DisconnectedPeer(*peers[slot]);
                for (const auto& [b, _] : mpeer->requests) std::erase(model.requesters[b], slot);
                mpeer->requests.clear();
                mpeer->disconnected = true;
            },
            [&] {
                // A peer is only destroyed after it is disconnected.
                if (!mpeer || !mpeer->disconnected) return;
                peers[slot].reset();
                mpeer.reset();
            },
            [&] {
                // Like net_processing, keep at most MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK
                // requests per block, and only request blocks from connected peers.
                if (!connected) return;
                const bool already{model.HasRequest(block, slot)};
                if (!already && model.requesters[block].size() >= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK) return;
                const bool compact{fuzzed_data_provider.ConsumeBool()};
                std::list<QueuedBlock>::iterator* pit{nullptr};
                bool added;
                {
                    LOCK(cs_main);
                    added = compact ? bdm.BlockRequested(*peers[slot], g_blocks[block], &pit, mempool) : bdm.BlockRequested(*peers[slot], g_blocks[block]);
                }
                Assert(added == !already);
                if (added) {
                    if (mpeer->requests.empty()) mpeer->downloading_since = now();
                    mpeer->requests.emplace_back(block, compact);
                    model.requesters[block].push_back(slot);
                }
                if (compact) {
                    Assert(pit && (*pit)->pindex == &g_blocks[block]);
                    auto& request{*std::ranges::find_if(mpeer->requests, [&](const auto& r) { return r.first == block; })};
                    Assert(bool{(*pit)->partialBlock} == (added || request.second));
                    // Like the compact block handler, give an existing request a partial block.
                    if (!(*pit)->partialBlock) (*pit)->partialBlock = std::make_unique<PartiallyDownloadedBlock>(mempool);
                    request.second = true;
                }
            },
            [&] {
                const bool from_slot{mpeer && fuzzed_data_provider.ConsumeBool()};
                bdm.RemoveBlockRequest(g_hashes[block], from_slot ? &*peers[slot] : nullptr);
                model.Remove(block, from_slot ? std::optional{slot} : std::nullopt, now());
            },
            [&] {
                if (!mpeer) return;
                const auto info{bdm.FindBlockInFlight(g_hashes[block], *peers[slot])};
                const auto& order{model.requesters[block]};
                Assert(info.already_in_flight == order.size());
                Assert(info.first_in_flight == (order.empty() || order.front() == slot));
                Assert(info.requested_from_peer == model.HasRequest(block, slot));
                const bool compact{std::ranges::find(mpeer->requests, std::pair{block, true}) != mpeer->requests.end()};
                Assert((info.compact_request != nullptr) == compact);
                if (info.compact_request) Assert(info.compact_request->pindex == &g_blocks[block] && info.compact_request->partialBlock);
            },
            [&] {
                if (!connected) return;
                const std::chrono::microseconds time{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
                bdm.SetStallingSince(*peers[slot], time);
                mpeer->stalling_since = time;
            },
            [&] {
                if (!connected) return;
                const auto until{now() + std::chrono::seconds{fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 600)}};
                bdm.PauseBlockDownload(*peers[slot], until);
                while (!mpeer->requests.empty()) model.Remove(mpeer->requests.front().first, slot, now());
                mpeer->paused_until = until;
            },
            [&] {
                const uint256& hash{fuzzed_data_provider.ConsumeBool() ? g_hashes[block] : uint256::ZERO};
                const NodeId source_id{fuzzed_data_provider.ConsumeIntegralInRange<NodeId>(0, next_id)};
                const bool punish{fuzzed_data_provider.ConsumeBool()};
                switch (fuzzed_data_provider.ConsumeIntegralInRange(0, 2)) {
                case 0:
                    bdm.AddBlockSource(hash, source_id, punish);
                    model.sources.emplace(hash, std::pair{source_id, punish});
                    break;
                case 1: {
                    const auto it{model.sources.find(hash)};
                    const auto expected{it == model.sources.end() ? std::nullopt : std::optional{it->second}};
                    Assert(bdm.TakeBlockSource(hash) == expected);
                    if (it != model.sources.end()) model.sources.erase(it);
                    break;
                }
                case 2:
                    bdm.EraseBlockSource(hash);
                    model.sources.erase(hash);
                    break;
                }
            },
            [&] {
                clock += std::chrono::seconds{fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 3600)};
            });

        // The manager and the peers agree with the model.
        size_t total{0};
        int downloading{0};
        for (size_t s{0}; s < NUM_PEERS; ++s) {
            Assert(peers[s].has_value() == model.peers[s].has_value());
            if (!peers[s]) continue;
            const auto& peer{*peers[s]};
            const auto& expected{*model.peers[s]};
            std::vector<int> heights;
            for (const auto& [b, _] : expected.requests) heights.push_back(g_blocks[b].nHeight);
            Assert(bdm.PeerId(peer) == expected.id);
            Assert(bdm.NumBlocksInFlight(peer) == expected.requests.size());
            Assert(bdm.BlocksInFlightHeights(peer) == heights);
            Assert(bdm.FirstBlockInFlight(peer) == (expected.requests.empty() ? nullptr : &g_blocks[expected.requests.front().first]));
            if (!expected.requests.empty()) Assert(bdm.DownloadingSince(peer) == expected.downloading_since);
            Assert(bdm.StallingSince(peer) == expected.stalling_since);
            Assert(bdm.PausedUntil(peer) == expected.paused_until);
            total += expected.requests.size();
            downloading += !expected.requests.empty();
        }
        Assert(bdm.GetTotalBlocksInFlight() == total);
        Assert(downloading_from.Get() == downloading);
        for (size_t b{0}; b < NUM_BLOCKS; ++b) {
            const auto& order{model.requesters[b]};
            Assert(bdm.IsBlockRequested(g_hashes[b]) == !order.empty());
            Assert(bdm.CountBlocksInFlight(g_hashes[b]) == order.size());
            Assert(bdm.FirstRequestedFrom(g_hashes[b]) == (order.empty() ? nullptr : &*peers[order.front()]));
            Assert(bdm.IsBlockRequestedFromOutbound(g_hashes[b]) ==
                   std::ranges::any_of(order, [&](size_t s) { return !model.peers[s]->inbound; }));
        }
    }

    // Disconnecting every peer drops every request.
    for (size_t s{0}; s < NUM_PEERS; ++s) {
        if (model.peers[s] && !model.peers[s]->disconnected) bdm.DisconnectedPeer(*peers[s]);
    }
    bdm.CheckIsEmpty();
}

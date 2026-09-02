// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <blockencodings.h>
#include <node/blockdownloadman.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/blockdownloadchain.h>
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
constexpr std::chrono::seconds MAX_BLOCK_STALLING_TIMEOUT{64};

struct MirrorRequest {
    node::BlockDownloadBlock block;
    std::shared_ptr<PartiallyDownloadedBlock> partial;
};

struct PeerMirror {
    bool registered{false};
    bool inbound{false};
    bool preferred{false};
    bool can_serve_witness{false};
    bool limited{false};
    bool sync_started{false};
    std::optional<node::BlockDownloadBlock> best_known;
    std::optional<node::BlockDownloadBlock> last_common;
    std::optional<node::BlockDownloadBlock> best_header_sent;
    std::optional<uint256> pending_hash;
    std::vector<MirrorRequest> requests;
    std::chrono::microseconds downloading_since{0};
    std::chrono::microseconds stalling_since{0};
    uint64_t generation{0};
};

struct IndexedMirrorRequest {
    uint256 hash;
    NodeId peer;
};

FUZZ_TARGET(blockdownloadman)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    auto chain{std::make_unique<node::test::FakeBlockDownloadChain>()};
    auto* const fake_chain{chain.get()};
    node::BlockDownloadManager manager{std::move(chain)};
    (void)fake_chain;
    std::array<PeerMirror, NUM_PEERS> peers;
    std::array<uint64_t, NUM_PEERS> last_peer_generation{};
    std::vector<IndexedMirrorRequest> index;
    std::array<node::BlockDownloadBlock, NUM_BLOCKS> blocks;
    std::array<node::BlockDownloadBlock, NUM_BLOCKS> chain_blocks;
    std::array<bool, NUM_BLOCKS> chain_known{};
    std::array<std::optional<size_t>, NUM_BLOCKS> chain_parent{};
    std::array<bool, NUM_BLOCKS> chain_valid{};
    std::array<bool, NUM_BLOCKS> chain_data{};
    std::array<bool, NUM_BLOCKS> chain_active{};
    std::array<bool, NUM_BLOCKS> chain_txs{};
    std::array<bool, NUM_BLOCKS> chain_segwit{};
    std::array<std::optional<node::BlockSource>, NUM_BLOCKS> sources;
    uint64_t next_peer_generation{0};
    uint64_t in_flight_generation{0};
    std::chrono::seconds last_tip_update{0};
    std::chrono::seconds stalling_timeout{node::DEFAULT_BLOCK_STALLING_TIMEOUT};
    for (size_t i{0}; i < blocks.size(); ++i) {
        blocks[i] = {
            .m_hash = ArithToUint256(arith_uint256{i + 1}),
            .m_height = static_cast<int>(i),
            .m_chain_work = arith_uint256{(i + 1) * 100},
        };
        chain_blocks[i] = blocks[i];
        chain_known[i] = true;
        chain_parent[i] = i == 0 ? std::nullopt : std::optional{i - 1};
        chain_valid[i] = true;
        chain_data[i] = i == 0;
        chain_active[i] = i == 0;
        chain_txs[i] = i == 0;
        fake_chain->SetCandidate({
            .m_block = chain_blocks[i],
            .m_valid_tree = chain_valid[i],
            .m_have_data = chain_data[i],
            .m_in_active_chain = chain_active[i],
            .m_have_chain_txs = chain_txs[i],
            .m_segwit_active = chain_segwit[i],
        }, chain_parent[i] ? std::optional{chain_blocks[*chain_parent[i]].m_hash} : std::nullopt);
    }
    fake_chain->SetActiveTip(chain_blocks[0].m_hash);
    fake_chain->SetCurrentChainstate(chain_blocks[0].m_hash);
    fake_chain->SetMinimumChainWork(0);

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
    auto resolve_chain = [&](const uint256& hash) -> std::optional<node::BlockDownloadBlock> {
        for (size_t i{0}; i < chain_blocks.size(); ++i) {
            if (chain_blocks[i].m_hash == hash && chain_known[i]) return chain_blocks[i];
        }
        return std::nullopt;
    };
    auto mirror_update_availability = [&](NodeId id, const uint256& hash) {
        auto& mirror{peers[id]};
        if (!mirror.registered) return;
        auto best{mirror.best_known};
        auto pending{mirror.pending_hash};
        if (pending) {
            const auto resolved{resolve_chain(*pending)};
            if (resolved && resolved->m_chain_work > 0) {
                if (!best || resolved->m_chain_work >= best->m_chain_work) best = resolved;
                pending.reset();
            }
        }
        const auto announced{resolve_chain(hash)};
        if (announced && announced->m_chain_work > 0) {
            if (!best || announced->m_chain_work >= best->m_chain_work) best = announced;
        } else {
            pending = hash.IsNull() ? std::nullopt : std::optional{hash};
        }
        if (best != mirror.best_known || pending != mirror.pending_hash) {
            mirror.best_known = std::move(best);
            mirror.pending_hash = std::move(pending);
            mirror.generation = ++next_peer_generation;
        }
    };
    auto mirror_process_availability = [&](NodeId id) {
        auto& mirror{peers[id]};
        if (!mirror.registered || !mirror.pending_hash) return;
        const auto resolved{resolve_chain(*mirror.pending_hash)};
        if (!resolved || resolved->m_chain_work <= 0) return;
        if (!mirror.best_known || resolved->m_chain_work >= mirror.best_known->m_chain_work) {
            mirror.best_known = resolved;
        }
        mirror.pending_hash.reset();
        mirror.generation = ++next_peer_generation;
    };
    auto mirror_has_header = [&](NodeId id, const uint256& target) {
        if (!peers[id].registered) return false;
        const auto is_ancestor = [&](const std::optional<node::BlockDownloadBlock>& descendant) {
            if (!descendant) return false;
            std::optional<size_t> target_pos;
            std::optional<size_t> descendant_pos;
            for (size_t i{0}; i < chain_blocks.size(); ++i) {
                if (chain_blocks[i].m_hash == target) target_pos = i;
                if (chain_blocks[i].m_hash == descendant->m_hash) descendant_pos = i;
            }
            if (!target_pos || !descendant_pos) return false;
            std::optional<size_t> walk{descendant_pos};
            while (walk && *walk != *target_pos) {
                if (!chain_known[*walk]) return false;
                walk = chain_parent[*walk];
            }
            return walk == target_pos && chain_known[*target_pos];
        };
        return is_ancestor(peers[id].best_known) || is_ancestor(peers[id].best_header_sent);
    };

    LIMITED_WHILE(provider.ConsumeBool(), 500) {
        const NodeId peer{random_peer()};
        const auto& block{random_block()};
        const auto now{random_time()};
        switch (provider.ConsumeIntegralInRange<unsigned>(0, 24)) {
        case 0: {
            const bool inserted{!peers[peer].registered};
            const bool inbound{peers[peer].registered ? peers[peer].inbound : provider.ConsumeBool()};
            const bool preferred{provider.ConsumeBool()};
            const bool can_serve_witness{provider.ConsumeBool()};
            const bool limited{provider.ConsumeBool()};
            const bool changed{inserted ||
                               peers[peer].preferred != preferred ||
                               peers[peer].can_serve_witness != can_serve_witness ||
                               peers[peer].limited != limited};
            manager.ConnectedPeer(peer, {
                .m_is_inbound = inbound,
                .m_preferred_download = preferred,
                .m_can_serve_witness = can_serve_witness,
                .m_limited_peer = limited,
            });
            peers[peer].registered = true;
            peers[peer].inbound = inbound;
            peers[peer].preferred = preferred;
            peers[peer].can_serve_witness = can_serve_witness;
            peers[peer].limited = limited;
            if (changed) peers[peer].generation = ++next_peer_generation;
            if (inserted) Assert(peers[peer].generation > last_peer_generation[peer]);
            break;
        }
        case 1: {
            const bool had_requests{!peers[peer].requests.empty()};
            manager.DisconnectedPeer(peer);
            index.erase(std::remove_if(index.begin(), index.end(), [&](const IndexedMirrorRequest& request) {
                return request.peer == peer;
            }), index.end());
            for (auto& source : sources) {
                if (source && source->m_peer == peer) source.reset();
            }
            peers[peer] = {};
            in_flight_generation += had_requests;
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
                peers[peer].generation = ++next_peer_generation;
                ++in_flight_generation;
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
                mirror.generation = ++next_peer_generation;
                it = index.erase(it);
                ++removed;
            }
            const auto result{manager.RemoveBlockRequest(block.m_hash, from_peer, now)};
            Assert(result.m_requests_before == count_before);
            Assert(result.m_removed == removed);
            in_flight_generation += removed != 0;
            break;
        }
        case 4: {
            const bool expected{now != std::chrono::microseconds{0} &&
                                peers[peer].registered &&
                                peers[peer].stalling_since == std::chrono::microseconds{0}};
            Assert(manager.StartStalling(peer, now) == expected);
            if (expected) {
                peers[peer].stalling_since = now;
                peers[peer].generation = ++next_peer_generation;
            }
            break;
        }
        case 5: {
            const bool expected{peers[peer].registered && peers[peer].stalling_since != std::chrono::microseconds{0}};
            Assert(manager.ClearStalling(peer) == expected);
            if (expected) {
                peers[peer].stalling_since = std::chrono::microseconds{0};
                peers[peer].generation = ++next_peer_generation;
            }
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
            (void)manager.GetGlobalSnapshot();
            break;
        case 8: {
            const bool expected{peers[peer].registered && !peers[peer].sync_started};
            Assert(manager.StartSync(peer) == expected);
            if (expected) {
                peers[peer].sync_started = true;
                peers[peer].generation = ++next_peer_generation;
            }
            break;
        }
        case 9: {
            const bool expected{peers[peer].registered && peers[peer].sync_started};
            Assert(manager.ClearSync(peer) == expected);
            if (expected) {
                peers[peer].sync_started = false;
                peers[peer].generation = ++next_peer_generation;
            }
            break;
        }
        case 10: {
            const size_t block_pos{static_cast<size_t>(block.m_height)};
            const bool punish{provider.ConsumeBool()};
            const bool expected{peers[peer].registered && !sources[block_pos]};
            Assert(manager.RecordBlockSource(block.m_hash, peer, punish) == expected);
            if (expected) sources[block_pos] = node::BlockSource{peer, punish};
            break;
        }
        case 11: {
            const size_t block_pos{static_cast<size_t>(block.m_height)};
            Assert(manager.ConsumeBlockSource(block.m_hash) == sources[block_pos]);
            sources[block_pos].reset();
            break;
        }
        case 12: {
            const size_t block_pos{static_cast<size_t>(block.m_height)};
            Assert(manager.EraseBlockSource(block.m_hash) == sources[block_pos].has_value());
            sources[block_pos].reset();
            break;
        }
        case 13: {
            const auto now_seconds{std::chrono::seconds{provider.ConsumeIntegral<uint32_t>()}};
            const auto stale_after{std::chrono::seconds{provider.ConsumeIntegral<uint16_t>()}};
            if (last_tip_update == std::chrono::seconds{0}) last_tip_update = now_seconds;
            const bool expected{last_tip_update < now_seconds - stale_after && index.empty()};
            Assert(manager.TipMayBeStale(now_seconds, stale_after) == expected);
            break;
        }
        case 14:
            last_tip_update = std::chrono::seconds{provider.ConsumeIntegral<uint32_t>()};
            manager.UpdatedBlockTip(last_tip_update);
            break;
        case 15: {
            const auto expected{provider.ConsumeBool() ? stalling_timeout : std::chrono::seconds{provider.ConsumeIntegral<uint16_t>()}};
            std::optional<std::chrono::seconds> expected_result;
            std::optional<std::chrono::seconds> result;
            if (provider.ConsumeBool()) {
                if (expected == stalling_timeout && expected >= node::DEFAULT_BLOCK_STALLING_TIMEOUT && expected < MAX_BLOCK_STALLING_TIMEOUT) {
                    expected_result = std::min(2 * expected, MAX_BLOCK_STALLING_TIMEOUT);
                }
                result = manager.TryIncreaseBlockStallingTimeout(expected);
            } else {
                if (expected == stalling_timeout && expected > node::DEFAULT_BLOCK_STALLING_TIMEOUT && expected <= MAX_BLOCK_STALLING_TIMEOUT) {
                    expected_result = std::max(
                        std::chrono::duration_cast<std::chrono::seconds>(expected * 0.85),
                        node::DEFAULT_BLOCK_STALLING_TIMEOUT);
                }
                result = manager.TryDecreaseBlockStallingTimeout(expected);
            }
            Assert(result == expected_result);
            if (result) stalling_timeout = *result;
            break;
        }
        case 16: {
            const size_t pos{static_cast<size_t>(block.m_height)};
            chain_known[pos] = provider.ConsumeBool();
            chain_blocks[pos].m_chain_work = arith_uint256{static_cast<uint64_t>(provider.ConsumeIntegralInRange<uint16_t>(0, 4)) * 100};
            if (chain_known[pos]) {
                fake_chain->SetCandidate({
                    .m_block = chain_blocks[pos],
                    .m_valid_tree = chain_valid[pos],
                    .m_have_data = chain_data[pos],
                    .m_in_active_chain = chain_active[pos],
                    .m_have_chain_txs = chain_txs[pos],
                    .m_segwit_active = chain_segwit[pos],
                }, chain_parent[pos] ? std::optional{chain_blocks[*chain_parent[pos]].m_hash} : std::nullopt);
            } else {
                fake_chain->RemoveBlock(chain_blocks[pos].m_hash);
            }
            break;
        }
        case 17:
            manager.UpdateBlockAvailability(peer, block.m_hash);
            mirror_update_availability(peer, block.m_hash);
            break;
        case 18:
            manager.ProcessBlockAvailability(peer);
            mirror_process_availability(peer);
            break;
        case 19:
            Assert(manager.PeerHasHeader(peer, block.m_hash) == mirror_has_header(peer, block.m_hash));
            break;
        case 20: {
            manager.RecordBestHeaderSent(peer, chain_blocks[static_cast<size_t>(block.m_height)]);
            if (peers[peer].registered && peers[peer].best_header_sent != chain_blocks[static_cast<size_t>(block.m_height)]) {
                peers[peer].best_header_sent = chain_blocks[static_cast<size_t>(block.m_height)];
                peers[peer].generation = ++next_peer_generation;
            }
            break;
        }
        case 21: {
            if (!peers[peer].registered) {
                manager.UpdateBlockAvailability(peer, block.m_hash);
                break;
            }
            uint256 interleaved_hash{ArithToUint256(arith_uint256{1000U + static_cast<uint64_t>(provider.ConsumeIntegral<uint16_t>())})};
            if (peers[peer].pending_hash == interleaved_hash) {
                interleaved_hash = ArithToUint256(UintToArith256(interleaved_hash) + 1);
            }
            fake_chain->SetCaptureHook([&manager, peer, interleaved_hash] {
                manager.UpdateBlockAvailability(peer, interleaved_hash);
            });
            manager.UpdateBlockAvailability(peer, block.m_hash);
            mirror_update_availability(peer, interleaved_hash);
            break;
        }
        case 22: {
            // Mutate the fake's owned planning facts: topology/forks,
            // pruning/data, invalidation, active-tip identity, and SegWit.
            const size_t pos{static_cast<size_t>(block.m_height)};
            chain_known[pos] = true;
            chain_valid[pos] = provider.ConsumeBool();
            chain_data[pos] = provider.ConsumeBool();
            chain_active[pos] = provider.ConsumeBool();
            chain_txs[pos] = provider.ConsumeBool();
            chain_segwit[pos] = provider.ConsumeBool();
            if (pos == 0) {
                chain_parent[pos].reset();
            } else {
                chain_parent[pos] = provider.ConsumeIntegralInRange<size_t>(0, pos - 1);
            }
            fake_chain->SetCandidate({
                .m_block = chain_blocks[pos],
                .m_valid_tree = chain_valid[pos],
                .m_have_data = chain_data[pos],
                .m_in_active_chain = chain_active[pos],
                .m_have_chain_txs = chain_txs[pos],
                .m_segwit_active = chain_segwit[pos],
            }, chain_parent[pos] ? std::optional{chain_blocks[*chain_parent[pos]].m_hash} : std::nullopt);
            const size_t tip_pos{provider.ConsumeIntegralInRange<size_t>(0, NUM_BLOCKS - 1)};
            fake_chain->SetActiveTip(chain_known[tip_pos] ? std::optional{chain_blocks[tip_pos].m_hash} : std::nullopt);
            fake_chain->SetMinimumChainWork(arith_uint256{provider.ConsumeIntegral<uint16_t>()});
            const bool use_snapshot{provider.ConsumeBool()};
            const auto assume_state{provider.ConsumeBool()
                ? node::BlockDownloadAssumeutxoState::UNVALIDATED
                : node::BlockDownloadAssumeutxoState::VALIDATED};
            fake_chain->SetCurrentChainstate(
                chain_known[tip_pos] ? std::optional{chain_blocks[tip_pos].m_hash} : std::nullopt,
                use_snapshot ? std::optional{chain_blocks[provider.ConsumeIntegralInRange<size_t>(0, NUM_BLOCKS - 1)].m_hash} : std::nullopt,
                use_snapshot ? assume_state : node::BlockDownloadAssumeutxoState::NONE);
            if (provider.ConsumeBool()) {
                const size_t start{provider.ConsumeIntegralInRange<size_t>(0, NUM_BLOCKS - 1)};
                const size_t target{provider.ConsumeIntegralInRange<size_t>(0, NUM_BLOCKS - 1)};
                fake_chain->SetHistoricalRange(std::pair{chain_blocks[start].m_hash, chain_blocks[target].m_hash});
            } else {
                fake_chain->SetHistoricalRange(std::nullopt);
            }
            break;
        }
        case 23:
        case 24: {
            if (!peers[peer].registered) break;
            // Resolve pending availability at the same linearization point
            // before recording the failed-commit baseline.
            manager.ProcessBlockAvailability(peer);
            mirror_process_availability(peer);
            const auto before_peer{*manager.GetPeerSnapshot(peer)};
            const auto before_global{manager.GetGlobalSnapshot()};
            const int failures{provider.ConsumeIntegralInRange<int>(0, 3)};
            const unsigned budget{provider.ConsumeIntegralInRange<unsigned>(0, 4)};
            fake_chain->FailRevalidations(failures);
            if (budget != 0 && provider.ConsumeBool()) {
                const size_t pos{provider.ConsumeIntegralInRange<size_t>(0, NUM_BLOCKS - 1)};
                fake_chain->SetRevalidateHook([&, pos] {
                    chain_data[pos] = !chain_data[pos];
                    fake_chain->SetCandidate({
                        .m_block = chain_blocks[pos],
                        .m_valid_tree = chain_valid[pos],
                        .m_have_data = chain_data[pos],
                        .m_in_active_chain = chain_active[pos],
                        .m_have_chain_txs = chain_txs[pos],
                        .m_segwit_active = chain_segwit[pos],
                    }, chain_parent[pos] ? std::optional{chain_blocks[*chain_parent[pos]].m_hash} : std::nullopt);
                });
            }
            const auto batch{manager.PlanAndReserve(
                peer,
                budget,
                now,
                provider.ConsumeBool())};
            const auto actual{*manager.GetPeerSnapshot(peer)};
            for (const auto& requested : batch.m_blocks) {
                Assert(manager.GetBlockInFlightInfo(requested.m_hash, peer).m_requested_from_peer);
            }

            if (failures == 3) {
                Assert(batch.m_blocks.empty());
                Assert(!batch.m_staller);
                Assert(actual.m_blocks == before_peer.m_blocks);
                Assert(actual.m_last_common_block == before_peer.m_last_common_block);
                Assert(manager.GetGlobalSnapshot().m_in_flight_generation == before_global.m_in_flight_generation);
            }

            if (actual.m_last_common_block != peers[peer].last_common) {
                peers[peer].last_common = actual.m_last_common_block;
                peers[peer].generation = ++next_peer_generation;
            }
            for (const auto& requested : batch.m_blocks) {
                Assert(find_request(peer, requested.m_hash) == peers[peer].requests.end());
                if (peers[peer].requests.empty()) peers[peer].downloading_since = now;
                peers[peer].requests.push_back({requested, {}});
                index.push_back({requested.m_hash, peer});
                peers[peer].generation = ++next_peer_generation;
                ++in_flight_generation;
            }
            if (batch.m_staller) {
                auto& stalled{peers[*batch.m_staller]};
                Assert(stalled.registered);
                Assert(stalled.stalling_since == std::chrono::microseconds{0});
                stalled.stalling_since = now;
                stalled.generation = ++next_peer_generation;
            }
            break;
        }
        }

        size_t total{0};
        int downloading_peers{0};
        int preferred_peers{0};
        int sync_started{0};
        for (NodeId id{0}; id < static_cast<NodeId>(NUM_PEERS); ++id) {
            const auto actual{manager.GetPeerSnapshot(id)};
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
            Assert(actual->m_is_inbound == peers[id].inbound);
            Assert(actual->m_preferred_download == peers[id].preferred);
            Assert(actual->m_can_serve_witness == peers[id].can_serve_witness);
            Assert(actual->m_limited_peer == peers[id].limited);
            Assert(actual->m_sync_started == peers[id].sync_started);
            Assert(actual->m_best_known_block == peers[id].best_known);
            Assert(actual->m_last_common_block == peers[id].last_common);
            Assert(actual->m_generation == peers[id].generation);
            last_peer_generation[id] = actual->m_generation;
            total += peers[id].requests.size();
            downloading_peers += !peers[id].requests.empty();
            preferred_peers += peers[id].preferred;
            sync_started += peers[id].sync_started;
        }
        const auto summary{manager.GetGlobalSnapshot()};
        Assert(summary.m_total_requests == total);
        Assert(summary.m_total_requests == index.size());
        Assert(summary.m_peers_downloading_from == downloading_peers);
        Assert(summary.m_num_preferred_download_peers == preferred_peers);
        Assert(summary.m_num_sync_started == sync_started);
        Assert(summary.m_in_flight_generation == in_flight_generation);
        Assert(summary.m_last_tip_update == last_tip_update);
        Assert(summary.m_block_stalling_timeout == stalling_timeout);
        Assert(manager.CheckConsistency());

        for (const auto& candidate : blocks) {
            bool outbound{false};
            for (const auto& request : index) {
                if (request.hash == candidate.m_hash && !peers[request.peer].inbound) outbound = true;
            }
            Assert(manager.IsBlockRequested(candidate.m_hash) == (count_hash(candidate.m_hash) != 0));
            Assert(manager.IsBlockRequestedFromOutbound(candidate.m_hash) == outbound);
            const size_t block_pos{static_cast<size_t>(candidate.m_height)};
            const auto source{manager.ConsumeBlockSource(candidate.m_hash)};
            Assert(source == sources[block_pos]);
            if (source) {
                Assert(manager.RecordBlockSource(
                    candidate.m_hash, source->m_peer, source->m_punish_on_invalid));
            }
        }
    }

    for (NodeId peer{0}; peer < static_cast<NodeId>(NUM_PEERS); ++peer) manager.DisconnectedPeer(peer);
    manager.CheckIsEmpty();
}

} // namespace

// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <blockencodings.h>
#include <node/blockdownloadman.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <latch>
#include <memory>
#include <optional>
#include <thread>
#include <utility>

using namespace std::chrono_literals;
using node::BlockDownloadBlock;
using node::BlockDownloadConnectionInfo;
using node::BlockDownloadManager;
using node::BlockRequestStatus;

namespace {

BlockDownloadBlock TestBlock(uint64_t value, int height)
{
    return {
        .m_hash = ArithToUint256(arith_uint256{value}),
        .m_height = height,
        .m_chain_work = arith_uint256{value * 100},
    };
}

template <typename Callable1, typename Callable2>
void RunConcurrently(Callable1&& callable_1, Callable2&& callable_2)
{
    std::latch ready{2};
    std::latch start{1};
    std::thread thread_1{[&] {
        ready.count_down();
        start.wait();
        callable_1();
    }};
    std::thread thread_2{[&] {
        ready.count_down();
        start.wait();
        callable_2();
    }};
    ready.wait();
    start.count_down();
    thread_1.join();
    thread_2.join();
}

} // namespace

BOOST_AUTO_TEST_SUITE(blockdownload_tests)

BOOST_AUTO_TEST_CASE(new_duplicate_parallel_and_removed_requests)
{
    BlockDownloadManager manager;
    const NodeId peer_1{1}, peer_2{2}, peer_3{3}, peer_4{4};
    manager.ConnectedPeer(peer_1, BlockDownloadConnectionInfo{.m_is_inbound = false});
    manager.ConnectedPeer(peer_2, BlockDownloadConnectionInfo{.m_is_inbound = true});
    manager.ConnectedPeer(peer_3, BlockDownloadConnectionInfo{.m_is_inbound = true});
    manager.ConnectedPeer(peer_4, BlockDownloadConnectionInfo{.m_is_inbound = false});
    const auto block{TestBlock(1, 10)};

    const auto first{manager.ReserveBlockRequest(peer_1, block, 10us)};
    BOOST_CHECK(first.m_status == BlockRequestStatus::NEW);
    BOOST_CHECK_EQUAL(first.m_requests_before, 0U);
    BOOST_CHECK(first.m_first_in_flight);

    const auto duplicate{manager.ReserveBlockRequest(peer_1, block, 11us)};
    BOOST_CHECK(duplicate.m_status == BlockRequestStatus::ALREADY_REQUESTED);
    BOOST_CHECK_EQUAL(duplicate.m_requests_before, 1U);
    BOOST_CHECK(duplicate.m_first_in_flight);

    const auto second{manager.ReserveBlockRequest(
        peer_2, block, 12us, std::make_shared<PartiallyDownloadedBlock>(nullptr))};
    BOOST_CHECK(second.m_status == BlockRequestStatus::NEW);
    BOOST_CHECK_EQUAL(second.m_requests_before, 1U);
    BOOST_CHECK(!second.m_first_in_flight);
    const auto third{manager.ReserveBlockRequest(
        peer_3, block, 13us, std::make_shared<PartiallyDownloadedBlock>(nullptr))};
    BOOST_CHECK(third.m_status == BlockRequestStatus::NEW);
    BOOST_CHECK_EQUAL(third.m_requests_before, 2U);

    const auto capped{manager.ReserveBlockRequest(
        peer_4, block, 14us, std::make_shared<PartiallyDownloadedBlock>(nullptr))};
    BOOST_CHECK(capped.m_status == BlockRequestStatus::MAX_REQUESTS_REACHED);
    BOOST_CHECK_EQUAL(capped.m_requests_before, node::MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    const auto info_1{manager.GetBlockInFlightInfo(block.m_hash, peer_1)};
    BOOST_CHECK_EQUAL(info_1.m_request_count, 3U);
    BOOST_REQUIRE(info_1.m_first_peer);
    BOOST_CHECK_EQUAL(*info_1.m_first_peer, peer_1);
    BOOST_CHECK(info_1.m_requested_from_peer);
    BOOST_CHECK(info_1.m_first_in_flight);
    BOOST_CHECK(manager.IsBlockRequested(block.m_hash));
    BOOST_CHECK(manager.IsBlockRequestedFromOutbound(block.m_hash));

    const auto wrong_peer{manager.RemoveBlockRequest(block.m_hash, peer_4, 20us)};
    BOOST_CHECK_EQUAL(wrong_peer.m_requests_before, 3U);
    BOOST_CHECK_EQUAL(wrong_peer.m_removed, 0U);

    const auto one_peer{manager.RemoveBlockRequest(block.m_hash, peer_2, 21us)};
    BOOST_CHECK_EQUAL(one_peer.m_requests_before, 3U);
    BOOST_CHECK_EQUAL(one_peer.m_removed, 1U);
    BOOST_CHECK_EQUAL(manager.GetBlockInFlightInfo(block.m_hash, peer_2).m_request_count, 2U);

    const auto all_peers{manager.RemoveBlockRequest(block.m_hash, std::nullopt, 22us)};
    BOOST_CHECK_EQUAL(all_peers.m_requests_before, 2U);
    BOOST_CHECK_EQUAL(all_peers.m_removed, 2U);
    BOOST_CHECK(!manager.IsBlockRequested(block.m_hash));
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_total_requests, 0U);
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_peers_downloading_from, 0);
    BOOST_CHECK(manager.CheckConsistency());

    manager.DisconnectedPeer(peer_1);
    manager.DisconnectedPeer(peer_2);
    manager.DisconnectedPeer(peer_3);
    manager.DisconnectedPeer(peer_4);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(queue_timers_stalling_and_disconnect_cleanup)
{
    BlockDownloadManager manager;
    const NodeId peer_1{1}, peer_2{2};
    manager.ConnectedPeer(peer_1, {.m_is_inbound = false});
    manager.ConnectedPeer(peer_2, {.m_is_inbound = true});
    const auto block_1{TestBlock(1, 1)};
    const auto block_2{TestBlock(2, 2)};
    const auto block_3{TestBlock(3, 3)};

    manager.ReserveBlockRequest(peer_1, block_1, 10us);
    manager.ReserveBlockRequest(peer_1, block_2, 11us);
    manager.ReserveBlockRequest(peer_2, block_3, 12us);

    const auto initial{manager.GetGlobalSnapshot()};
    BOOST_CHECK_EQUAL(initial.m_total_requests, 3U);
    BOOST_CHECK_EQUAL(initial.m_peers_downloading_from, 2);
    const auto copied_peer_info{*manager.GetPeerSnapshot(peer_1)};
    BOOST_REQUIRE_EQUAL(copied_peer_info.m_blocks.size(), 2U);
    BOOST_CHECK(copied_peer_info.m_blocks[0] == block_1);
    BOOST_CHECK(copied_peer_info.m_blocks[1] == block_2);
    BOOST_CHECK(copied_peer_info.m_downloading_since == 10us);

    const uint64_t generation_before_zero{manager.GetPeerSnapshot(peer_1)->m_generation};
    BOOST_CHECK(!manager.StartStalling(peer_1, 0us));
    BOOST_CHECK(manager.GetPeerSnapshot(peer_1)->m_stalling_since == 0us);
    BOOST_CHECK_EQUAL(manager.GetPeerSnapshot(peer_1)->m_generation, generation_before_zero);
    BOOST_CHECK(manager.StartStalling(peer_1, 15us));
    BOOST_CHECK(!manager.StartStalling(peer_1, 16us));
    BOOST_CHECK(manager.GetPeerSnapshot(peer_1)->m_stalling_since == 15us);

    // Removing a non-front request leaves the download timer unchanged but
    // clears stalling, matching the existing request-removal transition.
    manager.RemoveBlockRequest(block_2.m_hash, peer_1, 20us);
    auto peer_info{*manager.GetPeerSnapshot(peer_1)};
    BOOST_REQUIRE_EQUAL(peer_info.m_blocks.size(), 1U);
    BOOST_CHECK(peer_info.m_downloading_since == 10us);
    BOOST_CHECK(peer_info.m_stalling_since == 0us);

    BOOST_CHECK(manager.StartStalling(peer_1, 21us));
    manager.RemoveBlockRequest(block_1.m_hash, peer_1, 5us);
    peer_info = *manager.GetPeerSnapshot(peer_1);
    BOOST_CHECK(peer_info.m_blocks.empty());
    BOOST_CHECK(peer_info.m_downloading_since == 10us); // max(old, removal time)
    BOOST_CHECK(peer_info.m_stalling_since == 0us);
    BOOST_CHECK_EQUAL(peer_info.m_peers_downloading_from, 1);

    // Previously returned values are independent copies.
    BOOST_REQUIRE_EQUAL(copied_peer_info.m_blocks.size(), 2U);
    BOOST_CHECK(copied_peer_info.m_blocks[0] == block_1);
    BOOST_CHECK(copied_peer_info.m_downloading_since == 10us);

    manager.DisconnectedPeer(peer_2);
    BOOST_CHECK(!manager.IsBlockRequested(block_3.m_hash));
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_peers_downloading_from, 0);
    BOOST_CHECK(manager.CheckConsistency());
    manager.DisconnectedPeer(peer_1);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(compact_upgrade_duplicate_and_handle_lifetime)
{
    BlockDownloadManager manager;
    const NodeId peer{1};
    manager.ConnectedPeer(peer, {.m_is_inbound = false});
    const auto block{TestBlock(1, 1)};
    BOOST_CHECK(manager.ReserveBlockRequest(peer, block, 1us).m_status == BlockRequestStatus::NEW);

    auto proposed{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
    const std::weak_ptr<PartiallyDownloadedBlock> lifetime{proposed};
    const auto upgrade{manager.ReserveBlockRequest(peer, block, 2us, std::move(proposed))};
    BOOST_CHECK(upgrade.m_status == BlockRequestStatus::UPGRADED_TO_COMPACT);
    BOOST_CHECK_EQUAL(upgrade.m_requests_before, 1U);
    BOOST_REQUIRE(upgrade.m_partial_block);

    const auto copied_info{manager.GetBlockInFlightInfo(block.m_hash, peer)};
    BOOST_CHECK(copied_info.m_partial_block == upgrade.m_partial_block);
    auto duplicate_proposal{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
    const auto duplicate{manager.ReserveBlockRequest(peer, block, 3us, std::move(duplicate_proposal))};
    BOOST_CHECK(duplicate.m_status == BlockRequestStatus::DUPLICATE_COMPACT);
    BOOST_CHECK(duplicate.m_partial_block == upgrade.m_partial_block);

    manager.RemoveBlockRequest(block.m_hash, peer, 4us);
    BOOST_CHECK(!manager.GetBlockInFlightInfo(block.m_hash, peer).m_partial_block);
    BOOST_CHECK(!lifetime.expired());

    // Removal does not invalidate owned results. Mutation remains single-user
    // in this test, just as production message processing guarantees.
    copied_info.m_partial_block->header.nVersion = 7;
    BOOST_CHECK_EQUAL(upgrade.m_partial_block->header.nVersion, 7);

    manager.DisconnectedPeer(peer);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(connection_origin_and_missing_peer)
{
    BlockDownloadManager manager;
    const NodeId peer{1}, outbound_peer{2};
    const auto block{TestBlock(1, 1)};

    const auto missing{manager.ReserveBlockRequest(peer, block, 1us)};
    BOOST_CHECK(missing.m_status == BlockRequestStatus::PEER_NOT_FOUND);

    manager.ConnectedPeer(peer, {.m_is_inbound = true});
    manager.ConnectedPeer(peer, {.m_is_inbound = true}); // idempotent re-registration
    manager.ReserveBlockRequest(peer, block, 2us);
    BOOST_CHECK(!manager.IsBlockRequestedFromOutbound(block.m_hash));

    manager.ConnectedPeer(outbound_peer, {.m_is_inbound = false});
    manager.ReserveBlockRequest(outbound_peer, block, 3us);
    BOOST_CHECK(manager.IsBlockRequestedFromOutbound(block.m_hash));
    BOOST_CHECK(manager.AllRequestsAreFor(block.m_hash));

    const auto unrelated{TestBlock(2, 2)};
    BOOST_CHECK(!manager.AllRequestsAreFor(unrelated.m_hash));
    manager.DisconnectedPeer(peer);
    manager.DisconnectedPeer(outbound_peer);
    BOOST_CHECK(manager.AllRequestsAreFor(unrelated.m_hash)); // 0 == 0, preserving the original query
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(connection_reregistration_reconnect_counters_and_owned_snapshots)
{
    BlockDownloadManager manager;
    const NodeId peer{1}, other_peer{2};
    const auto block{TestBlock(1, 1)};
    manager.ConnectedPeer(peer, {
        .m_is_inbound = false,
        .m_preferred_download = true,
        .m_can_serve_witness = false,
        .m_limited_peer = true,
    });
    manager.ReserveBlockRequest(peer, block, 10us);
    BOOST_CHECK(manager.StartStalling(peer, 11us));
    BOOST_CHECK(manager.StartSync(peer));
    BOOST_CHECK(manager.RecordBlockSource(block.m_hash, peer, /*punish_on_invalid=*/true));

    const auto original{*manager.GetPeerSnapshot(peer)};
    const auto original_global{manager.GetGlobalSnapshot()};
    BOOST_CHECK(original.m_preferred_download);
    BOOST_CHECK(!original.m_can_serve_witness);
    BOOST_CHECK(original.m_limited_peer);
    BOOST_CHECK(original.m_sync_started);
    BOOST_CHECK_EQUAL(original.m_num_preferred_download_peers, 1);
    BOOST_CHECK_EQUAL(original.m_num_sync_started, 1);
    BOOST_CHECK_EQUAL(original_global.m_in_flight_generation, 1U);

    // Exact re-registration is idempotent, including its generation and counts.
    manager.ConnectedPeer(peer, {
        .m_is_inbound = false,
        .m_preferred_download = true,
        .m_can_serve_witness = false,
        .m_limited_peer = true,
    });
    const auto unchanged{*manager.GetPeerSnapshot(peer)};
    BOOST_CHECK_EQUAL(unchanged.m_generation, original.m_generation);
    BOOST_CHECK_EQUAL(unchanged.m_num_preferred_download_peers, 1);

    // Capability updates retain all queue, timer, sync, and source state.
    manager.ConnectedPeer(peer, {
        .m_is_inbound = false,
        .m_preferred_download = false,
        .m_can_serve_witness = true,
        .m_limited_peer = false,
    });
    const auto updated{*manager.GetPeerSnapshot(peer)};
    BOOST_CHECK(updated.m_generation > unchanged.m_generation);
    BOOST_CHECK(!updated.m_preferred_download);
    BOOST_CHECK(updated.m_can_serve_witness);
    BOOST_CHECK(!updated.m_limited_peer);
    BOOST_CHECK(updated.m_sync_started);
    BOOST_REQUIRE_EQUAL(updated.m_blocks.size(), 1U);
    BOOST_CHECK(updated.m_blocks.front() == block);
    BOOST_CHECK(updated.m_downloading_since == 10us);
    BOOST_CHECK(updated.m_stalling_since == 11us);
    BOOST_CHECK_EQUAL(updated.m_num_preferred_download_peers, 0);
    BOOST_CHECK_EQUAL(updated.m_num_sync_started, 1);
    BOOST_CHECK(manager.ConsumeBlockSource(block.m_hash) == (node::BlockSource{peer, true}));
    BOOST_CHECK(manager.RecordBlockSource(block.m_hash, peer, /*punish_on_invalid=*/true));
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_in_flight_generation, 1U);

    manager.ConnectedPeer(peer, {.m_is_inbound = false, .m_preferred_download = true});
    manager.ConnectedPeer(other_peer, {.m_is_inbound = true, .m_preferred_download = true});
    manager.ConnectedPeer(other_peer, {.m_is_inbound = true, .m_preferred_download = true});
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_num_preferred_download_peers, 2);
    const auto before_disconnect{*manager.GetPeerSnapshot(peer)};

    // Previously returned snapshots remain independent owned values.
    BOOST_CHECK(original.m_preferred_download);
    BOOST_CHECK(!original.m_can_serve_witness);
    BOOST_REQUIRE_EQUAL(original.m_blocks.size(), 1U);
    BOOST_CHECK_EQUAL(original_global.m_num_preferred_download_peers, 1);

    manager.DisconnectedPeer(peer);
    auto global{manager.GetGlobalSnapshot()};
    BOOST_CHECK_EQUAL(global.m_num_preferred_download_peers, 1);
    BOOST_CHECK_EQUAL(global.m_num_sync_started, 0);
    BOOST_CHECK(!manager.ConsumeBlockSource(block.m_hash));
    BOOST_REQUIRE_EQUAL(original.m_blocks.size(), 1U);
    BOOST_CHECK(original.m_blocks.front() == block);
    BOOST_CHECK_EQUAL(original_global.m_total_requests, 1U);
    BOOST_CHECK_EQUAL(original_global.m_num_sync_started, 1);

    manager.ConnectedPeer(peer, {
        .m_is_inbound = true,
        .m_preferred_download = false,
        .m_can_serve_witness = false,
        .m_limited_peer = false,
    });
    const auto reconnected{*manager.GetPeerSnapshot(peer)};
    BOOST_CHECK(reconnected.m_generation > before_disconnect.m_generation);
    BOOST_CHECK(reconnected.m_blocks.empty());
    BOOST_CHECK(reconnected.m_downloading_since == 0us);
    BOOST_CHECK(reconnected.m_stalling_since == 0us);
    BOOST_CHECK(reconnected.m_is_inbound);
    BOOST_CHECK(!reconnected.m_preferred_download);
    BOOST_CHECK(!reconnected.m_can_serve_witness);
    BOOST_CHECK(!reconnected.m_limited_peer);
    BOOST_CHECK(!reconnected.m_sync_started);
    BOOST_CHECK_EQUAL(reconnected.m_total_requests, 0U);
    BOOST_CHECK_EQUAL(reconnected.m_peers_downloading_from, 0);
    BOOST_CHECK_EQUAL(reconnected.m_num_preferred_download_peers, 1);
    BOOST_CHECK_EQUAL(reconnected.m_num_sync_started, 0);
    BOOST_CHECK(!manager.IsBlockRequested(block.m_hash));
    BOOST_CHECK(!manager.ConsumeBlockSource(block.m_hash));

    // The pre-disconnect owned snapshot is still unchanged and valid after reconnect.
    BOOST_CHECK(before_disconnect.m_preferred_download);
    BOOST_CHECK(!before_disconnect.m_can_serve_witness);
    BOOST_CHECK(!before_disconnect.m_limited_peer);
    BOOST_CHECK(before_disconnect.m_sync_started);
    BOOST_CHECK(before_disconnect.m_downloading_since == 10us);
    BOOST_CHECK(before_disconnect.m_stalling_since == 11us);
    BOOST_REQUIRE_EQUAL(before_disconnect.m_blocks.size(), 1U);
    BOOST_CHECK(before_disconnect.m_blocks.front() == block);

    manager.DisconnectedPeer(peer);
    manager.DisconnectedPeer(other_peer);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(sync_stale_tip_timeout_and_generations)
{
    BlockDownloadManager manager;
    const NodeId peer{1};
    const auto block_1{TestBlock(1, 1)};
    const auto block_2{TestBlock(2, 2)};
    manager.ConnectedPeer(peer, {.m_is_inbound = false, .m_preferred_download = true});

    auto peer_state{*manager.GetPeerSnapshot(peer)};
    const uint64_t connected_generation{peer_state.m_generation};
    BOOST_CHECK(manager.StartSync(peer));
    BOOST_CHECK(!manager.StartSync(peer));
    peer_state = *manager.GetPeerSnapshot(peer);
    BOOST_CHECK(peer_state.m_sync_started);
    BOOST_CHECK(peer_state.m_generation > connected_generation);
    BOOST_CHECK_EQUAL(peer_state.m_num_sync_started, 1);
    BOOST_CHECK(manager.ClearSync(peer));
    BOOST_CHECK(!manager.ClearSync(peer));
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_num_sync_started, 0);

    auto global{manager.GetGlobalSnapshot()};
    BOOST_CHECK(global.m_last_tip_update == 0s);
    BOOST_CHECK(global.m_block_stalling_timeout == node::DEFAULT_BLOCK_STALLING_TIMEOUT);
    BOOST_CHECK(!manager.TipMayBeStale(100s, 30s));
    BOOST_CHECK(manager.GetGlobalSnapshot().m_last_tip_update == 100s);
    BOOST_CHECK(!manager.TipMayBeStale(130s, 30s)); // Strictly older, not equal.
    BOOST_CHECK(manager.TipMayBeStale(131s, 30s));

    manager.ReserveBlockRequest(peer, block_1, 1us);
    global = manager.GetGlobalSnapshot();
    BOOST_CHECK_EQUAL(global.m_in_flight_generation, 1U);
    BOOST_CHECK(!manager.TipMayBeStale(200s, 30s));
    manager.ReserveBlockRequest(peer, block_1, 2us); // Duplicate is not a set change.
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_in_flight_generation, 1U);
    manager.ReserveBlockRequest(
        peer, block_1, 3us, std::make_shared<PartiallyDownloadedBlock>(nullptr));
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_in_flight_generation, 1U);
    manager.ReserveBlockRequest(peer, block_2, 4us);
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_in_flight_generation, 2U);
    manager.RemoveBlockRequest(block_1.m_hash, peer, 5us);
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_in_flight_generation, 3U);

    manager.UpdatedBlockTip(300s);
    BOOST_CHECK(!manager.TipMayBeStale(330s, 30s));
    manager.RemoveBlockRequest(block_2.m_hash, peer, 6us);
    BOOST_CHECK(manager.TipMayBeStale(331s, 30s));
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_in_flight_generation, 4U);

    BOOST_CHECK(manager.TryIncreaseBlockStallingTimeout(2s) == 4s);
    BOOST_CHECK(!manager.TryIncreaseBlockStallingTimeout(2s));
    BOOST_CHECK(manager.GetGlobalSnapshot().m_block_stalling_timeout == 4s);
    BOOST_CHECK(manager.TryDecreaseBlockStallingTimeout(4s) == 3s);
    BOOST_CHECK(manager.GetGlobalSnapshot().m_block_stalling_timeout == 3s);

    manager.ReserveBlockRequest(peer, block_1, 7us);
    manager.ReserveBlockRequest(peer, block_2, 8us);
    const auto before_disconnect{manager.GetGlobalSnapshot().m_in_flight_generation};
    manager.DisconnectedPeer(peer);
    BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_in_flight_generation, before_disconnect + 1);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(block_source_first_writer_consume_erase_and_disconnect)
{
    BlockDownloadManager manager;
    const NodeId peer_1{1}, peer_2{2};
    const auto hash_1{TestBlock(1, 1).m_hash};
    const auto hash_2{TestBlock(2, 2).m_hash};
    BOOST_CHECK(!manager.RecordBlockSource(hash_1, peer_1, /*punish_on_invalid=*/true));
    manager.ConnectedPeer(peer_1, {.m_is_inbound = false});
    manager.ConnectedPeer(peer_2, {.m_is_inbound = true});

    BOOST_CHECK(manager.RecordBlockSource(hash_1, peer_1, /*punish_on_invalid=*/false));
    BOOST_CHECK(!manager.RecordBlockSource(hash_1, peer_2, /*punish_on_invalid=*/true));
    const auto consumed{manager.ConsumeBlockSource(hash_1)};
    BOOST_CHECK(consumed == (node::BlockSource{peer_1, false}));
    BOOST_CHECK(!manager.ConsumeBlockSource(hash_1));

    BOOST_CHECK(manager.RecordBlockSource(hash_1, peer_2, /*punish_on_invalid=*/true));
    BOOST_CHECK(manager.EraseBlockSource(hash_1));
    BOOST_CHECK(!manager.EraseBlockSource(hash_1));
    BOOST_CHECK(manager.RecordBlockSource(hash_2, peer_1, /*punish_on_invalid=*/true));
    manager.DisconnectedPeer(peer_1);
    BOOST_CHECK(!manager.ConsumeBlockSource(hash_2));
    BOOST_CHECK(!manager.RecordBlockSource(hash_2, peer_1, /*punish_on_invalid=*/true));

    manager.DisconnectedPeer(peer_2);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(all_requests_are_for_mixed_hash)
{
    BlockDownloadManager manager;
    const NodeId peer{1};
    const auto block_1{TestBlock(1, 1)};
    const auto block_2{TestBlock(2, 2)};
    manager.ConnectedPeer(peer, {.m_is_inbound = false});
    manager.ReserveBlockRequest(peer, block_1, 1us);
    manager.ReserveBlockRequest(peer, block_2, 2us);

    BOOST_CHECK(!manager.AllRequestsAreFor(block_1.m_hash));
    BOOST_CHECK(!manager.AllRequestsAreFor(block_2.m_hash));

    manager.DisconnectedPeer(peer);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(concurrent_connect_disconnect_snapshot)
{
    static constexpr int iterations{32};
    const NodeId peer{1};
    for (int i{0}; i < iterations; ++i) {
        BlockDownloadManager manager;
        RunConcurrently(
            [&] {
                manager.ConnectedPeer(peer, {
                    .m_is_inbound = false,
                    .m_preferred_download = true,
                    .m_can_serve_witness = true,
                });
            },
            [&] { manager.DisconnectedPeer(peer); });

        if (const auto snapshot{manager.GetPeerSnapshot(peer)}) {
            BOOST_CHECK(!snapshot->m_is_inbound);
            BOOST_CHECK(snapshot->m_preferred_download);
            BOOST_CHECK(snapshot->m_can_serve_witness);
        }
        BOOST_CHECK(manager.CheckConsistency());
        manager.DisconnectedPeer(peer);
        manager.CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(concurrent_snapshot_remove_and_owned_lifetime)
{
    BlockDownloadManager manager;
    const NodeId peer{1};
    const auto block{TestBlock(1, 1)};
    manager.ConnectedPeer(peer, {.m_is_inbound = false});
    BOOST_REQUIRE(manager.ReserveBlockRequest(peer, block, 1us).m_status == BlockRequestStatus::NEW);
    const uint64_t requested_generation{manager.GetPeerSnapshot(peer)->m_generation};

    std::optional<node::PeerBlockDownloadSnapshot> snapshot_result;
    std::optional<node::BlockRequestRemoval> removal_result;
    RunConcurrently(
        [&] { snapshot_result = manager.GetPeerSnapshot(peer); },
        [&] { removal_result = manager.RemoveBlockRequest(block.m_hash, peer, 2us); });

    BOOST_REQUIRE(snapshot_result);
    BOOST_REQUIRE(removal_result);
    BOOST_CHECK_EQUAL(removal_result->m_requests_before, 1U);
    BOOST_CHECK_EQUAL(removal_result->m_removed, 1U);
    BOOST_CHECK(snapshot_result->m_blocks.empty() ||
                (snapshot_result->m_blocks.size() == 1 && snapshot_result->m_blocks.front() == block));
    if (snapshot_result->m_blocks.empty()) {
        BOOST_CHECK_EQUAL(snapshot_result->m_total_requests, 0U);
        BOOST_CHECK(snapshot_result->m_generation > requested_generation);
    } else {
        BOOST_CHECK_EQUAL(snapshot_result->m_total_requests, 1U);
        BOOST_CHECK_EQUAL(snapshot_result->m_generation, requested_generation);
    }
    BOOST_CHECK(!manager.IsBlockRequested(block.m_hash));
    // The owned vector remains valid after the concurrent removal completes.
    if (!snapshot_result->m_blocks.empty()) BOOST_CHECK(snapshot_result->m_blocks.front() == block);
    manager.DisconnectedPeer(peer);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(concurrent_source_first_writer_consume_and_disconnect)
{
    BlockDownloadManager manager;
    const NodeId peer_1{1}, peer_2{2};
    const auto hash{TestBlock(1, 1).m_hash};
    const auto disconnect_hash{TestBlock(2, 2).m_hash};
    manager.ConnectedPeer(peer_1, {.m_is_inbound = false});
    manager.ConnectedPeer(peer_2, {.m_is_inbound = true});

    bool writer_1{false};
    bool writer_2{false};
    RunConcurrently(
        [&] { writer_1 = manager.RecordBlockSource(hash, peer_1, /*punish_on_invalid=*/false); },
        [&] { writer_2 = manager.RecordBlockSource(hash, peer_2, /*punish_on_invalid=*/true); });

    BOOST_CHECK_NE(writer_1, writer_2);
    const auto consumed{manager.ConsumeBlockSource(hash)};
    BOOST_REQUIRE(consumed);
    BOOST_CHECK(*consumed == (writer_1 ? node::BlockSource{peer_1, false} : node::BlockSource{peer_2, true}));
    BOOST_CHECK(!manager.ConsumeBlockSource(hash));

    const NodeId winning_peer{consumed->m_peer};
    BOOST_CHECK(manager.RecordBlockSource(disconnect_hash, winning_peer, consumed->m_punish_on_invalid));
    manager.DisconnectedPeer(winning_peer);
    BOOST_CHECK(!manager.ConsumeBlockSource(disconnect_hash));
    // The consumed owned value remains valid after its peer is disconnected.
    BOOST_CHECK_EQUAL(consumed->m_peer, winning_peer);

    manager.DisconnectedPeer(peer_1);
    manager.DisconnectedPeer(peer_2);
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(concurrent_capability_and_sync_disconnect_linearization)
{
    const NodeId peer{1};
    {
        BlockDownloadManager manager;
        manager.ConnectedPeer(peer, {
            .m_is_inbound = false,
            .m_preferred_download = false,
            .m_can_serve_witness = false,
            .m_limited_peer = true,
        });
        const uint64_t old_generation{manager.GetPeerSnapshot(peer)->m_generation};
        std::optional<node::PeerBlockDownloadSnapshot> snapshot_result;
        RunConcurrently(
            [&] {
                manager.ConnectedPeer(peer, {
                    .m_is_inbound = false,
                    .m_preferred_download = true,
                    .m_can_serve_witness = true,
                    .m_limited_peer = false,
                });
            },
            [&] { snapshot_result = manager.GetPeerSnapshot(peer); });

        BOOST_REQUIRE(snapshot_result);
        const bool old_state{!snapshot_result->m_preferred_download};
        if (old_state) {
            BOOST_CHECK(!snapshot_result->m_can_serve_witness);
            BOOST_CHECK(snapshot_result->m_limited_peer);
            BOOST_CHECK_EQUAL(snapshot_result->m_num_preferred_download_peers, 0);
            BOOST_CHECK_EQUAL(snapshot_result->m_generation, old_generation);
        } else {
            BOOST_CHECK(snapshot_result->m_can_serve_witness);
            BOOST_CHECK(!snapshot_result->m_limited_peer);
            BOOST_CHECK_EQUAL(snapshot_result->m_num_preferred_download_peers, 1);
            BOOST_CHECK(snapshot_result->m_generation > old_generation);
        }
        manager.DisconnectedPeer(peer);
        manager.CheckIsEmpty();
    }
    {
        BlockDownloadManager manager;
        manager.ConnectedPeer(peer, {.m_is_inbound = false});
        std::optional<bool> started;
        RunConcurrently(
            [&] { started = manager.StartSync(peer); },
            [&] { manager.DisconnectedPeer(peer); });
        BOOST_REQUIRE(started);
        // true means start linearized first; false means disconnect did.
        BOOST_CHECK(!manager.GetPeerSnapshot(peer));
        BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_num_sync_started, 0);
        manager.CheckIsEmpty();
    }
    {
        BlockDownloadManager manager;
        manager.ConnectedPeer(peer, {.m_is_inbound = false});
        BOOST_REQUIRE(manager.StartSync(peer));
        std::optional<bool> cleared;
        RunConcurrently(
            [&] { cleared = manager.ClearSync(peer); },
            [&] { manager.DisconnectedPeer(peer); });
        BOOST_REQUIRE(cleared);
        // true means clear linearized first; false means disconnect did.
        BOOST_CHECK(!manager.GetPeerSnapshot(peer));
        BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_num_sync_started, 0);
        manager.CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(concurrent_stale_tip_and_timeout_commands)
{
    {
        BlockDownloadManager manager;
        manager.UpdatedBlockTip(100s);
        std::optional<std::pair<bool, node::BlockDownloadGlobalSnapshot>> observation;
        RunConcurrently(
            [&] {
                const bool stale{manager.TipMayBeStale(200s, 30s)};
                observation.emplace(stale, manager.GetGlobalSnapshot());
            },
            [&] { manager.UpdatedBlockTip(190s); });
        BOOST_REQUIRE(observation);
        const auto& [stale, snapshot]{*observation};
        // Query and its following snapshot can both precede the update, straddle
        // it, or both follow it. These are the complete legal outcomes.
        BOOST_CHECK((stale && snapshot.m_last_tip_update == 100s) ||
                    (stale && snapshot.m_last_tip_update == 190s) ||
                    (!stale && snapshot.m_last_tip_update == 190s));
        BOOST_CHECK(manager.GetGlobalSnapshot().m_last_tip_update == 190s);
    }
    {
        BlockDownloadManager manager;
        const NodeId peer{1};
        const auto block{TestBlock(1, 1)};
        manager.ConnectedPeer(peer, {.m_is_inbound = false});
        manager.UpdatedBlockTip(100s);
        manager.ReserveBlockRequest(peer, block, 1us);
        std::optional<std::pair<bool, node::BlockDownloadGlobalSnapshot>> observation;
        std::optional<node::BlockRequestRemoval> removal_result;
        RunConcurrently(
            [&] {
                const bool stale{manager.TipMayBeStale(200s, 30s)};
                observation.emplace(stale, manager.GetGlobalSnapshot());
            },
            [&] { removal_result = manager.RemoveBlockRequest(block.m_hash, peer, 2us); });
        BOOST_REQUIRE(observation);
        const auto& [stale, snapshot]{*observation};
        // Query and its following snapshot can both precede removal, straddle
        // it, or both follow it. A stale result with a remaining request is
        // impossible because each query is one manager-mutex transaction.
        BOOST_CHECK((!stale && snapshot.m_total_requests == 1U) ||
                    (!stale && snapshot.m_total_requests == 0U) ||
                    (stale && snapshot.m_total_requests == 0U));
        BOOST_REQUIRE(removal_result);
        BOOST_CHECK_EQUAL(removal_result->m_removed, 1U);
        BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_total_requests, 0U);
        manager.DisconnectedPeer(peer);
        manager.CheckIsEmpty();
    }
    {
        BlockDownloadManager manager;
        BOOST_REQUIRE(manager.TryIncreaseBlockStallingTimeout(2s) == 4s);
        std::optional<std::chrono::seconds> increased;
        std::optional<std::chrono::seconds> decreased;
        RunConcurrently(
            [&] { increased = manager.TryIncreaseBlockStallingTimeout(4s); },
            [&] { decreased = manager.TryDecreaseBlockStallingTimeout(4s); });
        BOOST_REQUIRE(increased.has_value() != decreased.has_value());
        const auto final_timeout{manager.GetGlobalSnapshot().m_block_stalling_timeout};
        BOOST_CHECK(final_timeout == (increased ? *increased : *decreased));
        BOOST_CHECK(final_timeout >= 2s);
        BOOST_CHECK(final_timeout <= 64s);

        auto timeout{final_timeout};
        while (const auto next{manager.TryDecreaseBlockStallingTimeout(timeout)}) timeout = *next;
        BOOST_CHECK(timeout == 2s);
        BOOST_CHECK(!manager.TryDecreaseBlockStallingTimeout(2s));
        while (const auto next{manager.TryIncreaseBlockStallingTimeout(timeout)}) timeout = *next;
        BOOST_CHECK(timeout == 64s);
        BOOST_CHECK(!manager.TryIncreaseBlockStallingTimeout(64s));
        BOOST_CHECK(manager.GetGlobalSnapshot().m_block_stalling_timeout == 64s);
    }
}

BOOST_AUTO_TEST_CASE(concurrent_reserve_disconnect_and_remove)
{
    static constexpr int iterations{32};
    const NodeId peer{1};
    const auto block{TestBlock(1, 1)};

    for (int i{0}; i < iterations; ++i) {
        BlockDownloadManager manager;
        manager.ConnectedPeer(peer, {.m_is_inbound = false});
        std::optional<node::BlockRequestReservation> reservation;
        std::optional<node::PeerBlockDownloadSnapshot> copied_snapshot;
        std::optional<node::BlockSource> copied_source;
        std::weak_ptr<PartiallyDownloadedBlock> partial_lifetime;

        RunConcurrently(
            [&] {
                manager.RecordBlockSource(block.m_hash, peer, /*punish_on_invalid=*/true);
                copied_source = manager.ConsumeBlockSource(block.m_hash);
                if (const auto snapshot{manager.GetPeerSnapshot(peer)}) copied_snapshot = *snapshot;
                auto partial{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
                partial_lifetime = partial;
                reservation.emplace(manager.ReserveBlockRequest(peer, block, 1us, std::move(partial)));
            },
            [&] { manager.DisconnectedPeer(peer); });

        BOOST_REQUIRE(reservation);
        BOOST_CHECK(reservation->m_status == BlockRequestStatus::NEW ||
                    reservation->m_status == BlockRequestStatus::PEER_NOT_FOUND);
        BOOST_CHECK(!manager.GetPeerSnapshot(peer));
        BOOST_CHECK(!manager.IsBlockRequested(block.m_hash));
        BOOST_CHECK(!manager.ConsumeBlockSource(block.m_hash));
        if (copied_source) BOOST_CHECK(*copied_source == (node::BlockSource{peer, true}));
        if (copied_snapshot) BOOST_CHECK_EQUAL(copied_snapshot->m_is_inbound, false);
        const auto info{manager.GetBlockInFlightInfo(block.m_hash, peer)};
        BOOST_CHECK_EQUAL(info.m_request_count, 0U);
        BOOST_CHECK(!info.m_requested_from_peer);
        BOOST_CHECK(!info.m_partial_block);
        const auto summary{manager.GetGlobalSnapshot()};
        BOOST_CHECK_EQUAL(summary.m_total_requests, 0U);
        BOOST_CHECK_EQUAL(summary.m_peers_downloading_from, 0);
        BOOST_CHECK(manager.CheckConsistency());
        manager.CheckIsEmpty();

        const bool reserved{reservation->m_status == BlockRequestStatus::NEW};
        BOOST_CHECK_EQUAL(static_cast<bool>(reservation->m_partial_block), reserved);
        BOOST_CHECK_EQUAL(partial_lifetime.expired(), !reserved);
        reservation->m_partial_block.reset();
        BOOST_CHECK(partial_lifetime.expired());
    }

    for (int i{0}; i < iterations; ++i) {
        BlockDownloadManager manager;
        manager.ConnectedPeer(peer, {.m_is_inbound = false});
        std::optional<node::BlockRequestReservation> reservation;
        std::optional<node::BlockRequestRemoval> removal;
        std::weak_ptr<PartiallyDownloadedBlock> partial_lifetime;

        RunConcurrently(
            [&] {
                auto partial{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
                partial_lifetime = partial;
                reservation.emplace(manager.ReserveBlockRequest(peer, block, 1us, std::move(partial)));
            },
            [&] { removal.emplace(manager.RemoveBlockRequest(block.m_hash, peer, 2us)); });

        BOOST_REQUIRE(reservation);
        BOOST_REQUIRE(removal);
        BOOST_CHECK(reservation->m_status == BlockRequestStatus::NEW);
        BOOST_CHECK((removal->m_requests_before == 0U && removal->m_removed == 0U) ||
                    (removal->m_requests_before == 1U && removal->m_removed == 1U));
        auto info{manager.GetBlockInFlightInfo(block.m_hash, peer)};
        const bool removed{removal->m_removed == 1U};
        BOOST_CHECK_EQUAL(info.m_request_count, removed ? 0U : 1U);
        BOOST_CHECK_EQUAL(info.m_requested_from_peer, !removed);
        BOOST_CHECK_EQUAL(info.m_partial_block == reservation->m_partial_block, !removed);
        BOOST_CHECK(manager.CheckConsistency());

        manager.RemoveBlockRequest(block.m_hash, peer, 3us);
        BOOST_CHECK(!manager.IsBlockRequested(block.m_hash));
        BOOST_CHECK_EQUAL(manager.GetGlobalSnapshot().m_total_requests, 0U);
        info.m_partial_block.reset();
        reservation->m_partial_block.reset();
        BOOST_CHECK(partial_lifetime.expired());
        manager.DisconnectedPeer(peer);
        BOOST_CHECK(manager.CheckConsistency());
        manager.CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_SUITE_END()

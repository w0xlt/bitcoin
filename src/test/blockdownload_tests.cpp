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
    BOOST_CHECK_EQUAL(manager.GetRequestSummary().m_total_requests, 0U);
    BOOST_CHECK_EQUAL(manager.GetRequestSummary().m_peers_downloading_from, 0);
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

    const auto initial{manager.GetRequestSummary()};
    BOOST_CHECK_EQUAL(initial.m_total_requests, 3U);
    BOOST_CHECK_EQUAL(initial.m_peers_downloading_from, 2);
    const auto copied_peer_info{*manager.GetPeerRequestInfo(peer_1)};
    BOOST_REQUIRE_EQUAL(copied_peer_info.m_blocks.size(), 2U);
    BOOST_CHECK(copied_peer_info.m_blocks[0] == block_1);
    BOOST_CHECK(copied_peer_info.m_blocks[1] == block_2);
    BOOST_CHECK(copied_peer_info.m_downloading_since == 10us);

    BOOST_CHECK(manager.StartStalling(peer_1, 15us));
    BOOST_CHECK(!manager.StartStalling(peer_1, 16us));
    BOOST_CHECK(manager.GetPeerRequestInfo(peer_1)->m_stalling_since == 15us);

    // Removing a non-front request leaves the download timer unchanged but
    // clears stalling, matching the existing request-removal transition.
    manager.RemoveBlockRequest(block_2.m_hash, peer_1, 20us);
    auto peer_info{*manager.GetPeerRequestInfo(peer_1)};
    BOOST_REQUIRE_EQUAL(peer_info.m_blocks.size(), 1U);
    BOOST_CHECK(peer_info.m_downloading_since == 10us);
    BOOST_CHECK(peer_info.m_stalling_since == 0us);

    BOOST_CHECK(manager.StartStalling(peer_1, 21us));
    manager.RemoveBlockRequest(block_1.m_hash, peer_1, 5us);
    peer_info = *manager.GetPeerRequestInfo(peer_1);
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
    BOOST_CHECK_EQUAL(manager.GetRequestSummary().m_peers_downloading_from, 0);
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

BOOST_AUTO_TEST_CASE(concurrent_reserve_disconnect_and_remove)
{
    static constexpr int iterations{32};
    const NodeId peer{1};
    const auto block{TestBlock(1, 1)};

    for (int i{0}; i < iterations; ++i) {
        BlockDownloadManager manager;
        manager.ConnectedPeer(peer, {.m_is_inbound = false});
        std::optional<node::BlockRequestReservation> reservation;
        std::weak_ptr<PartiallyDownloadedBlock> partial_lifetime;

        RunConcurrently(
            [&] {
                auto partial{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
                partial_lifetime = partial;
                reservation.emplace(manager.ReserveBlockRequest(peer, block, 1us, std::move(partial)));
            },
            [&] { manager.DisconnectedPeer(peer); });

        BOOST_REQUIRE(reservation);
        BOOST_CHECK(reservation->m_status == BlockRequestStatus::NEW ||
                    reservation->m_status == BlockRequestStatus::PEER_NOT_FOUND);
        BOOST_CHECK(!manager.GetPeerRequestInfo(peer));
        BOOST_CHECK(!manager.IsBlockRequested(block.m_hash));
        const auto info{manager.GetBlockInFlightInfo(block.m_hash, peer)};
        BOOST_CHECK_EQUAL(info.m_request_count, 0U);
        BOOST_CHECK(!info.m_requested_from_peer);
        BOOST_CHECK(!info.m_partial_block);
        const auto summary{manager.GetRequestSummary()};
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
        BOOST_CHECK_EQUAL(manager.GetRequestSummary().m_total_requests, 0U);
        info.m_partial_block.reset();
        reservation->m_partial_block.reset();
        BOOST_CHECK(partial_lifetime.expired());
        manager.DisconnectedPeer(peer);
        BOOST_CHECK(manager.CheckConsistency());
        manager.CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_SUITE_END()

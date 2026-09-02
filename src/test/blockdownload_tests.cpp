// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <blockencodings.h>
#include <chain.h>
#include <node/blockdownloadchain_impl.h>
#include <node/blockdownloadman.h>
#include <script/script.h>
#include <test/util/blockdownloadchain.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <functional>
#include <latch>
#include <memory>
#include <optional>
#include <thread>
#include <utility>

using namespace std::chrono_literals;
using node::BlockDownloadBlock;
using node::BlockDownloadCandidate;
using node::BlockDownloadConnectionInfo;
using node::BlockDownloadManager;
using node::BlockDownloadAssumeutxoState;
using node::BlockRequestStatus;
using node::test::FakeBlockDownloadChain;

namespace {

BlockDownloadBlock TestBlock(uint64_t value, int height)
{
    return {
        .m_hash = ArithToUint256(arith_uint256{value}),
        .m_height = height,
        .m_chain_work = arith_uint256{value * 100},
    };
}

BlockDownloadCandidate TestCandidate(
    BlockDownloadBlock block,
    bool valid_tree = true,
    bool have_data = false,
    bool in_active_chain = false,
    bool have_chain_txs = false,
    bool segwit_active = false)
{
    return {
        .m_block = std::move(block),
        .m_valid_tree = valid_tree,
        .m_have_data = have_data,
        .m_in_active_chain = in_active_chain,
        .m_have_chain_txs = have_chain_txs,
        .m_segwit_active = segwit_active,
    };
}

void SetPlanningTip(FakeBlockDownloadChain& chain, const BlockDownloadBlock& tip)
{
    chain.SetActiveTip(tip.m_hash);
    chain.SetCurrentChainstate(tip.m_hash);
    chain.SetMinimumChainWork(0);
}

std::unique_ptr<BlockDownloadManager> MakeManager()
{
    return node::MakeBlockDownloadManager(std::make_unique<FakeBlockDownloadChain>());
}

class BlockDataCleanupSubscriber final : public CValidationInterface
{
public:
    BlockDataCleanupSubscriber(
        BlockDownloadManager& manager,
        ChainstateManager& chainman,
        uint256 target,
        NodeId peer)
        : m_manager{manager}, m_chainman{chainman}, m_target{std::move(target)}, m_peer{peer}
    {
    }

    void BlockDataAvailable(const uint256& hash) override EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        if (hash != m_target) return;

        AssertLockHeld(cs_main);
        const CBlockIndex* index{m_chainman.m_blockman.LookupBlockIndex(hash)};
        m_called = true;
        m_saw_have_data = index && (index->nStatus & BLOCK_HAVE_DATA);
        m_saw_side_chain = index && !m_chainman.ActiveChain().Contains(*index);
        m_saw_request = m_manager.IsBlockRequested(hash);
        m_removed = m_manager.RemoveBlockRequest(hash, m_peer, 2us).m_removed;
    }

    bool m_called{false};
    bool m_saw_have_data{false};
    bool m_saw_side_chain{false};
    bool m_saw_request{false};
    size_t m_removed{0};

private:
    BlockDownloadManager& m_manager;
    ChainstateManager& m_chainman;
    const uint256 m_target;
    const NodeId m_peer;
};

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

BOOST_AUTO_TEST_CASE(availability_resolution_comparison_and_owned_snapshots)
{
    auto fake{std::make_unique<FakeBlockDownloadChain>()};
    auto* const chain{fake.get()};
    auto manager{node::MakeBlockDownloadManager(std::move(fake))};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false});

    const auto first{TestBlock(1, 1)};
    auto equal_work{TestBlock(2, 2)};
    equal_work.m_chain_work = first.m_chain_work;
    auto lower_work{TestBlock(3, 3)};
    lower_work.m_chain_work = first.m_chain_work - 1;
    auto nonpositive{TestBlock(4, 4)};
    nonpositive.m_chain_work = 0;
    const auto unknown_1{TestBlock(5, 5)};
    const auto unknown_2{TestBlock(6, 6)};

    chain->SetBlock(first);
    chain->SetBlock(equal_work);
    chain->SetBlock(lower_work);
    chain->SetBlock(nonpositive);

    manager->UpdateBlockAvailability(peer, first.m_hash);
    auto snapshot{*manager->GetPeerSnapshot(peer)};
    BOOST_REQUIRE(snapshot.m_best_known_block);
    BOOST_CHECK(*snapshot.m_best_known_block == first);
    const uint64_t first_generation{snapshot.m_generation};

    manager->UpdateBlockAvailability(peer, lower_work.m_hash);
    BOOST_CHECK_EQUAL(manager->GetPeerSnapshot(peer)->m_generation, first_generation);
    manager->UpdateBlockAvailability(peer, equal_work.m_hash);
    snapshot = *manager->GetPeerSnapshot(peer);
    BOOST_REQUIRE(snapshot.m_best_known_block);
    BOOST_CHECK(*snapshot.m_best_known_block == equal_work); // Equal work replaces.
    const auto owned_snapshot{snapshot};

    manager->UpdateBlockAvailability(peer, unknown_1.m_hash);
    manager->UpdateBlockAvailability(peer, unknown_2.m_hash); // Latest unknown replaces pending.
    const uint64_t unknown_generation{manager->GetPeerSnapshot(peer)->m_generation};
    manager->ProcessBlockAvailability(peer);
    BOOST_CHECK_EQUAL(manager->GetPeerSnapshot(peer)->m_generation, unknown_generation);

    auto now_known_1{unknown_1};
    now_known_1.m_chain_work = equal_work.m_chain_work + 100;
    chain->SetBlock(now_known_1);
    manager->ProcessBlockAvailability(peer);
    BOOST_CHECK(*manager->GetPeerSnapshot(peer)->m_best_known_block == equal_work);

    auto now_known_2{unknown_2};
    now_known_2.m_chain_work = equal_work.m_chain_work + 50;
    chain->SetBlock(now_known_2);
    manager->ProcessBlockAvailability(peer);
    BOOST_CHECK(*manager->GetPeerSnapshot(peer)->m_best_known_block == now_known_2);

    // A known nonpositive-work block remains pending until it becomes positive.
    manager->UpdateBlockAvailability(peer, nonpositive.m_hash);
    const uint64_t nonpositive_generation{manager->GetPeerSnapshot(peer)->m_generation};
    manager->ProcessBlockAvailability(peer);
    BOOST_CHECK_EQUAL(manager->GetPeerSnapshot(peer)->m_generation, nonpositive_generation);
    nonpositive.m_chain_work = now_known_2.m_chain_work + 1;
    chain->SetBlock(nonpositive);
    manager->ProcessBlockAvailability(peer);
    BOOST_CHECK(*manager->GetPeerSnapshot(peer)->m_best_known_block == nonpositive);
    const uint64_t resolved_generation{manager->GetPeerSnapshot(peer)->m_generation};
    manager->ProcessBlockAvailability(peer);
    BOOST_CHECK_EQUAL(manager->GetPeerSnapshot(peer)->m_generation, resolved_generation);

    // A null announcement retains the old null-sentinel/no-pending behavior.
    manager->UpdateBlockAvailability(peer, uint256{});
    BOOST_CHECK_EQUAL(manager->GetPeerSnapshot(peer)->m_generation, resolved_generation);

    BOOST_REQUIRE(owned_snapshot.m_best_known_block);
    BOOST_CHECK(*owned_snapshot.m_best_known_block == equal_work);
    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(peer_header_ancestry_on_competing_branches)
{
    auto fake{std::make_unique<FakeBlockDownloadChain>()};
    auto* const chain{fake.get()};
    auto manager{node::MakeBlockDownloadManager(std::move(fake))};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false});

    const auto root{TestBlock(1, 0)};
    const auto a1{TestBlock(2, 1)};
    const auto a2{TestBlock(3, 2)};
    const auto b1{TestBlock(4, 1)};
    const auto b2{TestBlock(5, 2)};
    chain->SetBlock(root);
    chain->SetBlock(a1, root.m_hash);
    chain->SetBlock(a2, a1.m_hash);
    chain->SetBlock(b1, root.m_hash);
    chain->SetBlock(b2, b1.m_hash);

    manager->UpdateBlockAvailability(peer, a2.m_hash);
    BOOST_CHECK(manager->PeerHasHeader(peer, root.m_hash));
    BOOST_CHECK(manager->PeerHasHeader(peer, a1.m_hash));
    BOOST_CHECK(manager->PeerHasHeader(peer, a2.m_hash));
    BOOST_CHECK(!manager->PeerHasHeader(peer, b1.m_hash));

    const uint64_t before_header{manager->GetPeerSnapshot(peer)->m_generation};
    manager->RecordBestHeaderSent(peer, b2);
    BOOST_CHECK(manager->GetPeerSnapshot(peer)->m_generation > before_header);
    BOOST_CHECK(manager->PeerHasHeader(peer, b1.m_hash));
    BOOST_CHECK(manager->PeerHasHeader(peer, b2.m_hash));
    BOOST_CHECK(manager->PeerHasHeader(peer, a1.m_hash));

    const uint64_t recorded_generation{manager->GetPeerSnapshot(peer)->m_generation};
    manager->RecordBestHeaderSent(peer, b2);
    BOOST_CHECK_EQUAL(manager->GetPeerSnapshot(peer)->m_generation, recorded_generation);

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(stale_availability_capture_does_not_resurrect_or_overwrite)
{
    auto fake{std::make_unique<FakeBlockDownloadChain>()};
    auto* const chain{fake.get()};
    auto manager{node::MakeBlockDownloadManager(std::move(fake))};
    const NodeId peer{1};
    auto old_announcement{TestBlock(1, 1)};
    old_announcement.m_chain_work = 300;
    const auto new_announcement{TestBlock(2, 2)};
    chain->SetBlock(old_announcement);
    chain->SetBlock(new_announcement);
    manager->ConnectedPeer(peer, {.m_is_inbound = false});

    const uint64_t initial_generation{manager->GetPeerSnapshot(peer)->m_generation};
    chain->SetCaptureHook([&] {
        manager->DisconnectedPeer(peer);
        manager->ConnectedPeer(peer, {.m_is_inbound = false});
    });
    manager->UpdateBlockAvailability(peer, old_announcement.m_hash);
    auto snapshot{*manager->GetPeerSnapshot(peer)};
    BOOST_CHECK(snapshot.m_generation > initial_generation);
    BOOST_CHECK(!snapshot.m_best_known_block);

    // A pending hash that becomes known during a later processing pass must
    // not resurrect state across a disconnect/reconnect ABA transition.
    const auto pending_announcement{TestBlock(3, 3)};
    manager->UpdateBlockAvailability(peer, pending_announcement.m_hash);
    chain->SetBlock(pending_announcement);
    const uint64_t pending_generation{manager->GetPeerSnapshot(peer)->m_generation};
    chain->SetCaptureHook([&] {
        manager->DisconnectedPeer(peer);
        manager->ConnectedPeer(peer, {.m_is_inbound = false});
    });
    manager->ProcessBlockAvailability(peer);
    snapshot = *manager->GetPeerSnapshot(peer);
    BOOST_CHECK(snapshot.m_generation > pending_generation);
    BOOST_CHECK(!snapshot.m_best_known_block);

    uint64_t interleaved_generation{0};
    chain->SetCaptureHook([&] {
        manager->UpdateBlockAvailability(peer, new_announcement.m_hash);
        interleaved_generation = manager->GetPeerSnapshot(peer)->m_generation;
    });
    manager->UpdateBlockAvailability(peer, old_announcement.m_hash);
    snapshot = *manager->GetPeerSnapshot(peer);
    BOOST_REQUIRE(snapshot.m_best_known_block);
    BOOST_CHECK(*snapshot.m_best_known_block == new_announcement);
    BOOST_CHECK_EQUAL(snapshot.m_generation, interleaved_generation);

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(unrelated_peer_mutation_does_not_discard_availability_capture)
{
    auto fake{std::make_unique<FakeBlockDownloadChain>()};
    auto* const chain{fake.get()};
    auto manager{node::MakeBlockDownloadManager(std::move(fake))};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false});

    const auto root{TestBlock(1, 0)};
    const auto announced{TestBlock(2, 1)};
    const auto header_1{TestBlock(3, 1)};
    const auto header_2{TestBlock(4, 2)};
    const auto pending{TestBlock(5, 2)};
    const auto later_header{TestBlock(6, 1)};
    chain->SetBlock(root);
    chain->SetBlock(announced, root.m_hash);
    chain->SetBlock(header_1, root.m_hash);
    chain->SetBlock(header_2, header_1.m_hash);
    chain->SetBlock(later_header, root.m_hash);

    uint64_t header_generation{0};
    chain->SetCaptureHook([&] {
        manager->RecordBestHeaderSent(peer, header_2);
        header_generation = manager->GetPeerSnapshot(peer)->m_generation;
    });
    manager->UpdateBlockAvailability(peer, announced.m_hash);
    auto snapshot{*manager->GetPeerSnapshot(peer)};
    BOOST_REQUIRE(snapshot.m_best_known_block);
    BOOST_CHECK(*snapshot.m_best_known_block == announced);
    BOOST_CHECK_EQUAL(snapshot.m_generation, header_generation + 1);
    BOOST_CHECK(manager->PeerHasHeader(peer, announced.m_hash));
    BOOST_CHECK(manager->PeerHasHeader(peer, header_2.m_hash));

    // ProcessBlockAvailability has the same independence from relay-header
    // changes while retaining its pending/best availability stale checks.
    manager->UpdateBlockAvailability(peer, pending.m_hash);
    const uint64_t pending_generation{manager->GetPeerSnapshot(peer)->m_generation};
    chain->SetBlock(pending, announced.m_hash);
    uint64_t later_header_generation{0};
    chain->SetCaptureHook([&] {
        manager->RecordBestHeaderSent(peer, later_header);
        later_header_generation = manager->GetPeerSnapshot(peer)->m_generation;
    });
    manager->ProcessBlockAvailability(peer);
    snapshot = *manager->GetPeerSnapshot(peer);
    BOOST_REQUIRE(snapshot.m_best_known_block);
    BOOST_CHECK(*snapshot.m_best_known_block == pending);
    BOOST_CHECK_EQUAL(later_header_generation, pending_generation + 1);
    BOOST_CHECK_EQUAL(snapshot.m_generation, later_header_generation + 1);
    BOOST_CHECK(manager->PeerHasHeader(peer, later_header.m_hash));

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(newer_announcement_during_process_availability_wins)
{
    auto fake{std::make_unique<FakeBlockDownloadChain>()};
    auto* const chain{fake.get()};
    auto manager{node::MakeBlockDownloadManager(std::move(fake))};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false});

    const auto old_announcement{TestBlock(1, 1)};
    const auto new_announcement{TestBlock(2, 2)};
    manager->UpdateBlockAvailability(peer, old_announcement.m_hash);
    const uint64_t pending_generation{manager->GetPeerSnapshot(peer)->m_generation};
    chain->SetBlock(old_announcement);

    uint64_t interleaved_generation{0};
    chain->SetCaptureHook([&] {
        manager->UpdateBlockAvailability(peer, new_announcement.m_hash);
        interleaved_generation = manager->GetPeerSnapshot(peer)->m_generation;
    });
    manager->ProcessBlockAvailability(peer);
    auto snapshot{*manager->GetPeerSnapshot(peer)};
    BOOST_REQUIRE(snapshot.m_best_known_block);
    BOOST_CHECK(*snapshot.m_best_known_block == old_announcement);
    BOOST_CHECK_EQUAL(interleaved_generation, pending_generation + 1);
    BOOST_CHECK_EQUAL(snapshot.m_generation, interleaved_generation);

    // Resolving the newer hash proves that the stale outer Process call did
    // not clear the interleaved announcement's pending state.
    chain->SetBlock(new_announcement, old_announcement.m_hash);
    manager->ProcessBlockAvailability(peer);
    snapshot = *manager->GetPeerSnapshot(peer);
    BOOST_REQUIRE(snapshot.m_best_known_block);
    BOOST_CHECK(*snapshot.m_best_known_block == new_announcement);
    BOOST_CHECK_EQUAL(snapshot.m_generation, interleaved_generation + 1);

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_FIXTURE_TEST_CASE(validation_chain_snapshot_translation, TestChain100Setup)
{
    auto chain{node::MakeValidationBlockDownloadChain(*m_node.chainman)};
    node::BlockDownloadBlock tip;
    node::BlockDownloadBlock ancestor;
    {
        LOCK(cs_main);
        const CBlockIndex* tip_index{m_node.chainman->ActiveChain().Tip()};
        const CBlockIndex* ancestor_index{tip_index->GetAncestor(tip_index->nHeight - 2)};
        tip = {tip_index->GetBlockHash(), tip_index->nHeight, tip_index->nChainWork};
        ancestor = {ancestor_index->GetBlockHash(), ancestor_index->nHeight, ancestor_index->nChainWork};
    }

    node::BlockDownloadChainQuery query;
    query.m_pending_hash = ArithToUint256(arith_uint256{999999});
    query.m_announced_hash = tip.m_hash;
    query.m_ancestor_hash = ancestor.m_hash;
    query.m_best_known_hash = tip.m_hash;
    query.m_best_header_sent_hash = query.m_pending_hash;
    const auto snapshot{chain->Capture(query)};
    BOOST_CHECK(!snapshot.m_pending_block);
    BOOST_REQUIRE(snapshot.m_announced_block);
    BOOST_CHECK(*snapshot.m_announced_block == tip);
    BOOST_CHECK(snapshot.m_ancestor_of_best_known);
    BOOST_CHECK(!snapshot.m_ancestor_of_best_header_sent);

    node::BlockDownloadChainQuery planning_query;
    planning_query.m_best_known_hash = tip.m_hash;
    planning_query.m_last_common_hash = ancestor.m_hash;
    planning_query.m_plan_blocks = true;
    planning_query.m_download_window = 1024;
    const auto planning_snapshot{chain->Capture(planning_query)};
    bool committed{false};
    BOOST_CHECK(chain->Revalidate(planning_snapshot, {}, [&] {
        committed = true;
        return true;
    }));
    BOOST_CHECK(committed);

    chain.reset();
    BOOST_CHECK(*snapshot.m_announced_block == tip); // Owned after adapter lifetime ends.
}

BOOST_FIXTURE_TEST_CASE(block_data_notification_cleans_side_chain_reservation, TestChain100Setup)
{
    // Both blocks build on the same tip. Storing the second one exercises the
    // path that does not necessarily produce a BlockConnected notification.
    const CBlock active_block{CreateBlock({}, CScript{} << OP_TRUE)};
    const CBlock side_block{CreateBlock({}, CScript{} << OP_FALSE)};
    BOOST_REQUIRE(active_block.GetHash() != side_block.GetHash());
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(active_block), true, true, nullptr));

    auto chain{node::MakeValidationBlockDownloadChain(*m_node.chainman)};
    auto manager{node::MakeBlockDownloadManager(std::move(chain))};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false});
    const BlockDownloadBlock request{
        .m_hash = side_block.GetHash(),
        .m_height = 101,
        .m_chain_work = arith_uint256{1},
    };
    BOOST_REQUIRE(
        manager->ReserveBlockRequest(peer, request, 1us).m_status == BlockRequestStatus::NEW);

    auto subscriber{std::make_shared<BlockDataCleanupSubscriber>(
        *manager, *m_node.chainman, side_block.GetHash(), peer)};
    m_node.validation_signals->RegisterSharedValidationInterface(subscriber);
    bool new_block{false};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(side_block), true, true, &new_block));
    BOOST_CHECK(new_block);

    // BlockDataAvailable is synchronous, so all observations and cleanup are
    // complete before ProcessNewBlock returns.
    BOOST_CHECK(subscriber->m_called);
    BOOST_CHECK(subscriber->m_saw_have_data);
    BOOST_CHECK(subscriber->m_saw_side_chain);
    BOOST_CHECK(subscriber->m_saw_request);
    BOOST_CHECK_EQUAL(subscriber->m_removed, 1U);
    BOOST_CHECK(!manager->IsBlockRequested(side_block.GetHash()));
    m_node.validation_signals->UnregisterSharedValidationInterface(subscriber);

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(normal_planning_policy_and_atomic_reservation)
{
    auto fake{std::make_unique<FakeBlockDownloadChain>()};
    auto* const chain{fake.get()};
    auto manager{node::MakeBlockDownloadManager(std::move(fake))};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_can_serve_witness = true});

    const auto root{TestBlock(1, 0)};
    const auto block_1{TestBlock(2, 1)};
    const auto block_2{TestBlock(3, 2)};
    const auto block_3{TestBlock(4, 3)};
    const auto block_4{TestBlock(5, 4)};
    chain->SetCandidate(TestCandidate(root, true, true, true, true));
    chain->SetCandidate(TestCandidate(block_1), root.m_hash);
    chain->SetCandidate(TestCandidate(block_2), block_1.m_hash);
    chain->SetCandidate(TestCandidate(block_3), block_2.m_hash);
    chain->SetCandidate(TestCandidate(block_4), block_3.m_hash);
    SetPlanningTip(*chain, root);
    manager->UpdateBlockAvailability(peer, block_4.m_hash);

    const auto batch{manager->PlanAndReserve(peer, 3, 10us, /*allow_historical=*/false)};
    BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 3U);
    BOOST_CHECK(batch.m_blocks[0] == block_1);
    BOOST_CHECK(batch.m_blocks[1] == block_2);
    BOOST_CHECK(batch.m_blocks[2] == block_3);
    BOOST_CHECK(!batch.m_staller);
    const auto reserved{*manager->GetPeerSnapshot(peer)};
    BOOST_CHECK(reserved.m_blocks == batch.m_blocks);
    BOOST_REQUIRE(reserved.m_last_common_block);
    BOOST_CHECK(*reserved.m_last_common_block == root);
    for (const auto& block : batch.m_blocks) BOOST_CHECK(manager->IsBlockRequested(block.m_hash));

    manager->RemoveBlockRequest(block_1.m_hash, peer, 20us);
    manager->RemoveBlockRequest(block_2.m_hash, peer, 20us);
    manager->RemoveBlockRequest(block_3.m_hash, peer, 20us);
    chain->SetMinimumChainWork(block_4.m_chain_work + 1);
    BOOST_CHECK(manager->PlanAndReserve(peer, 1, 21us, false).m_blocks.empty());
    BOOST_CHECK(*manager->GetPeerSnapshot(peer)->m_last_common_block == root);

    chain->SetMinimumChainWork(0);
    chain->SetCandidate(TestCandidate(block_1, /*valid_tree=*/false), root.m_hash);
    BOOST_CHECK(manager->PlanAndReserve(peer, 1, 22us, false).m_blocks.empty());
    chain->SetCandidate(TestCandidate(block_1, true, false, false, false, /*segwit_active=*/true), root.m_hash);
    manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_can_serve_witness = false});
    BOOST_CHECK(manager->PlanAndReserve(peer, 1, 23us, false).m_blocks.empty());
    manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_can_serve_witness = true});
    const auto witness_batch{manager->PlanAndReserve(peer, 1, 24us, false)};
    BOOST_REQUIRE_EQUAL(witness_batch.m_blocks.size(), 1U);
    BOOST_CHECK(witness_batch.m_blocks.front() == block_1);

    manager->RemoveBlockRequest(block_1.m_hash, peer, 25us);
    chain->SetCandidate(
        TestCandidate(block_1, true, true, /*in_active_chain=*/false, /*have_chain_txs=*/true),
        root.m_hash);
    const auto side_chain_batch{manager->PlanAndReserve(peer, 1, 26us, false)};
    BOOST_REQUIRE_EQUAL(side_chain_batch.m_blocks.size(), 1U);
    BOOST_CHECK(side_chain_batch.m_blocks.front() == block_2);
    BOOST_CHECK(*manager->GetPeerSnapshot(peer)->m_last_common_block == block_1);

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(historical_priority_data_and_chain_tx_policy)
{
    auto fake{std::make_unique<FakeBlockDownloadChain>()};
    auto* const chain{fake.get()};
    auto manager{node::MakeBlockDownloadManager(std::move(fake))};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_can_serve_witness = true});

    const auto root{TestBlock(1, 0)};
    const auto historical_1{TestBlock(2, 1)};
    const auto historical_2{TestBlock(3, 2)};
    const auto normal_1{TestBlock(4, 3)};
    const auto normal_2{TestBlock(5, 4)};
    chain->SetCandidate(TestCandidate(root, true, true, true, true));
    // Active-but-pruned blocks advance normal last-common and remain eligible
    // for historical download, which deliberately ignores active membership.
    chain->SetCandidate(TestCandidate(historical_1, true, false, true, true), root.m_hash);
    chain->SetCandidate(TestCandidate(historical_2, true, false, true, true), historical_1.m_hash);
    chain->SetCandidate(TestCandidate(normal_1), historical_2.m_hash);
    chain->SetCandidate(TestCandidate(normal_2), normal_1.m_hash);
    SetPlanningTip(*chain, historical_2);
    chain->SetHistoricalRange(std::pair{root.m_hash, historical_2.m_hash});
    manager->UpdateBlockAvailability(peer, normal_2.m_hash);

    const auto batch{manager->PlanAndReserve(peer, 3, 10us, /*allow_historical=*/true)};
    BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 3U);
    BOOST_CHECK(batch.m_blocks[0] == normal_1);
    BOOST_CHECK(batch.m_blocks[1] == normal_2);
    BOOST_CHECK(batch.m_blocks[2] == historical_1);
    BOOST_CHECK(*manager->GetPeerSnapshot(peer)->m_last_common_block == historical_2);

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(historical_revalidation_tracks_planner_consultation)
{
    // Filling the normal budget makes background-chain movement irrelevant to
    // this proposal. Rearm the hook so checking it would exhaust all retries.
    {
        auto fake{std::make_unique<FakeBlockDownloadChain>()};
        auto* const chain{fake.get()};
        auto manager{node::MakeBlockDownloadManager(std::move(fake))};
        const NodeId peer{1};
        manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_can_serve_witness = true});

        const auto root{TestBlock(1, 0)};
        const auto block_1{TestBlock(2, 1)};
        const auto block_2{TestBlock(3, 2)};
        const auto block_3{TestBlock(4, 3)};
        const auto block_4{TestBlock(5, 4)};
        chain->SetCandidate(TestCandidate(root, true, true, true, true));
        chain->SetCandidate(TestCandidate(block_1), root.m_hash);
        chain->SetCandidate(TestCandidate(block_2), block_1.m_hash);
        chain->SetCandidate(TestCandidate(block_3), block_2.m_hash);
        chain->SetCandidate(TestCandidate(block_4), block_3.m_hash);
        SetPlanningTip(*chain, root);
        chain->SetHistoricalRange(std::pair{root.m_hash, block_4.m_hash});
        manager->UpdateBlockAvailability(peer, block_4.m_hash);

        const std::array historical_starts{block_1.m_hash, block_2.m_hash, block_3.m_hash};
        size_t next_start{0};
        std::function<void()> advance_historical_start;
        advance_historical_start = [&] {
            chain->SetHistoricalRange(std::pair{historical_starts[next_start], block_4.m_hash});
            ++next_start;
            if (next_start < historical_starts.size()) {
                chain->SetRevalidateHook(advance_historical_start);
            }
        };
        chain->SetRevalidateHook(advance_historical_start);

        const auto batch{manager->PlanAndReserve(peer, 1, 10us, /*allow_historical=*/true)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK(batch.m_blocks.front() == block_1);
        BOOST_CHECK_EQUAL(chain->RevalidationCount(), 1);
        BOOST_CHECK_EQUAL(next_start, 1U);
        BOOST_CHECK(manager->IsBlockRequested(block_1.m_hash));

        manager->DisconnectedPeer(peer);
        manager->CheckIsEmpty();
    }

    // With budget remaining, the historical start determines the first block.
    // Moving it rejects the old proposal and the retry uses the new range.
    {
        auto fake{std::make_unique<FakeBlockDownloadChain>()};
        auto* const chain{fake.get()};
        auto manager{node::MakeBlockDownloadManager(std::move(fake))};
        const NodeId peer{1};
        manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_can_serve_witness = true});

        const auto root{TestBlock(1, 0)};
        const auto historical_1{TestBlock(2, 1)};
        const auto historical_2{TestBlock(3, 2)};
        chain->SetCandidate(TestCandidate(root, true, true, true, true));
        chain->SetCandidate(TestCandidate(historical_1, true, false, true, true), root.m_hash);
        chain->SetCandidate(TestCandidate(historical_2, true, false, true, true), historical_1.m_hash);
        SetPlanningTip(*chain, historical_2);
        chain->SetHistoricalRange(std::pair{root.m_hash, historical_2.m_hash});
        manager->UpdateBlockAvailability(peer, historical_2.m_hash);
        chain->SetRevalidateHook([&] {
            chain->SetHistoricalRange(std::pair{historical_1.m_hash, historical_2.m_hash});
        });

        const auto batch{manager->PlanAndReserve(peer, 1, 10us, /*allow_historical=*/true)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK(batch.m_blocks.front() == historical_2);
        BOOST_CHECK_EQUAL(chain->RevalidationCount(), 2);
        BOOST_CHECK(!manager->IsBlockRequested(historical_1.m_hash));
        BOOST_CHECK(manager->IsBlockRequested(historical_2.m_hash));

        manager->DisconnectedPeer(peer);
        manager->CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(last_common_revalidation_uses_role_specific_facts)
{
    const auto make_fixture = [] {
        auto fake{std::make_unique<FakeBlockDownloadChain>()};
        auto* const chain{fake.get()};
        auto manager{node::MakeBlockDownloadManager(std::move(fake))};
        const auto root{TestBlock(1, 0)};
        const auto block_1{TestBlock(2, 1)};
        const auto block_2{TestBlock(3, 2)};
        chain->SetCandidate(TestCandidate(root, true, true, true, true));
        chain->SetCandidate(TestCandidate(block_1, true, true, false, true), root.m_hash);
        chain->SetCandidate(TestCandidate(block_2), block_1.m_hash);
        SetPlanningTip(*chain, root);
        manager->ConnectedPeer(1, {.m_is_inbound = false, .m_can_serve_witness = true});
        manager->UpdateBlockAvailability(1, block_2.m_hash);
        return std::tuple{std::move(manager), chain, root, block_1, block_2};
    };

    // The initial effective last-common is only a topology/window identity.
    // Planning advances beyond it, so its candidate flags are not relevant.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        chain->SetRevalidateHook([&] {
            chain->SetCandidate(
                TestCandidate(root, true, false, true, true),
                std::nullopt);
        });
        const auto batch{manager->PlanAndReserve(1, 1, 10us, false)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK(batch.m_blocks.front() == block_2);
        BOOST_CHECK_EQUAL(chain->RevalidationCount(), 1);
        BOOST_REQUIRE(manager->GetPeerSnapshot(1)->m_last_common_block);
        BOOST_CHECK(*manager->GetPeerSnapshot(1)->m_last_common_block == block_1);
        manager->DisconnectedPeer(1);
        manager->CheckIsEmpty();
    }

    // The advanced final last-common remains a full candidate revalidation
    // entry. Pruning it rejects the old successor proposal; retry requests the
    // newly missing final entry instead.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        chain->SetRevalidateHook([&] {
            chain->SetCandidate(
                TestCandidate(block_1, true, false, false, true),
                root.m_hash);
        });
        const auto batch{manager->PlanAndReserve(1, 1, 10us, false)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK(batch.m_blocks.front() == block_1);
        BOOST_CHECK_EQUAL(chain->RevalidationCount(), 2);
        BOOST_REQUIRE(manager->GetPeerSnapshot(1)->m_last_common_block);
        BOOST_CHECK(*manager->GetPeerSnapshot(1)->m_last_common_block == root);
        BOOST_CHECK(!manager->IsBlockRequested(block_2.m_hash));
        manager->DisconnectedPeer(1);
        manager->CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(fork_reorg_and_assumeutxo_transitions)
{
    auto fake{std::make_unique<FakeBlockDownloadChain>()};
    auto* const chain{fake.get()};
    auto manager{node::MakeBlockDownloadManager(std::move(fake))};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_can_serve_witness = true});

    const auto root{TestBlock(1, 0)};
    const auto active_1{TestBlock(2, 1)};
    const auto peer_1{TestBlock(3, 1)};
    const auto peer_2{TestBlock(4, 2)};
    chain->SetCandidate(TestCandidate(root, true, true, true, true));
    chain->SetCandidate(TestCandidate(active_1, true, true, true, true), root.m_hash);
    chain->SetCandidate(TestCandidate(peer_1), root.m_hash);
    chain->SetCandidate(TestCandidate(peer_2), peer_1.m_hash);
    SetPlanningTip(*chain, active_1);
    manager->UpdateBlockAvailability(peer, peer_2.m_hash);

    chain->SetCurrentChainstate(active_1.m_hash, active_1.m_hash, BlockDownloadAssumeutxoState::UNVALIDATED);
    const auto blocked{manager->PlanAndReserve(peer, 1, 10us, false)};
    BOOST_CHECK(blocked.m_blocks.empty());
    BOOST_CHECK(blocked.m_assumeutxo_blocked);
    BOOST_CHECK(!manager->GetPeerSnapshot(peer)->m_last_common_block);

    chain->SetCurrentChainstate(active_1.m_hash, active_1.m_hash, BlockDownloadAssumeutxoState::VALIDATED);
    const auto fork_batch{manager->PlanAndReserve(peer, 1, 11us, false)};
    BOOST_REQUIRE_EQUAL(fork_batch.m_blocks.size(), 1U);
    BOOST_CHECK(fork_batch.m_blocks.front() == peer_1);
    BOOST_CHECK(*manager->GetPeerSnapshot(peer)->m_last_common_block == root);
    manager->RemoveBlockRequest(peer_1.m_hash, peer, 12us);

    chain->SetCandidate(TestCandidate(peer_1, true, true, true, true), root.m_hash);
    chain->SetActiveTip(peer_1.m_hash);
    chain->SetCurrentChainstate(peer_1.m_hash);
    const auto reorg_batch{manager->PlanAndReserve(peer, 1, 13us, false)};
    BOOST_REQUIRE_EQUAL(reorg_batch.m_blocks.size(), 1U);
    BOOST_CHECK(reorg_batch.m_blocks.front() == peer_2);
    BOOST_CHECK(*manager->GetPeerSnapshot(peer)->m_last_common_block == peer_1);

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(limited_peer_distance_and_download_window_staller)
{
    {
        auto fake{std::make_unique<FakeBlockDownloadChain>()};
        auto* const chain{fake.get()};
        auto manager{node::MakeBlockDownloadManager(std::move(fake))};
        const NodeId peer{1};
        manager->ConnectedPeer(peer, {
            .m_is_inbound = false,
            .m_can_serve_witness = true,
            .m_limited_peer = true,
        });
        BlockDownloadBlock previous{TestBlock(1, 0)};
        chain->SetCandidate(TestCandidate(previous, true, true, true, true));
        const auto root{previous};
        for (int height{1}; height <= 300; ++height) {
            const auto block{TestBlock(static_cast<uint64_t>(height + 1), height)};
            chain->SetCandidate(TestCandidate(block), previous.m_hash);
            previous = block;
        }
        SetPlanningTip(*chain, root);
        manager->UpdateBlockAvailability(peer, previous.m_hash);
        const auto batch{manager->PlanAndReserve(peer, 2, 10us, true)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 2U);
        BOOST_CHECK_EQUAL(batch.m_blocks[0].m_height, 15);
        BOOST_CHECK_EQUAL(batch.m_blocks[1].m_height, 16);
        manager->DisconnectedPeer(peer);
        manager->CheckIsEmpty();
    }
    {
        auto fake{std::make_unique<FakeBlockDownloadChain>()};
        auto* const chain{fake.get()};
        auto manager{node::MakeBlockDownloadManager(std::move(fake))};
        const NodeId peer{1}, staller{2};
        manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_can_serve_witness = true});
        manager->ConnectedPeer(staller, {.m_is_inbound = false, .m_can_serve_witness = true});
        BlockDownloadBlock previous{TestBlock(1, 0)};
        chain->SetCandidate(TestCandidate(previous, true, true, true, true));
        const auto root{previous};
        BlockDownloadBlock first;
        for (int height{1}; height <= 1025; ++height) {
            const auto block{TestBlock(static_cast<uint64_t>(height + 1), height)};
            const bool stored{height > 1 && height <= 1024};
            chain->SetCandidate(TestCandidate(block, true, stored), previous.m_hash);
            if (height == 1) first = block;
            previous = block;
        }
        SetPlanningTip(*chain, root);
        manager->UpdateBlockAvailability(peer, previous.m_hash);
        BOOST_REQUIRE(manager->ReserveBlockRequest(staller, first, 5us).m_status == BlockRequestStatus::NEW);

        chain->FailRevalidations(3);
        const auto failed{manager->PlanAndReserve(peer, 1, 9us, false)};
        BOOST_CHECK(failed.m_blocks.empty());
        BOOST_CHECK(!failed.m_staller);
        BOOST_CHECK(manager->GetPeerSnapshot(staller)->m_stalling_since == 0us);
        BOOST_CHECK(!manager->GetPeerSnapshot(peer)->m_last_common_block);

        const auto batch{manager->PlanAndReserve(peer, 1, 10us, false)};
        BOOST_CHECK(batch.m_blocks.empty());
        BOOST_REQUIRE(batch.m_staller);
        BOOST_CHECK_EQUAL(*batch.m_staller, staller);
        BOOST_CHECK(manager->GetPeerSnapshot(staller)->m_stalling_since == 10us);
        manager->DisconnectedPeer(peer);
        manager->DisconnectedPeer(staller);
        manager->CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(planning_revalidation_manager_and_chain_races)
{
    const auto make_fixture = [] {
        auto fake{std::make_unique<FakeBlockDownloadChain>()};
        auto* const chain{fake.get()};
        auto manager{node::MakeBlockDownloadManager(std::move(fake))};
        const auto root{TestBlock(1, 0)};
        const auto block_1{TestBlock(2, 1)};
        const auto block_2{TestBlock(3, 2)};
        chain->SetCandidate(TestCandidate(root, true, true, true, true));
        chain->SetCandidate(TestCandidate(block_1), root.m_hash);
        chain->SetCandidate(TestCandidate(block_2), block_1.m_hash);
        SetPlanningTip(*chain, root);
        return std::tuple{std::move(manager), chain, root, block_1, block_2};
    };

    // Disconnect after capture: the commit cannot resurrect the peer.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        manager->ConnectedPeer(1, {.m_is_inbound = false, .m_can_serve_witness = true});
        manager->UpdateBlockAvailability(1, block_2.m_hash);
        chain->SetRevalidateHook([&] { manager->DisconnectedPeer(1); });
        BOOST_CHECK(manager->PlanAndReserve(1, 1, 10us, false).m_blocks.empty());
        BOOST_CHECK(!manager->GetPeerSnapshot(1));
        manager->CheckIsEmpty();
    }

    // A competing reservation invalidates the global in-flight generation;
    // retry observes it and reserves no subset for the original peer.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        manager->ConnectedPeer(1, {.m_is_inbound = false, .m_can_serve_witness = true});
        manager->ConnectedPeer(2, {.m_is_inbound = false, .m_can_serve_witness = true});
        manager->UpdateBlockAvailability(1, block_2.m_hash);
        chain->SetRevalidateHook([&] {
            BOOST_REQUIRE(manager->ReserveBlockRequest(2, block_1, 5us).m_status == BlockRequestStatus::NEW);
        });
        const auto batch{manager->PlanAndReserve(1, 1, 10us, false)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK(batch.m_blocks.front() == block_2);
        BOOST_CHECK(!manager->GetBlockInFlightInfo(block_1.m_hash, 1).m_requested_from_peer);
        BOOST_CHECK(manager->GetBlockInFlightInfo(block_1.m_hash, 2).m_requested_from_peer);
        manager->DisconnectedPeer(1);
        manager->DisconnectedPeer(2);
        manager->CheckIsEmpty();
    }

    // Data availability after capture rejects the stale proposal; the retry
    // sees the stored block and selects its successor.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        manager->ConnectedPeer(1, {.m_is_inbound = false, .m_can_serve_witness = true});
        manager->UpdateBlockAvailability(1, block_2.m_hash);
        chain->SetRevalidateHook([&] {
            chain->SetCandidate(TestCandidate(block_1, true, true), root.m_hash);
        });
        const auto batch{manager->PlanAndReserve(1, 1, 10us, false)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK(batch.m_blocks.front() == block_2);
        BOOST_CHECK(!manager->IsBlockRequested(block_1.m_hash));
        BOOST_CHECK(manager->IsBlockRequested(block_2.m_hash));
        manager->DisconnectedPeer(1);
        manager->CheckIsEmpty();
    }

    // Availability changes are peer-planning mutations and discard the old
    // best-known proposal before the retry.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        const auto alternate{TestBlock(4, 1)};
        chain->SetCandidate(TestCandidate(alternate), root.m_hash);
        manager->ConnectedPeer(1, {.m_is_inbound = false, .m_can_serve_witness = true});
        manager->UpdateBlockAvailability(1, block_2.m_hash);
        chain->SetRevalidateHook([&] { manager->UpdateBlockAvailability(1, alternate.m_hash); });
        const auto batch{manager->PlanAndReserve(1, 1, 10us, false)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK(batch.m_blocks.front() == alternate);
        BOOST_CHECK(!manager->IsBlockRequested(block_1.m_hash));
        manager->DisconnectedPeer(1);
        manager->CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(planning_revalidation_tip_assumeutxo_and_retry_boundaries)
{
    auto make_fixture = [] {
        auto fake{std::make_unique<FakeBlockDownloadChain>()};
        auto* const chain{fake.get()};
        auto manager{node::MakeBlockDownloadManager(std::move(fake))};
        const auto root{TestBlock(1, 0)};
        const auto block_1{TestBlock(2, 1)};
        const auto block_2{TestBlock(3, 2)};
        chain->SetCandidate(TestCandidate(root, true, true, true, true));
        chain->SetCandidate(TestCandidate(block_1), root.m_hash);
        chain->SetCandidate(TestCandidate(block_2), block_1.m_hash);
        SetPlanningTip(*chain, root);
        manager->ConnectedPeer(1, {.m_is_inbound = false, .m_can_serve_witness = true});
        manager->UpdateBlockAvailability(1, block_2.m_hash);
        return std::tuple{std::move(manager), chain, root, block_1, block_2};
    };

    // Reorg between capture and validation changes both active-tip identity
    // and the effective last-common before the retry commits.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        chain->SetRevalidateHook([&] {
            chain->SetCandidate(TestCandidate(block_1, true, true, true, true), root.m_hash);
            chain->SetActiveTip(block_1.m_hash);
            chain->SetCurrentChainstate(block_1.m_hash);
        });
        const auto batch{manager->PlanAndReserve(1, 1, 10us, false)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK(batch.m_blocks.front() == block_2);
        BOOST_CHECK(*manager->GetPeerSnapshot(1)->m_last_common_block == block_1);
        manager->DisconnectedPeer(1);
        manager->CheckIsEmpty();
    }

    // An AssumeUTXO transition between capture and revalidation rejects the
    // old view; retry applies the new gate without a reservation.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        const auto snapshot_base{TestBlock(4, 1)};
        chain->SetCandidate(TestCandidate(snapshot_base, true, true, true, true), root.m_hash);
        chain->SetRevalidateHook([&] {
            chain->SetCurrentChainstate(root.m_hash, snapshot_base.m_hash, BlockDownloadAssumeutxoState::UNVALIDATED);
        });
        const auto batch{manager->PlanAndReserve(1, 1, 10us, false)};
        BOOST_CHECK(batch.m_blocks.empty());
        BOOST_CHECK(batch.m_assumeutxo_blocked);
        BOOST_CHECK(!manager->IsBlockRequested(block_1.m_hash));
        manager->DisconnectedPeer(1);
        manager->CheckIsEmpty();
    }

    // Two stale attempts may use the final allowed retry and return an
    // already-visible reservation.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        chain->FailRevalidations(2);
        const auto batch{manager->PlanAndReserve(1, 1, 10us, false)};
        BOOST_REQUIRE_EQUAL(batch.m_blocks.size(), 1U);
        BOOST_CHECK_EQUAL(chain->RevalidationCount(), 3);
        BOOST_CHECK(manager->IsBlockRequested(batch.m_blocks.front().m_hash));
        manager->DisconnectedPeer(1);
        manager->CheckIsEmpty();
    }

    // Initial attempt plus both retries failing returns empty and commits
    // neither a request nor the proposed last-common update.
    {
        auto [manager, chain, root, block_1, block_2]{make_fixture()};
        chain->FailRevalidations(3);
        const auto batch{manager->PlanAndReserve(1, 2, 10us, false)};
        BOOST_CHECK(batch.m_blocks.empty());
        BOOST_CHECK(!batch.m_staller);
        BOOST_CHECK_EQUAL(chain->RevalidationCount(), 3);
        const auto peer{*manager->GetPeerSnapshot(1)};
        BOOST_CHECK(peer.m_blocks.empty());
        BOOST_CHECK(!peer.m_last_common_block);
        manager->DisconnectedPeer(1);
        manager->CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(new_duplicate_parallel_and_removed_requests)
{
    auto manager{MakeManager()};
    const NodeId peer_1{1}, peer_2{2}, peer_3{3}, peer_4{4};
    manager->ConnectedPeer(peer_1, BlockDownloadConnectionInfo{.m_is_inbound = false});
    manager->ConnectedPeer(peer_2, BlockDownloadConnectionInfo{.m_is_inbound = true});
    manager->ConnectedPeer(peer_3, BlockDownloadConnectionInfo{.m_is_inbound = true});
    manager->ConnectedPeer(peer_4, BlockDownloadConnectionInfo{.m_is_inbound = false});
    const auto block{TestBlock(1, 10)};

    const auto first{manager->ReserveBlockRequest(peer_1, block, 10us)};
    BOOST_CHECK(first.m_status == BlockRequestStatus::NEW);
    BOOST_CHECK_EQUAL(first.m_requests_before, 0U);
    BOOST_CHECK(first.m_first_in_flight);

    const auto duplicate{manager->ReserveBlockRequest(peer_1, block, 11us)};
    BOOST_CHECK(duplicate.m_status == BlockRequestStatus::ALREADY_REQUESTED);
    BOOST_CHECK_EQUAL(duplicate.m_requests_before, 1U);
    BOOST_CHECK(duplicate.m_first_in_flight);

    const auto second{manager->ReserveBlockRequest(
        peer_2, block, 12us, std::make_shared<PartiallyDownloadedBlock>(nullptr))};
    BOOST_CHECK(second.m_status == BlockRequestStatus::NEW);
    BOOST_CHECK_EQUAL(second.m_requests_before, 1U);
    BOOST_CHECK(!second.m_first_in_flight);
    const auto third{manager->ReserveBlockRequest(
        peer_3, block, 13us, std::make_shared<PartiallyDownloadedBlock>(nullptr))};
    BOOST_CHECK(third.m_status == BlockRequestStatus::NEW);
    BOOST_CHECK_EQUAL(third.m_requests_before, 2U);

    const auto capped{manager->ReserveBlockRequest(
        peer_4, block, 14us, std::make_shared<PartiallyDownloadedBlock>(nullptr))};
    BOOST_CHECK(capped.m_status == BlockRequestStatus::MAX_REQUESTS_REACHED);
    BOOST_CHECK_EQUAL(capped.m_requests_before, node::MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    const auto info_1{manager->GetBlockInFlightInfo(block.m_hash, peer_1)};
    BOOST_CHECK_EQUAL(info_1.m_request_count, 3U);
    BOOST_REQUIRE(info_1.m_first_peer);
    BOOST_CHECK_EQUAL(*info_1.m_first_peer, peer_1);
    BOOST_CHECK(info_1.m_requested_from_peer);
    BOOST_CHECK(info_1.m_first_in_flight);
    BOOST_CHECK(manager->IsBlockRequested(block.m_hash));
    BOOST_CHECK(manager->IsBlockRequestedFromOutbound(block.m_hash));

    const auto wrong_peer{manager->RemoveBlockRequest(block.m_hash, peer_4, 20us)};
    BOOST_CHECK_EQUAL(wrong_peer.m_requests_before, 3U);
    BOOST_CHECK_EQUAL(wrong_peer.m_removed, 0U);

    const auto one_peer{manager->RemoveBlockRequest(block.m_hash, peer_2, 21us)};
    BOOST_CHECK_EQUAL(one_peer.m_requests_before, 3U);
    BOOST_CHECK_EQUAL(one_peer.m_removed, 1U);
    BOOST_CHECK_EQUAL(manager->GetBlockInFlightInfo(block.m_hash, peer_2).m_request_count, 2U);

    const auto all_peers{manager->RemoveBlockRequest(block.m_hash, std::nullopt, 22us)};
    BOOST_CHECK_EQUAL(all_peers.m_requests_before, 2U);
    BOOST_CHECK_EQUAL(all_peers.m_removed, 2U);
    BOOST_CHECK(!manager->IsBlockRequested(block.m_hash));
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_total_requests, 0U);
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_peers_downloading_from, 0);
    BOOST_CHECK(manager->CheckConsistency());

    manager->DisconnectedPeer(peer_1);
    manager->DisconnectedPeer(peer_2);
    manager->DisconnectedPeer(peer_3);
    manager->DisconnectedPeer(peer_4);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(queue_timers_stalling_and_disconnect_cleanup)
{
    auto manager{MakeManager()};
    const NodeId peer_1{1}, peer_2{2};
    manager->ConnectedPeer(peer_1, {.m_is_inbound = false});
    manager->ConnectedPeer(peer_2, {.m_is_inbound = true});
    const auto block_1{TestBlock(1, 1)};
    const auto block_2{TestBlock(2, 2)};
    const auto block_3{TestBlock(3, 3)};

    manager->ReserveBlockRequest(peer_1, block_1, 10us);
    manager->ReserveBlockRequest(peer_1, block_2, 11us);
    manager->ReserveBlockRequest(peer_2, block_3, 12us);

    const auto initial{manager->GetGlobalSnapshot()};
    BOOST_CHECK_EQUAL(initial.m_total_requests, 3U);
    BOOST_CHECK_EQUAL(initial.m_peers_downloading_from, 2);
    const auto copied_peer_info{*manager->GetPeerSnapshot(peer_1)};
    BOOST_REQUIRE_EQUAL(copied_peer_info.m_blocks.size(), 2U);
    BOOST_CHECK(copied_peer_info.m_blocks[0] == block_1);
    BOOST_CHECK(copied_peer_info.m_blocks[1] == block_2);
    BOOST_CHECK(copied_peer_info.m_downloading_since == 10us);

    const uint64_t generation_before_zero{manager->GetPeerSnapshot(peer_1)->m_generation};
    BOOST_CHECK(!manager->StartStalling(peer_1, 0us));
    BOOST_CHECK(manager->GetPeerSnapshot(peer_1)->m_stalling_since == 0us);
    BOOST_CHECK_EQUAL(manager->GetPeerSnapshot(peer_1)->m_generation, generation_before_zero);
    BOOST_CHECK(manager->StartStalling(peer_1, 15us));
    BOOST_CHECK(!manager->StartStalling(peer_1, 16us));
    BOOST_CHECK(manager->GetPeerSnapshot(peer_1)->m_stalling_since == 15us);

    // Removing a non-front request leaves the download timer unchanged but
    // clears stalling, matching the existing request-removal transition.
    manager->RemoveBlockRequest(block_2.m_hash, peer_1, 20us);
    auto peer_info{*manager->GetPeerSnapshot(peer_1)};
    BOOST_REQUIRE_EQUAL(peer_info.m_blocks.size(), 1U);
    BOOST_CHECK(peer_info.m_downloading_since == 10us);
    BOOST_CHECK(peer_info.m_stalling_since == 0us);

    BOOST_CHECK(manager->StartStalling(peer_1, 21us));
    manager->RemoveBlockRequest(block_1.m_hash, peer_1, 5us);
    peer_info = *manager->GetPeerSnapshot(peer_1);
    BOOST_CHECK(peer_info.m_blocks.empty());
    BOOST_CHECK(peer_info.m_downloading_since == 10us); // max(old, removal time)
    BOOST_CHECK(peer_info.m_stalling_since == 0us);
    BOOST_CHECK_EQUAL(peer_info.m_peers_downloading_from, 1);

    // Previously returned values are independent copies.
    BOOST_REQUIRE_EQUAL(copied_peer_info.m_blocks.size(), 2U);
    BOOST_CHECK(copied_peer_info.m_blocks[0] == block_1);
    BOOST_CHECK(copied_peer_info.m_downloading_since == 10us);

    manager->DisconnectedPeer(peer_2);
    BOOST_CHECK(!manager->IsBlockRequested(block_3.m_hash));
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_peers_downloading_from, 0);
    BOOST_CHECK(manager->CheckConsistency());
    manager->DisconnectedPeer(peer_1);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(compact_upgrade_duplicate_and_handle_lifetime)
{
    auto manager{MakeManager()};
    const NodeId peer{1};
    manager->ConnectedPeer(peer, {.m_is_inbound = false});
    const auto block{TestBlock(1, 1)};
    BOOST_CHECK(manager->ReserveBlockRequest(peer, block, 1us).m_status == BlockRequestStatus::NEW);

    auto proposed{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
    const std::weak_ptr<PartiallyDownloadedBlock> lifetime{proposed};
    const auto upgrade{manager->ReserveBlockRequest(peer, block, 2us, std::move(proposed))};
    BOOST_CHECK(upgrade.m_status == BlockRequestStatus::UPGRADED_TO_COMPACT);
    BOOST_CHECK_EQUAL(upgrade.m_requests_before, 1U);
    BOOST_REQUIRE(upgrade.m_partial_block);

    const auto copied_info{manager->GetBlockInFlightInfo(block.m_hash, peer)};
    BOOST_CHECK(copied_info.m_partial_block == upgrade.m_partial_block);
    auto duplicate_proposal{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
    const auto duplicate{manager->ReserveBlockRequest(peer, block, 3us, std::move(duplicate_proposal))};
    BOOST_CHECK(duplicate.m_status == BlockRequestStatus::DUPLICATE_COMPACT);
    BOOST_CHECK(duplicate.m_partial_block == upgrade.m_partial_block);

    manager->RemoveBlockRequest(block.m_hash, peer, 4us);
    BOOST_CHECK(!manager->GetBlockInFlightInfo(block.m_hash, peer).m_partial_block);
    BOOST_CHECK(!lifetime.expired());

    // Removal does not invalidate owned results. Mutation remains single-user
    // in this test, just as production message processing guarantees.
    copied_info.m_partial_block->header.nVersion = 7;
    BOOST_CHECK_EQUAL(upgrade.m_partial_block->header.nVersion, 7);

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(connection_origin_and_missing_peer)
{
    auto manager{MakeManager()};
    const NodeId peer{1}, outbound_peer{2};
    const auto block{TestBlock(1, 1)};

    const auto missing{manager->ReserveBlockRequest(peer, block, 1us)};
    BOOST_CHECK(missing.m_status == BlockRequestStatus::PEER_NOT_FOUND);

    manager->ConnectedPeer(peer, {.m_is_inbound = true});
    manager->ConnectedPeer(peer, {.m_is_inbound = true}); // idempotent re-registration
    manager->ReserveBlockRequest(peer, block, 2us);
    BOOST_CHECK(!manager->IsBlockRequestedFromOutbound(block.m_hash));

    manager->ConnectedPeer(outbound_peer, {.m_is_inbound = false});
    manager->ReserveBlockRequest(outbound_peer, block, 3us);
    BOOST_CHECK(manager->IsBlockRequestedFromOutbound(block.m_hash));
    BOOST_CHECK(manager->AllRequestsAreFor(block.m_hash));

    const auto unrelated{TestBlock(2, 2)};
    BOOST_CHECK(!manager->AllRequestsAreFor(unrelated.m_hash));
    manager->DisconnectedPeer(peer);
    manager->DisconnectedPeer(outbound_peer);
    BOOST_CHECK(manager->AllRequestsAreFor(unrelated.m_hash)); // 0 == 0, preserving the original query
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(connection_reregistration_reconnect_counters_and_owned_snapshots)
{
    auto manager{MakeManager()};
    const NodeId peer{1}, other_peer{2};
    const auto block{TestBlock(1, 1)};
    manager->ConnectedPeer(peer, {
        .m_is_inbound = false,
        .m_preferred_download = true,
        .m_can_serve_witness = false,
        .m_limited_peer = true,
    });
    manager->ReserveBlockRequest(peer, block, 10us);
    BOOST_CHECK(manager->StartStalling(peer, 11us));
    BOOST_CHECK(manager->StartSync(peer));
    BOOST_CHECK(manager->RecordBlockSource(block.m_hash, peer, /*punish_on_invalid=*/true));

    const auto original{*manager->GetPeerSnapshot(peer)};
    const auto original_global{manager->GetGlobalSnapshot()};
    BOOST_CHECK(original.m_preferred_download);
    BOOST_CHECK(!original.m_can_serve_witness);
    BOOST_CHECK(original.m_limited_peer);
    BOOST_CHECK(original.m_sync_started);
    BOOST_CHECK_EQUAL(original.m_num_preferred_download_peers, 1);
    BOOST_CHECK_EQUAL(original.m_num_sync_started, 1);
    BOOST_CHECK_EQUAL(original_global.m_in_flight_generation, 1U);

    // Exact re-registration is idempotent, including its generation and counts.
    manager->ConnectedPeer(peer, {
        .m_is_inbound = false,
        .m_preferred_download = true,
        .m_can_serve_witness = false,
        .m_limited_peer = true,
    });
    const auto unchanged{*manager->GetPeerSnapshot(peer)};
    BOOST_CHECK_EQUAL(unchanged.m_generation, original.m_generation);
    BOOST_CHECK_EQUAL(unchanged.m_num_preferred_download_peers, 1);

    // Capability updates retain all queue, timer, sync, and source state.
    manager->ConnectedPeer(peer, {
        .m_is_inbound = false,
        .m_preferred_download = false,
        .m_can_serve_witness = true,
        .m_limited_peer = false,
    });
    const auto updated{*manager->GetPeerSnapshot(peer)};
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
    BOOST_CHECK(manager->ConsumeBlockSource(block.m_hash) == (node::BlockSource{peer, true}));
    BOOST_CHECK(manager->RecordBlockSource(block.m_hash, peer, /*punish_on_invalid=*/true));
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_in_flight_generation, 1U);

    manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_preferred_download = true});
    manager->ConnectedPeer(other_peer, {.m_is_inbound = true, .m_preferred_download = true});
    manager->ConnectedPeer(other_peer, {.m_is_inbound = true, .m_preferred_download = true});
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_num_preferred_download_peers, 2);
    const auto before_disconnect{*manager->GetPeerSnapshot(peer)};

    // Previously returned snapshots remain independent owned values.
    BOOST_CHECK(original.m_preferred_download);
    BOOST_CHECK(!original.m_can_serve_witness);
    BOOST_REQUIRE_EQUAL(original.m_blocks.size(), 1U);
    BOOST_CHECK_EQUAL(original_global.m_num_preferred_download_peers, 1);

    manager->DisconnectedPeer(peer);
    auto global{manager->GetGlobalSnapshot()};
    BOOST_CHECK_EQUAL(global.m_num_preferred_download_peers, 1);
    BOOST_CHECK_EQUAL(global.m_num_sync_started, 0);
    BOOST_CHECK(!manager->ConsumeBlockSource(block.m_hash));
    BOOST_REQUIRE_EQUAL(original.m_blocks.size(), 1U);
    BOOST_CHECK(original.m_blocks.front() == block);
    BOOST_CHECK_EQUAL(original_global.m_total_requests, 1U);
    BOOST_CHECK_EQUAL(original_global.m_num_sync_started, 1);

    manager->ConnectedPeer(peer, {
        .m_is_inbound = true,
        .m_preferred_download = false,
        .m_can_serve_witness = false,
        .m_limited_peer = false,
    });
    const auto reconnected{*manager->GetPeerSnapshot(peer)};
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
    BOOST_CHECK(!manager->IsBlockRequested(block.m_hash));
    BOOST_CHECK(!manager->ConsumeBlockSource(block.m_hash));

    // The pre-disconnect owned snapshot is still unchanged and valid after reconnect.
    BOOST_CHECK(before_disconnect.m_preferred_download);
    BOOST_CHECK(!before_disconnect.m_can_serve_witness);
    BOOST_CHECK(!before_disconnect.m_limited_peer);
    BOOST_CHECK(before_disconnect.m_sync_started);
    BOOST_CHECK(before_disconnect.m_downloading_since == 10us);
    BOOST_CHECK(before_disconnect.m_stalling_since == 11us);
    BOOST_REQUIRE_EQUAL(before_disconnect.m_blocks.size(), 1U);
    BOOST_CHECK(before_disconnect.m_blocks.front() == block);

    manager->DisconnectedPeer(peer);
    manager->DisconnectedPeer(other_peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(sync_stale_tip_timeout_and_generations)
{
    auto manager{MakeManager()};
    const NodeId peer{1};
    const auto block_1{TestBlock(1, 1)};
    const auto block_2{TestBlock(2, 2)};
    manager->ConnectedPeer(peer, {.m_is_inbound = false, .m_preferred_download = true});

    auto peer_state{*manager->GetPeerSnapshot(peer)};
    const uint64_t connected_generation{peer_state.m_generation};
    BOOST_CHECK(manager->StartSync(peer));
    BOOST_CHECK(!manager->StartSync(peer));
    peer_state = *manager->GetPeerSnapshot(peer);
    BOOST_CHECK(peer_state.m_sync_started);
    BOOST_CHECK(peer_state.m_generation > connected_generation);
    BOOST_CHECK_EQUAL(peer_state.m_num_sync_started, 1);
    BOOST_CHECK(manager->ClearSync(peer));
    BOOST_CHECK(!manager->ClearSync(peer));
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_num_sync_started, 0);

    auto global{manager->GetGlobalSnapshot()};
    BOOST_CHECK(global.m_last_tip_update == 0s);
    BOOST_CHECK(global.m_block_stalling_timeout == node::DEFAULT_BLOCK_STALLING_TIMEOUT);
    BOOST_CHECK(!manager->TipMayBeStale(100s, 30s));
    BOOST_CHECK(manager->GetGlobalSnapshot().m_last_tip_update == 100s);
    BOOST_CHECK(!manager->TipMayBeStale(130s, 30s)); // Strictly older, not equal.
    BOOST_CHECK(manager->TipMayBeStale(131s, 30s));

    manager->ReserveBlockRequest(peer, block_1, 1us);
    global = manager->GetGlobalSnapshot();
    BOOST_CHECK_EQUAL(global.m_in_flight_generation, 1U);
    BOOST_CHECK(!manager->TipMayBeStale(200s, 30s));
    manager->ReserveBlockRequest(peer, block_1, 2us); // Duplicate is not a set change.
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_in_flight_generation, 1U);
    manager->ReserveBlockRequest(
        peer, block_1, 3us, std::make_shared<PartiallyDownloadedBlock>(nullptr));
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_in_flight_generation, 1U);
    manager->ReserveBlockRequest(peer, block_2, 4us);
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_in_flight_generation, 2U);
    manager->RemoveBlockRequest(block_1.m_hash, peer, 5us);
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_in_flight_generation, 3U);

    manager->UpdatedBlockTip(300s);
    BOOST_CHECK(!manager->TipMayBeStale(330s, 30s));
    manager->RemoveBlockRequest(block_2.m_hash, peer, 6us);
    BOOST_CHECK(manager->TipMayBeStale(331s, 30s));
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_in_flight_generation, 4U);

    BOOST_CHECK(manager->TryIncreaseBlockStallingTimeout(2s) == 4s);
    BOOST_CHECK(!manager->TryIncreaseBlockStallingTimeout(2s));
    BOOST_CHECK(manager->GetGlobalSnapshot().m_block_stalling_timeout == 4s);
    BOOST_CHECK(manager->TryDecreaseBlockStallingTimeout(4s) == 3s);
    BOOST_CHECK(manager->GetGlobalSnapshot().m_block_stalling_timeout == 3s);

    manager->ReserveBlockRequest(peer, block_1, 7us);
    manager->ReserveBlockRequest(peer, block_2, 8us);
    const auto before_disconnect{manager->GetGlobalSnapshot().m_in_flight_generation};
    manager->DisconnectedPeer(peer);
    BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_in_flight_generation, before_disconnect + 1);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(block_source_first_writer_consume_erase_and_disconnect)
{
    auto manager{MakeManager()};
    const NodeId peer_1{1}, peer_2{2};
    const auto hash_1{TestBlock(1, 1).m_hash};
    const auto hash_2{TestBlock(2, 2).m_hash};
    BOOST_CHECK(!manager->RecordBlockSource(hash_1, peer_1, /*punish_on_invalid=*/true));
    manager->ConnectedPeer(peer_1, {.m_is_inbound = false});
    manager->ConnectedPeer(peer_2, {.m_is_inbound = true});

    BOOST_CHECK(manager->RecordBlockSource(hash_1, peer_1, /*punish_on_invalid=*/false));
    BOOST_CHECK(!manager->RecordBlockSource(hash_1, peer_2, /*punish_on_invalid=*/true));
    const auto consumed{manager->ConsumeBlockSource(hash_1)};
    BOOST_CHECK(consumed == (node::BlockSource{peer_1, false}));
    BOOST_CHECK(!manager->ConsumeBlockSource(hash_1));

    BOOST_CHECK(manager->RecordBlockSource(hash_1, peer_2, /*punish_on_invalid=*/true));
    BOOST_CHECK(manager->EraseBlockSource(hash_1));
    BOOST_CHECK(!manager->EraseBlockSource(hash_1));
    BOOST_CHECK(manager->RecordBlockSource(hash_2, peer_1, /*punish_on_invalid=*/true));
    manager->DisconnectedPeer(peer_1);
    BOOST_CHECK(!manager->ConsumeBlockSource(hash_2));
    BOOST_CHECK(!manager->RecordBlockSource(hash_2, peer_1, /*punish_on_invalid=*/true));

    manager->DisconnectedPeer(peer_2);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(all_requests_are_for_mixed_hash)
{
    auto manager{MakeManager()};
    const NodeId peer{1};
    const auto block_1{TestBlock(1, 1)};
    const auto block_2{TestBlock(2, 2)};
    manager->ConnectedPeer(peer, {.m_is_inbound = false});
    manager->ReserveBlockRequest(peer, block_1, 1us);
    manager->ReserveBlockRequest(peer, block_2, 2us);

    BOOST_CHECK(!manager->AllRequestsAreFor(block_1.m_hash));
    BOOST_CHECK(!manager->AllRequestsAreFor(block_2.m_hash));

    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(concurrent_connect_disconnect_snapshot)
{
    static constexpr int iterations{32};
    const NodeId peer{1};
    for (int i{0}; i < iterations; ++i) {
        auto manager{MakeManager()};
        RunConcurrently(
            [&] {
                manager->ConnectedPeer(peer, {
                    .m_is_inbound = false,
                    .m_preferred_download = true,
                    .m_can_serve_witness = true,
                });
            },
            [&] { manager->DisconnectedPeer(peer); });

        if (const auto snapshot{manager->GetPeerSnapshot(peer)}) {
            BOOST_CHECK(!snapshot->m_is_inbound);
            BOOST_CHECK(snapshot->m_preferred_download);
            BOOST_CHECK(snapshot->m_can_serve_witness);
        }
        BOOST_CHECK(manager->CheckConsistency());
        manager->DisconnectedPeer(peer);
        manager->CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(concurrent_snapshot_remove_and_owned_lifetime)
{
    auto manager{MakeManager()};
    const NodeId peer{1};
    const auto block{TestBlock(1, 1)};
    manager->ConnectedPeer(peer, {.m_is_inbound = false});
    BOOST_REQUIRE(manager->ReserveBlockRequest(peer, block, 1us).m_status == BlockRequestStatus::NEW);
    const uint64_t requested_generation{manager->GetPeerSnapshot(peer)->m_generation};

    std::optional<node::PeerBlockDownloadSnapshot> snapshot_result;
    std::optional<node::BlockRequestRemoval> removal_result;
    RunConcurrently(
        [&] { snapshot_result = manager->GetPeerSnapshot(peer); },
        [&] { removal_result = manager->RemoveBlockRequest(block.m_hash, peer, 2us); });

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
    BOOST_CHECK(!manager->IsBlockRequested(block.m_hash));
    // The owned vector remains valid after the concurrent removal completes.
    if (!snapshot_result->m_blocks.empty()) BOOST_CHECK(snapshot_result->m_blocks.front() == block);
    manager->DisconnectedPeer(peer);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(concurrent_source_first_writer_consume_and_disconnect)
{
    auto manager{MakeManager()};
    const NodeId peer_1{1}, peer_2{2};
    const auto hash{TestBlock(1, 1).m_hash};
    const auto disconnect_hash{TestBlock(2, 2).m_hash};
    manager->ConnectedPeer(peer_1, {.m_is_inbound = false});
    manager->ConnectedPeer(peer_2, {.m_is_inbound = true});

    bool writer_1{false};
    bool writer_2{false};
    RunConcurrently(
        [&] { writer_1 = manager->RecordBlockSource(hash, peer_1, /*punish_on_invalid=*/false); },
        [&] { writer_2 = manager->RecordBlockSource(hash, peer_2, /*punish_on_invalid=*/true); });

    BOOST_CHECK_NE(writer_1, writer_2);
    const auto consumed{manager->ConsumeBlockSource(hash)};
    BOOST_REQUIRE(consumed);
    BOOST_CHECK(*consumed == (writer_1 ? node::BlockSource{peer_1, false} : node::BlockSource{peer_2, true}));
    BOOST_CHECK(!manager->ConsumeBlockSource(hash));

    const NodeId winning_peer{consumed->m_peer};
    BOOST_CHECK(manager->RecordBlockSource(disconnect_hash, winning_peer, consumed->m_punish_on_invalid));
    manager->DisconnectedPeer(winning_peer);
    BOOST_CHECK(!manager->ConsumeBlockSource(disconnect_hash));
    // The consumed owned value remains valid after its peer is disconnected.
    BOOST_CHECK_EQUAL(consumed->m_peer, winning_peer);

    manager->DisconnectedPeer(peer_1);
    manager->DisconnectedPeer(peer_2);
    manager->CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(concurrent_capability_and_sync_disconnect_linearization)
{
    const NodeId peer{1};
    {
        auto manager{MakeManager()};
        manager->ConnectedPeer(peer, {
            .m_is_inbound = false,
            .m_preferred_download = false,
            .m_can_serve_witness = false,
            .m_limited_peer = true,
        });
        const uint64_t old_generation{manager->GetPeerSnapshot(peer)->m_generation};
        std::optional<node::PeerBlockDownloadSnapshot> snapshot_result;
        RunConcurrently(
            [&] {
                manager->ConnectedPeer(peer, {
                    .m_is_inbound = false,
                    .m_preferred_download = true,
                    .m_can_serve_witness = true,
                    .m_limited_peer = false,
                });
            },
            [&] { snapshot_result = manager->GetPeerSnapshot(peer); });

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
        manager->DisconnectedPeer(peer);
        manager->CheckIsEmpty();
    }
    {
        auto manager{MakeManager()};
        manager->ConnectedPeer(peer, {.m_is_inbound = false});
        std::optional<bool> started;
        RunConcurrently(
            [&] { started = manager->StartSync(peer); },
            [&] { manager->DisconnectedPeer(peer); });
        BOOST_REQUIRE(started);
        // true means start linearized first; false means disconnect did.
        BOOST_CHECK(!manager->GetPeerSnapshot(peer));
        BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_num_sync_started, 0);
        manager->CheckIsEmpty();
    }
    {
        auto manager{MakeManager()};
        manager->ConnectedPeer(peer, {.m_is_inbound = false});
        BOOST_REQUIRE(manager->StartSync(peer));
        std::optional<bool> cleared;
        RunConcurrently(
            [&] { cleared = manager->ClearSync(peer); },
            [&] { manager->DisconnectedPeer(peer); });
        BOOST_REQUIRE(cleared);
        // true means clear linearized first; false means disconnect did.
        BOOST_CHECK(!manager->GetPeerSnapshot(peer));
        BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_num_sync_started, 0);
        manager->CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_CASE(concurrent_stale_tip_and_timeout_commands)
{
    {
        auto manager{MakeManager()};
        manager->UpdatedBlockTip(100s);
        std::optional<std::pair<bool, node::BlockDownloadGlobalSnapshot>> observation;
        RunConcurrently(
            [&] {
                const bool stale{manager->TipMayBeStale(200s, 30s)};
                observation.emplace(stale, manager->GetGlobalSnapshot());
            },
            [&] { manager->UpdatedBlockTip(190s); });
        BOOST_REQUIRE(observation);
        const auto& [stale, snapshot]{*observation};
        // Query and its following snapshot can both precede the update, straddle
        // it, or both follow it. These are the complete legal outcomes.
        BOOST_CHECK((stale && snapshot.m_last_tip_update == 100s) ||
                    (stale && snapshot.m_last_tip_update == 190s) ||
                    (!stale && snapshot.m_last_tip_update == 190s));
        BOOST_CHECK(manager->GetGlobalSnapshot().m_last_tip_update == 190s);
    }
    {
        auto manager{MakeManager()};
        const NodeId peer{1};
        const auto block{TestBlock(1, 1)};
        manager->ConnectedPeer(peer, {.m_is_inbound = false});
        manager->UpdatedBlockTip(100s);
        manager->ReserveBlockRequest(peer, block, 1us);
        std::optional<std::pair<bool, node::BlockDownloadGlobalSnapshot>> observation;
        std::optional<node::BlockRequestRemoval> removal_result;
        RunConcurrently(
            [&] {
                const bool stale{manager->TipMayBeStale(200s, 30s)};
                observation.emplace(stale, manager->GetGlobalSnapshot());
            },
            [&] { removal_result = manager->RemoveBlockRequest(block.m_hash, peer, 2us); });
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
        BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_total_requests, 0U);
        manager->DisconnectedPeer(peer);
        manager->CheckIsEmpty();
    }
    {
        auto manager{MakeManager()};
        BOOST_REQUIRE(manager->TryIncreaseBlockStallingTimeout(2s) == 4s);
        std::optional<std::chrono::seconds> increased;
        std::optional<std::chrono::seconds> decreased;
        RunConcurrently(
            [&] { increased = manager->TryIncreaseBlockStallingTimeout(4s); },
            [&] { decreased = manager->TryDecreaseBlockStallingTimeout(4s); });
        BOOST_REQUIRE(increased.has_value() != decreased.has_value());
        const auto final_timeout{manager->GetGlobalSnapshot().m_block_stalling_timeout};
        BOOST_CHECK(final_timeout == (increased ? *increased : *decreased));
        BOOST_CHECK(final_timeout >= 2s);
        BOOST_CHECK(final_timeout <= 64s);

        auto timeout{final_timeout};
        while (const auto next{manager->TryDecreaseBlockStallingTimeout(timeout)}) timeout = *next;
        BOOST_CHECK(timeout == 2s);
        BOOST_CHECK(!manager->TryDecreaseBlockStallingTimeout(2s));
        while (const auto next{manager->TryIncreaseBlockStallingTimeout(timeout)}) timeout = *next;
        BOOST_CHECK(timeout == 64s);
        BOOST_CHECK(!manager->TryIncreaseBlockStallingTimeout(64s));
        BOOST_CHECK(manager->GetGlobalSnapshot().m_block_stalling_timeout == 64s);
    }
}

BOOST_AUTO_TEST_CASE(concurrent_reserve_disconnect_and_remove)
{
    static constexpr int iterations{32};
    const NodeId peer{1};
    const auto block{TestBlock(1, 1)};

    for (int i{0}; i < iterations; ++i) {
        auto manager{MakeManager()};
        manager->ConnectedPeer(peer, {.m_is_inbound = false});
        std::optional<node::BlockRequestReservation> reservation;
        std::optional<node::PeerBlockDownloadSnapshot> copied_snapshot;
        std::optional<node::BlockSource> copied_source;
        std::weak_ptr<PartiallyDownloadedBlock> partial_lifetime;

        RunConcurrently(
            [&] {
                manager->RecordBlockSource(block.m_hash, peer, /*punish_on_invalid=*/true);
                copied_source = manager->ConsumeBlockSource(block.m_hash);
                if (const auto snapshot{manager->GetPeerSnapshot(peer)}) copied_snapshot = *snapshot;
                auto partial{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
                partial_lifetime = partial;
                reservation.emplace(manager->ReserveBlockRequest(peer, block, 1us, std::move(partial)));
            },
            [&] { manager->DisconnectedPeer(peer); });

        BOOST_REQUIRE(reservation);
        BOOST_CHECK(reservation->m_status == BlockRequestStatus::NEW ||
                    reservation->m_status == BlockRequestStatus::PEER_NOT_FOUND);
        BOOST_CHECK(!manager->GetPeerSnapshot(peer));
        BOOST_CHECK(!manager->IsBlockRequested(block.m_hash));
        BOOST_CHECK(!manager->ConsumeBlockSource(block.m_hash));
        if (copied_source) BOOST_CHECK(*copied_source == (node::BlockSource{peer, true}));
        if (copied_snapshot) BOOST_CHECK_EQUAL(copied_snapshot->m_is_inbound, false);
        const auto info{manager->GetBlockInFlightInfo(block.m_hash, peer)};
        BOOST_CHECK_EQUAL(info.m_request_count, 0U);
        BOOST_CHECK(!info.m_requested_from_peer);
        BOOST_CHECK(!info.m_partial_block);
        const auto summary{manager->GetGlobalSnapshot()};
        BOOST_CHECK_EQUAL(summary.m_total_requests, 0U);
        BOOST_CHECK_EQUAL(summary.m_peers_downloading_from, 0);
        BOOST_CHECK(manager->CheckConsistency());
        manager->CheckIsEmpty();

        const bool reserved{reservation->m_status == BlockRequestStatus::NEW};
        BOOST_CHECK_EQUAL(static_cast<bool>(reservation->m_partial_block), reserved);
        BOOST_CHECK_EQUAL(partial_lifetime.expired(), !reserved);
        reservation->m_partial_block.reset();
        BOOST_CHECK(partial_lifetime.expired());
    }

    for (int i{0}; i < iterations; ++i) {
        auto manager{MakeManager()};
        manager->ConnectedPeer(peer, {.m_is_inbound = false});
        std::optional<node::BlockRequestReservation> reservation;
        std::optional<node::BlockRequestRemoval> removal;
        std::weak_ptr<PartiallyDownloadedBlock> partial_lifetime;

        RunConcurrently(
            [&] {
                auto partial{std::make_shared<PartiallyDownloadedBlock>(nullptr)};
                partial_lifetime = partial;
                reservation.emplace(manager->ReserveBlockRequest(peer, block, 1us, std::move(partial)));
            },
            [&] { removal.emplace(manager->RemoveBlockRequest(block.m_hash, peer, 2us)); });

        BOOST_REQUIRE(reservation);
        BOOST_REQUIRE(removal);
        BOOST_CHECK(reservation->m_status == BlockRequestStatus::NEW);
        BOOST_CHECK((removal->m_requests_before == 0U && removal->m_removed == 0U) ||
                    (removal->m_requests_before == 1U && removal->m_removed == 1U));
        auto info{manager->GetBlockInFlightInfo(block.m_hash, peer)};
        const bool removed{removal->m_removed == 1U};
        BOOST_CHECK_EQUAL(info.m_request_count, removed ? 0U : 1U);
        BOOST_CHECK_EQUAL(info.m_requested_from_peer, !removed);
        BOOST_CHECK_EQUAL(info.m_partial_block == reservation->m_partial_block, !removed);
        BOOST_CHECK(manager->CheckConsistency());

        manager->RemoveBlockRequest(block.m_hash, peer, 3us);
        BOOST_CHECK(!manager->IsBlockRequested(block.m_hash));
        BOOST_CHECK_EQUAL(manager->GetGlobalSnapshot().m_total_requests, 0U);
        info.m_partial_block.reset();
        reservation->m_partial_block.reset();
        BOOST_CHECK(partial_lifetime.expired());
        manager->DisconnectedPeer(peer);
        BOOST_CHECK(manager->CheckConsistency());
        manager->CheckIsEmpty();
    }
}

BOOST_AUTO_TEST_SUITE_END()

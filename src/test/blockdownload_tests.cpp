// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <blockencodings.h>
#include <chain.h>
#include <consensus/validation.h>
#include <node/blockdownloadman.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

using node::BLOCK_STALLING_TIMEOUT_DEFAULT;
using node::BlockDownloadManager;
using node::BlockDownloadOptions;

BOOST_FIXTURE_TEST_SUITE(blockdownload_tests, TestingSetup)

// Test the full peer lifecycle: registration, sync state, blocks in flight,
// and disconnection with correct counter maintenance. Also covers sync-started
// idempotency and explicit unsetting.
BOOST_AUTO_TEST_CASE(peer_lifecycle)
{
    LOCK(cs_main);
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});

    const NodeId peer1{0}, peer2{1};
    bdm.ConnectedPeer(peer1, /*is_inbound=*/false);
    bdm.ConnectedPeer(peer2, /*is_inbound=*/true);

    BOOST_CHECK_EQUAL(bdm.GetNumSyncStarted(), 0);
    BOOST_CHECK_EQUAL(bdm.GetPeersDownloadingFrom(), 0);
    BOOST_CHECK(!bdm.HasBlocksInFlight());

    // Set sync started for both peers
    bdm.SetSyncStarted(peer1, true);
    bdm.SetSyncStarted(peer2, true);
    BOOST_CHECK_EQUAL(bdm.GetNumSyncStarted(), 2);
    BOOST_CHECK(bdm.GetSyncStarted(peer1));
    BOOST_CHECK(bdm.GetSyncStarted(peer2));

    // Setting same value again should not change count (idempotency)
    bdm.SetSyncStarted(peer1, true);
    BOOST_CHECK_EQUAL(bdm.GetNumSyncStarted(), 2);

    // Explicitly unset sync for peer2
    bdm.SetSyncStarted(peer2, false);
    BOOST_CHECK_EQUAL(bdm.GetNumSyncStarted(), 1);
    BOOST_CHECK(!bdm.GetSyncStarted(peer2));

    // Request a block from peer1 — should update in-flight counters
    const CBlockIndex* genesis = m_node.chainman->ActiveChain().Genesis();
    BOOST_REQUIRE(genesis != nullptr);
    bdm.BlockRequested(peer1, *genesis);
    BOOST_CHECK(bdm.HasBlocksInFlight());
    BOOST_CHECK_EQUAL(bdm.GetPeersDownloadingFrom(), 1);
    BOOST_CHECK(bdm.IsBlockRequested(genesis->GetBlockHash()));

    // Disconnect peer1 — should clean up sync and in-flight state
    bdm.DisconnectedPeer(peer1);
    BOOST_CHECK_EQUAL(bdm.GetNumSyncStarted(), 0);
    BOOST_CHECK_EQUAL(bdm.GetPeersDownloadingFrom(), 0);
    BOOST_CHECK(!bdm.HasBlocksInFlight());

    // Disconnect peer2
    bdm.DisconnectedPeer(peer2);
    bdm.CheckIsEmpty();
}

// Test that block source attribution (which peer sent a block) can be
// set, queried, and erased, and that unrelated hashes are not affected.
BOOST_AUTO_TEST_CASE(block_source_tracking)
{
    LOCK(cs_main);
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});

    uint256 hash1 = uint256::ONE;
    uint256 hash2{ArithToUint256(arith_uint256{2})};
    NodeId peer1{0};

    // Initially no source
    BOOST_CHECK(!bdm.GetBlockSource(hash1).has_value());

    // Set source
    bdm.SetBlockSource(hash1, peer1, /*punish_on_invalid=*/true);
    auto source = bdm.GetBlockSource(hash1);
    BOOST_CHECK(source.has_value());
    BOOST_CHECK_EQUAL(source->first, peer1);
    BOOST_CHECK_EQUAL(source->second, true);

    // No source for different hash
    BOOST_CHECK(!bdm.GetBlockSource(hash2).has_value());

    // Erase source
    bdm.EraseBlockSource(hash1);
    BOOST_CHECK(!bdm.GetBlockSource(hash1).has_value());
}

// Test last tip update get/set and TipMayBeStale logic: lazy initialization,
// recent vs old tip, and staleness threshold.
BOOST_AUTO_TEST_CASE(stalling_and_tip_staleness)
{
    LOCK(cs_main);
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});

    int64_t pow_spacing = 600; // 10 minutes
    auto now = GetTime<std::chrono::seconds>();

    // Last tip update: initially zero, then set/read back
    BOOST_CHECK(bdm.GetLastTipUpdate() == std::chrono::seconds{0});

    // First call with last_tip_update at 0 initializes it to now and returns false
    BOOST_CHECK(!bdm.TipMayBeStale(now, pow_spacing));

    // Set a recent tip update — not stale
    bdm.SetLastTipUpdate(now);
    BOOST_CHECK(bdm.GetLastTipUpdate() == now);
    BOOST_CHECK(!bdm.TipMayBeStale(now, pow_spacing));

    // Set an old tip update — stale (no blocks in flight)
    bdm.SetLastTipUpdate(now - std::chrono::seconds{pow_spacing * 4});
    BOOST_CHECK(bdm.TipMayBeStale(now, pow_spacing));
}

// Test basic block request flow: requesting a block marks it in-flight,
// updates counters, detects outbound requests, rejects duplicate requests
// from the same peer, and cleans up on removal.
BOOST_AUTO_TEST_CASE(block_requested_basic)
{
    LOCK(cs_main);
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});

    NodeId peer1{0};
    bdm.ConnectedPeer(peer1, /*is_inbound=*/false);

    // Use the genesis block as our test block
    const CBlockIndex* genesis = m_node.chainman->ActiveChain().Genesis();
    BOOST_REQUIRE(genesis != nullptr);

    // Initially not requested
    BOOST_CHECK(!bdm.IsBlockRequested(genesis->GetBlockHash()));

    // Request it
    bool first = bdm.BlockRequested(peer1, *genesis);
    BOOST_CHECK(first);
    BOOST_CHECK(bdm.IsBlockRequested(genesis->GetBlockHash()));
    // peer1 is NOT inbound (m_is_inbound=false), so it IS outbound
    BOOST_CHECK(bdm.IsBlockRequestedFromOutbound(genesis->GetBlockHash()));
    BOOST_CHECK_EQUAL(bdm.GetPeersDownloadingFrom(), 1);
    BOOST_CHECK_EQUAL(bdm.CountBlocksInFlight(genesis->GetBlockHash()), 1u);

    // Request same block from same peer — returns false
    bool second = bdm.BlockRequested(peer1, *genesis);
    BOOST_CHECK(!second);

    // Remove the request
    bdm.RemoveBlockRequest(genesis->GetBlockHash(), std::nullopt);
    BOOST_CHECK(!bdm.IsBlockRequested(genesis->GetBlockHash()));
    BOOST_CHECK_EQUAL(bdm.GetPeersDownloadingFrom(), 0);

    bdm.DisconnectedPeer(peer1);
    bdm.CheckIsEmpty();
}

// Test that RemoveBlockRequest with a specific peer only removes that
// peer's request, leaving requests from other peers intact.
BOOST_AUTO_TEST_CASE(remove_block_request_from_specific_peer)
{
    LOCK(cs_main);
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});

    NodeId peer1{0}, peer2{1};
    bdm.ConnectedPeer(peer1, /*is_inbound=*/false);
    bdm.ConnectedPeer(peer2, /*is_inbound=*/true);

    const CBlockIndex* genesis = m_node.chainman->ActiveChain().Genesis();

    // Request from peer1
    bdm.BlockRequested(peer1, *genesis);
    BOOST_CHECK(bdm.IsBlockRequested(genesis->GetBlockHash()));

    // Try to remove from peer2 — should not remove
    bdm.RemoveBlockRequest(genesis->GetBlockHash(), peer2);
    BOOST_CHECK(bdm.IsBlockRequested(genesis->GetBlockHash()));

    // Remove from peer1 — should remove
    bdm.RemoveBlockRequest(genesis->GetBlockHash(), peer1);
    BOOST_CHECK(!bdm.IsBlockRequested(genesis->GetBlockHash()));

    bdm.DisconnectedPeer(peer1);
    bdm.DisconnectedPeer(peer2);
    bdm.CheckIsEmpty();
}

// Test that TipMayBeStale returns false when blocks are in flight,
// even if the last tip update is old enough to trigger staleness.
BOOST_AUTO_TEST_CASE(tip_not_stale_with_blocks_in_flight)
{
    LOCK(cs_main);
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});

    NodeId peer1{0};
    bdm.ConnectedPeer(peer1, /*is_inbound=*/false);

    int64_t pow_spacing = 600;
    auto now = GetTime<std::chrono::seconds>();

    // Initialize lazy tip update
    bdm.TipMayBeStale(now, pow_spacing);

    // Set an old tip update — stale when no blocks are in flight
    bdm.SetLastTipUpdate(now - std::chrono::seconds{pow_spacing * 4});
    BOOST_CHECK(bdm.TipMayBeStale(now, pow_spacing));

    // Put a block in flight
    const CBlockIndex* genesis = m_node.chainman->ActiveChain().Genesis();
    bdm.BlockRequested(peer1, *genesis);
    BOOST_CHECK(bdm.HasBlocksInFlight());

    // Tip should NOT be stale — blocks in flight means we're making progress
    BOOST_CHECK(!bdm.TipMayBeStale(now, pow_spacing));

    // Remove the in-flight block — staleness returns
    bdm.RemoveBlockRequest(genesis->GetBlockHash(), std::nullopt);
    BOOST_CHECK(bdm.TipMayBeStale(now, pow_spacing));

    bdm.DisconnectedPeer(peer1);
    bdm.CheckIsEmpty();
}

// Test CompareExchangeBlockStallingTimeout CAS semantics: fails when the
// expected value does not match current (updating expected to actual),
// succeeds when it does match.
BOOST_AUTO_TEST_CASE(compare_exchange_stalling_timeout)
{
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});

    // Initial value is default
    BOOST_CHECK(bdm.GetBlockStallingTimeout() == BLOCK_STALLING_TIMEOUT_DEFAULT);

    // CAS with wrong expected value — should fail
    auto wrong = std::chrono::seconds{999};
    BOOST_CHECK(!bdm.CompareExchangeBlockStallingTimeout(wrong, std::chrono::seconds{10}));
    // On failure, expected is updated to the actual current value
    BOOST_CHECK(wrong == BLOCK_STALLING_TIMEOUT_DEFAULT);
    // Value unchanged
    BOOST_CHECK(bdm.GetBlockStallingTimeout() == BLOCK_STALLING_TIMEOUT_DEFAULT);

    // CAS with correct expected value — should succeed
    auto expected = BLOCK_STALLING_TIMEOUT_DEFAULT;
    BOOST_CHECK(bdm.CompareExchangeBlockStallingTimeout(expected, std::chrono::seconds{4}));
    BOOST_CHECK(bdm.GetBlockStallingTimeout() == std::chrono::seconds{4});
}

// Test block download scheduling against headers-only blocks: peers that have
// announced nothing yield no requests; announced headers are scheduled in
// height order, capped by count and skipping blocks already in flight; and
// historical download refuses peers that cannot serve the target chain.
BOOST_FIXTURE_TEST_CASE(find_next_blocks_to_download, TestChain100Setup)
{
    ChainstateManager& chainman = *m_node.chainman;

    // Build 5 headers-only successors of the current tip (no block data).
    const CBlockIndex* tip = WITH_LOCK(cs_main, return chainman.ActiveChain().Tip());
    std::vector<CBlockHeader> headers;
    uint256 prev_hash{tip->GetBlockHash()};
    uint32_t prev_time{static_cast<uint32_t>(tip->GetBlockTime())};
    for (size_t i = 0; i < 5; ++i) {
        CBlockHeader header;
        header.nVersion = 0x20000000;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = ArithToUint256(arith_uint256{i + 1});
        header.nTime = ++prev_time;
        header.nBits = tip->nBits;
        header.nNonce = 0;
        while (!CheckProofOfWork(header.GetHash(), header.nBits, chainman.GetConsensus())) {
            ++header.nNonce;
        }
        prev_hash = header.GetHash();
        headers.push_back(header);
    }
    BlockValidationState state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state));

    LOCK(cs_main);
    BlockDownloadManager bdm(BlockDownloadOptions{chainman});

    const NodeId peer1{0}, peer2{1};
    bdm.ConnectedPeer(peer1, /*is_inbound=*/false);
    bdm.ConnectedPeer(peer2, /*is_inbound=*/false);

    // A peer that has not announced anything yields no requests.
    std::vector<const CBlockIndex*> blocks;
    NodeId staller{-1};
    bdm.FindNextBlocksToDownload(peer1, {.m_can_serve_witnesses = true, .m_is_limited_peer = false}, /*count=*/16, blocks, staller);
    BOOST_CHECK(blocks.empty());

    // Announce the last header: all 5 blocks are scheduled in height order,
    // and the last common block becomes the old tip.
    bdm.UpdateBlockAvailability(peer1, headers.back().GetHash());
    BOOST_REQUIRE(bdm.GetBestKnownBlock(peer1) != nullptr);
    BOOST_CHECK_EQUAL(bdm.GetBestKnownBlock(peer1)->nHeight, tip->nHeight + 5);

    bdm.FindNextBlocksToDownload(peer1, {.m_can_serve_witnesses = true, .m_is_limited_peer = false}, /*count=*/16, blocks, staller);
    BOOST_REQUIRE_EQUAL(blocks.size(), 5u);
    for (size_t i = 0; i < blocks.size(); ++i) {
        BOOST_CHECK_EQUAL(blocks[i]->GetBlockHash().ToString(), headers[i].GetHash().ToString());
    }
    BOOST_CHECK(bdm.GetLastCommonBlock(peer1) == tip);

    // The count limit caps the schedule.
    blocks.clear();
    bdm.FindNextBlocksToDownload(peer1, {.m_can_serve_witnesses = true, .m_is_limited_peer = false}, /*count=*/2, blocks, staller);
    BOOST_REQUIRE_EQUAL(blocks.size(), 2u);

    // Blocks already in flight (from any peer) are skipped.
    const CBlockIndex* first_index{chainman.m_blockman.LookupBlockIndex(headers[0].GetHash())};
    BOOST_REQUIRE(first_index != nullptr);
    bdm.BlockRequested(peer2, *first_index);
    blocks.clear();
    bdm.FindNextBlocksToDownload(peer1, {.m_can_serve_witnesses = true, .m_is_limited_peer = false}, /*count=*/16, blocks, staller);
    BOOST_REQUIRE_EQUAL(blocks.size(), 4u);
    BOOST_CHECK_EQUAL(blocks[0]->GetBlockHash().ToString(), headers[1].GetHash().ToString());

    // count == 0 is a no-op.
    blocks.clear();
    bdm.FindNextBlocksToDownload(peer1, {.m_can_serve_witnesses = true, .m_is_limited_peer = false}, /*count=*/0, blocks, staller);
    BOOST_CHECK(blocks.empty());

    bdm.RemoveBlockRequest(first_index->GetBlockHash(), std::nullopt);

    // Historical download: peer2 has not announced the target block's chain,
    // so it cannot serve the blocks leading up to it.
    const CBlockIndex* target{chainman.m_blockman.LookupBlockIndex(headers.back().GetHash())};
    BOOST_REQUIRE(target != nullptr);
    blocks.clear();
    bdm.TryDownloadingHistoricalBlocks(peer2, {.m_can_serve_witnesses = true, .m_is_limited_peer = false}, /*count=*/16, blocks, tip, target);
    BOOST_CHECK(blocks.empty());

    // peer1 announced the chain containing the target, so the full range of
    // historical blocks up to the target is scheduled.
    blocks.clear();
    bdm.TryDownloadingHistoricalBlocks(peer1, {.m_can_serve_witnesses = true, .m_is_limited_peer = false}, /*count=*/16, blocks, tip, target);
    BOOST_REQUIRE_EQUAL(blocks.size(), 5u);

    bdm.DisconnectedPeer(peer1);
    bdm.DisconnectedPeer(peer2);
    bdm.CheckIsEmpty();
}


// Registration is independent of capabilities learned in VERSION. Scheduling
// uses the capabilities supplied for each call, including after a change.
BOOST_FIXTURE_TEST_CASE(scheduling_capabilities, TestChain100Setup)
{
    const CBlockIndex* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    std::vector<std::shared_ptr<CBlock>> chain;
    BOOST_REQUIRE(BuildChain(m_node, tip, CScript{} << OP_TRUE, 1, chain));

    LOCK(cs_main);
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});
    bdm.ConnectedPeer(0, /*is_inbound=*/false);
    bdm.UpdateBlockAvailability(0, chain.back()->GetHash());

    std::vector<const CBlockIndex*> blocks;
    NodeId staller{-1};
    bdm.FindNextBlocksToDownload(0, {.m_can_serve_witnesses = false, .m_is_limited_peer = false}, 16, blocks, staller);
    BOOST_CHECK(blocks.empty());
    bdm.FindNextBlocksToDownload(0, {.m_can_serve_witnesses = true, .m_is_limited_peer = false}, 16, blocks, staller);
    BOOST_REQUIRE_EQUAL(blocks.size(), 1U);
    BOOST_CHECK(blocks.front()->GetBlockHash() == chain.front()->GetHash());
    bdm.DisconnectedPeer(0);
    bdm.CheckIsEmpty();
}

// Removing a request from one peer preserves another peer's request and the
// order of the remaining queue. Disconnect/reconnect resets pause and sync state.
BOOST_FIXTURE_TEST_CASE(request_queue_and_pause, TestChain100Setup)
{
    LOCK(cs_main);
    auto& chain = m_node.chainman->ActiveChain();
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});
    bdm.ConnectedPeer(0, /*is_inbound=*/false);
    bdm.ConnectedPeer(1, /*is_inbound=*/true);
    bdm.BlockRequested(0, *chain[1]);
    bdm.BlockRequested(0, *chain[2]);
    bdm.BlockRequested(1, *chain[1]);
    const auto heights = bdm.GetRequestedBlockHeights(0);
    BOOST_CHECK(heights == std::vector<int>({1, 2}));
    BOOST_CHECK(bdm.GetFirstBlockInFlight(0) == chain[1]->GetBlockHash());
    BOOST_CHECK_EQUAL(bdm.GetPeersDownloadingFrom(), 2);
    bdm.SetStallingSince(0, 1s);
    bdm.PauseDownload(0, 60s);
    bdm.SetSyncStarted(0, true);
    bdm.RemoveBlockRequest(chain[1]->GetBlockHash(), 0);
    BOOST_CHECK_EQUAL(bdm.GetNumBlocksInFlight(0), 1U);
    BOOST_CHECK(bdm.GetFirstBlockInFlight(0) == chain[2]->GetBlockHash());
    BOOST_CHECK(bdm.GetStallingSince(0) == 0us);
    BOOST_CHECK(bdm.GetDownloadPausedUntil(0) == 60s);
    BOOST_CHECK(bdm.IsBlockRequested(chain[1]->GetBlockHash()));
    BOOST_CHECK(!bdm.IsBlockRequestedFromOutbound(chain[1]->GetBlockHash()));
    bdm.DisconnectedPeer(0);
    bdm.ConnectedPeer(0, /*is_inbound=*/false);
    BOOST_CHECK(!bdm.GetFirstBlockInFlight(0));
    BOOST_CHECK(bdm.GetDownloadPausedUntil(0) == 0us);
    BOOST_CHECK(!bdm.GetSyncStarted(0));
    BOOST_CHECK_EQUAL(bdm.GetPeersDownloadingFrom(), 1);
    bdm.DisconnectedPeer(0);
    bdm.DisconnectedPeer(1);
    bdm.CheckIsEmpty();
}

// Compact reconstruction never exposes a queue iterator or partial block.
// A duplicate announcement keeps the original request and its ordering.
BOOST_FIXTURE_TEST_CASE(compact_block_lifecycle, TestChain100Setup)
{
    const CBlockIndex* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    std::vector<std::shared_ptr<CBlock>> chain;
    BOOST_REQUIRE(BuildChain(m_node, tip, CScript{} << OP_TRUE, 1, chain));
    const auto& block = *chain.front();
    const auto hash = block.GetHash();
    CBlockHeaderAndShortTxIDs compact{block, /*nonce=*/0};

    LOCK(cs_main);
    const auto& index = *Assert(m_node.chainman->m_blockman.LookupBlockIndex(hash));
    BlockDownloadManager bdm(BlockDownloadOptions{*m_node.chainman});
    bdm.ConnectedPeer(0, /*is_inbound=*/false);
    bdm.ConnectedPeer(1, /*is_inbound=*/true);
    bdm.BlockRequested(0, index);
    BOOST_CHECK(!bdm.FindBlockInFlight(hash, 0).has_partial_block);
    auto result = bdm.InitCompactBlock(1, index, compact, {}, *m_node.mempool);
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(result->status, READ_STATUS_OK);
    BOOST_CHECK(result->missing_transactions.empty());
    const auto info = bdm.FindBlockInFlight(hash, 1);
    BOOST_CHECK_EQUAL(info.already_in_flight, 2U);
    BOOST_CHECK(!info.first_in_flight);
    BOOST_CHECK(info.requested_from_peer);
    BOOST_CHECK(info.has_partial_block);
    BOOST_CHECK(!info.partial_block_failed);
    BOOST_CHECK(!bdm.InitCompactBlock(1, index, compact, {}, *m_node.mempool));
    BOOST_CHECK_EQUAL(bdm.CountBlocksInFlight(hash), 2U);

    BlockTransactions transactions;
    transactions.blockhash = hash;
    CBlock reconstructed;
    BOOST_CHECK_EQUAL(bdm.FillBlock(1, transactions, reconstructed), READ_STATUS_OK);
    BOOST_CHECK(reconstructed.GetHash() == hash);
    // FillBlock consumes the header, even though request removal is the caller's decision.
    BOOST_CHECK(bdm.FindBlockInFlight(hash, 1).partial_block_failed);
    BOOST_CHECK(!bdm.InitCompactBlock(1, index, compact, {}, *m_node.mempool));
    bdm.RemoveBlockRequest(hash, 1);
    BOOST_CHECK(bdm.FindBlockInFlight(hash, 0).first_in_flight);
    BOOST_CHECK_EQUAL(bdm.CountBlocksInFlight(hash), 1U);

    // A full-block request can be upgraded to compact reconstruction without
    // changing the request count or starting a new download timer.
    const auto downloading_since = bdm.GetDownloadingSince(0);
    BOOST_REQUIRE(bdm.InitCompactBlock(0, index, compact, {}, *m_node.mempool));
    BOOST_CHECK(bdm.GetDownloadingSince(0) == downloading_since);
    BOOST_CHECK_EQUAL(bdm.CountBlocksInFlight(hash), 1U);
    bdm.DisconnectedPeer(0);
    bdm.DisconnectedPeer(1);
    bdm.CheckIsEmpty();
}

BOOST_AUTO_TEST_SUITE_END()

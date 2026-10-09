// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <blockencodings.h>
#include <chain.h>
#include <node/blockdownloadman.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <uint256.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <list>
#include <vector>

using node::BlockDownloadCounter;
using node::BlockDownloadManager;
using node::BlockDownloadPeer;
using node::QueuedBlock;

namespace {
/** Block index entries for requests. The manager only reads their hash and height. */
struct TestBlocks {
    std::array<uint256, 4> hashes;
    std::array<CBlockIndex, 4> index;

    TestBlocks()
    {
        for (size_t i{0}; i < index.size(); ++i) {
            hashes[i] = ArithToUint256(arith_uint256{i + 1});
            index[i].phashBlock = &hashes[i];
            index[i].nHeight = static_cast<int>(i + 1);
        }
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(blockdownload_tests, TestingSetup)

// Requests are tracked per peer and globally, and dropped when the peer
// disconnects. A disconnected peer has nothing in flight.
BOOST_AUTO_TEST_CASE(peer_lifecycle)
{
    LOCK(cs_main);
    BlockDownloadCounter downloading_from;
    BlockDownloadManager bdm{downloading_from};
    TestBlocks blocks;
    BlockDownloadPeer peer1{/*id=*/0, /*is_inbound=*/false};
    BlockDownloadPeer peer2{/*id=*/1, /*is_inbound=*/true};

    BOOST_CHECK(bdm.BlockRequested(peer1, blocks.index[0]));
    BOOST_CHECK(bdm.BlockRequested(peer1, blocks.index[1]));
    BOOST_CHECK(bdm.BlockRequested(peer2, blocks.index[2]));
    BOOST_CHECK_EQUAL(bdm.GetTotalBlocksInFlight(), 3U);
    BOOST_CHECK_EQUAL(downloading_from.Get(), 2);
    BOOST_CHECK_EQUAL(bdm.NumBlocksInFlight(peer1), 2U);
    BOOST_CHECK(bdm.BlocksInFlightHeights(peer1) == (std::vector<int>{1, 2}));
    BOOST_CHECK_EQUAL(bdm.FirstBlockInFlight(peer1), &blocks.index[0]);
    BOOST_CHECK_EQUAL(bdm.PeerId(peer2), 1);

    bdm.DisconnectedPeer(peer1);
    BOOST_CHECK(!bdm.IsBlockRequested(blocks.hashes[0]));
    BOOST_CHECK(!bdm.IsBlockRequested(blocks.hashes[1]));
    BOOST_CHECK(bdm.IsBlockRequested(blocks.hashes[2]));
    BOOST_CHECK_EQUAL(bdm.GetTotalBlocksInFlight(), 1U);
    BOOST_CHECK_EQUAL(downloading_from.Get(), 1);
    BOOST_CHECK_EQUAL(bdm.NumBlocksInFlight(peer1), 0U);
    BOOST_CHECK(bdm.BlocksInFlightHeights(peer1).empty());
    BOOST_CHECK(bdm.FirstBlockInFlight(peer1) == nullptr);

    bdm.DisconnectedPeer(peer2);
    bdm.CheckIsEmpty();
}

// A repeated request from the same peer is not added again, and the request
// is reported as outbound only if an outbound peer has it.
BOOST_AUTO_TEST_CASE(block_requested_basic)
{
    LOCK(cs_main);
    BlockDownloadCounter downloading_from;
    BlockDownloadManager bdm{downloading_from};
    TestBlocks blocks;
    BlockDownloadPeer inbound{/*id=*/0, /*is_inbound=*/true};
    BlockDownloadPeer outbound{/*id=*/1, /*is_inbound=*/false};
    const uint256& hash{blocks.hashes[0]};

    BOOST_CHECK(!bdm.IsBlockRequested(hash));
    BOOST_CHECK(bdm.BlockRequested(inbound, blocks.index[0]));
    BOOST_CHECK(bdm.IsBlockRequested(hash));
    BOOST_CHECK(!bdm.IsBlockRequestedFromOutbound(hash));
    BOOST_CHECK(!bdm.BlockRequested(inbound, blocks.index[0]));
    BOOST_CHECK_EQUAL(bdm.CountBlocksInFlight(hash), 1U);

    BOOST_CHECK(bdm.BlockRequested(outbound, blocks.index[0]));
    BOOST_CHECK(bdm.IsBlockRequestedFromOutbound(hash));
    BOOST_CHECK_EQUAL(bdm.CountBlocksInFlight(hash), 2U);
    BOOST_CHECK(bdm.FirstRequestedFrom(hash) == &inbound);

    bdm.RemoveBlockRequest(hash, nullptr);
    BOOST_CHECK(!bdm.IsBlockRequested(hash));
    BOOST_CHECK(bdm.FirstRequestedFrom(hash) == nullptr);
    BOOST_CHECK_EQUAL(downloading_from.Get(), 0);

    bdm.DisconnectedPeer(inbound);
    bdm.DisconnectedPeer(outbound);
    bdm.CheckIsEmpty();
}

// Removing a request on behalf of one peer leaves other peers' requests for
// the same block alone.
BOOST_AUTO_TEST_CASE(remove_block_request_from_specific_peer)
{
    LOCK(cs_main);
    BlockDownloadCounter downloading_from;
    BlockDownloadManager bdm{downloading_from};
    TestBlocks blocks;
    BlockDownloadPeer peer1{/*id=*/0, /*is_inbound=*/false};
    BlockDownloadPeer peer2{/*id=*/1, /*is_inbound=*/false};
    const uint256& hash{blocks.hashes[0]};

    bdm.BlockRequested(peer1, blocks.index[0]);
    bdm.RemoveBlockRequest(hash, &peer2);
    BOOST_CHECK(bdm.IsBlockRequested(hash));

    bdm.BlockRequested(peer2, blocks.index[0]);
    bdm.RemoveBlockRequest(hash, &peer2);
    BOOST_CHECK_EQUAL(bdm.CountBlocksInFlight(hash), 1U);
    BOOST_CHECK(bdm.FirstRequestedFrom(hash) == &peer1);
    BOOST_CHECK_EQUAL(bdm.NumBlocksInFlight(peer1), 1U);
    BOOST_CHECK_EQUAL(bdm.NumBlocksInFlight(peer2), 0U);
    BOOST_CHECK_EQUAL(downloading_from.Get(), 1);

    bdm.RemoveBlockRequest(hash, &peer1);
    BOOST_CHECK(!bdm.IsBlockRequested(hash));

    bdm.DisconnectedPeer(peer1);
    bdm.DisconnectedPeer(peer2);
    bdm.CheckIsEmpty();
}

// The view of a block's requests from each peer, including the partial block
// that only compact block requests have.
BOOST_AUTO_TEST_CASE(find_block_in_flight)
{
    LOCK(cs_main);
    BlockDownloadCounter downloading_from;
    BlockDownloadManager bdm{downloading_from};
    TestBlocks blocks;
    BlockDownloadPeer peer1{/*id=*/0, /*is_inbound=*/false};
    BlockDownloadPeer peer2{/*id=*/1, /*is_inbound=*/true};
    BlockDownloadPeer peer3{/*id=*/2, /*is_inbound=*/true};
    const uint256& hash{blocks.hashes[0]};

    auto info{bdm.FindBlockInFlight(hash, peer1)};
    BOOST_CHECK_EQUAL(info.already_in_flight, 0U);
    BOOST_CHECK(info.first_in_flight);
    BOOST_CHECK(!info.requested_from_peer);
    BOOST_CHECK(info.compact_request == nullptr);

    bdm.BlockRequested(peer1, blocks.index[0]);
    std::list<QueuedBlock>::iterator* pit{nullptr};
    BOOST_CHECK(bdm.BlockRequested(peer2, blocks.index[0], &pit, m_node.mempool.get()));
    BOOST_REQUIRE(pit != nullptr);
    BOOST_CHECK((*pit)->partialBlock);

    info = bdm.FindBlockInFlight(hash, peer1);
    BOOST_CHECK_EQUAL(info.already_in_flight, 2U);
    BOOST_CHECK(info.first_in_flight);
    BOOST_CHECK(info.requested_from_peer);
    BOOST_CHECK(info.compact_request == nullptr);

    info = bdm.FindBlockInFlight(hash, peer2);
    BOOST_CHECK_EQUAL(info.already_in_flight, 2U);
    BOOST_CHECK(!info.first_in_flight);
    BOOST_CHECK(info.requested_from_peer);
    BOOST_CHECK(info.compact_request == &**pit);

    info = bdm.FindBlockInFlight(hash, peer3);
    BOOST_CHECK_EQUAL(info.already_in_flight, 2U);
    BOOST_CHECK(!info.first_in_flight);
    BOOST_CHECK(!info.requested_from_peer);
    BOOST_CHECK(info.compact_request == nullptr);

    // A repeated compact request from the same peer returns its existing request.
    std::list<QueuedBlock>::iterator* pit_again{nullptr};
    BOOST_CHECK(!bdm.BlockRequested(peer2, blocks.index[0], &pit_again, m_node.mempool.get()));
    BOOST_CHECK(pit_again != nullptr && &**pit_again == &**pit);

    bdm.DisconnectedPeer(peer1);
    bdm.DisconnectedPeer(peer2);
    bdm.DisconnectedPeer(peer3);
    bdm.CheckIsEmpty();
}

// The download timer starts with a peer's first request and moves on when its
// oldest request completes. Any completed request ends a stall.
BOOST_AUTO_TEST_CASE(download_and_stalling_times)
{
    LOCK(cs_main);
    BlockDownloadCounter downloading_from;
    BlockDownloadManager bdm{downloading_from};
    TestBlocks blocks;
    BlockDownloadPeer peer{/*id=*/0, /*is_inbound=*/false};

    FakeNodeClock clock;
    const auto start{GetTime<std::chrono::seconds>()};
    bdm.BlockRequested(peer, blocks.index[0]);
    clock += 10s;
    bdm.BlockRequested(peer, blocks.index[1]);
    BOOST_CHECK(bdm.DownloadingSince(peer) == start);

    bdm.SetStallingSince(peer, start + 20s);
    BOOST_CHECK(bdm.StallingSince(peer) == start + 20s);

    // Completing a later request leaves the timer, but ends the stall.
    clock += 20s;
    bdm.RemoveBlockRequest(blocks.hashes[1], &peer);
    BOOST_CHECK(bdm.DownloadingSince(peer) == start);
    BOOST_CHECK(bdm.StallingSince(peer) == 0us);

    bdm.BlockRequested(peer, blocks.index[1]);
    clock += 10s;
    bdm.RemoveBlockRequest(blocks.hashes[0], &peer);
    BOOST_CHECK(bdm.DownloadingSince(peer) == start + 40s);
    BOOST_CHECK_EQUAL(bdm.FirstBlockInFlight(peer), &blocks.index[1]);

    bdm.DisconnectedPeer(peer);
    bdm.CheckIsEmpty();
}

// Pausing a peer releases its requests, so other peers can take them.
BOOST_AUTO_TEST_CASE(pause_block_download)
{
    LOCK(cs_main);
    BlockDownloadCounter downloading_from;
    BlockDownloadManager bdm{downloading_from};
    TestBlocks blocks;
    BlockDownloadPeer paused{/*id=*/0, /*is_inbound=*/false};
    BlockDownloadPeer other{/*id=*/1, /*is_inbound=*/false};

    bdm.BlockRequested(paused, blocks.index[0]);
    bdm.BlockRequested(paused, blocks.index[1]);
    bdm.BlockRequested(other, blocks.index[1]);
    BOOST_CHECK(bdm.PausedUntil(paused) == 0us);

    bdm.PauseBlockDownload(paused, 100s);
    BOOST_CHECK(bdm.PausedUntil(paused) == 100s);
    BOOST_CHECK_EQUAL(bdm.NumBlocksInFlight(paused), 0U);
    BOOST_CHECK(!bdm.IsBlockRequested(blocks.hashes[0]));
    BOOST_CHECK(bdm.FirstRequestedFrom(blocks.hashes[1]) == &other);
    BOOST_CHECK_EQUAL(downloading_from.Get(), 1);

    bdm.DisconnectedPeer(paused);
    bdm.DisconnectedPeer(other);
    bdm.CheckIsEmpty();
}

// The first recorded source of a block is kept until it is taken or erased.
BOOST_AUTO_TEST_CASE(block_source_tracking)
{
    BlockDownloadCounter downloading_from;
    BlockDownloadManager bdm{downloading_from};
    TestBlocks blocks;
    const uint256& hash{blocks.hashes[0]};

    BOOST_CHECK(!bdm.TakeBlockSource(hash));

    bdm.AddBlockSource(hash, /*peer=*/1, /*punish_on_invalid=*/true);
    bdm.AddBlockSource(hash, /*peer=*/2, /*punish_on_invalid=*/false);
    const auto source{bdm.TakeBlockSource(hash)};
    BOOST_REQUIRE(source);
    BOOST_CHECK_EQUAL(source->first, 1);
    BOOST_CHECK(source->second);
    BOOST_CHECK(!bdm.TakeBlockSource(hash));

    bdm.AddBlockSource(hash, /*peer=*/2, /*punish_on_invalid=*/false);
    bdm.EraseBlockSource(hash);
    BOOST_CHECK(!bdm.TakeBlockSource(hash));
}

BOOST_AUTO_TEST_SUITE_END()

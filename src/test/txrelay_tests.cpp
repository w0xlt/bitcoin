// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>
#include <node/txrelay.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <vector>

using namespace std::chrono_literals;
using node::TxRelay;

BOOST_FIXTURE_TEST_SUITE(txrelay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(push_inventory_gated_on_scheduled_send)
{
    TxRelay tx_relay;
    const uint256 hash{m_rng.rand256()};
    const auto wtxid{Wtxid::FromUint256(hash)};

    // Before the first inv send is scheduled (i.e. before the version
    // handshake completes), announcements must be dropped so the arrival
    // time cannot leak to a spy.
    BOOST_CHECK(tx_relay.IsInventoryPristine());
    tx_relay.PushInventory(hash, wtxid);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 0U);

    // Once a send is scheduled, announcements are queued.
    WITH_LOCK(tx_relay.GetTxInventoryMutex(), tx_relay.SetNextInvSendTime(1us));
    BOOST_CHECK(!tx_relay.IsInventoryPristine());
    tx_relay.PushInventory(hash, wtxid);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);

    // Re-announcing the same transaction does not grow the queue.
    tx_relay.PushInventory(hash, wtxid);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);
}

BOOST_AUTO_TEST_CASE(push_inventory_skips_known_transactions)
{
    TxRelay tx_relay;
    WITH_LOCK(tx_relay.GetTxInventoryMutex(), tx_relay.SetNextInvSendTime(1us));

    // A transaction the peer already knows about is not queued again.
    const uint256 hash{m_rng.rand256()};
    tx_relay.AddKnownTx(hash);
    tx_relay.PushInventory(hash, Wtxid::FromUint256(hash));
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 0U);

    LOCK(tx_relay.GetTxInventoryMutex());
    BOOST_CHECK(tx_relay.TxInventoryKnownContains(hash));
    BOOST_CHECK(!tx_relay.TxInventoryKnownContains(m_rng.rand256()));
}

BOOST_AUTO_TEST_CASE(consume_send_mempool_is_one_shot)
{
    TxRelay tx_relay;
    {
        LOCK(tx_relay.GetTxInventoryMutex());
        BOOST_CHECK(!tx_relay.ConsumeSendMempool());
    }
    tx_relay.SetSendMempool();
    {
        LOCK(tx_relay.GetTxInventoryMutex());
        BOOST_CHECK(tx_relay.ConsumeSendMempool());
        BOOST_CHECK(!tx_relay.ConsumeSendMempool());
    }
}

BOOST_AUTO_TEST_CASE(bloom_filter_lifecycle)
{
    TxRelay tx_relay;
    // Relay is disabled until the version (or a filter*) message enables it.
    BOOST_CHECK(!tx_relay.GetRelayTxs());

    // FILTERADD without a loaded filter fails (the peer is misbehaving).
    const std::vector<unsigned char> data(32, 0x5a);
    BOOST_CHECK(!tx_relay.AddToBloomFilter(data));

    // FILTERLOAD installs the filter and enables relay.
    tx_relay.SetBloomFilter(CBloomFilter{10, 0.000001, /*nTweak=*/0, BLOOM_UPDATE_ALL});
    BOOST_CHECK(tx_relay.GetRelayTxs());
    BOOST_CHECK(tx_relay.AddToBloomFilter(data));

    // FILTERCLEAR removes the filter but keeps relaying.
    tx_relay.ClearBloomFilter();
    BOOST_CHECK(tx_relay.GetRelayTxs());
    BOOST_CHECK(!tx_relay.AddToBloomFilter(data));
}

BOOST_AUTO_TEST_CASE(clear_inventory_unless_relaying)
{
    TxRelay tx_relay;
    WITH_LOCK(tx_relay.GetTxInventoryMutex(), tx_relay.SetNextInvSendTime(1us));
    const uint256 hash{m_rng.rand256()};
    tx_relay.PushInventory(hash, Wtxid::FromUint256(hash));

    // The peer has not (yet) asked for transaction relay: trickle clears the queue.
    {
        LOCK(tx_relay.GetTxInventoryMutex());
        BOOST_CHECK_EQUAL(tx_relay.TxInventoryToSendSize(), 1U);
        tx_relay.ClearTxInventoryToSendIfNoRelayTxs();
        BOOST_CHECK_EQUAL(tx_relay.TxInventoryToSendSize(), 0U);
    }

    // With relay enabled the queue survives the trickle check.
    tx_relay.SetRelayTxs(true);
    tx_relay.PushInventory(hash, Wtxid::FromUint256(hash));
    {
        LOCK(tx_relay.GetTxInventoryMutex());
        tx_relay.ClearTxInventoryToSendIfNoRelayTxs();
        BOOST_CHECK_EQUAL(tx_relay.TxInventoryToSendSize(), 1U);
    }
}

BOOST_AUTO_TEST_CASE(inv_send_time_comparison_is_strict)
{
    TxRelay tx_relay;
    LOCK(tx_relay.GetTxInventoryMutex());
    // The default send time of zero means a send is due immediately.
    BOOST_CHECK(tx_relay.IsInvSendTimeReached(1us));

    tx_relay.SetNextInvSendTime(100us);
    BOOST_CHECK(!tx_relay.IsInvSendTimeReached(99us));
    BOOST_CHECK(!tx_relay.IsInvSendTimeReached(100us));
    BOOST_CHECK(tx_relay.IsInvSendTimeReached(101us));
}

BOOST_AUTO_TEST_CASE(last_inv_sequence_and_fee_filter)
{
    TxRelay tx_relay;
    // The default sequence of 1 permits relay of anything already in the
    // mempool at connection time (see CTxMemPool::info_for_relay).
    BOOST_CHECK_EQUAL(tx_relay.GetLastInvSequence(), 1U);
    WITH_LOCK(tx_relay.GetTxInventoryMutex(), tx_relay.SetLastInvSequence(42));
    BOOST_CHECK_EQUAL(tx_relay.GetLastInvSequence(), 42U);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_last_inv_seq, 42U);

    BOOST_CHECK_EQUAL(tx_relay.GetFeeFilterReceived(), 0);
    tx_relay.SetFeeFilterReceived(1000);
    BOOST_CHECK_EQUAL(tx_relay.GetFeeFilterReceived(), 1000);
}

BOOST_AUTO_TEST_CASE(make_merkle_block_requires_filter)
{
    TxRelay tx_relay;
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));

    // Without a loaded filter there is nothing to serve.
    BOOST_CHECK(!tx_relay.MakeMerkleBlock(block).has_value());

    // With a filter matching the transaction, the merkle block matches it.
    CBloomFilter filter{10, 0.000001, /*nTweak=*/0, BLOOM_UPDATE_ALL};
    filter.insert(block.vtx[0]->GetHash().ToUint256());
    tx_relay.SetBloomFilter(std::move(filter));
    const auto merkle_block{tx_relay.MakeMerkleBlock(block)};
    BOOST_REQUIRE(merkle_block.has_value());
    BOOST_REQUIRE_EQUAL(merkle_block->vMatchedTxn.size(), 1U);
    BOOST_CHECK(merkle_block->vMatchedTxn[0].second == block.vtx[0]->GetHash());

    // A filter matching nothing yields a merkle block with no matches.
    tx_relay.SetBloomFilter(CBloomFilter{10, 0.000001, /*nTweak=*/0, BLOOM_UPDATE_ALL});
    const auto empty_match{tx_relay.MakeMerkleBlock(block)};
    BOOST_REQUIRE(empty_match.has_value());
    BOOST_CHECK_EQUAL(empty_match->vMatchedTxn.size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()

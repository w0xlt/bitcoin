// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txrelay.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(txrelay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(txrelay_bloom_filter_lifecycle)
{
    node::TxRelay tx_relay;
    const std::vector<unsigned char> data{1, 2, 3};

    BOOST_CHECK(!tx_relay.GetRelayTxs());
    BOOST_CHECK(!tx_relay.AddToBloomFilter(data));

    tx_relay.SetBloomFilter(CBloomFilter{10, 0.001, 0, BLOOM_UPDATE_NONE});
    BOOST_CHECK(tx_relay.GetRelayTxs());
    BOOST_CHECK(tx_relay.AddToBloomFilter(data));

    tx_relay.ClearBloomFilter();
    BOOST_CHECK(tx_relay.GetRelayTxs());
    BOOST_CHECK(!tx_relay.AddToBloomFilter(data));
}

BOOST_AUTO_TEST_CASE(txrelay_inventory_gated_until_send_scheduled)
{
    node::TxRelay tx_relay;
    const uint256 hash{uint256::ONE};
    const Wtxid wtxid{Wtxid::FromUint256(hash)};

    BOOST_CHECK(tx_relay.IsInventoryPristine());
    tx_relay.PushInventory(hash, wtxid);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 0U);
    BOOST_CHECK(tx_relay.IsInventoryPristine());

    tx_relay.SetNextInvSendTime(1us);
    BOOST_CHECK(!tx_relay.IsInventoryPristine());

    tx_relay.PushInventory(hash, wtxid);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);
}

BOOST_AUTO_TEST_CASE(txrelay_known_inventory_not_requeued)
{
    node::TxRelay tx_relay;
    tx_relay.SetRelayTxs(true);
    tx_relay.SetNextInvSendTime(1us);

    const uint256 first_hash{uint256::ONE};
    tx_relay.PushInventory(first_hash, Wtxid::FromUint256(first_hash));
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);

    const uint256 known_hash{uint256{2}};
    tx_relay.AddKnownTx(known_hash);
    tx_relay.PushInventory(known_hash, Wtxid::FromUint256(known_hash));
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);
}

BOOST_AUTO_TEST_CASE(txrelay_state_accessors)
{
    node::TxRelay tx_relay;

    BOOST_CHECK_EQUAL(tx_relay.GetLastInvSequence(), 1U);
    tx_relay.SetLastInvSequence(42);
    BOOST_CHECK_EQUAL(tx_relay.GetLastInvSequence(), 42U);

    BOOST_CHECK(!tx_relay.StartTxInventoryBatch(/*send_trickle=*/true, std::chrono::microseconds::min()).m_send_mempool);
    tx_relay.SetSendMempool();
    BOOST_CHECK(tx_relay.StartTxInventoryBatch(/*send_trickle=*/true, std::chrono::microseconds::min()).m_send_mempool);
    BOOST_CHECK(!tx_relay.StartTxInventoryBatch(/*send_trickle=*/true, std::chrono::microseconds::min()).m_send_mempool);

    tx_relay.SetFeeFilterReceived(123);
    BOOST_CHECK_EQUAL(tx_relay.GetFeeFilterReceived(), 123);
}

BOOST_AUTO_TEST_CASE(txrelay_inventory_batch_schedules_before_snapshot)
{
    node::TxRelay tx_relay;

    auto batch{tx_relay.StartTxInventoryBatch(/*send_trickle=*/false, 1us)};
    BOOST_CHECK(batch.m_send_trickle);
    BOOST_CHECK(batch.m_inv_send_time_reached);
    tx_relay.SetNextInvSendTime(2us);

    const uint256 hash{uint256::ONE};
    tx_relay.PushInventory(hash, Wtxid::FromUint256(hash));
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);

    auto early_batch{tx_relay.StartTxInventoryBatch(/*send_trickle=*/false, 1us)};
    BOOST_CHECK(!early_batch.m_send_trickle);
    BOOST_CHECK(!early_batch.m_inv_send_time_reached);
}

// StartTxInventoryBatch drops queued inventory at snapshot time when the peer
// has disabled tx relay. This exercises the nested bloom-lock branch (the only
// place both mutexes are held, in the m_tx_inventory_mutex -> m_bloom_filter_mutex
// order).
BOOST_AUTO_TEST_CASE(txrelay_inventory_batch_cleared_when_relay_disabled)
{
    node::TxRelay tx_relay;
    tx_relay.SetNextInvSendTime(1us); // open the gate (PushInventory ignores the relay flag)

    const uint256 hash{uint256::ONE};
    tx_relay.PushInventory(hash, Wtxid::FromUint256(hash));
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);

    tx_relay.SetRelayTxs(false); // peer asked us not to relay transactions
    auto batch{tx_relay.StartTxInventoryBatch(/*send_trickle=*/true, std::chrono::microseconds::min())};
    BOOST_CHECK_EQUAL(batch.m_tx_inventory_to_send.size(), 0U);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 0U);
}

BOOST_AUTO_TEST_CASE(txrelay_inventory_batch_moves_and_returns_queued_inventory)
{
    node::TxRelay tx_relay;
    tx_relay.SetRelayTxs(true);
    tx_relay.SetNextInvSendTime(1us);

    const uint256 hash{uint256::ONE};
    tx_relay.PushInventory(hash, Wtxid::FromUint256(hash));
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);

    auto batch{tx_relay.StartTxInventoryBatch(/*send_trickle=*/true, std::chrono::microseconds::min())};
    BOOST_CHECK(batch.m_send_trickle);
    BOOST_CHECK_EQUAL(batch.m_tx_inventory_to_send.size(), 1U);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 0U);

    tx_relay.ReturnTxInventory(std::move(batch.m_tx_inventory_to_send));
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);
}

// MakeMerkleBlock returns nullopt when no bloom filter is loaded, and a
// CMerkleBlock filtered through the peer's bloom filter when one is.
BOOST_AUTO_TEST_CASE(txrelay_make_merkle_block)
{
    node::TxRelay tx_relay;

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.resize(1);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(coinbase));
    const Txid txid{block.vtx[0]->GetHash()};

    // No filter loaded -> no merkle block.
    BOOST_CHECK(!tx_relay.MakeMerkleBlock(block).has_value());

    // A filter matching the coinbase -> a merkle block containing it.
    CBloomFilter filter{10, 0.001, 0, BLOOM_UPDATE_ALL};
    filter.insert(txid.ToUint256());
    tx_relay.SetBloomFilter(filter);

    const auto merkle_block{tx_relay.MakeMerkleBlock(block)};
    BOOST_REQUIRE(merkle_block.has_value());
    BOOST_REQUIRE_EQUAL(merkle_block->vMatchedTxn.size(), 1U);
    BOOST_CHECK(merkle_block->vMatchedTxn[0].second == txid);
}

BOOST_AUTO_TEST_SUITE_END()

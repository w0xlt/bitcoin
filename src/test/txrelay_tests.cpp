// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txrelay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
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

    WITH_LOCK(tx_relay.m_tx_inventory_mutex, tx_relay.m_next_inv_send_time = 1us);
    BOOST_CHECK(!tx_relay.IsInventoryPristine());

    tx_relay.PushInventory(hash, wtxid);
    BOOST_CHECK_EQUAL(tx_relay.GetInventoryStats().m_inv_to_send, 1U);
}

BOOST_AUTO_TEST_CASE(txrelay_known_inventory_not_requeued)
{
    node::TxRelay tx_relay;
    WITH_LOCK(tx_relay.m_tx_inventory_mutex, tx_relay.m_next_inv_send_time = 1us);

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
    WITH_LOCK(tx_relay.m_tx_inventory_mutex, tx_relay.m_last_inv_sequence = 42);
    BOOST_CHECK_EQUAL(tx_relay.GetLastInvSequence(), 42U);

    BOOST_CHECK(!WITH_LOCK(tx_relay.m_tx_inventory_mutex, return tx_relay.m_send_mempool));
    tx_relay.SetSendMempool();
    BOOST_CHECK(WITH_LOCK(tx_relay.m_tx_inventory_mutex, return tx_relay.m_send_mempool));

    tx_relay.SetFeeFilterReceived(123);
    BOOST_CHECK_EQUAL(tx_relay.GetFeeFilterReceived(), 123);
}

BOOST_AUTO_TEST_SUITE_END()

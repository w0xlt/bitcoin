// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <index/txospenderindex.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txospenderindex_tests)

BOOST_FIXTURE_TEST_CASE(txospenderindex_initial_sync, TestChain100Setup)
{
    TxoSpenderIndex txospenderindex(1 << 20, true);
    // Mine blocks for coinbase maturity, so we can spend some coinbase outputs in the test.
     for (int i = 0; i < 50; i++) {
         std::vector<CMutableTransaction> no_txns;
         CreateAndProcessBlock(no_txns, this->m_coinbase_txns[i]->vout[0].scriptPubKey);
     }
    std::vector<COutPoint> spent(10);
    std::vector<CMutableTransaction> spender(spent.size());

    for (size_t i = 0; i < spent.size(); i++) {
        spent[i] = COutPoint(this->m_coinbase_txns[i]->GetHash(), 0);
        spender[i].nVersion = 1;
        spender[i].vin.resize(1);
        spender[i].vin[0].prevout.hash = spent[i].hash;
        spender[i].vin[0].prevout.n = spent[i].n;
        spender[i].vout.resize(1);
        spender[i].vout[0].nValue = this->m_coinbase_txns[i]->GetValueOut();
        spender[i].vout[0].scriptPubKey = this->m_coinbase_txns[i]->vout[0].scriptPubKey;

        // Sign:
        std::vector<unsigned char> vchSig;
        const uint256 hash = SignatureHash(this->m_coinbase_txns[i]->vout[0].scriptPubKey, spender[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        coinbaseKey.Sign(hash, vchSig);
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spender[i].vin[0].scriptSig << vchSig;
    }

    CreateAndProcessBlock(spender, this->m_coinbase_txns[0]->vout[0].scriptPubKey);
    std::pair<uint256, int> txid;

    // Transaction should not be found in the index before it is started.
    for (const auto& outpoint : spent) {
        BOOST_CHECK(!txospenderindex.FindSpender(outpoint, txid));
    }

    // BlockUntilSyncedToCurrentChain should return false before txindex is started.
    BOOST_CHECK(!txospenderindex.BlockUntilSyncedToCurrentChain());

    BOOST_REQUIRE(txospenderindex.Start(m_node.chainman->ActiveChainstate()));


    // Allow tx index to catch up with the block index.
    constexpr int64_t timeout_ms = 10 * 1000;
    int64_t time_start = GetTimeMillis();
    while (!txospenderindex.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout_ms > GetTimeMillis());
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }
    for (size_t i = 0; i < spent.size(); i++) {
        BOOST_CHECK(txospenderindex.FindSpender(spent[i], txid) && txid.first == spender[i].GetHash());
    }

    // shutdown sequence (c.f. Shutdown() in init.cpp)
    txospenderindex.Stop();

    // Let scheduler events finish running to avoid accessing any memory related to txindex after it is destructed
    SyncWithValidationInterfaceQueue();
}

BOOST_AUTO_TEST_SUITE_END()

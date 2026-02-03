// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/amount.h>
#include <kernel/coinstats.h>
#include <kernel/cs_main.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <memory>
#include <thread>
#include <utility>

namespace {

// Determine if cs_main is currently held by the calling thread.
//
// We can't directly introspect RecursiveMutex ownership, but we can try to
// acquire it from a helper thread: if that fails, then the calling thread
// must be holding it (tests run single-threaded except for this probe).
bool IsCsMainHeldByCallingThread()
{
    std::atomic<bool> acquired{false};
    std::thread t{[&] {
        acquired = cs_main.try_lock();
        if (acquired) cs_main.unlock();
    }};
    t.join();
    return !acquired.load();
}

class SingleCoinCursor final : public CCoinsViewCursor
{
    bool m_valid{true};
    const COutPoint m_key;
    const Coin m_coin;

public:
    SingleCoinCursor(const uint256& best_block, COutPoint key, Coin coin)
        : CCoinsViewCursor(best_block), m_key(std::move(key)), m_coin(std::move(coin))
    {
    }

    bool GetKey(COutPoint& key) const override
    {
        if (!m_valid) return false;
        key = m_key;
        return true;
    }

    bool GetValue(Coin& coin) const override
    {
        if (!m_valid) return false;
        coin = m_coin;
        return true;
    }

    bool Valid() const override { return m_valid; }
    void Next() override { m_valid = false; }
};

class LockSensitiveCoinsView final : public CCoinsView
{
    const uint256 m_best_block;
    const CAmount m_amount_if_locked;
    const CAmount m_amount_if_unlocked;

public:
    LockSensitiveCoinsView(uint256 best_block, CAmount amount_if_locked, CAmount amount_if_unlocked)
        : m_best_block(best_block),
          m_amount_if_locked(amount_if_locked),
          m_amount_if_unlocked(amount_if_unlocked)
    {
    }

    uint256 GetBestBlock() const override { return m_best_block; }

    std::unique_ptr<CCoinsViewCursor> Cursor() const override
    {
        const bool locked{IsCsMainHeldByCallingThread()};
        const CAmount amount{locked ? m_amount_if_locked : m_amount_if_unlocked};

        const Txid txid{Txid::FromUint256(uint256{1})};
        COutPoint outpoint{txid, 0};
        Coin coin{/*out*/ CTxOut{amount, CScript{}}, /*height*/ 1, /*coinbase*/ false};

        return std::make_unique<SingleCoinCursor>(m_best_block, std::move(outpoint), std::move(coin));
    }

    size_t EstimateSize() const override { return 0; }
};

} // namespace

BOOST_AUTO_TEST_SUITE(coinstats_kernel_tests)

// Regression test for the coinstats race described in #34451/#34263: the
// coinstats code must acquire the coin-view cursor while holding cs_main so
// that the cursor snapshot matches the "best block" the stats are labeled
// with.
//
// This test is deterministic: our fake CoinsView cursor returns different data
// depending on whether cs_main is held at cursor acquisition time. Old code
// (cursor acquired without cs_main) will fail.
BOOST_FIXTURE_TEST_CASE(kernel_coinstats_acquires_cursor_under_cs_main, TestChain100Setup)
{
    uint256 best_block_hash;
    {
        LOCK(cs_main);
        best_block_hash = m_node.chainman->ActiveChain().Tip()->GetBlockHash();
    }

    constexpr CAmount AMOUNT_IF_LOCKED{1};
    constexpr CAmount AMOUNT_IF_UNLOCKED{2};
    LockSensitiveCoinsView view{best_block_hash, AMOUNT_IF_LOCKED, AMOUNT_IF_UNLOCKED};

    auto stats = kernel::ComputeUTXOStats(kernel::CoinStatsHashType::NONE, &view, m_node.chainman->m_blockman);
    BOOST_REQUIRE(stats.has_value());
    BOOST_CHECK_EQUAL(stats->hashBlock, best_block_hash);
    BOOST_REQUIRE(stats->total_amount.has_value());
    BOOST_CHECK_EQUAL(*stats->total_amount, AMOUNT_IF_LOCKED);
    BOOST_CHECK_EQUAL(stats->coins_count, 1U);
    BOOST_CHECK_EQUAL(stats->nTransactionOutputs, 1U);
}

BOOST_AUTO_TEST_SUITE_END()

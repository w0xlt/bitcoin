// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file coinselection_wrapper_tests.cpp
 * @brief Unit tests for libbitcoincoinselection C++ wrapper API
 *
 * These tests verify the C++ wrapper classes and functions for coin selection.
 */

#include <coinselection/bitcoincoinselection_wrapper.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <set>
#include <vector>

using namespace btccs;

namespace {

/** Standard P2WPKH input size */
constexpr int P2WPKH_INPUT_BYTES = 68;

/** Standard P2WPKH output size (change output) */
constexpr int P2WPKH_OUTPUT_BYTES = 31;

/** Test feerate: 10 sat/vB = 10000 sat/kvB */
constexpr int64_t TEST_FEERATE_SAT_PER_KVB = 10000;

/** Default long-term feerate: ~3.3 sat/vB = 3333 sat/kvB */
constexpr int64_t DEFAULT_LT_FEERATE_SAT_PER_KVB = TEST_FEERATE_SAT_PER_KVB / 3;

/** Default discard feerate: 3 sat/vB = 3000 sat/kvB */
constexpr int64_t DEFAULT_DISCARD_FEERATE_SAT_PER_KVB = 3000;

// ==========================================================================
// Helper functions for fee calculations
// ==========================================================================

/** Calculate fee for a given size at a given feerate */
inline Amount CalculateFee(int bytes, int64_t feerate_sat_per_kvb) {
    return (static_cast<int64_t>(bytes) * feerate_sat_per_kvb) / 1000;
}

/** Calculate the fee for spending an input at effective feerate */
inline Amount GetInputFee(int input_bytes, int64_t effective_feerate_sat_per_kvb = TEST_FEERATE_SAT_PER_KVB) {
    return CalculateFee(input_bytes, effective_feerate_sat_per_kvb);
}

/** Calculate the fee for creating a change output */
inline Amount GetChangeFee(int64_t effective_feerate_sat_per_kvb = TEST_FEERATE_SAT_PER_KVB) {
    return CalculateFee(P2WPKH_OUTPUT_BYTES, effective_feerate_sat_per_kvb);
}

/** Calculate the cost of creating and later spending change */
inline Amount GetCostOfChange(int64_t effective_feerate_sat_per_kvb = TEST_FEERATE_SAT_PER_KVB,
                               int64_t discard_feerate_sat_per_kvb = DEFAULT_DISCARD_FEERATE_SAT_PER_KVB) {
    // Cost = change_output_fee + discard_spend_fee
    return CalculateFee(P2WPKH_OUTPUT_BYTES, effective_feerate_sat_per_kvb) +
           CalculateFee(P2WPKH_INPUT_BYTES, discard_feerate_sat_per_kvb);
}

/** Get a FeeRate object for the test feerate */
inline FeeRate GetEffectiveFeeRate(int64_t feerate_sat_per_kvb = TEST_FEERATE_SAT_PER_KVB) {
    return FeeRate(feerate_sat_per_kvb);
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(coinselection_wrapper_tests)

// ==========================================================================
// Version Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(version_string)
{
    std::string version = Version();
    BOOST_CHECK(!version.empty());
    // Version should be in semver format
    BOOST_CHECK(version.find('.') != std::string::npos);
}

// ==========================================================================
// Utility Function Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(max_standard_tx_weight)
{
    int max_weight = GetMaxStandardTxWeight();
    BOOST_CHECK_EQUAL(max_weight, 400000);
}

BOOST_AUTO_TEST_CASE(input_weight_calculation)
{
    int weight = GetInputWeight(P2WPKH_INPUT_BYTES);
    BOOST_CHECK_EQUAL(weight, P2WPKH_INPUT_BYTES * 4);
}

BOOST_AUTO_TEST_CASE(make_txid_helper)
{
    auto txid1 = MakeTxid(0);
    auto txid2 = MakeTxid(1);
    auto txid3 = MakeTxid(0);

    // Different seeds produce different txids
    BOOST_CHECK(txid1 != txid2);

    // Same seed produces same txid
    BOOST_CHECK(txid1 == txid3);

    // Check that the seed is encoded in the first bytes
    BOOST_CHECK_EQUAL(txid1[0], 0);
    BOOST_CHECK_EQUAL(txid2[0], 1);
}

// ==========================================================================
// Fee Calculation Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(fee_calculations)
{
    // Change fee = 31 * 10000 / 1000 = 310 sats
    BOOST_CHECK_EQUAL(GetChangeFee(), 310);

    // Cost of change = change_fee + discard_spend_fee
    // = 310 + (68 * 3000 / 1000) = 310 + 204 = 514 sats
    BOOST_CHECK_EQUAL(GetCostOfChange(), 514);

    // Input fee at 10 sat/vB for 68 byte input = 680 sats
    BOOST_CHECK_EQUAL(GetInputFee(P2WPKH_INPUT_BYTES), 680);

    // Long-term fee at ~3.3 sat/vB for 68 byte input ≈ 226 sats
    Amount lt_fee = CalculateFee(P2WPKH_INPUT_BYTES, DEFAULT_LT_FEERATE_SAT_PER_KVB);
    BOOST_CHECK_GT(lt_fee, 0);
    BOOST_CHECK_LT(lt_fee, GetInputFee(P2WPKH_INPUT_BYTES));
}

BOOST_AUTO_TEST_CASE(explicit_feerates)
{
    FeeRate effective(10000);  // 10 sat/vB
    FeeRate long_term(5000);   // 5 sat/vB
    FeeRate discard(3000);     // 3 sat/vB

    BOOST_CHECK_EQUAL(effective.GetFeePerK(), 10000);
    BOOST_CHECK_EQUAL(long_term.GetFeePerK(), 5000);
    BOOST_CHECK_EQUAL(discard.GetFeePerK(), 3000);
}

// ==========================================================================
// UtxoPool Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(utxo_pool_empty)
{
    UtxoPool pool;
    BOOST_CHECK(pool.Empty());
    BOOST_CHECK_EQUAL(pool.Size(), 0u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_add_with_fees)
{
    UtxoPool pool;
    auto txid = MakeTxid(1);

    pool.Add(txid, 0, 100000, P2WPKH_INPUT_BYTES, 6, 680, 226);

    BOOST_CHECK(!pool.Empty());
    BOOST_CHECK_EQUAL(pool.Size(), 1u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_add_with_feerate)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();
    auto txid = MakeTxid(1);

    pool.Add(txid, 0, 100000, P2WPKH_INPUT_BYTES, 6, effective_feerate);

    BOOST_CHECK_EQUAL(pool.Size(), 1u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_add_multiple)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};

    for (size_t i = 0; i < values.size(); ++i) {
        auto txid = MakeTxid(static_cast<uint32_t>(i));
        pool.Add(txid, 0, values[i], P2WPKH_INPUT_BYTES, 6, effective_feerate);
    }

    BOOST_CHECK_EQUAL(pool.Size(), values.size());
}

BOOST_AUTO_TEST_CASE(utxo_pool_chaining)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();

    // Test fluent builder pattern
    pool.Add(MakeTxid(0), 0, 100000, P2WPKH_INPUT_BYTES, 6, effective_feerate)
        .Add(MakeTxid(1), 0, 200000, P2WPKH_INPUT_BYTES, 6, effective_feerate)
        .Add(MakeTxid(2), 0, 300000, P2WPKH_INPUT_BYTES, 6, effective_feerate);

    BOOST_CHECK_EQUAL(pool.Size(), 3u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_clear)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();

    pool.Add(MakeTxid(0), 0, 100000, P2WPKH_INPUT_BYTES, 6, effective_feerate);
    BOOST_CHECK_EQUAL(pool.Size(), 1u);

    pool.Clear();
    BOOST_CHECK(pool.Empty());
    BOOST_CHECK_EQUAL(pool.Size(), 0u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_groups_access)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();

    pool.Add(MakeTxid(0), 0, 100000, P2WPKH_INPUT_BYTES, 6, effective_feerate);

    // Direct access to groups
    BOOST_CHECK_EQUAL(pool.Groups().size(), 1u);

    const UtxoPool& const_pool = pool;
    BOOST_CHECK_EQUAL(const_pool.Groups().size(), 1u);
}

// ==========================================================================
// Branch and Bound (BnB) Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(bnb_empty_pool)
{
    UtxoPool pool;

    auto result = pool.SelectBnB(100000, GetCostOfChange());

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(bnb_insufficient_funds)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();

    // Add small UTXO
    pool.Add(MakeTxid(0), 0, 10000, P2WPKH_INPUT_BYTES, 6, effective_feerate);

    // Try to select more than available
    auto result = pool.SelectBnB(1000000, GetCostOfChange());

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(bnb_exact_match)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();

    // Calculate effective value for exact match
    Amount fee = GetInputFee(P2WPKH_INPUT_BYTES);
    Amount target_effective = 100000;
    Amount utxo_value = target_effective + fee;

    pool.Add(MakeTxid(0), 0, utxo_value, P2WPKH_INPUT_BYTES, 6, effective_feerate);

    auto result = pool.SelectBnB(target_effective, GetCostOfChange());

    if (result) {
        BOOST_CHECK_EQUAL(result->GetInputSet().size(), 1u);

        Amount total_value = 0;
        Amount total_effective = 0;
        for (const auto& coin : result->GetInputSet()) {
            total_value += coin->txout.nValue;
            total_effective += coin->GetEffectiveValue();
        }

        BOOST_CHECK_EQUAL(total_value, utxo_value);
        BOOST_CHECK_EQUAL(total_effective, target_effective);
    }
}

BOOST_AUTO_TEST_CASE(bnb_multiple_utxos)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();

    std::vector<Amount> values = {50000, 100000, 150000, 200000, 250000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, effective_feerate);
    }

    // BnB tries to find changeless solution
    auto result = pool.SelectBnB(148640, GetCostOfChange());

    if (result) {
        BOOST_CHECK_GE(result->GetInputSet().size(), 1u);
        BOOST_CHECK_GT(result->GetWeight(), 0);
    }
}

// ==========================================================================
// Single Random Draw (SRD) Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(srd_empty_pool)
{
    UtxoPool pool;
    FastRandomContext rng;

    auto result = pool.SelectSRD(100000, GetChangeFee(), rng);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(srd_success)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();
    FastRandomContext rng;

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, effective_feerate);
    }

    Amount target = 300000;
    auto result = pool.SelectSRD(target, GetChangeFee(), rng);

    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_GE(result->GetInputSet().size(), 1u);

    Amount total_value = 0;
    for (const auto& coin : result->GetInputSet()) {
        total_value += coin->txout.nValue;
    }
    BOOST_CHECK_GE(total_value, target);
}

BOOST_AUTO_TEST_CASE(srd_deterministic_with_seed)
{
    FeeRate effective_feerate = GetEffectiveFeeRate();
    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};
    Amount target = 300000;

    Amount selected1 = 0, selected2 = 0;

    for (int run = 0; run < 2; ++run) {
        UtxoPool pool;
        // Create seeded RNG - same seed each time
        uint256 seed;
        std::memset(seed.begin(), 0, 32);
        seed.begin()[0] = 42;  // Simple deterministic seed
        FastRandomContext rng(seed);

        for (size_t i = 0; i < values.size(); ++i) {
            pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                     P2WPKH_INPUT_BYTES, 6, effective_feerate);
        }

        auto result = pool.SelectSRD(target, GetChangeFee(), rng);

        if (result) {
            Amount total = 0;
            for (const auto& coin : result->GetInputSet()) {
                total += coin->txout.nValue;
            }
            if (run == 0) selected1 = total;
            else selected2 = total;
        }
    }

    // Same seed should produce same result
    BOOST_CHECK_EQUAL(selected1, selected2);
}

// ==========================================================================
// CoinGrinder Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(coingrinder_empty_pool)
{
    UtxoPool pool;

    auto result = pool.SelectCoinGrinder(100000, 1000);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(coingrinder_success)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();
    FastRandomContext rng;

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, effective_feerate);
    }

    Amount target = 300000;
    Amount change_target = GenerateChangeTarget(target, GetChangeFee(), rng);

    auto result = pool.SelectCoinGrinder(target, change_target);

    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_GE(result->GetInputSet().size(), 1u);
}

BOOST_AUTO_TEST_CASE(coingrinder_minimizes_weight)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();
    FastRandomContext rng;

    // Add a large UTXO and several small ones
    pool.Add(MakeTxid(0), 0, 1000000, P2WPKH_INPUT_BYTES, 6, effective_feerate);
    for (uint32_t i = 1; i <= 10; ++i) {
        pool.Add(MakeTxid(i), 0, 50000, P2WPKH_INPUT_BYTES, 6, effective_feerate);
    }

    Amount target = 300000;
    Amount change_target = GenerateChangeTarget(target, GetChangeFee(), rng);

    auto result = pool.SelectCoinGrinder(target, change_target);

    if (result) {
        // CoinGrinder should prefer fewer inputs to minimize weight
        // The large UTXO alone should satisfy the target
        BOOST_CHECK_LE(result->GetInputSet().size(), 3u);
    }
}

// ==========================================================================
// Knapsack Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(knapsack_empty_pool)
{
    UtxoPool pool;
    FastRandomContext rng;

    auto result = pool.SelectKnapsack(100000, 1000, rng);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(knapsack_success)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();
    FastRandomContext rng;

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, effective_feerate);
    }

    Amount target = 300000;
    Amount change_target = GenerateChangeTarget(target, GetChangeFee(), rng);

    auto result = pool.SelectKnapsack(target, change_target, rng);

    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_GE(result->GetInputSet().size(), 1u);

    Amount total_value = 0;
    for (const auto& coin : result->GetInputSet()) {
        total_value += coin->txout.nValue;
    }
    BOOST_CHECK_GE(total_value, target);
}

// ==========================================================================
// SelectionResult Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(selection_result_getters)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();
    FastRandomContext rng;

    Amount value = 1000000;
    pool.Add(MakeTxid(0), 0, value, P2WPKH_INPUT_BYTES, 6, effective_feerate);

    Amount target = 100000;
    Amount change_target = GenerateChangeTarget(target, GetChangeFee(), rng);

    auto result = pool.SelectKnapsack(target, change_target, rng);

    BOOST_REQUIRE(result.has_value());

    // Check input set
    BOOST_CHECK_EQUAL(result->GetInputSet().size(), 1u);

    // Check weight
    int expected_weight = P2WPKH_INPUT_BYTES * 4; // WITNESS_SCALE_FACTOR = 4
    BOOST_CHECK_EQUAL(result->GetWeight(), expected_weight);

    // Verify selected value
    Amount total_value = 0;
    Amount total_effective = 0;
    for (const auto& coin : result->GetInputSet()) {
        total_value += coin->txout.nValue;
        total_effective += coin->GetEffectiveValue();
    }
    BOOST_CHECK_EQUAL(total_value, value);
    BOOST_CHECK_EQUAL(total_effective, value - GetInputFee(P2WPKH_INPUT_BYTES));
}

// ==========================================================================
// GenerateChangeTarget Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(generate_change_target_positive)
{
    FastRandomContext rng;
    Amount payment = 100000;
    Amount change_fee = 310;

    Amount target = GenerateChangeTarget(payment, change_fee, rng);

    BOOST_CHECK_GT(target, 0);
}

BOOST_AUTO_TEST_CASE(generate_change_target_varies)
{
    FastRandomContext rng;
    Amount payment = 100000;
    Amount change_fee = 310;

    // Generate multiple targets and check they're not all the same
    std::set<Amount> targets;
    for (int i = 0; i < 10; ++i) {
        targets.insert(GenerateChangeTarget(payment, change_fee, rng));
    }

    // Should have some variation (with random RNG)
    // Note: This could theoretically fail with very low probability
    BOOST_CHECK_GT(targets.size(), 1u);
}

// ==========================================================================
// Exception Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(coin_selection_error)
{
    CoinSelectionError error("Test error", SelectionStatus::INSUFFICIENT_FUNDS);

    BOOST_CHECK(error.status() == SelectionStatus::INSUFFICIENT_FUNDS);
    BOOST_CHECK(std::string(error.what()).find("Test error") != std::string::npos);
}

// ==========================================================================
// Integration Test (matching main.cpp example values)
// ==========================================================================

BOOST_AUTO_TEST_CASE(example_values_match)
{
    // This test uses the same values as main.cpp to verify consistency
    constexpr int64_t FEERATE_SAT_PER_KVB = 10000; // 10 sat/vB
    FeeRate effective_feerate(FEERATE_SAT_PER_KVB);

    // Verify parameter calculations
    BOOST_CHECK_EQUAL(GetCostOfChange(FEERATE_SAT_PER_KVB), 514);
    BOOST_CHECK_EQUAL(GetChangeFee(FEERATE_SAT_PER_KVB), 310);

    UtxoPool pool;
    FastRandomContext rng;

    std::vector<Amount> utxo_values = {
        50000,    // 0.0005 BTC
        100000,   // 0.001 BTC
        250000,   // 0.0025 BTC
        500000,   // 0.005 BTC
        1000000,  // 0.01 BTC
        2500000,  // 0.025 BTC
        5000000,  // 0.05 BTC
    };

    for (size_t i = 0; i < utxo_values.size(); ++i) {
        auto txid = MakeTxid(static_cast<uint32_t>(i));
        pool.Add(txid, 0, utxo_values[i], P2WPKH_INPUT_BYTES, 6, effective_feerate);

        // Verify effective value
        Amount fee = GetInputFee(P2WPKH_INPUT_BYTES, FEERATE_SAT_PER_KVB);
        BOOST_CHECK_EQUAL(fee, 680); // 68 * 10000 / 1000
    }

    BOOST_CHECK_EQUAL(pool.Size(), utxo_values.size());

    constexpr Amount TARGET = 300000;
    Amount change_fee = GetChangeFee(FEERATE_SAT_PER_KVB);

    // Test SRD
    auto srd_result = pool.SelectSRD(TARGET, change_fee, rng);
    BOOST_CHECK(srd_result.has_value());
    if (srd_result) {
        Amount total = 0;
        for (const auto& coin : srd_result->GetInputSet()) {
            total += coin->txout.nValue;
        }
        BOOST_CHECK_GE(total, TARGET);
    }

    // Test CoinGrinder
    Amount change_target = GenerateChangeTarget(TARGET, change_fee, rng);
    auto cg_result = pool.SelectCoinGrinder(TARGET, change_target);
    BOOST_CHECK(cg_result.has_value());
    if (cg_result) {
        Amount total = 0;
        for (const auto& coin : cg_result->GetInputSet()) {
            total += coin->txout.nValue;
        }
        BOOST_CHECK_GE(total, TARGET);
    }

    // Test Knapsack
    auto ks_result = pool.SelectKnapsack(TARGET, change_target, rng);
    BOOST_CHECK(ks_result.has_value());
    if (ks_result) {
        Amount total = 0;
        for (const auto& coin : ks_result->GetInputSet()) {
            total += coin->txout.nValue;
        }
        BOOST_CHECK_GE(total, TARGET);
    }
}

// ==========================================================================
// Stress Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(large_utxo_pool)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();
    FastRandomContext rng;

    // Add many UTXOs
    for (uint32_t i = 0; i < 100; ++i) {
        pool.Add(MakeTxid(i), 0, 10000 + i * 1000, P2WPKH_INPUT_BYTES, 6, effective_feerate);
    }

    BOOST_CHECK_EQUAL(pool.Size(), 100u);

    Amount target = 500000;
    Amount change_target = GenerateChangeTarget(target, GetChangeFee(), rng);

    // All algorithms should handle large pools
    auto srd_result = pool.SelectSRD(target, GetChangeFee(), rng);
    BOOST_CHECK(srd_result.has_value());

    auto cg_result = pool.SelectCoinGrinder(target, change_target);
    BOOST_CHECK(cg_result.has_value());

    auto ks_result = pool.SelectKnapsack(target, change_target, rng);
    BOOST_CHECK(ks_result.has_value());
}

BOOST_AUTO_TEST_CASE(repeated_selection)
{
    UtxoPool pool;
    FeeRate effective_feerate = GetEffectiveFeeRate();
    FastRandomContext rng;

    std::vector<Amount> values = {100000, 200000, 300000, 400000, 500000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, effective_feerate);
    }

    // Repeated selections should all succeed
    for (int i = 0; i < 10; ++i) {
        Amount target = 150000 + i * 10000;

        auto result = pool.SelectSRD(target, GetChangeFee(), rng);
        BOOST_CHECK(result.has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()

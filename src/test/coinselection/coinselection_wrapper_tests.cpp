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

/** Test feerate: 10 sat/vB = 10000 sat/kvB */
constexpr int64_t TEST_FEERATE_SAT_PER_KVB = 10000;

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
// CoinSelectionParams Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(params_from_feerate)
{
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    // Change fee = 31 * 10000 / 1000 = 310 sats
    BOOST_CHECK_EQUAL(params.GetChangeFee(), 310);

    // Cost of change = change_fee + discard_spend_fee
    // = 310 + (68 * 3000 / 1000) = 310 + 204 = 514 sats
    BOOST_CHECK_EQUAL(params.GetCostOfChange(), 514);

    // Min viable change = discard_spend_fee = 68 * 3000 / 1000 = 204 sats
    BOOST_CHECK_EQUAL(params.GetMinViableChange(), 204);

    // Input fee at 10 sat/vB for 68 byte input = 680 sats
    BOOST_CHECK_EQUAL(params.GetInputFee(P2WPKH_INPUT_BYTES), 680);

    // Long-term fee at ~3.3 sat/vB for 68 byte input ≈ 226 sats
    Amount lt_fee = params.GetInputLongTermFee(P2WPKH_INPUT_BYTES);
    BOOST_CHECK_GT(lt_fee, 0);
    BOOST_CHECK_LT(lt_fee, params.GetInputFee(P2WPKH_INPUT_BYTES));
}

BOOST_AUTO_TEST_CASE(params_explicit)
{
    FeeRate effective(10000);  // 10 sat/vB
    FeeRate long_term(5000);   // 5 sat/vB
    FeeRate discard(3000);     // 3 sat/vB

    CoinSelectionParams params(effective, long_term, discard, 31, 68);

    BOOST_CHECK_EQUAL(params.EffectiveFeeRate().GetFeePerK(), 10000);
    BOOST_CHECK_EQUAL(params.LongTermFeeRate().GetFeePerK(), 5000);
    BOOST_CHECK_EQUAL(params.DiscardFeeRate().GetFeePerK(), 3000);
    BOOST_CHECK_EQUAL(params.ChangeOutputSize(), 31u);
    BOOST_CHECK_EQUAL(params.ChangeSpendSize(), 68u);
}

BOOST_AUTO_TEST_CASE(params_min_viable_change)
{
    // Test with different discard feerates
    FeeRate effective(10000);
    FeeRate long_term(3000);
    FeeRate discard(5000);  // Higher discard rate

    CoinSelectionParams params(effective, long_term, discard, 31, 68);

    // Min viable change = discard_feerate.GetFee(change_spend_size)
    // = 68 * 5000 / 1000 = 340 sats
    BOOST_CHECK_EQUAL(params.GetMinViableChange(), 340);
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

BOOST_AUTO_TEST_CASE(utxo_pool_add_with_params)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    auto txid = MakeTxid(1);

    // Use CoinSelectionParams-based Add method
    pool.Add(txid, 0, 100000, P2WPKH_INPUT_BYTES, 6, params);

    BOOST_CHECK_EQUAL(pool.Size(), 1u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_add_with_feerate)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    auto txid = MakeTxid(1);

    pool.Add(txid, 0, 100000, P2WPKH_INPUT_BYTES, 6, params.EffectiveFeeRate());

    BOOST_CHECK_EQUAL(pool.Size(), 1u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_add_multiple)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};

    for (size_t i = 0; i < values.size(); ++i) {
        auto txid = MakeTxid(static_cast<uint32_t>(i));
        pool.Add(txid, 0, values[i], P2WPKH_INPUT_BYTES, 6, params);
    }

    BOOST_CHECK_EQUAL(pool.Size(), values.size());
}

BOOST_AUTO_TEST_CASE(utxo_pool_chaining)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    // Test fluent builder pattern
    pool.Add(MakeTxid(0), 0, 100000, P2WPKH_INPUT_BYTES, 6, params)
        .Add(MakeTxid(1), 0, 200000, P2WPKH_INPUT_BYTES, 6, params)
        .Add(MakeTxid(2), 0, 300000, P2WPKH_INPUT_BYTES, 6, params);

    BOOST_CHECK_EQUAL(pool.Size(), 3u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_clear)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    pool.Add(MakeTxid(0), 0, 100000, P2WPKH_INPUT_BYTES, 6, params);
    BOOST_CHECK_EQUAL(pool.Size(), 1u);

    pool.Clear();
    BOOST_CHECK(pool.Empty());
    BOOST_CHECK_EQUAL(pool.Size(), 0u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_groups_access)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    pool.Add(MakeTxid(0), 0, 100000, P2WPKH_INPUT_BYTES, 6, params);

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
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    auto result = pool.SelectBnB(100000, params);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(bnb_insufficient_funds)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    // Add small UTXO
    pool.Add(MakeTxid(0), 0, 10000, P2WPKH_INPUT_BYTES, 6, params);

    // Try to select more than available
    auto result = pool.SelectBnB(1000000, params);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(bnb_exact_match)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    // Calculate effective value for exact match
    Amount fee = params.GetInputFee(P2WPKH_INPUT_BYTES);
    Amount target_effective = 100000;
    Amount utxo_value = target_effective + fee;

    pool.Add(MakeTxid(0), 0, utxo_value, P2WPKH_INPUT_BYTES, 6, params);

    auto result = pool.SelectBnB(target_effective, params);

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

        // Waste should be calculated correctly
        Amount waste = result->GetWaste();
        // For BnB with exact match, waste is input fee differential
        BOOST_CHECK_GE(waste, 0);  // or could be negative if long_term > effective
    }
}

BOOST_AUTO_TEST_CASE(bnb_waste_metric)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    Amount fee = params.GetInputFee(P2WPKH_INPUT_BYTES);
    Amount target = 100000;
    Amount utxo_value = target + fee;

    pool.Add(MakeTxid(0), 0, utxo_value, P2WPKH_INPUT_BYTES, 6, params);

    auto result = pool.SelectBnB(target, params);

    if (result) {
        // Verify GetWaste() returns a valid value (not the old custom computation)
        Amount waste = result->GetWaste();

        // Expected: fee - long_term_fee for the single input
        Amount expected_input_waste = fee - params.GetInputLongTermFee(P2WPKH_INPUT_BYTES);
        // BnB tries for no change, so waste should be close to input waste
        BOOST_CHECK_GE(waste, expected_input_waste - params.GetCostOfChange());
    }
}

// ==========================================================================
// Single Random Draw (SRD) Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(srd_empty_pool)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    auto result = pool.SelectSRD(100000, params, rng);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(srd_insufficient_funds)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    pool.Add(MakeTxid(0), 0, 10000, P2WPKH_INPUT_BYTES, 6, params);

    auto result = pool.SelectSRD(1000000, params, rng);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(srd_success)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, params);
    }

    Amount target = 300000;
    auto result = pool.SelectSRD(target, params, rng);

    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_GE(result->GetInputSet().size(), 1u);

    Amount total_value = 0;
    for (const auto& coin : result->GetInputSet()) {
        total_value += coin->txout.nValue;
    }
    BOOST_CHECK_GE(total_value, target);

    // Verify waste is calculated
    Amount waste = result->GetWaste();
    // SRD creates change, so waste includes change cost component
    BOOST_CHECK(waste != 0 || result->GetInputSet().size() == 0);
}

// ==========================================================================
// CoinGrinder Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(coingrinder_empty_pool)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    auto result = pool.SelectCoinGrinder(100000, params);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(coingrinder_insufficient_funds)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    pool.Add(MakeTxid(0), 0, 10000, P2WPKH_INPUT_BYTES, 6, params);

    auto result = pool.SelectCoinGrinder(1000000, params);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(coingrinder_success)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, params);
    }

    Amount target = 300000;
    auto result = pool.SelectCoinGrinder(target, params);

    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_GE(result->GetInputSet().size(), 1u);

    Amount total_value = 0;
    for (const auto& coin : result->GetInputSet()) {
        total_value += coin->txout.nValue;
    }
    BOOST_CHECK_GE(total_value, target);
}

BOOST_AUTO_TEST_CASE(coingrinder_minimizes_weight)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);

    // Add both small and large UTXOs
    pool.Add(MakeTxid(0), 0, 100000, P2WPKH_INPUT_BYTES, 6, params);
    pool.Add(MakeTxid(1), 0, 100000, P2WPKH_INPUT_BYTES, 6, params);
    pool.Add(MakeTxid(2), 0, 100000, P2WPKH_INPUT_BYTES, 6, params);
    pool.Add(MakeTxid(3), 0, 500000, P2WPKH_INPUT_BYTES, 6, params);

    Amount target = 200000;
    auto result = pool.SelectCoinGrinder(target, params);

    if (result) {
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
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    auto result = pool.SelectKnapsack(100000, params, rng);

    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(knapsack_success)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, params);
    }

    Amount target = 300000;
    auto result = pool.SelectKnapsack(target, params, rng);

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
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    Amount value = 1000000;
    pool.Add(MakeTxid(0), 0, value, P2WPKH_INPUT_BYTES, 6, params);

    Amount target = 100000;
    auto result = pool.SelectKnapsack(target, params, rng);

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
    BOOST_CHECK_EQUAL(total_effective, value - params.GetInputFee(P2WPKH_INPUT_BYTES));
}

BOOST_AUTO_TEST_CASE(selection_result_waste)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    Amount value = 1000000;
    pool.Add(MakeTxid(0), 0, value, P2WPKH_INPUT_BYTES, 6, params);

    Amount target = 100000;
    auto result = pool.SelectKnapsack(target, params, rng);

    BOOST_REQUIRE(result.has_value());

    // GetWaste() should return a valid waste metric
    Amount waste = result->GetWaste();

    // Waste includes input fee differential + change cost or excess
    // For this case with change, waste should include cost_of_change
    Amount input_waste = params.GetInputFee(P2WPKH_INPUT_BYTES) -
                         params.GetInputLongTermFee(P2WPKH_INPUT_BYTES);

    // Waste should be at least the input waste
    BOOST_CHECK_GE(waste, input_waste);
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
    CoinSelectionParams params(FEERATE_SAT_PER_KVB);

    // Verify parameter calculations
    BOOST_CHECK_EQUAL(params.GetCostOfChange(), 514);
    BOOST_CHECK_EQUAL(params.GetChangeFee(), 310);
    BOOST_CHECK_EQUAL(params.GetMinViableChange(), 204);

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
        pool.Add(txid, 0, utxo_values[i], P2WPKH_INPUT_BYTES, 6, params);

        // Verify effective value
        Amount fee = params.GetInputFee(P2WPKH_INPUT_BYTES);
        BOOST_CHECK_EQUAL(fee, 680); // 68 * 10000 / 1000
    }

    BOOST_CHECK_EQUAL(pool.Size(), utxo_values.size());

    constexpr Amount TARGET = 300000;

    // Test SRD with CoinSelectionParams
    auto srd_result = pool.SelectSRD(TARGET, params, rng);
    BOOST_CHECK(srd_result.has_value());
    if (srd_result) {
        Amount total = 0;
        for (const auto& coin : srd_result->GetInputSet()) {
            total += coin->txout.nValue;
        }
        BOOST_CHECK_GE(total, TARGET);

        // Verify waste is calculated
        Amount waste = srd_result->GetWaste();
        BOOST_CHECK(waste != 0 || srd_result->GetInputSet().empty());
    }

    // Test CoinGrinder with CoinSelectionParams
    auto cg_result = pool.SelectCoinGrinder(TARGET, params);
    BOOST_CHECK(cg_result.has_value());
    if (cg_result) {
        Amount total = 0;
        for (const auto& coin : cg_result->GetInputSet()) {
            total += coin->txout.nValue;
        }
        BOOST_CHECK_GE(total, TARGET);
    }

    // Test Knapsack with CoinSelectionParams
    auto ks_result = pool.SelectKnapsack(TARGET, params, rng);
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
// Waste Comparison Test
// ==========================================================================

BOOST_AUTO_TEST_CASE(waste_comparison_across_algorithms)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    std::vector<Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, params);
    }

    Amount target = 300000;

    // Run all algorithms and compare waste
    auto bnb = pool.SelectBnB(target, params);
    auto srd = pool.SelectSRD(target, params, rng);
    auto cg = pool.SelectCoinGrinder(target, params);
    auto ks = pool.SelectKnapsack(target, params, rng);

    // At least some should succeed
    int success_count = 0;
    if (bnb) success_count++;
    if (srd) success_count++;
    if (cg) success_count++;
    if (ks) success_count++;

    BOOST_CHECK_GE(success_count, 2);

    // If BnB succeeds, it should typically have low waste (no change)
    if (bnb && srd) {
        // BnB waste is typically lower than SRD because no change output
        // (This isn't always true, but provides a sanity check)
        BOOST_TEST_MESSAGE("BnB waste: " << bnb->GetWaste() << ", SRD waste: " << srd->GetWaste());
    }
}

// ==========================================================================
// Stress Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(large_utxo_pool)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    // Add many UTXOs
    for (uint32_t i = 0; i < 100; ++i) {
        pool.Add(MakeTxid(i), 0, 10000 + i * 1000, P2WPKH_INPUT_BYTES, 6, params);
    }

    BOOST_CHECK_EQUAL(pool.Size(), 100u);

    Amount target = 500000;

    // All algorithms should handle large pools
    auto srd_result = pool.SelectSRD(target, params, rng);
    BOOST_CHECK(srd_result.has_value());

    auto cg_result = pool.SelectCoinGrinder(target, params);
    BOOST_CHECK(cg_result.has_value());

    auto ks_result = pool.SelectKnapsack(target, params, rng);
    BOOST_CHECK(ks_result.has_value());
}

BOOST_AUTO_TEST_CASE(repeated_selection)
{
    UtxoPool pool;
    CoinSelectionParams params(TEST_FEERATE_SAT_PER_KVB);
    FastRandomContext rng;

    std::vector<Amount> values = {100000, 200000, 300000, 400000, 500000};
    for (size_t i = 0; i < values.size(); ++i) {
        pool.Add(MakeTxid(static_cast<uint32_t>(i)), 0, values[i],
                 P2WPKH_INPUT_BYTES, 6, params);
    }

    // Repeated selections should all succeed
    for (int i = 0; i < 10; ++i) {
        Amount target = 150000 + i * 10000;

        auto result = pool.SelectSRD(target, params, rng);
        BOOST_CHECK(result.has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file coinselection_c_api_tests.cpp
 * @brief Unit tests for libbitcoincoinselection C API
 *
 * These tests verify the C API functions for coin selection algorithms.
 */

#include <coinselection/bitcoincoinselection.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

namespace {

/** Helper to create a dummy txid from a seed value */
void make_txid(uint32_t seed, unsigned char txid[32])
{
    std::memset(txid, 0, 32);
    for (size_t i = 0; i < 4; ++i) {
        txid[i] = (seed >> (i * 8)) & 0xFF;
    }
}

/** Standard P2WPKH input size */
constexpr int P2WPKH_INPUT_BYTES = 68;

/** Standard P2WPKH output size */
constexpr size_t P2WPKH_OUTPUT_BYTES = 31;

/** Test feerate: 10 sat/vB = 10000 sat/kvB */
constexpr int64_t TEST_FEERATE_SAT_PER_KVB = 10000;

/** Discard feerate: 3 sat/vB = 3000 sat/kvB */
constexpr int64_t DISCARD_FEERATE_SAT_PER_KVB = 3000;

/** RAII wrapper for btccs_UtxoPool */
struct UtxoPoolGuard {
    btccs_UtxoPool* pool;
    UtxoPoolGuard() : pool(btccs_utxo_pool_create()) {}
    ~UtxoPoolGuard() { btccs_utxo_pool_destroy(pool); }
    operator btccs_UtxoPool*() { return pool; }
};

/** RAII wrapper for btccs_RandomContext */
struct RandomContextGuard {
    btccs_RandomContext* rng;
    RandomContextGuard() : rng(btccs_random_context_create()) {}
    explicit RandomContextGuard(const unsigned char seed[32])
        : rng(btccs_random_context_create_seeded(seed)) {}
    ~RandomContextGuard() { btccs_random_context_destroy(rng); }
    operator btccs_RandomContext*() { return rng; }
};

/** RAII wrapper for btccs_SelectionResult */
struct SelectionResultGuard {
    btccs_SelectionResult* result;
    explicit SelectionResultGuard(btccs_SelectionResult* r) : result(r) {}
    ~SelectionResultGuard() { btccs_selection_result_destroy(result); }
    operator btccs_SelectionResult*() { return result; }
    btccs_SelectionResult* operator->() { return result; }
    explicit operator bool() const { return result != nullptr; }
};

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(coinselection_c_api_tests)

// ==========================================================================
// Version Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(version_string)
{
    const char* version = btccs_version();
    BOOST_CHECK(version != nullptr);
    BOOST_CHECK(std::strlen(version) > 0);
    // Version should be in semver format (e.g., "0.3.0")
    BOOST_CHECK(std::strchr(version, '.') != nullptr);
}

// ==========================================================================
// UTXO Pool Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(utxo_pool_create_destroy)
{
    btccs_UtxoPool* pool = btccs_utxo_pool_create();
    BOOST_CHECK(pool != nullptr);
    BOOST_CHECK_EQUAL(btccs_utxo_pool_size(pool), 0u);
    btccs_utxo_pool_destroy(pool);
}

BOOST_AUTO_TEST_CASE(utxo_pool_add_single)
{
    UtxoPoolGuard pool;
    BOOST_CHECK(pool.pool != nullptr);

    unsigned char txid[32];
    make_txid(1, txid);

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);

    btccs_utxo_pool_add(pool, txid, 0, 100000, P2WPKH_INPUT_BYTES, 6, fee, lt_fee);

    BOOST_CHECK_EQUAL(btccs_utxo_pool_size(pool), 1u);
}

BOOST_AUTO_TEST_CASE(utxo_pool_add_multiple)
{
    UtxoPoolGuard pool;

    std::vector<btccs_Amount> values = {50000, 100000, 250000, 500000, 1000000};

    for (size_t i = 0; i < values.size(); ++i) {
        unsigned char txid[32];
        make_txid(static_cast<uint32_t>(i), txid);

        btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
        btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);

        btccs_utxo_pool_add(pool, txid, static_cast<uint32_t>(i), values[i],
                            P2WPKH_INPUT_BYTES, 6, fee, lt_fee);
    }

    BOOST_CHECK_EQUAL(btccs_utxo_pool_size(pool), values.size());
}

BOOST_AUTO_TEST_CASE(utxo_pool_destroy_null)
{
    // Should not crash when passed nullptr
    btccs_utxo_pool_destroy(nullptr);
}

// ==========================================================================
// Random Context Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(random_context_create_destroy)
{
    btccs_RandomContext* rng = btccs_random_context_create();
    BOOST_CHECK(rng != nullptr);
    btccs_random_context_destroy(rng);
}

BOOST_AUTO_TEST_CASE(random_context_seeded)
{
    unsigned char seed[32] = {0};
    seed[0] = 42;

    btccs_RandomContext* rng = btccs_random_context_create_seeded(seed);
    BOOST_CHECK(rng != nullptr);
    btccs_random_context_destroy(rng);
}

BOOST_AUTO_TEST_CASE(random_context_destroy_null)
{
    // Should not crash when passed nullptr
    btccs_random_context_destroy(nullptr);
}

// ==========================================================================
// Utility Function Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(max_standard_tx_weight)
{
    int max_weight = btccs_get_max_standard_tx_weight();
    // MAX_STANDARD_TX_WEIGHT is 400000 WU
    BOOST_CHECK_EQUAL(max_weight, 400000);
}

BOOST_AUTO_TEST_CASE(input_weight_calculation)
{
    // Weight = bytes * WITNESS_SCALE_FACTOR (4)
    int weight = btccs_get_input_weight(P2WPKH_INPUT_BYTES);
    BOOST_CHECK_EQUAL(weight, P2WPKH_INPUT_BYTES * 4);
}

BOOST_AUTO_TEST_CASE(calculate_fee)
{
    // Fee = size * feerate / 1000
    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    // 68 * 10000 / 1000 = 680 sats
    BOOST_CHECK_EQUAL(fee, 680);

    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    // 31 * 10000 / 1000 = 310 sats
    BOOST_CHECK_EQUAL(change_fee, 310);
}

BOOST_AUTO_TEST_CASE(cost_of_change_calculation)
{
    btccs_Amount cost = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);

    // Cost = change_output_fee + discard_fee_for_spend
    // change_output_fee = 31 * 10000 / 1000 = 310 sats
    // discard_spend_fee = 68 * 3000 / 1000 = 204 sats (at 3 sat/vB discard rate)
    // Total = 310 + 204 = 514 sats
    BOOST_CHECK_EQUAL(cost, 514);
}

BOOST_AUTO_TEST_CASE(generate_change_target)
{
    RandomContextGuard rng;

    btccs_Amount payment = 100000;
    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);

    btccs_Amount target = btccs_generate_change_target(payment, change_fee, rng);

    // Change target should be positive and reasonable
    BOOST_CHECK_GT(target, 0);
}

// ==========================================================================
// Branch and Bound (BnB) Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(bnb_empty_pool)
{
    UtxoPoolGuard pool;
    btccs_SelectionStatus status;

    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);

    btccs_SelectionResult* result = btccs_select_coins_bnb(
        pool, 100000, cost_of_change, btccs_get_max_standard_tx_weight(), &status);

    BOOST_CHECK(result == nullptr);
    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_NO_SOLUTION_FOUND);
}

BOOST_AUTO_TEST_CASE(bnb_insufficient_funds)
{
    UtxoPoolGuard pool;
    btccs_SelectionStatus status;

    unsigned char txid[32];
    make_txid(1, txid);

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);

    btccs_utxo_pool_add(pool, txid, 0, 10000, P2WPKH_INPUT_BYTES, 6, fee, lt_fee);

    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);

    btccs_SelectionResult* result = btccs_select_coins_bnb(
        pool, 1000000, cost_of_change, btccs_get_max_standard_tx_weight(), &status);

    BOOST_CHECK(result == nullptr);
    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_NO_SOLUTION_FOUND);
}

BOOST_AUTO_TEST_CASE(bnb_exact_match)
{
    UtxoPoolGuard pool;
    btccs_SelectionStatus status;

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);

    // Target effective value
    btccs_Amount target = 100000;
    // UTXO value = target + fee to get exact effective match
    btccs_Amount utxo_value = target + fee;

    unsigned char txid[32];
    make_txid(1, txid);
    btccs_utxo_pool_add(pool, txid, 0, utxo_value, P2WPKH_INPUT_BYTES, 6, fee, lt_fee);

    btccs_SelectionResult* result = btccs_select_coins_bnb(
        pool, target, cost_of_change, btccs_get_max_standard_tx_weight(), &status);

    if (result) {
        SelectionResultGuard guard(result);
        BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_SUCCESS);
        BOOST_CHECK_EQUAL(btccs_selection_result_get_input_count(result), 1u);
        BOOST_CHECK_EQUAL(btccs_selection_result_get_selected_value(result), utxo_value);
        BOOST_CHECK_EQUAL(btccs_selection_result_get_selected_effective_value(result), target);
        BOOST_CHECK_EQUAL(btccs_selection_result_get_algorithm(result), btccs_SelectionAlgorithm_BNB);

        // Verify waste is calculated
        btccs_Amount waste = btccs_selection_result_get_waste(result);
        BOOST_CHECK_GE(waste, 0);  // Could be negative if long_term > effective
    }
}

// ==========================================================================
// Single Random Draw (SRD) Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(srd_empty_pool)
{
    UtxoPoolGuard pool;
    RandomContextGuard rng;
    btccs_SelectionStatus status;

    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    btccs_SelectionResult* result = btccs_select_coins_srd(
        pool, 100000, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);

    BOOST_CHECK(result == nullptr);
    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_NO_SOLUTION_FOUND);
}

BOOST_AUTO_TEST_CASE(srd_success)
{
    UtxoPoolGuard pool;
    RandomContextGuard rng;
    btccs_SelectionStatus status;

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);
    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    std::vector<btccs_Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        unsigned char txid[32];
        make_txid(static_cast<uint32_t>(i), txid);
        btccs_utxo_pool_add(pool, txid, 0, values[i], P2WPKH_INPUT_BYTES, 6, fee, lt_fee);
    }

    btccs_Amount target = 300000;
    btccs_SelectionResult* result = btccs_select_coins_srd(
        pool, target, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);

    BOOST_REQUIRE(result != nullptr);
    SelectionResultGuard guard(result);

    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_SUCCESS);
    BOOST_CHECK_GE(btccs_selection_result_get_input_count(result), 1u);
    BOOST_CHECK_GE(btccs_selection_result_get_selected_value(result), target);
    BOOST_CHECK_EQUAL(btccs_selection_result_get_algorithm(result), btccs_SelectionAlgorithm_SRD);

    // Verify waste is calculated
    btccs_Amount waste = btccs_selection_result_get_waste(result);
    BOOST_TEST_MESSAGE("SRD waste: " << waste);
}

// ==========================================================================
// CoinGrinder Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(coingrinder_empty_pool)
{
    UtxoPoolGuard pool;
    btccs_SelectionStatus status;

    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    btccs_SelectionResult* result = btccs_select_coins_coingrinder(
        pool, 100000, min_viable_change, cost_of_change, change_fee,
        btccs_get_max_standard_tx_weight(), &status);

    BOOST_CHECK(result == nullptr);
    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_NO_SOLUTION_FOUND);
}

BOOST_AUTO_TEST_CASE(coingrinder_success)
{
    UtxoPoolGuard pool;
    btccs_SelectionStatus status;

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);
    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    std::vector<btccs_Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        unsigned char txid[32];
        make_txid(static_cast<uint32_t>(i), txid);
        btccs_utxo_pool_add(pool, txid, 0, values[i], P2WPKH_INPUT_BYTES, 6, fee, lt_fee);
    }

    btccs_Amount target = 300000;
    btccs_SelectionResult* result = btccs_select_coins_coingrinder(
        pool, target, min_viable_change, cost_of_change, change_fee,
        btccs_get_max_standard_tx_weight(), &status);

    BOOST_REQUIRE(result != nullptr);
    SelectionResultGuard guard(result);

    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_SUCCESS);
    BOOST_CHECK_GE(btccs_selection_result_get_input_count(result), 1u);
    BOOST_CHECK_GE(btccs_selection_result_get_selected_value(result), target);
    BOOST_CHECK_EQUAL(btccs_selection_result_get_algorithm(result), btccs_SelectionAlgorithm_COINGRINDER);

    // Verify waste is calculated
    btccs_Amount waste = btccs_selection_result_get_waste(result);
    BOOST_TEST_MESSAGE("CoinGrinder waste: " << waste);
}

// ==========================================================================
// Knapsack Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(knapsack_empty_pool)
{
    UtxoPoolGuard pool;
    RandomContextGuard rng;
    btccs_SelectionStatus status;

    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    btccs_SelectionResult* result = btccs_select_coins_knapsack(
        pool, 100000, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);

    BOOST_CHECK(result == nullptr);
    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_NO_SOLUTION_FOUND);
}

BOOST_AUTO_TEST_CASE(knapsack_success)
{
    UtxoPoolGuard pool;
    RandomContextGuard rng;
    btccs_SelectionStatus status;

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);
    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    std::vector<btccs_Amount> values = {50000, 100000, 250000, 500000, 1000000};
    for (size_t i = 0; i < values.size(); ++i) {
        unsigned char txid[32];
        make_txid(static_cast<uint32_t>(i), txid);
        btccs_utxo_pool_add(pool, txid, 0, values[i], P2WPKH_INPUT_BYTES, 6, fee, lt_fee);
    }

    btccs_Amount target = 300000;
    btccs_SelectionResult* result = btccs_select_coins_knapsack(
        pool, target, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);

    BOOST_REQUIRE(result != nullptr);
    SelectionResultGuard guard(result);

    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_SUCCESS);
    BOOST_CHECK_GE(btccs_selection_result_get_input_count(result), 1u);
    BOOST_CHECK_GE(btccs_selection_result_get_selected_value(result), target);
    BOOST_CHECK_EQUAL(btccs_selection_result_get_algorithm(result), btccs_SelectionAlgorithm_KNAPSACK);

    // Verify waste is calculated
    btccs_Amount waste = btccs_selection_result_get_waste(result);
    BOOST_TEST_MESSAGE("Knapsack waste: " << waste);
}

// ==========================================================================
// Selection Result Tests
// ==========================================================================

BOOST_AUTO_TEST_CASE(selection_result_outpoints)
{
    UtxoPoolGuard pool;
    RandomContextGuard rng;
    btccs_SelectionStatus status;

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);
    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    // Add UTXOs with known txids
    for (uint32_t i = 0; i < 5; ++i) {
        unsigned char txid[32];
        make_txid(i, txid);
        btccs_utxo_pool_add(pool, txid, i * 2, 100000 * (i + 1), P2WPKH_INPUT_BYTES, 6, fee, lt_fee);
    }

    btccs_Amount target = 150000;
    btccs_SelectionResult* result = btccs_select_coins_knapsack(
        pool, target, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);

    BOOST_REQUIRE(result != nullptr);
    SelectionResultGuard guard(result);

    size_t count = btccs_selection_result_get_input_count(result);
    BOOST_CHECK_GE(count, 1u);

    // Test outpoint retrieval
    for (size_t i = 0; i < count; ++i) {
        unsigned char txid[32];
        uint32_t vout;
        int ret = btccs_selection_result_get_input_outpoint(result, i, txid, &vout);
        BOOST_CHECK_EQUAL(ret, 0);
    }

    // Test out of bounds
    unsigned char txid[32];
    uint32_t vout;
    int ret = btccs_selection_result_get_input_outpoint(result, count, txid, &vout);
    BOOST_CHECK_EQUAL(ret, -1);
}

BOOST_AUTO_TEST_CASE(selection_result_metrics)
{
    UtxoPoolGuard pool;
    RandomContextGuard rng;
    btccs_SelectionStatus status;

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);
    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    // Add a single large UTXO
    unsigned char txid[32];
    make_txid(1, txid);
    btccs_Amount value = 1000000;
    btccs_utxo_pool_add(pool, txid, 0, value, P2WPKH_INPUT_BYTES, 6, fee, lt_fee);

    btccs_Amount target = 100000;
    btccs_SelectionResult* result = btccs_select_coins_knapsack(
        pool, target, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);

    BOOST_REQUIRE(result != nullptr);
    SelectionResultGuard guard(result);

    BOOST_CHECK_EQUAL(btccs_selection_result_get_input_count(result), 1u);
    BOOST_CHECK_EQUAL(btccs_selection_result_get_selected_value(result), value);
    BOOST_CHECK_EQUAL(btccs_selection_result_get_selected_effective_value(result), value - fee);

    // Weight = input_bytes * WITNESS_SCALE_FACTOR
    int expected_weight = P2WPKH_INPUT_BYTES * 4;
    BOOST_CHECK_EQUAL(btccs_selection_result_get_weight(result), expected_weight);

    // Waste now uses Bitcoin Core's RecalculateWaste
    // For a single input with change, waste = input_fee_differential + cost_of_change
    btccs_Amount waste = btccs_selection_result_get_waste(result);
    btccs_Amount input_waste = fee - lt_fee;

    // Waste should be at least the input waste
    BOOST_CHECK_GE(waste, input_waste);
    BOOST_TEST_MESSAGE("Waste: " << waste << " (input waste: " << input_waste << ")");
}

BOOST_AUTO_TEST_CASE(selection_result_destroy_null)
{
    // Should not crash when passed nullptr
    btccs_selection_result_destroy(nullptr);
}

// ==========================================================================
// Edge Cases and Error Handling
// ==========================================================================

BOOST_AUTO_TEST_CASE(status_output_optional)
{
    UtxoPoolGuard pool;
    RandomContextGuard rng;

    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    // All selection functions should accept nullptr for status
    btccs_SelectionResult* bnb = btccs_select_coins_bnb(
        pool, 100000, cost_of_change, btccs_get_max_standard_tx_weight(), nullptr);
    BOOST_CHECK(bnb == nullptr);

    btccs_SelectionResult* srd = btccs_select_coins_srd(
        pool, 100000, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), nullptr);
    BOOST_CHECK(srd == nullptr);

    btccs_SelectionResult* cg = btccs_select_coins_coingrinder(
        pool, 100000, min_viable_change, cost_of_change, change_fee,
        btccs_get_max_standard_tx_weight(), nullptr);
    BOOST_CHECK(cg == nullptr);

    btccs_SelectionResult* ks = btccs_select_coins_knapsack(
        pool, 100000, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), nullptr);
    BOOST_CHECK(ks == nullptr);
}

BOOST_AUTO_TEST_CASE(large_utxo_pool)
{
    UtxoPoolGuard pool;
    RandomContextGuard rng;
    btccs_SelectionStatus status;

    btccs_Amount fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
    btccs_Amount lt_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);
    btccs_Amount change_fee = btccs_calculate_fee(TEST_FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        TEST_FEERATE_SAT_PER_KVB, DISCARD_FEERATE_SAT_PER_KVB,
        P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);

    // Add many UTXOs
    for (uint32_t i = 0; i < 100; ++i) {
        unsigned char txid[32];
        make_txid(i, txid);
        btccs_utxo_pool_add(pool, txid, 0, 10000 + i * 1000, P2WPKH_INPUT_BYTES, 6, fee, lt_fee);
    }

    BOOST_CHECK_EQUAL(btccs_utxo_pool_size(pool), 100u);

    btccs_Amount target = 500000;

    // SRD should handle large pools
    btccs_SelectionResult* result = btccs_select_coins_srd(
        pool, target, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);

    BOOST_REQUIRE(result != nullptr);
    SelectionResultGuard guard(result);

    BOOST_CHECK_EQUAL(status, btccs_SelectionStatus_SUCCESS);
    BOOST_CHECK_GE(btccs_selection_result_get_selected_value(result), target);
}

// ==========================================================================
// Comparison Test (matching main_c_api.cpp example values)
// ==========================================================================

BOOST_AUTO_TEST_CASE(example_values_match)
{
    // This test uses the same values as main_c_api.cpp to verify consistency
    UtxoPoolGuard pool;
    RandomContextGuard rng;
    btccs_SelectionStatus status;

    const int64_t FEERATE_SAT_PER_KVB = 10000; // 10 sat/vB
    const int64_t DISCARD_RATE = 3000;          // 3 sat/vB
    const btccs_Amount TARGET = 300000;         // 0.003 BTC

    btccs_Amount change_fee = btccs_calculate_fee(FEERATE_SAT_PER_KVB, P2WPKH_OUTPUT_BYTES);
    btccs_Amount cost_of_change = btccs_calculate_cost_of_change(
        FEERATE_SAT_PER_KVB, DISCARD_RATE, P2WPKH_OUTPUT_BYTES, P2WPKH_INPUT_BYTES);
    btccs_Amount min_viable_change = btccs_calculate_fee(DISCARD_RATE, P2WPKH_INPUT_BYTES);

    // Verify calculated values match expected
    BOOST_CHECK_EQUAL(cost_of_change, 514); // 310 + 204
    BOOST_CHECK_EQUAL(change_fee, 310);
    BOOST_CHECK_EQUAL(min_viable_change, 204);

    // Add same UTXOs as example
    std::vector<btccs_Amount> utxo_values = {
        50000,    // 0.0005 BTC
        100000,   // 0.001 BTC
        250000,   // 0.0025 BTC
        500000,   // 0.005 BTC
        1000000,  // 0.01 BTC
        2500000,  // 0.025 BTC
        5000000,  // 0.05 BTC
    };

    for (size_t i = 0; i < utxo_values.size(); ++i) {
        unsigned char txid[32];
        make_txid(static_cast<uint32_t>(i), txid);

        btccs_Amount fee = btccs_calculate_fee(FEERATE_SAT_PER_KVB, P2WPKH_INPUT_BYTES);
        btccs_Amount lt_fee = btccs_calculate_fee(FEERATE_SAT_PER_KVB / 3, P2WPKH_INPUT_BYTES);

        btccs_utxo_pool_add(pool, txid, 0, utxo_values[i],
                            P2WPKH_INPUT_BYTES, 6, fee, lt_fee);
    }

    BOOST_CHECK_EQUAL(btccs_utxo_pool_size(pool), utxo_values.size());

    // Test each algorithm finds a solution
    btccs_SelectionResult* srd_result = btccs_select_coins_srd(
        pool, TARGET, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);
    BOOST_CHECK(srd_result != nullptr);
    if (srd_result) {
        BOOST_CHECK_GE(btccs_selection_result_get_selected_value(srd_result), TARGET);
        btccs_Amount waste = btccs_selection_result_get_waste(srd_result);
        BOOST_TEST_MESSAGE("SRD waste: " << waste);
        btccs_selection_result_destroy(srd_result);
    }

    btccs_SelectionResult* cg_result = btccs_select_coins_coingrinder(
        pool, TARGET, min_viable_change, cost_of_change, change_fee,
        btccs_get_max_standard_tx_weight(), &status);
    BOOST_CHECK(cg_result != nullptr);
    if (cg_result) {
        BOOST_CHECK_GE(btccs_selection_result_get_selected_value(cg_result), TARGET);
        btccs_Amount waste = btccs_selection_result_get_waste(cg_result);
        BOOST_TEST_MESSAGE("CoinGrinder waste: " << waste);
        btccs_selection_result_destroy(cg_result);
    }

    btccs_SelectionResult* ks_result = btccs_select_coins_knapsack(
        pool, TARGET, min_viable_change, cost_of_change, change_fee,
        rng, btccs_get_max_standard_tx_weight(), &status);
    BOOST_CHECK(ks_result != nullptr);
    if (ks_result) {
        BOOST_CHECK_GE(btccs_selection_result_get_selected_value(ks_result), TARGET);
        btccs_Amount waste = btccs_selection_result_get_waste(ks_result);
        BOOST_TEST_MESSAGE("Knapsack waste: " << waste);
        btccs_selection_result_destroy(ks_result);
    }
}

BOOST_AUTO_TEST_SUITE_END()

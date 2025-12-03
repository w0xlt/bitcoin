// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H
#define BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H

/**
 * @file bitcoincoinselection.h
 * @brief C API for Bitcoin Core coin selection algorithms
 *
 * This header provides a C-compatible interface for external language bindings.
 * For C++ users, prefer using bitcoincoinselection_wrapper.h which provides
 * direct access to Bitcoin Core types with RAII wrappers.
 *
 */

#ifndef __cplusplus
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif

#ifndef BITCOINCOINSELECTION_API
    #ifdef BITCOINCOINSELECTION_BUILD
        #if defined(_WIN32)
            #define BITCOINCOINSELECTION_API __declspec(dllexport)
        #else
            #define BITCOINCOINSELECTION_API __attribute__((visibility("default")))
        #endif
    #else
        #if defined(_WIN32) && !defined(BITCOINCOINSELECTION_STATIC)
            #define BITCOINCOINSELECTION_API __declspec(dllimport)
        #else
            #define BITCOINCOINSELECTION_API
        #endif
    #endif
#endif

#if defined(__GNUC__)
    #define BITCOINCOINSELECTION_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
    #define BITCOINCOINSELECTION_ARG_NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
    #define BITCOINCOINSELECTION_WARN_UNUSED_RESULT
    #define BITCOINCOINSELECTION_ARG_NONNULL(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*                              Type Definitions                               */
/* ========================================================================== */

/** Bitcoin amount in satoshis (signed 64-bit) */
typedef int64_t btccs_Amount;

/** Opaque handle to a UTXO pool (vector of OutputGroups) */
typedef struct btccs_UtxoPool btccs_UtxoPool;

/** Opaque handle to a selection result */
typedef struct btccs_SelectionResult btccs_SelectionResult;

/** Opaque handle to a random context */
typedef struct btccs_RandomContext btccs_RandomContext;

/* ========================================================================== */
/*                              Enumerations                                   */
/* ========================================================================== */

typedef uint8_t btccs_SelectionStatus;
#define btccs_SelectionStatus_SUCCESS              ((btccs_SelectionStatus)0)
#define btccs_SelectionStatus_INSUFFICIENT_FUNDS   ((btccs_SelectionStatus)1)
#define btccs_SelectionStatus_MAX_WEIGHT_EXCEEDED  ((btccs_SelectionStatus)2)
#define btccs_SelectionStatus_NO_SOLUTION_FOUND    ((btccs_SelectionStatus)3)
#define btccs_SelectionStatus_INVALID_PARAMETER    ((btccs_SelectionStatus)4)
#define btccs_SelectionStatus_INTERNAL_ERROR       ((btccs_SelectionStatus)5)

typedef uint8_t btccs_SelectionAlgorithm;
#define btccs_SelectionAlgorithm_BNB         ((btccs_SelectionAlgorithm)0)
#define btccs_SelectionAlgorithm_SRD         ((btccs_SelectionAlgorithm)1)
#define btccs_SelectionAlgorithm_COINGRINDER ((btccs_SelectionAlgorithm)2)
#define btccs_SelectionAlgorithm_KNAPSACK    ((btccs_SelectionAlgorithm)3)
#define btccs_SelectionAlgorithm_MANUAL      ((btccs_SelectionAlgorithm)4)

/* ========================================================================== */
/*                           UTXO Pool Functions                               */
/* ========================================================================== */

/**
 * @brief Create an empty UTXO pool.
 * @return New UTXO pool handle, or NULL on error.
 */
BITCOINCOINSELECTION_API btccs_UtxoPool* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_utxo_pool_create(void);

/**
 * @brief Add a UTXO to the pool.
 *
 * @param pool         Pool handle. Non-null.
 * @param txid         Transaction ID (32 bytes, little-endian). Non-null.
 * @param vout         Output index.
 * @param value        Output value in satoshis.
 * @param input_bytes  Estimated input size when spent (e.g., 68 for P2WPKH).
 * @param depth        Confirmation depth (0 for unconfirmed).
 * @param fee          Fee to spend at current feerate.
 * @param long_term_fee Fee to spend at long-term feerate.
 */
BITCOINCOINSELECTION_API void btccs_utxo_pool_add(
    btccs_UtxoPool* pool,
    const unsigned char txid[32],
    uint32_t vout,
    btccs_Amount value,
    int input_bytes,
    int depth,
    btccs_Amount fee,
    btccs_Amount long_term_fee) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * @brief Get the number of UTXOs in the pool.
 */
BITCOINCOINSELECTION_API size_t BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_utxo_pool_size(const btccs_UtxoPool* pool) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Destroy a UTXO pool.
 */
BITCOINCOINSELECTION_API void btccs_utxo_pool_destroy(btccs_UtxoPool* pool);

/* ========================================================================== */
/*                        Random Context Functions                             */
/* ========================================================================== */

/**
 * @brief Create a cryptographically secure random context.
 */
BITCOINCOINSELECTION_API btccs_RandomContext* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_random_context_create(void);

/**
 * @brief Create a seeded random context (for deterministic testing).
 * @param seed 32-byte seed.
 */
BITCOINCOINSELECTION_API btccs_RandomContext* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_random_context_create_seeded(const unsigned char seed[32]) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Destroy a random context.
 */
BITCOINCOINSELECTION_API void btccs_random_context_destroy(btccs_RandomContext* rng);

/* ========================================================================== */
/*                     Coin Selection Algorithms                               */
/* ========================================================================== */

/**
 * @brief Select coins using Branch and Bound (finds changeless solutions).
 *
 * BnB attempts to find an exact match for the selection target, avoiding
 * change creation. If no exact match is possible within cost_of_change,
 * it returns no solution.
 *
 * @param pool                 UTXO pool. Non-null.
 * @param selection_target     Target effective value in satoshis.
 * @param cost_of_change       Cost of creating and spending change.
 *                             Used as tolerance for inexact matches.
 * @param max_weight           Maximum selection weight (use btccs_get_max_standard_tx_weight()).
 * @param status               Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 *
 * @note For BnB, the waste metric reflects only input fee differential
 *       plus any small excess, since change is not created.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_select_coins_bnb(
    btccs_UtxoPool* pool,
    btccs_Amount selection_target,
    btccs_Amount cost_of_change,
    int max_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Select coins using Single Random Draw.
 *
 * SRD randomly selects UTXOs until the target is met. It typically
 * creates change output.
 *
 * @param pool              UTXO pool. Non-null.
 * @param target_value      Target value in satoshis.
 * @param min_viable_change Minimum worthwhile change amount (dust threshold).
 *                          Use btccs_generate_change_target() for randomized value.
 * @param cost_of_change    Total cost of creating and spending change.
 *                          Calculate with btccs_calculate_cost_of_change().
 * @param change_fee        Fee for the change output at current feerate.
 *                          Calculate with btccs_calculate_fee(feerate, change_output_size).
 * @param rng               Random context. Non-null.
 * @param max_weight        Maximum selection weight.
 * @param status            Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_select_coins_srd(
    btccs_UtxoPool* pool,
    btccs_Amount target_value,
    btccs_Amount min_viable_change,
    btccs_Amount cost_of_change,
    btccs_Amount change_fee,
    btccs_RandomContext* rng,
    int max_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1, 6);

/**
 * @brief Select coins using CoinGrinder (minimizes input weight).
 *
 * CoinGrinder finds the minimum-weight selection that meets the target.
 * Best used when feerates are high and minimizing input count matters.
 *
 * @param pool              UTXO pool. Non-null.
 * @param selection_target  Target value in satoshis.
 * @param min_viable_change Minimum worthwhile change amount.
 * @param cost_of_change    Total cost of creating and spending change.
 * @param change_fee        Fee for the change output at current feerate.
 * @param max_weight        Maximum selection weight.
 * @param status            Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_select_coins_coingrinder(
    btccs_UtxoPool* pool,
    btccs_Amount selection_target,
    btccs_Amount min_viable_change,
    btccs_Amount cost_of_change,
    btccs_Amount change_fee,
    int max_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Select coins using Knapsack (legacy randomized solver).
 *
 * The Knapsack solver uses stochastic approximation to find a solution.
 * It's a fallback when other algorithms don't find a solution.
 *
 * @param pool              UTXO pool. Non-null.
 * @param target_value      Target value in satoshis.
 * @param min_viable_change Minimum worthwhile change amount.
 * @param cost_of_change    Total cost of creating and spending change.
 * @param change_fee        Fee for the change output at current feerate.
 * @param rng               Random context. Non-null.
 * @param max_weight        Maximum selection weight.
 * @param status            Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_select_coins_knapsack(
    btccs_UtxoPool* pool,
    btccs_Amount target_value,
    btccs_Amount min_viable_change,
    btccs_Amount cost_of_change,
    btccs_Amount change_fee,
    btccs_RandomContext* rng,
    int max_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1, 6);

/* ========================================================================== */
/*                       Selection Result Functions                            */
/* ========================================================================== */

/** Get number of selected inputs. */
BITCOINCOINSELECTION_API size_t BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_input_count(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/** Get total selected value (before fees). */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_selected_value(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/** Get total selected effective value (after fees). */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_selected_effective_value(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the waste metric for this selection.
 *
 * The waste metric is computed by Bitcoin Core's SelectionResult::GetWaste()
 * and includes:
 * - Input fee differential: sum of (fee - long_term_fee) for each input
 * - Change cost: if change is created, the cost of creating and spending it
 * - Excess: if no change, any amount over target that goes to fees
 *
 * Lower waste values indicate more efficient selections.
 * Waste can be negative if long_term_fee > fee (consolidation opportunity).
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_waste(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/** Get total weight of selected inputs. */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_weight(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/** Get algorithm used for selection. */
BITCOINCOINSELECTION_API btccs_SelectionAlgorithm BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_algorithm(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get outpoint of a selected input.
 * @param result   Selection result. Non-null.
 * @param index    Input index.
 * @param txid_out Buffer for txid (32 bytes). Non-null.
 * @param vout_out Output for vout index. Non-null.
 * @return 0 on success, -1 if index out of bounds.
 */
BITCOINCOINSELECTION_API int btccs_selection_result_get_input_outpoint(
    const btccs_SelectionResult* result,
    size_t index,
    unsigned char txid_out[32],
    uint32_t* vout_out) BITCOINCOINSELECTION_ARG_NONNULL(1, 3, 4);

/** Destroy a selection result. */
BITCOINCOINSELECTION_API void btccs_selection_result_destroy(btccs_SelectionResult* result);

/* ========================================================================== */
/*                         Utility Functions                                   */
/* ========================================================================== */

/** Get the maximum standard transaction weight (400,000 WU). */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_get_max_standard_tx_weight(void);

/** Convert input bytes to weight units. */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_get_input_weight(int input_bytes);

/**
 * @brief Calculate fee for a given size at a feerate.
 * @param feerate_sat_per_kvb Feerate in sat/kvB.
 * @param size                Size in virtual bytes.
 * @return Fee in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_calculate_fee(int64_t feerate_sat_per_kvb, size_t size);

/**
 * @brief Calculate cost of change output (creation + future spend).
 *
 * cost_of_change = feerate.GetFee(change_output_size)
 *                + discard_feerate.GetFee(change_spend_size)
 *
 * @param feerate_sat_per_kvb         Current feerate in sat/kvB.
 * @param discard_feerate_sat_per_kvb Discard/long-term feerate in sat/kvB.
 *                                    Typically 3000 (3 sat/vB) or the long-term rate.
 * @param change_output_size          Change output size (31 for P2WPKH).
 * @param change_spend_size           Change spend size (68 for P2WPKH).
 * @return Total cost of change in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_calculate_cost_of_change(
    int64_t feerate_sat_per_kvb,
    int64_t discard_feerate_sat_per_kvb,
    size_t change_output_size,
    size_t change_spend_size);

/**
 * @brief Generate randomized change target for privacy.
 *
 * Returns a randomized minimum change amount to avoid creating
 * predictable change outputs that could aid chain analysis.
 *
 * @param payment_value Total payment value.
 * @param change_fee    Fee for change output.
 * @param rng           Random context. Non-null.
 * @return Randomized change target.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_generate_change_target(
    btccs_Amount payment_value,
    btccs_Amount change_fee,
    btccs_RandomContext* rng) BITCOINCOINSELECTION_ARG_NONNULL(3);

/** Get library version string. */
BITCOINCOINSELECTION_API const char* btccs_version(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H

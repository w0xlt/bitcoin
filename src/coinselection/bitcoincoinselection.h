// Copyright (c) 2024-present The Bitcoin Core developers
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
 */

#ifndef __cplusplus
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
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

/** Opaque handle to coin selection source (chain interface) */
typedef struct btccs_CoinSelectionSource btccs_CoinSelectionSource;

/** Opaque handle to coins result (available coins organized by output type) */
typedef struct btccs_CoinsResult btccs_CoinsResult;

/** Opaque handle to pre-selected inputs */
typedef struct btccs_PreSelectedInputs btccs_PreSelectedInputs;

/** Opaque handle to coin control settings */
typedef struct btccs_CoinControl btccs_CoinControl;

/** Opaque handle to coin selection parameters */
typedef struct btccs_CoinSelectionParams btccs_CoinSelectionParams;

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

typedef uint8_t btccs_OutputType;
#define btccs_OutputType_LEGACY      ((btccs_OutputType)0)
#define btccs_OutputType_P2SH_SEGWIT ((btccs_OutputType)1)
#define btccs_OutputType_BECH32      ((btccs_OutputType)2)
#define btccs_OutputType_BECH32M     ((btccs_OutputType)3)
#define btccs_OutputType_UNKNOWN     ((btccs_OutputType)4)

/* ========================================================================== */
/*                    Coin Selection Options (simple struct)                   */
/* ========================================================================== */

/**
 * Options/settings for coin selection.
 * Can be passed directly without opaque pointer.
 */
typedef struct btccs_CoinSelectionOptions {
    /** Whether to allow spending zero-confirmation change outputs. */
    bool spend_zero_conf_change;
    /** Whether to reject transactions with long mempool chains. */
    bool reject_long_chains;
} btccs_CoinSelectionOptions;

/** Create default options (spend_zero_conf_change=true, reject_long_chains=false) */
BITCOINCOINSELECTION_API btccs_CoinSelectionOptions btccs_coin_selection_options_default(void);

/* ========================================================================== */
/*                    Coin Selection Source Callbacks                          */
/* ========================================================================== */

/**
 * Callback type for getting transaction ancestry.
 *
 * @param user_data    User-provided context pointer.
 * @param txid         Transaction ID (32 bytes, little-endian).
 * @param ancestors    Output: number of in-mempool ancestors.
 * @param descendants  Output: number of in-mempool descendants.
 */
typedef void (*btccs_get_transaction_ancestry_fn)(
    void* user_data,
    const unsigned char txid[32],
    size_t* ancestors,
    size_t* descendants);

/**
 * Callback type for calculating combined bump fee.
 *
 * @param user_data       User-provided context pointer.
 * @param outpoints       Array of outpoints (each is 32-byte txid + 4-byte vout).
 * @param outpoints_count Number of outpoints.
 * @param feerate_sat_per_kvb  Target feerate in sat/kvB.
 * @param bump_fee_out    Output: the combined bump fee in satoshis.
 * @return                true if calculation succeeded, false on failure.
 */
typedef bool (*btccs_calculate_combined_bump_fee_fn)(
    void* user_data,
    const unsigned char* outpoints,
    size_t outpoints_count,
    int64_t feerate_sat_per_kvb,
    btccs_Amount* bump_fee_out);

/**
 * Callback type for getting package limits.
 *
 * @param user_data              User-provided context pointer.
 * @param limit_ancestor_count   Output: maximum number of ancestors.
 * @param limit_descendant_count Output: maximum number of descendants.
 */
typedef void (*btccs_get_package_limits_fn)(
    void* user_data,
    unsigned int* limit_ancestor_count,
    unsigned int* limit_descendant_count);

/**
 * Callback table for coin selection source.
 * All callbacks are required (non-null).
 */
typedef struct btccs_CoinSelectionSourceCallbacks {
    btccs_get_transaction_ancestry_fn get_transaction_ancestry;
    btccs_calculate_combined_bump_fee_fn calculate_combined_bump_fee;
    btccs_get_package_limits_fn get_package_limits;
} btccs_CoinSelectionSourceCallbacks;

/* ========================================================================== */
/*                     Coin Selection Source Functions                         */
/* ========================================================================== */

/**
 * @brief Create a coin selection source from callbacks.
 *
 * @param callbacks  Callback function table. Non-null.
 * @param user_data  User-provided context passed to callbacks. May be NULL.
 * @return Source handle, or NULL on error.
 */
BITCOINCOINSELECTION_API btccs_CoinSelectionSource* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_coin_selection_source_create(
    const btccs_CoinSelectionSourceCallbacks* callbacks,
    void* user_data) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Create a simple coin selection source with default/no-op callbacks.
 *
 * This source returns 0 ancestors/descendants, no bump fees, and default limits.
 * Useful for simple use cases where mempool tracking is not needed.
 *
 * @param limit_ancestor_count   Maximum ancestor count (e.g., 25).
 * @param limit_descendant_count Maximum descendant count (e.g., 25).
 * @return Source handle, or NULL on error.
 */
BITCOINCOINSELECTION_API btccs_CoinSelectionSource* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_coin_selection_source_create_simple(
    unsigned int limit_ancestor_count,
    unsigned int limit_descendant_count);

/**
 * @brief Destroy a coin selection source.
 */
BITCOINCOINSELECTION_API void btccs_coin_selection_source_destroy(btccs_CoinSelectionSource* source);

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
/*                          Coins Result Functions                             */
/* ========================================================================== */

/**
 * @brief Create an empty coins result container.
 * @return New coins result handle, or NULL on error.
 */
BITCOINCOINSELECTION_API btccs_CoinsResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_coins_result_create(void);

/**
 * @brief Add a coin to the coins result.
 *
 * @param coins        Coins result handle. Non-null.
 * @param output_type  Output type (LEGACY, P2SH_SEGWIT, BECH32, BECH32M, UNKNOWN).
 * @param txid         Transaction ID (32 bytes, little-endian). Non-null.
 * @param vout         Output index.
 * @param value        Output value in satoshis.
 * @param input_bytes  Estimated input size when spent.
 * @param depth        Confirmation depth.
 * @param solvable     Whether we know how to spend this output.
 * @param safe         Whether this output is considered safe to spend.
 * @param time         The transaction time.
 * @param from_me      Whether sent from the owning wallet.
 * @param fee          Fee to spend at current feerate (0 if unknown).
 * @param long_term_fee Fee to spend at long-term feerate (0 if unknown).
 */
BITCOINCOINSELECTION_API void btccs_coins_result_add(
    btccs_CoinsResult* coins,
    btccs_OutputType output_type,
    const unsigned char txid[32],
    uint32_t vout,
    btccs_Amount value,
    int input_bytes,
    int depth,
    bool solvable,
    bool safe,
    int64_t time,
    bool from_me,
    btccs_Amount fee,
    btccs_Amount long_term_fee) BITCOINCOINSELECTION_ARG_NONNULL(1, 3);

/**
 * @brief Get the total number of coins across all output types.
 */
BITCOINCOINSELECTION_API size_t BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_coins_result_size(const btccs_CoinsResult* coins) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the total value of all coins.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_coins_result_get_total_amount(const btccs_CoinsResult* coins) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Shuffle the coins for privacy.
 */
BITCOINCOINSELECTION_API void btccs_coins_result_shuffle(
    btccs_CoinsResult* coins,
    btccs_RandomContext* rng) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * @brief Destroy a coins result.
 */
BITCOINCOINSELECTION_API void btccs_coins_result_destroy(btccs_CoinsResult* coins);

/* ========================================================================== */
/*                       Pre-Selected Inputs Functions                         */
/* ========================================================================== */

/**
 * @brief Create an empty pre-selected inputs container.
 * @return New handle, or NULL on error.
 */
BITCOINCOINSELECTION_API btccs_PreSelectedInputs* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_preselected_inputs_create(void);

/**
 * @brief Add a pre-selected input.
 *
 * @param inputs              Handle. Non-null.
 * @param txid                Transaction ID (32 bytes). Non-null.
 * @param vout                Output index.
 * @param value               Output value in satoshis.
 * @param input_bytes         Estimated input size.
 * @param depth               Confirmation depth.
 * @param fee                 Fee at current feerate.
 * @param subtract_fee_outputs Whether to use raw value (true) or effective value (false).
 */
BITCOINCOINSELECTION_API void btccs_preselected_inputs_add(
    btccs_PreSelectedInputs* inputs,
    const unsigned char txid[32],
    uint32_t vout,
    btccs_Amount value,
    int input_bytes,
    int depth,
    btccs_Amount fee,
    bool subtract_fee_outputs) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * @brief Get the total amount of pre-selected inputs.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_preselected_inputs_get_total(const btccs_PreSelectedInputs* inputs) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Destroy pre-selected inputs.
 */
BITCOINCOINSELECTION_API void btccs_preselected_inputs_destroy(btccs_PreSelectedInputs* inputs);

/* ========================================================================== */
/*                         Coin Control Functions                              */
/* ========================================================================== */

/**
 * @brief Create coin control with default settings.
 * @return New handle, or NULL on error.
 */
BITCOINCOINSELECTION_API btccs_CoinControl* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_coin_control_create(void);

/**
 * @brief Set whether to allow other inputs beyond pre-selected.
 */
BITCOINCOINSELECTION_API void btccs_coin_control_set_allow_other_inputs(
    btccs_CoinControl* coin_control,
    bool allow) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Set whether to include unsafe inputs.
 */
BITCOINCOINSELECTION_API void btccs_coin_control_set_include_unsafe_inputs(
    btccs_CoinControl* coin_control,
    bool include) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Set whether to avoid partial spends.
 */
BITCOINCOINSELECTION_API void btccs_coin_control_set_avoid_partial_spends(
    btccs_CoinControl* coin_control,
    bool avoid) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Destroy coin control.
 */
BITCOINCOINSELECTION_API void btccs_coin_control_destroy(btccs_CoinControl* coin_control);

/* ========================================================================== */
/*                    Coin Selection Params Functions                          */
/* ========================================================================== */

/**
 * @brief Create coin selection parameters.
 *
 * @param rng                    Random context. Non-null.
 * @param change_output_size     Size of change output in bytes (e.g., 31 for P2WPKH).
 * @param change_spend_size      Size of spending change in bytes (e.g., 68 for P2WPKH).
 * @param min_change_target      Minimum change to target.
 * @param effective_feerate_sat_per_kvb  Current feerate in sat/kvB.
 * @param long_term_feerate_sat_per_kvb  Long-term feerate in sat/kvB.
 * @param discard_feerate_sat_per_kvb    Discard threshold feerate in sat/kvB.
 * @param tx_noinputs_size       Size of tx before adding inputs.
 * @param avoid_partial_spends   Whether to avoid partial spends.
 * @return New handle, or NULL on error.
 */
BITCOINCOINSELECTION_API btccs_CoinSelectionParams* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_coin_selection_params_create(
    btccs_RandomContext* rng,
    int change_output_size,
    int change_spend_size,
    btccs_Amount min_change_target,
    int64_t effective_feerate_sat_per_kvb,
    int64_t long_term_feerate_sat_per_kvb,
    int64_t discard_feerate_sat_per_kvb,
    int tx_noinputs_size,
    bool avoid_partial_spends) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Set whether to subtract fee from outputs.
 */
BITCOINCOINSELECTION_API void btccs_coin_selection_params_set_subtract_fee_outputs(
    btccs_CoinSelectionParams* params,
    bool subtract) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Set the maximum transaction weight.
 */
BITCOINCOINSELECTION_API void btccs_coin_selection_params_set_max_tx_weight(
    btccs_CoinSelectionParams* params,
    int max_weight) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Destroy coin selection params.
 */
BITCOINCOINSELECTION_API void btccs_coin_selection_params_destroy(btccs_CoinSelectionParams* params);

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
/*                     Individual Algorithm Functions                          */
/* ========================================================================== */

/**
 * @brief Select coins using Branch and Bound (finds changeless solutions).
 *
 * @param pool                 UTXO pool. Non-null.
 * @param selection_target     Target effective value in satoshis.
 * @param cost_of_change       Cost of creating and spending change.
 * @param max_weight           Maximum selection weight (use btccs_get_max_standard_tx_weight()).
 * @param status               Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
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
 * @param pool             UTXO pool. Non-null.
 * @param target_value     Target value in satoshis.
 * @param change_fee       Fee for change output.
 * @param rng              Random context. Non-null.
 * @param max_weight       Maximum selection weight.
 * @param status           Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_select_coins_srd(
    btccs_UtxoPool* pool,
    btccs_Amount target_value,
    btccs_Amount change_fee,
    btccs_RandomContext* rng,
    int max_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1, 4);

/**
 * @brief Select coins using CoinGrinder (minimizes input weight).
 *
 * @param pool              UTXO pool. Non-null.
 * @param selection_target  Target value in satoshis.
 * @param change_target     Minimum change amount.
 * @param max_weight        Maximum selection weight.
 * @param status            Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_select_coins_coingrinder(
    btccs_UtxoPool* pool,
    btccs_Amount selection_target,
    btccs_Amount change_target,
    int max_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Select coins using Knapsack (legacy randomized solver).
 *
 * @param pool           UTXO pool. Non-null.
 * @param target_value   Target value in satoshis.
 * @param change_target  Minimum change amount.
 * @param rng            Random context. Non-null.
 * @param max_weight     Maximum selection weight.
 * @param status         Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_select_coins_knapsack(
    btccs_UtxoPool* pool,
    btccs_Amount target_value,
    btccs_Amount change_target,
    btccs_RandomContext* rng,
    int max_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1, 4);

/* ========================================================================== */
/*                      Full Coin Selection (SelectCoins)                      */
/* ========================================================================== */

/**
 * @brief Perform full coin selection using the wallet's algorithm.
 *
 * This is the main entry point that:
 * - Uses pre-selected inputs if provided
 * - Calls AutomaticCoinSelection if more inputs are needed
 * - Tries multiple eligibility filters
 * - Picks the best result based on waste metric
 *
 * @param source            Chain interface for ancestry/bump fees. Non-null.
 * @param options           Selection options.
 * @param available_coins   Available coins to select from. Non-null.
 * @param pre_set_inputs    Pre-selected inputs (may be empty). Non-null.
 * @param target_value      Target amount in satoshis.
 * @param coin_control      Coin control settings. Non-null.
 * @param params            Selection parameters. Non-null.
 * @param status            Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_select_coins(
    btccs_CoinSelectionSource* source,
    btccs_CoinSelectionOptions options,
    btccs_CoinsResult* available_coins,
    btccs_PreSelectedInputs* pre_set_inputs,
    btccs_Amount target_value,
    btccs_CoinControl* coin_control,
    btccs_CoinSelectionParams* params,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1, 3, 4, 6, 7);

/**
 * @brief Perform automatic coin selection without pre-selected inputs.
 *
 * Simplified version of btccs_select_coins for cases without manual selection.
 *
 * @param source            Chain interface. Non-null.
 * @param options           Selection options.
 * @param available_coins   Available coins. Non-null.
 * @param target_value      Target amount in satoshis.
 * @param params            Selection parameters. Non-null.
 * @param status            Output status code. May be NULL.
 * @return Selection result, or NULL on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_automatic_coin_selection(
    btccs_CoinSelectionSource* source,
    btccs_CoinSelectionOptions options,
    btccs_CoinsResult* available_coins,
    btccs_Amount target_value,
    btccs_CoinSelectionParams* params,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(1, 3, 5);

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

/** Get the waste metric. */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_waste(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/** Get total weight of selected inputs. */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_weight(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/** Get algorithm used for selection. */
BITCOINCOINSELECTION_API btccs_SelectionAlgorithm BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_algorithm(const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the change amount.
 * @param result          Selection result. Non-null.
 * @param min_viable_change Minimum viable change.
 * @param change_fee      Fee for creating change.
 * @return Change amount, or 0 if no change.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_selection_result_get_change(
    const btccs_SelectionResult* result,
    btccs_Amount min_viable_change,
    btccs_Amount change_fee) BITCOINCOINSELECTION_ARG_NONNULL(1);

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
 * @brief Calculate cost of change output.
 * @param feerate_sat_per_kvb Feerate in sat/kvB.
 * @param change_output_size  Change output size (31 for P2WPKH).
 * @param change_spend_size   Change spend size (68 for P2WPKH).
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_calculate_cost_of_change(
    int64_t feerate_sat_per_kvb,
    size_t change_output_size,
    size_t change_spend_size);

/**
 * @brief Calculate cost of change output with custom discard feerate.
 * @param feerate_sat_per_kvb         Feerate in sat/kvB.
 * @param discard_feerate_sat_per_kvb Discard feerate in sat/kvB.
 * @param change_output_size          Change output size (31 for P2WPKH).
 * @param change_spend_size           Change spend size (68 for P2WPKH).
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT
btccs_calculate_cost_of_change_ex(
    int64_t feerate_sat_per_kvb,
    int64_t discard_feerate_sat_per_kvb,
    size_t change_output_size,
    size_t change_spend_size);

/**
 * @brief Generate randomized change target for privacy.
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

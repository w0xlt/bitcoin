// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H
#define BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H

#ifndef __cplusplus
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif // __cplusplus

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

/* Warning attributes */
#if defined(__GNUC__)
    #define BITCOINCOINSELECTION_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
    #define BITCOINCOINSELECTION_WARN_UNUSED_RESULT
#endif

/**
 * BITCOINCOINSELECTION_ARG_NONNULL is a compiler attribute used to indicate that
 * certain pointer arguments to a function are not expected to be null.
 */
#if !defined(BITCOINCOINSELECTION_BUILD) && defined(__GNUC__)
    #define BITCOINCOINSELECTION_ARG_NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
    #define BITCOINCOINSELECTION_ARG_NONNULL(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @page remarks Remarks
 *
 * @section purpose Purpose
 *
 * This header exposes an API for Bitcoin Core's coin selection algorithms.
 * Users can select coins from a UTXO pool using various algorithms including
 * Branch and Bound (BnB), Single Random Draw (SRD), CoinGrinder, and Knapsack.
 *
 * @section error Error handling
 *
 * Functions communicate an error through their return types, usually returning
 * a nullptr, 0, or false if an error is encountered. Additionally, selection
 * functions may communicate more detailed error information through status
 * code out parameters.
 *
 * @section pointer Pointer and argument conventions
 *
 * The user is responsible for de-allocating the memory owned by pointers
 * returned by functions. Typically pointers returned by *_create(...) functions
 * can be de-allocated by corresponding *_destroy(...) functions.
 */

/* ========================================================================== */
/*                              Type Definitions                               */
/* ========================================================================== */

/**
 * Signed 64-bit integer representing a Bitcoin amount in satoshis.
 * This is equivalent to CAmount in Bitcoin Core.
 */
typedef int64_t btccs_Amount;

/**
 * Opaque data structure for holding a transaction outpoint (txid + vout index).
 */
typedef struct btccs_OutPoint btccs_OutPoint;

/**
 * Opaque data structure for holding a transaction output.
 * Contains the value (amount) and scriptPubKey.
 */
typedef struct btccs_TxOut btccs_TxOut;

/**
 * Opaque data structure for holding a coin output.
 *
 * This represents an unspent transaction output (UTXO) with all metadata
 * required for coin selection, including the outpoint, txout, depth in chain,
 * estimated input size, fees, and spending eligibility information.
 */
typedef struct btccs_CoinOutput btccs_CoinOutput;

/**
 * Opaque data structure for holding an output group.
 *
 * An OutputGroup is a collection of UTXOs, typically grouped by script
 * (i.e., outputs sent to the same address). Grouping outputs helps with
 * privacy by avoiding partial spends of address clusters.
 */
typedef struct btccs_OutputGroup btccs_OutputGroup;

/**
 * Opaque data structure for holding the result of a coin selection.
 *
 * Contains the selected coins, total value, fees, waste metric, and
 * other metadata about the selection.
 */
typedef struct btccs_SelectionResult btccs_SelectionResult;

/**
 * Opaque data structure for holding coin selection parameters.
 *
 * Contains fee rates (effective and long-term), change output costs,
 * and other parameters that influence coin selection behavior.
 */
typedef struct btccs_CoinSelectionParams btccs_CoinSelectionParams;

/**
 * Opaque data structure for holding a random context.
 *
 * Used for algorithms that require randomness (SRD, Knapsack).
 */
typedef struct btccs_RandomContext btccs_RandomContext;

/* ========================================================================== */
/*                              Enumerations                                   */
/* ========================================================================== */

/**
 * Status codes for coin selection operations.
 */
typedef uint8_t btccs_SelectionStatus;
#define btccs_SelectionStatus_SUCCESS ((btccs_SelectionStatus)(0))
#define btccs_SelectionStatus_INSUFFICIENT_FUNDS ((btccs_SelectionStatus)(1))
#define btccs_SelectionStatus_MAX_WEIGHT_EXCEEDED ((btccs_SelectionStatus)(2))
#define btccs_SelectionStatus_NO_SOLUTION_FOUND ((btccs_SelectionStatus)(3))
#define btccs_SelectionStatus_INVALID_PARAMETER ((btccs_SelectionStatus)(4))
#define btccs_SelectionStatus_INTERNAL_ERROR ((btccs_SelectionStatus)(5))

/**
 * Coin selection algorithm identifiers.
 */
typedef uint8_t btccs_SelectionAlgorithm;
#define btccs_SelectionAlgorithm_BNB ((btccs_SelectionAlgorithm)(0))
#define btccs_SelectionAlgorithm_SRD ((btccs_SelectionAlgorithm)(1))
#define btccs_SelectionAlgorithm_COINGRINDER ((btccs_SelectionAlgorithm)(2))
#define btccs_SelectionAlgorithm_KNAPSACK ((btccs_SelectionAlgorithm)(3))
#define btccs_SelectionAlgorithm_MANUAL ((btccs_SelectionAlgorithm)(4))

/* ========================================================================== */
/*                          OutPoint Functions                                 */
/* ========================================================================== */

/** @name OutPoint
 * Functions for working with transaction outpoints.
 */
///@{

/**
 * @brief Create a new outpoint from txid and output index.
 *
 * @param[in] txid    The transaction id (32 bytes, little-endian).
 * @param[in] vout    The output index within the transaction.
 * @return            The created outpoint, or null on error.
 */
BITCOINCOINSELECTION_API btccs_OutPoint* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_outpoint_create(
    const unsigned char txid[32], uint32_t vout) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Copy an outpoint.
 *
 * @param[in] outpoint Non-null.
 * @return             The copied outpoint.
 */
BITCOINCOINSELECTION_API btccs_OutPoint* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_outpoint_copy(
    const btccs_OutPoint* outpoint) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the txid from an outpoint.
 *
 * @param[in] outpoint  Non-null.
 * @param[out] txid_out Buffer to receive the txid (32 bytes).
 */
BITCOINCOINSELECTION_API void btccs_outpoint_get_txid(
    const btccs_OutPoint* outpoint, unsigned char txid_out[32]) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * @brief Get the output index from an outpoint.
 *
 * @param[in] outpoint Non-null.
 * @return             The output index.
 */
BITCOINCOINSELECTION_API uint32_t BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_outpoint_get_vout(
    const btccs_OutPoint* outpoint) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Check if two outpoints are equal.
 *
 * @param[in] a Non-null.
 * @param[in] b Non-null.
 * @return      1 if equal, 0 otherwise.
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_outpoint_equals(
    const btccs_OutPoint* a, const btccs_OutPoint* b) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * Destroy an outpoint.
 */
BITCOINCOINSELECTION_API void btccs_outpoint_destroy(btccs_OutPoint* outpoint);

///@}

/* ========================================================================== */
/*                            TxOut Functions                                  */
/* ========================================================================== */

/** @name TxOut
 * Functions for working with transaction outputs.
 */
///@{

/**
 * @brief Create a new transaction output.
 *
 * @param[in] value             The output value in satoshis.
 * @param[in] script_pubkey     The scriptPubKey bytes.
 * @param[in] script_pubkey_len Length of the scriptPubKey.
 * @return                      The created txout, or null on error.
 */
BITCOINCOINSELECTION_API btccs_TxOut* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_txout_create(
    btccs_Amount value, const unsigned char* script_pubkey, size_t script_pubkey_len);

/**
 * @brief Copy a transaction output.
 *
 * @param[in] txout Non-null.
 * @return          The copied txout.
 */
BITCOINCOINSELECTION_API btccs_TxOut* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_txout_copy(
    const btccs_TxOut* txout) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the value of a transaction output.
 *
 * @param[in] txout Non-null.
 * @return          The value in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_txout_get_value(
    const btccs_TxOut* txout) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the scriptPubKey of a transaction output.
 *
 * @param[in] txout         Non-null.
 * @param[out] script_out   Buffer to receive the scriptPubKey (caller must allocate).
 * @param[in,out] script_len On input, size of buffer. On output, actual length.
 * @return                  0 on success, -1 if buffer too small.
 */
BITCOINCOINSELECTION_API int btccs_txout_get_script_pubkey(
    const btccs_TxOut* txout, unsigned char* script_out, size_t* script_len) BITCOINCOINSELECTION_ARG_NONNULL(1, 3);

/**
 * Destroy a transaction output.
 */
BITCOINCOINSELECTION_API void btccs_txout_destroy(btccs_TxOut* txout);

///@}

/* ========================================================================== */
/*                         CoinOutput Functions                                */
/* ========================================================================== */

/** @name CoinOutput
 * Functions for working with coin outputs (UTXOs).
 */
///@{

/**
 * @brief Create a new coin output with all metadata.
 *
 * @param[in] outpoint       The outpoint identifying this UTXO. Non-null.
 * @param[in] txout          The transaction output. Non-null.
 * @param[in] depth          Confirmation depth (0 for unconfirmed).
 * @param[in] input_bytes    Estimated size in bytes when spent as an input.
 *                           Use -1 if unknown.
 * @param[in] spendable      Whether the output is spendable (keys available).
 * @param[in] solvable       Whether we know how to spend this output.
 * @param[in] safe           Whether this is a safe output to spend (not from
 *                           conflicting/replaceable unconfirmed tx).
 * @param[in] time           Time the output was received.
 * @param[in] from_me        Whether this output is from our own wallet.
 * @param[in] fee            The fee paid when this output is spent (at current feerate).
 * @param[in] long_term_fee  The fee paid when spent (at long-term feerate).
 * @return                   The created coin output, or null on error.
 */
BITCOINCOINSELECTION_API btccs_CoinOutput* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_create(
    const btccs_OutPoint* outpoint,
    const btccs_TxOut* txout,
    int depth,
    int input_bytes,
    int spendable,
    int solvable,
    int safe,
    int64_t time,
    int from_me,
    btccs_Amount fee,
    btccs_Amount long_term_fee) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * @brief Create a simple coin output with minimal parameters.
 *
 * This is a convenience function for creating coin outputs when only
 * basic information is available.
 *
 * @param[in] outpoint    The outpoint identifying this UTXO. Non-null.
 * @param[in] txout       The transaction output. Non-null.
 * @param[in] depth       Confirmation depth.
 * @param[in] input_bytes Estimated input size in bytes.
 * @return                The created coin output, or null on error.
 */
BITCOINCOINSELECTION_API btccs_CoinOutput* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_create_simple(
    const btccs_OutPoint* outpoint,
    const btccs_TxOut* txout,
    int depth,
    int input_bytes) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * @brief Copy a coin output.
 *
 * @param[in] coin Non-null.
 * @return         The copied coin output.
 */
BITCOINCOINSELECTION_API btccs_CoinOutput* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_copy(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the outpoint of a coin output.
 *
 * @param[in] coin Non-null.
 * @return         The outpoint (unowned, valid for lifetime of coin).
 */
BITCOINCOINSELECTION_API const btccs_OutPoint* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_get_outpoint(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the txout of a coin output.
 *
 * @param[in] coin Non-null.
 * @return         The txout (unowned, valid for lifetime of coin).
 */
BITCOINCOINSELECTION_API const btccs_TxOut* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_get_txout(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the value of a coin output in satoshis.
 *
 * @param[in] coin Non-null.
 * @return         The value in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_get_value(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the effective value of a coin output.
 *
 * Effective value = nominal value - fee to spend the output.
 *
 * @param[in] coin Non-null.
 * @return         The effective value in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_get_effective_value(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the confirmation depth of a coin output.
 *
 * @param[in] coin Non-null.
 * @return         The confirmation depth (0 for unconfirmed).
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_get_depth(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the input bytes estimate for a coin output.
 *
 * @param[in] coin Non-null.
 * @return         The estimated input size in bytes, or -1 if unknown.
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_get_input_bytes(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the fee for spending this coin output.
 *
 * @param[in] coin Non-null.
 * @return         The fee in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_get_fee(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the long-term fee for spending this coin output.
 *
 * @param[in] coin Non-null.
 * @return         The long-term fee in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_get_long_term_fee(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Check if a coin output is spendable.
 *
 * @param[in] coin Non-null.
 * @return         1 if spendable, 0 otherwise.
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_is_spendable(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Check if a coin output is safe to spend.
 *
 * @param[in] coin Non-null.
 * @return         1 if safe, 0 otherwise.
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_output_is_safe(
    const btccs_CoinOutput* coin) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Set the fees for a coin output.
 *
 * @param[in] coin          Non-null.
 * @param[in] fee           The fee at current feerate.
 * @param[in] long_term_fee The fee at long-term feerate.
 */
BITCOINCOINSELECTION_API void btccs_coin_output_set_fees(
    btccs_CoinOutput* coin, btccs_Amount fee, btccs_Amount long_term_fee) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * Destroy a coin output.
 */
BITCOINCOINSELECTION_API void btccs_coin_output_destroy(btccs_CoinOutput* coin);

///@}

/* ========================================================================== */
/*                        OutputGroup Functions                                */
/* ========================================================================== */

/** @name OutputGroup
 * Functions for working with output groups.
 */
///@{

/**
 * @brief Create a new empty output group.
 *
 * @return The created output group, or null on error.
 */
BITCOINCOINSELECTION_API btccs_OutputGroup* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_create(void);

/**
 * @brief Copy an output group.
 *
 * @param[in] group Non-null.
 * @return          The copied output group.
 */
BITCOINCOINSELECTION_API btccs_OutputGroup* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_copy(
    const btccs_OutputGroup* group) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Insert a coin output into an output group.
 *
 * @param[in] group       Non-null.
 * @param[in] coin        The coin to insert. Non-null. A copy is made.
 * @param[in] ancestors   Number of unconfirmed ancestors.
 * @param[in] descendants Number of unconfirmed descendants.
 */
BITCOINCOINSELECTION_API void btccs_output_group_insert(
    btccs_OutputGroup* group,
    const btccs_CoinOutput* coin,
    size_t ancestors,
    size_t descendants) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * @brief Get the number of coins in an output group.
 *
 * @param[in] group Non-null.
 * @return          The number of coins.
 */
BITCOINCOINSELECTION_API size_t BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_size(
    const btccs_OutputGroup* group) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get a coin from an output group by index.
 *
 * @param[in] group Non-null.
 * @param[in] index The index of the coin.
 * @return          The coin (unowned, valid for lifetime of group), or null if out of bounds.
 */
BITCOINCOINSELECTION_API const btccs_CoinOutput* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_get_coin_at(
    const btccs_OutputGroup* group, size_t index) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the total value of an output group.
 *
 * @param[in] group Non-null.
 * @return          The total value in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_get_value(
    const btccs_OutputGroup* group) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the selection amount of an output group.
 *
 * This returns the effective value used for coin selection.
 *
 * @param[in] group Non-null.
 * @return          The selection amount in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_get_selection_amount(
    const btccs_OutputGroup* group) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the total fee of an output group.
 *
 * @param[in] group Non-null.
 * @return          The total fee in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_get_fee(
    const btccs_OutputGroup* group) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the total long-term fee of an output group.
 *
 * @param[in] group Non-null.
 * @return          The total long-term fee in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_get_long_term_fee(
    const btccs_OutputGroup* group) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the weight of an output group.
 *
 * @param[in] group Non-null.
 * @return          The weight in weight units.
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_get_weight(
    const btccs_OutputGroup* group) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Check if an output group is eligible for selection.
 *
 * @param[in] group               Non-null.
 * @param[in] required_confirms   Required confirmation depth.
 * @param[in] max_ancestors       Maximum allowed unconfirmed ancestors.
 * @param[in] max_descendants     Maximum allowed unconfirmed descendants.
 * @return                        1 if eligible, 0 otherwise.
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_output_group_is_eligible(
    const btccs_OutputGroup* group,
    int required_confirms,
    size_t max_ancestors,
    size_t max_descendants) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * Destroy an output group.
 */
BITCOINCOINSELECTION_API void btccs_output_group_destroy(btccs_OutputGroup* group);

///@}

/* ========================================================================== */
/*                    CoinSelectionParams Functions                            */
/* ========================================================================== */

/** @name CoinSelectionParams
 * Functions for working with coin selection parameters.
 */
///@{

/**
 * @brief Create coin selection parameters.
 *
 * @param[in] effective_feerate_sat_per_kvb  Effective fee rate in sat/kvB.
 * @param[in] long_term_feerate_sat_per_kvb  Long-term fee rate in sat/kvB.
 * @param[in] discard_feerate_sat_per_kvb    Discard fee rate in sat/kvB.
 * @param[in] change_output_size             Size of a change output in bytes.
 * @param[in] change_spend_size              Size of spending a change output in bytes.
 * @param[in] min_viable_change              Minimum viable change amount in satoshis.
 * @param[in] tx_noinputs_size               Base transaction size without inputs.
 * @param[in] avoid_partial_spends           Whether to avoid partial address spends.
 * @return                                   The created parameters, or null on error.
 */
BITCOINCOINSELECTION_API btccs_CoinSelectionParams* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_selection_params_create(
    int64_t effective_feerate_sat_per_kvb,
    int64_t long_term_feerate_sat_per_kvb,
    int64_t discard_feerate_sat_per_kvb,
    size_t change_output_size,
    size_t change_spend_size,
    btccs_Amount min_viable_change,
    size_t tx_noinputs_size,
    int avoid_partial_spends);

/**
 * @brief Create coin selection parameters with default values.
 *
 * Uses default fee rates and standard P2WPKH sizes.
 *
 * @param[in] effective_feerate_sat_per_kvb Effective fee rate in sat/kvB.
 * @return                                  The created parameters, or null on error.
 */
BITCOINCOINSELECTION_API btccs_CoinSelectionParams* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_selection_params_create_default(
    int64_t effective_feerate_sat_per_kvb);

/**
 * @brief Copy coin selection parameters.
 *
 * @param[in] params Non-null.
 * @return           The copied parameters.
 */
BITCOINCOINSELECTION_API btccs_CoinSelectionParams* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_selection_params_copy(
    const btccs_CoinSelectionParams* params) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the cost of change.
 *
 * This is the cost to create and later spend a change output.
 *
 * @param[in] params Non-null.
 * @return           The cost of change in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_selection_params_get_cost_of_change(
    const btccs_CoinSelectionParams* params) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the change fee.
 *
 * This is the fee for adding a change output to the transaction.
 *
 * @param[in] params Non-null.
 * @return           The change fee in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_coin_selection_params_get_change_fee(
    const btccs_CoinSelectionParams* params) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Set whether to subtract fee from outputs.
 *
 * @param[in] params                Non-null.
 * @param[in] subtract_fee_outputs  1 to subtract fee from outputs, 0 otherwise.
 */
BITCOINCOINSELECTION_API void btccs_coin_selection_params_set_subtract_fee_outputs(
    btccs_CoinSelectionParams* params, int subtract_fee_outputs) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * Destroy coin selection parameters.
 */
BITCOINCOINSELECTION_API void btccs_coin_selection_params_destroy(btccs_CoinSelectionParams* params);

///@}

/* ========================================================================== */
/*                       RandomContext Functions                               */
/* ========================================================================== */

/** @name RandomContext
 * Functions for working with random contexts.
 */
///@{

/**
 * @brief Create a new random context.
 *
 * Creates a cryptographically secure random context.
 *
 * @return The created random context, or null on error.
 */
BITCOINCOINSELECTION_API btccs_RandomContext* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_random_context_create(void);

/**
 * @brief Create a random context with a specific seed.
 *
 * Useful for deterministic testing.
 *
 * @param[in] seed The 256-bit seed (32 bytes).
 * @return         The created random context, or null on error.
 */
BITCOINCOINSELECTION_API btccs_RandomContext* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_random_context_create_seeded(
    const unsigned char seed[32]) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * Destroy a random context.
 */
BITCOINCOINSELECTION_API void btccs_random_context_destroy(btccs_RandomContext* rng);

///@}

/* ========================================================================== */
/*                      SelectionResult Functions                              */
/* ========================================================================== */

/** @name SelectionResult
 * Functions for working with selection results.
 */
///@{

/**
 * @brief Create an empty selection result.
 *
 * @param[in] target    The target amount in satoshis.
 * @param[in] algorithm The algorithm used for selection.
 * @return              The created selection result, or null on error.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_create(
    btccs_Amount target, btccs_SelectionAlgorithm algorithm);

/**
 * @brief Copy a selection result.
 *
 * @param[in] result Non-null.
 * @return           The copied selection result.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_copy(
    const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Add an output group to a selection result.
 *
 * @param[in] result Non-null.
 * @param[in] group  The group to add. Non-null.
 */
BITCOINCOINSELECTION_API void btccs_selection_result_add_input(
    btccs_SelectionResult* result, const btccs_OutputGroup* group) BITCOINCOINSELECTION_ARG_NONNULL(1, 2);

/**
 * @brief Get the number of selected coins.
 *
 * @param[in] result Non-null.
 * @return           The number of selected coins.
 */
BITCOINCOINSELECTION_API size_t BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_input_count(
    const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get a selected coin by index.
 *
 * @param[in] result Non-null.
 * @param[in] index  The index of the coin.
 * @return           The coin (unowned), or null if out of bounds.
 */
BITCOINCOINSELECTION_API const btccs_CoinOutput* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_input_at(
    const btccs_SelectionResult* result, size_t index) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the total selected value.
 *
 * @param[in] result Non-null.
 * @return           The total value in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_selected_value(
    const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the total selected effective value.
 *
 * @param[in] result Non-null.
 * @return           The total effective value in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_selected_effective_value(
    const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the target amount.
 *
 * @param[in] result Non-null.
 * @return           The target amount in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_target(
    const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the waste metric of the selection.
 *
 * @param[in] result Non-null.
 * @return           The waste in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_waste(
    const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the change amount.
 *
 * @param[in] result            Non-null.
 * @param[in] cost_of_change    The cost of creating and spending change.
 * @param[in] change_fee        The fee for the change output.
 * @return                      The change amount in satoshis (0 if changeless).
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_change(
    const btccs_SelectionResult* result, btccs_Amount cost_of_change, btccs_Amount change_fee) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the total weight of selected inputs.
 *
 * @param[in] result Non-null.
 * @return           The weight in weight units.
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_weight(
    const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Get the algorithm used for this selection.
 *
 * @param[in] result Non-null.
 * @return           The algorithm identifier.
 */
BITCOINCOINSELECTION_API btccs_SelectionAlgorithm BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_selection_result_get_algorithm(
    const btccs_SelectionResult* result) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * @brief Recalculate the waste metric.
 *
 * @param[in] result            Non-null.
 * @param[in] min_viable_change Minimum viable change amount.
 * @param[in] change_cost       Cost of creating and spending change.
 * @param[in] change_fee        Fee for the change output.
 */
BITCOINCOINSELECTION_API void btccs_selection_result_recalculate_waste(
    btccs_SelectionResult* result,
    btccs_Amount min_viable_change,
    btccs_Amount change_cost,
    btccs_Amount change_fee) BITCOINCOINSELECTION_ARG_NONNULL(1);

/**
 * Destroy a selection result.
 */
BITCOINCOINSELECTION_API void btccs_selection_result_destroy(btccs_SelectionResult* result);

///@}

/* ========================================================================== */
/*                     Coin Selection Algorithms                               */
/* ========================================================================== */

/** @name Selection Algorithms
 * Coin selection algorithm functions.
 */
///@{

/**
 * @brief Select coins using Branch and Bound algorithm.
 *
 * This algorithm searches for an exact match (changeless solution) to minimize
 * fees. It is most effective when there are UTXOs that can exactly match the
 * target amount plus fees.
 *
 * @param[in] utxo_pool          Array of output groups to select from.
 * @param[in] utxo_pool_size     Number of output groups.
 * @param[in] selection_target   Target amount in satoshis (effective value).
 * @param[in] cost_of_change     Cost of creating and spending a change output.
 * @param[in] max_selection_weight Maximum allowed weight for the selection.
 * @param[out] status            Output status code. May be null.
 * @return                       The selection result, or null on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_select_coins_bnb(
    btccs_OutputGroup* const* utxo_pool,
    size_t utxo_pool_size,
    btccs_Amount selection_target,
    btccs_Amount cost_of_change,
    int max_selection_weight,
    btccs_SelectionStatus* status);

/**
 * @brief Select coins using Single Random Draw algorithm.
 *
 * This algorithm randomly shuffles UTXOs and selects them until the target is
 * met. It's simple and fast but may not produce optimal results.
 *
 * @param[in] utxo_pool          Array of output groups to select from.
 * @param[in] utxo_pool_size     Number of output groups.
 * @param[in] target_value       Target amount in satoshis.
 * @param[in] change_fee         Fee for the change output.
 * @param[in] rng                Random context for shuffling. Non-null.
 * @param[in] max_selection_weight Maximum allowed weight for the selection.
 * @param[out] status            Output status code. May be null.
 * @return                       The selection result, or null on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_select_coins_srd(
    const btccs_OutputGroup* const* utxo_pool,
    size_t utxo_pool_size,
    btccs_Amount target_value,
    btccs_Amount change_fee,
    btccs_RandomContext* rng,
    int max_selection_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(5);

/**
 * @brief Select coins using CoinGrinder algorithm.
 *
 * This algorithm minimizes the input set weight, which is useful at high fee
 * rates to minimize transaction fees. It always produces a change output.
 *
 * @param[in] utxo_pool          Array of output groups to select from.
 * @param[in] utxo_pool_size     Number of output groups.
 * @param[in] selection_target   Target amount in satoshis.
 * @param[in] change_target      Minimum change amount.
 * @param[in] max_selection_weight Maximum allowed weight for the selection.
 * @param[out] status            Output status code. May be null.
 * @return                       The selection result, or null on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_select_coins_coingrinder(
    btccs_OutputGroup* const* utxo_pool,
    size_t utxo_pool_size,
    btccs_Amount selection_target,
    btccs_Amount change_target,
    int max_selection_weight,
    btccs_SelectionStatus* status);

/**
 * @brief Select coins using Knapsack algorithm.
 *
 * This is the legacy coin selection algorithm that uses randomized subset sum
 * approximation. It tries to find a good solution but may not be optimal.
 *
 * @param[in] groups             Array of output groups to select from.
 * @param[in] groups_size        Number of output groups.
 * @param[in] target_value       Target amount in satoshis.
 * @param[in] change_target      Minimum change amount.
 * @param[in] rng                Random context. Non-null.
 * @param[in] max_selection_weight Maximum allowed weight for the selection.
 * @param[out] status            Output status code. May be null.
 * @return                       The selection result, or null on failure.
 */
BITCOINCOINSELECTION_API btccs_SelectionResult* BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_select_coins_knapsack(
    btccs_OutputGroup* const* groups,
    size_t groups_size,
    btccs_Amount target_value,
    btccs_Amount change_target,
    btccs_RandomContext* rng,
    int max_selection_weight,
    btccs_SelectionStatus* status) BITCOINCOINSELECTION_ARG_NONNULL(5);

///@}

/* ========================================================================== */
/*                         Utility Functions                                   */
/* ========================================================================== */

/** @name Utility Functions
 * Helper functions for coin selection.
 */
///@{

/**
 * @brief Generate a random change target.
 *
 * Adds randomness to the change output amount to make it harder to
 * fingerprint the wallet.
 *
 * @param[in] payment_value The payment amount in satoshis.
 * @param[in] change_fee    The fee for the change output.
 * @param[in] rng           Random context. Non-null.
 * @return                  A randomized change target.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_generate_change_target(
    btccs_Amount payment_value, btccs_Amount change_fee, btccs_RandomContext* rng) BITCOINCOINSELECTION_ARG_NONNULL(3);

/**
 * @brief Calculate the waste metric for a given selection.
 *
 * Waste = fee difference from long-term + excess (if changeless) or
 *         change cost (if creating change).
 *
 * @param[in] inputs                Array of coin outputs. Non-null.
 * @param[in] inputs_count          Number of inputs.
 * @param[in] change_cost           Cost of creating and spending change.
 * @param[in] target                Target amount.
 * @param[in] use_effective_value   Whether to use effective values.
 * @return                          The waste metric in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_calculate_waste(
    const btccs_CoinOutput* const* inputs,
    size_t inputs_count,
    btccs_Amount change_cost,
    btccs_Amount target,
    int use_effective_value);

/**
 * @brief Calculate the fee for spending inputs.
 *
 * @param[in] inputs       Array of coin outputs. Non-null.
 * @param[in] inputs_count Number of inputs.
 * @return                 Total fee in satoshis.
 */
BITCOINCOINSELECTION_API btccs_Amount BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_calculate_input_fee(
    const btccs_CoinOutput* const* inputs, size_t inputs_count);

/**
 * @brief Get the maximum standard transaction weight.
 *
 * @return The maximum weight in weight units (400,000).
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_get_max_standard_tx_weight(void);

/**
 * @brief Calculate the input weight for a given input size.
 *
 * @param[in] input_bytes Input size in bytes.
 * @return                Input weight in weight units.
 */
BITCOINCOINSELECTION_API int BITCOINCOINSELECTION_WARN_UNUSED_RESULT btccs_get_input_weight(int input_bytes);

/**
 * @brief Get the version string for the library.
 *
 * @return The version string.
 */
BITCOINCOINSELECTION_API const char* btccs_version(void);

///@}

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSELECTION_BITCOINCOINSELECTION_WRAPPER_H
#define BITCOIN_COINSELECTION_BITCOINCOINSELECTION_WRAPPER_H

/**
 * @file bitcoincoinselection_wrapper.h
 * @brief C++ API for Bitcoin Core coin selection algorithms
 *
 * This header provides a clean C++ interface that directly uses Bitcoin Core
 * types (wallet::OutputGroup, wallet::SelectionResult) with RAII wrappers
 * for convenient resource management.
 */

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>
#include <util/result.h>
#include <wallet/coinselection.h>

#include <array>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace btccs {

// ==========================================================================
// Type Aliases - Use Bitcoin Core types directly
// ==========================================================================

using Amount = CAmount;
using FeeRate = CFeeRate;

// Re-export Bitcoin Core wallet types for convenience
using COutput = wallet::COutput;
using OutputGroup = wallet::OutputGroup;
using SelectionResult = wallet::SelectionResult;

// ==========================================================================
// Enums
// ==========================================================================

enum class SelectionStatus : uint8_t {
    SUCCESS = 0,
    INSUFFICIENT_FUNDS = 1,
    MAX_WEIGHT_EXCEEDED = 2,
    NO_SOLUTION_FOUND = 3,
    INVALID_PARAMETER = 4,
    INTERNAL_ERROR = 5
};

enum class SelectionAlgorithm : uint8_t {
    BNB = 0,
    SRD = 1,
    COINGRINDER = 2,
    KNAPSACK = 3,
    MANUAL = 4
};

// ==========================================================================
// Exception
// ==========================================================================

class CoinSelectionError : public std::runtime_error {
public:
    explicit CoinSelectionError(const std::string& msg,
                                SelectionStatus status = SelectionStatus::INTERNAL_ERROR)
        : std::runtime_error(msg), m_status(status) {}

    SelectionStatus status() const { return m_status; }

private:
    SelectionStatus m_status;
};

// ==========================================================================
// CoinSelectionParams - Fee calculation helper
// ==========================================================================

// From src/wallet/wallet.h
static const CAmount DEFAULT_CONSOLIDATE_FEERATE{10000}; // 10 sat/vB

/**
 * @brief Helper class for calculating coin selection parameters.
 *
 * This provides convenient calculation of change costs and fees
 * based on feerates and output sizes. Required for accurate waste
 * calculation using Bitcoin Core's RecalculateWaste().
 *
 * Example usage:
 * @code
 *   // Simple construction with just effective feerate
 *   CoinSelectionParams params(10000); // 10 sat/vB
 *
 *   // Or with explicit control
 *   CoinSelectionParams params(
 *       CFeeRate(10000),                    // effective feerate
 *       CFeeRate(DEFAULT_CONSOLIDATE_FEERATE), // long-term feerate (10 sat/vB)
 *       CFeeRate(DUST_RELAY_TX_FEE),        // discard feerate (3 sat/vB)
 *       31,                                 // change output size (P2WPKH)
 *       68                                  // change spend size (P2WPKH)
 *   );
 *
 *   // Use with selection
 *   auto result = pool.SelectBnB(target, params);
 * @endcode
 */
class CoinSelectionParams {
public:
    /**
     * @brief Create parameters with explicit sizes and feerates.
     *
     * @param effective_feerate  Current transaction feerate.
     * @param long_term_feerate  Long-term expected feerate for consolidation.
     * @param discard_feerate    Minimum feerate for dust threshold.
     * @param change_output_size Size of change output (31 for P2WPKH).
     * @param change_spend_size  Size of spending change (68 for P2WPKH).
     */
    CoinSelectionParams(FeeRate effective_feerate,
                        FeeRate long_term_feerate,
                        FeeRate discard_feerate,
                        size_t change_output_size = 31,
                        size_t change_spend_size = 68)
        : m_effective_feerate(effective_feerate)
        , m_long_term_feerate(long_term_feerate)
        , m_discard_feerate(discard_feerate)
        , m_change_output_size(change_output_size)
        , m_change_spend_size(change_spend_size)
    {}

    /**
     * @brief Create parameters with just the effective feerate.
     *
     * Uses Bitcoin Core defaults:
     * - Long-term feerate = DEFAULT_CONSOLIDATE_FEERATE (10 sat/vB)
     * - Discard feerate = DUST_RELAY_TX_FEE (3 sat/vB)
     * - P2WPKH sizes (31 bytes output, 68 bytes spend)
     */
    explicit CoinSelectionParams(FeeRate effective_feerate)
        : m_effective_feerate(effective_feerate)
        , m_long_term_feerate(DEFAULT_CONSOLIDATE_FEERATE)
        , m_discard_feerate(DUST_RELAY_TX_FEE)
        , m_change_output_size(31)
        , m_change_spend_size(68)
    {}

    /**
     * @brief Create parameters from sat/kvB value.
     */
    explicit CoinSelectionParams(int64_t effective_feerate_sat_per_kvb)
        : CoinSelectionParams(FeeRate(effective_feerate_sat_per_kvb))
    {}

    /** Fee for creating the change output at current feerate. */
    Amount GetChangeFee() const
    {
        return m_effective_feerate.GetFee(m_change_output_size);
    }

    /** Total cost of change (creation + future spend at discard rate). */
    Amount GetCostOfChange() const
    {
        return GetChangeFee() + m_discard_feerate.GetFee(m_change_spend_size);
    }

    /**
     * @brief Get minimum viable change amount.
     *
     * Returns a value that ensures change is worth creating.
     * Typically the cost of spending the change output.
     */
    Amount GetMinViableChange() const
    {
        return m_discard_feerate.GetFee(m_change_spend_size);
    }

    /** Calculate fee for an input of given size. */
    Amount GetInputFee(int input_bytes) const
    {
        return m_effective_feerate.GetFee(input_bytes);
    }

    /** Calculate long-term fee for an input. */
    Amount GetInputLongTermFee(int input_bytes) const
    {
        return m_long_term_feerate.GetFee(input_bytes);
    }

    // Accessors
    const FeeRate& EffectiveFeeRate() const { return m_effective_feerate; }
    const FeeRate& LongTermFeeRate() const { return m_long_term_feerate; }
    const FeeRate& DiscardFeeRate() const { return m_discard_feerate; }
    size_t ChangeOutputSize() const { return m_change_output_size; }
    size_t ChangeSpendSize() const { return m_change_spend_size; }

private:
    FeeRate m_effective_feerate;
    FeeRate m_long_term_feerate;
    FeeRate m_discard_feerate;
    size_t m_change_output_size;
    size_t m_change_spend_size;
};

// ==========================================================================
// UtxoPool - Builder for creating a pool of UTXOs
// ==========================================================================

/**
 * @brief A builder class for creating UTXO pools for coin selection.
 *
 * Example usage:
 * @code
 *   CoinSelectionParams params(10000); // 10 sat/vB
 *
 *   UtxoPool pool;
 *   pool.Add(txid1, 0, 100000, 68, 6, params);
 *   pool.Add(txid2, 1, 250000, 68, 3, params);
 *
 *   auto result = pool.SelectBnB(target, params);
 *   if (result) {
 *       // Use result->GetWaste() for the full waste metric
 *   }
 * @endcode
 */
class UtxoPool {
public:
    UtxoPool() = default;

    /**
     * @brief Add a UTXO to the pool with explicit fee values.
     *
     * @param txid          Transaction ID (32 bytes).
     * @param vout          Output index.
     * @param value         Output value in satoshis.
     * @param input_bytes   Estimated input size when spent (68 for P2WPKH).
     * @param depth         Confirmation depth (0 = unconfirmed).
     * @param fee           Fee at current feerate.
     * @param long_term_fee Fee at long-term feerate.
     * @return Reference to this pool for chaining.
     */
    UtxoPool& Add(const std::array<unsigned char, 32>& txid,
                  uint32_t vout,
                  Amount value,
                  int input_bytes,
                  int depth,
                  Amount fee,
                  Amount long_term_fee)
    {
        uint256 hash;
        std::memcpy(hash.begin(), txid.data(), 32);
        COutPoint outpoint(Txid::FromUint256(hash), vout);

        CTxOut txout(value, CScript());
        auto coin = std::make_shared<COutput>(
            outpoint, txout, depth, input_bytes,
            /*solvable=*/true, /*safe=*/true, /*time=*/0, /*from_me=*/false, fee);
        coin->long_term_fee = long_term_fee;

        OutputGroup group;
        group.Insert(coin, 0, 0);
        m_groups.push_back(std::move(group));

        return *this;
    }

    /**
     * @brief Add a UTXO using CoinSelectionParams for fee calculation.
     *
     * @param txid         Transaction ID.
     * @param vout         Output index.
     * @param value        Output value in satoshis.
     * @param input_bytes  Estimated input size (68 for P2WPKH).
     * @param depth        Confirmation depth.
     * @param params       Coin selection parameters for fee calculation.
     * @return Reference to this pool for chaining.
     */
    UtxoPool& Add(const std::array<unsigned char, 32>& txid,
                  uint32_t vout,
                  Amount value,
                  int input_bytes,
                  int depth,
                  const CoinSelectionParams& params)
    {
        return Add(txid, vout, value, input_bytes, depth,
                   params.GetInputFee(input_bytes),
                   params.GetInputLongTermFee(input_bytes));
    }

    /**
     * @brief Add a UTXO using explicit feerates.
     *
     * @param txid         Transaction ID.
     * @param vout         Output index.
     * @param value        Output value in satoshis.
     * @param input_bytes  Estimated input size (68 for P2WPKH).
     * @param depth        Confirmation depth.
     * @param feerate      Current feerate.
     * @param lt_feerate   Long-term feerate (optional, defaults to DEFAULT_CONSOLIDATE_FEERATE).
     * @return Reference to this pool for chaining.
     */
    UtxoPool& Add(const std::array<unsigned char, 32>& txid,
                  uint32_t vout,
                  Amount value,
                  int input_bytes,
                  int depth,
                  const FeeRate& feerate,
                  std::optional<FeeRate> lt_feerate = std::nullopt)
    {
        Amount fee = feerate.GetFee(input_bytes);
        Amount lt_fee = lt_feerate ? lt_feerate->GetFee(input_bytes)
                                   : FeeRate(DEFAULT_CONSOLIDATE_FEERATE).GetFee(input_bytes);
        return Add(txid, vout, value, input_bytes, depth, fee, lt_fee);
    }

    /**
     * @brief Add an existing OutputGroup to the pool.
     */
    UtxoPool& AddGroup(OutputGroup group)
    {
        m_groups.push_back(std::move(group));
        return *this;
    }

    /** Get the number of groups in the pool. */
    size_t Size() const { return m_groups.size(); }

    /** Check if pool is empty. */
    bool Empty() const { return m_groups.empty(); }

    /** Clear all UTXOs from the pool. */
    void Clear() { m_groups.clear(); }

    /** Get direct access to the groups (for advanced use). */
    std::vector<OutputGroup>& Groups() { return m_groups; }
    const std::vector<OutputGroup>& Groups() const { return m_groups; }

    // ======================================================================
    // Coin Selection Methods
    // ======================================================================

    /**
     * @brief Select coins using Branch and Bound (changeless solutions).
     *
     * BnB attempts to find an exact match for the target, avoiding
     * change creation entirely.
     *
     * @param target  Target effective value.
     * @param params  Coin selection parameters (for cost_of_change).
     * @param max_weight  Maximum selection weight (default: MAX_STANDARD_TX_WEIGHT).
     * @return Selection result with waste calculated, or nullopt if no solution.
     */
    std::optional<SelectionResult> SelectBnB(
        Amount target,
        const CoinSelectionParams& params,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::SelectCoinsBnB(groups, target, params.GetCostOfChange(), max_weight);
        if (!result) return std::nullopt;

        // BnB targets exact matches, so min_viable_change = 0
        result->RecalculateWaste(0, params.GetCostOfChange(), 0);
        return std::move(*result);
    }

    /**
     * @brief Select coins using Single Random Draw.
     *
     * @param target      Target value.
     * @param params      Coin selection parameters.
     * @param rng         Random context.
     * @param max_weight  Maximum selection weight.
     * @return Selection result with waste calculated, or nullopt if no solution.
     */
    std::optional<SelectionResult> SelectSRD(
        Amount target,
        const CoinSelectionParams& params,
        FastRandomContext& rng,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::SelectCoinsSRD(groups, target, params.GetChangeFee(), rng, max_weight);
        if (!result) return std::nullopt;

        result->RecalculateWaste(
            params.GetMinViableChange(),
            params.GetCostOfChange(),
            params.GetChangeFee()
        );
        return std::move(*result);
    }

    /**
     * @brief Select coins using CoinGrinder (minimizes weight).
     *
     * Best used when feerates are high and minimizing input count matters.
     *
     * @param target      Target value.
     * @param params      Coin selection parameters.
     * @param max_weight  Maximum selection weight.
     * @return Selection result with waste calculated, or nullopt if no solution.
     */
    std::optional<SelectionResult> SelectCoinGrinder(
        Amount target,
        const CoinSelectionParams& params,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::CoinGrinder(groups, target, params.GetMinViableChange(), max_weight);
        if (!result) return std::nullopt;

        result->RecalculateWaste(
            params.GetMinViableChange(),
            params.GetCostOfChange(),
            params.GetChangeFee()
        );
        return std::move(*result);
    }

    /**
     * @brief Select coins using Knapsack solver.
     *
     * The legacy randomized solver, used as a fallback.
     *
     * @param target      Target value.
     * @param params      Coin selection parameters.
     * @param rng         Random context.
     * @param max_weight  Maximum selection weight.
     * @return Selection result with waste calculated, or nullopt if no solution.
     */
    std::optional<SelectionResult> SelectKnapsack(
        Amount target,
        const CoinSelectionParams& params,
        FastRandomContext& rng,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::KnapsackSolver(groups, target, params.GetMinViableChange(), rng, max_weight);
        if (!result) return std::nullopt;

        result->RecalculateWaste(
            params.GetMinViableChange(),
            params.GetCostOfChange(),
            params.GetChangeFee()
        );
        return std::move(*result);
    }

    // ======================================================================
    // Legacy Selection Methods (for backward compatibility)
    // ======================================================================

    /**
     * @brief Select coins using BnB with explicit cost_of_change.
     * @deprecated Use SelectBnB(target, params) instead.
     */
    [[deprecated("Use SelectBnB(target, params) for accurate waste calculation")]]
    std::optional<SelectionResult> SelectBnB(
        Amount target,
        Amount cost_of_change,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::SelectCoinsBnB(groups, target, cost_of_change, max_weight);
        if (!result) return std::nullopt;
        result->RecalculateWaste(0, cost_of_change, 0);
        return std::move(*result);
    }

private:
    std::vector<OutputGroup> m_groups;
};

// ==========================================================================
// Utility Functions
// ==========================================================================

/**
 * @brief Generate a randomized change target for privacy.
 */
inline Amount GenerateChangeTarget(Amount payment_value, Amount change_fee, FastRandomContext& rng)
{
    return wallet::GenerateChangeTarget(payment_value, change_fee, rng);
}

/**
 * @brief Get maximum standard transaction weight.
 */
inline int GetMaxStandardTxWeight()
{
    return MAX_STANDARD_TX_WEIGHT;
}

/**
 * @brief Convert input bytes to weight units.
 */
inline int GetInputWeight(int input_bytes)
{
    return input_bytes * WITNESS_SCALE_FACTOR;
}

/**
 * @brief Get library version string.
 */
inline std::string Version()
{
    return "0.0.1";
}

} // namespace btccs

#endif // BITCOIN_COINSELECTION_BITCOINCOINSELECTION_WRAPPER_H

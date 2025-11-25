// Copyright (c) 2024-present The Bitcoin Core developers
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
 *
 * For C bindings or FFI, use bitcoincoinselection.h instead.
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
// UtxoPool - Builder for creating a pool of UTXOs
// ==========================================================================

/**
 * @brief A builder class for creating UTXO pools for coin selection.
 *
 * Example usage:
 * @code
 *   UtxoPool pool;
 *   pool.Add(txid1, 0, 100000, 68, 6, fee1, ltfee1);
 *   pool.Add(txid2, 1, 250000, 68, 3, fee2, ltfee2);
 *
 *   auto result = pool.SelectBnB(target, costOfChange);
 * @endcode
 */
class UtxoPool {
public:
    UtxoPool() = default;

    /**
     * @brief Add a UTXO to the pool.
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
     * @brief Add a UTXO using simplified parameters with feerate calculation.
     *
     * @param txid         Transaction ID.
     * @param vout         Output index.
     * @param value        Output value in satoshis.
     * @param input_bytes  Estimated input size (68 for P2WPKH).
     * @param depth        Confirmation depth.
     * @param feerate      Current feerate.
     * @param lt_feerate   Long-term feerate (optional, defaults to feerate/3).
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
                                   : FeeRate(feerate.GetFeePerK() / 3).GetFee(input_bytes);
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
     * @param target          Target effective value.
     * @param cost_of_change  Cost of creating and spending change.
     * @param max_weight      Maximum selection weight (default: MAX_STANDARD_TX_WEIGHT).
     * @return Selection result, or nullopt if no solution found.
     */
    std::optional<SelectionResult> SelectBnB(
        Amount target,
        Amount cost_of_change,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups; // Copy since BnB may sort
        auto result = wallet::SelectCoinsBnB(groups, target, cost_of_change, max_weight);
        if (!result) return std::nullopt;
        return std::move(*result);
    }

    /**
     * @brief Select coins using Single Random Draw.
     *
     * @param target      Target value.
     * @param change_fee  Fee for change output.
     * @param rng         Random context.
     * @param max_weight  Maximum selection weight.
     * @return Selection result, or nullopt if no solution found.
     */
    std::optional<SelectionResult> SelectSRD(
        Amount target,
        Amount change_fee,
        FastRandomContext& rng,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::SelectCoinsSRD(groups, target, change_fee, rng, max_weight);
        if (!result) return std::nullopt;
        return std::move(*result);
    }

    /**
     * @brief Select coins using CoinGrinder (minimizes weight).
     *
     * @param target         Target value.
     * @param change_target  Minimum change amount.
     * @param max_weight     Maximum selection weight.
     * @return Selection result, or nullopt if no solution found.
     */
    std::optional<SelectionResult> SelectCoinGrinder(
        Amount target,
        Amount change_target,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::CoinGrinder(groups, target, change_target, max_weight);
        if (!result) return std::nullopt;
        return std::move(*result);
    }

    /**
     * @brief Select coins using Knapsack solver.
     *
     * @param target         Target value.
     * @param change_target  Minimum change amount.
     * @param rng            Random context.
     * @param max_weight     Maximum selection weight.
     * @return Selection result, or nullopt if no solution found.
     */
    std::optional<SelectionResult> SelectKnapsack(
        Amount target,
        Amount change_target,
        FastRandomContext& rng,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::KnapsackSolver(groups, target, change_target, rng, max_weight);
        if (!result) return std::nullopt;
        return std::move(*result);
    }

private:
    std::vector<OutputGroup> m_groups;
};

// ==========================================================================
// CoinSelectionParams - Fee calculation helper
// ==========================================================================

/**
 * @brief Helper class for calculating coin selection parameters.
 *
 * This provides convenient calculation of change costs and fees
 * based on feerates and output sizes.
 */
class CoinSelectionParams {
public:
    /**
     * @brief Create parameters with explicit sizes.
     *
     * @param effective_feerate  Current transaction feerate.
     * @param long_term_feerate  Long-term expected feerate.
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
     * Uses sensible defaults:
     * - Long-term feerate = effective / 3
     * - Discard feerate = 3 sat/vB
     * - P2WPKH sizes (31 bytes output, 68 bytes spend)
     */
    explicit CoinSelectionParams(FeeRate effective_feerate)
        : m_effective_feerate(effective_feerate)
        , m_long_term_feerate(effective_feerate.GetFeePerK() / 3)
        , m_discard_feerate(3000)
        , m_change_output_size(31)
        , m_change_spend_size(68)
    {}

    /**
     * @brief Create parameters from sat/kvB value.
     */
    explicit CoinSelectionParams(int64_t effective_feerate_sat_per_kvb)
        : CoinSelectionParams(FeeRate(effective_feerate_sat_per_kvb))
    {}

    /** Cost of creating a change output. */
    Amount GetChangeFee() const
    {
        return m_effective_feerate.GetFee(m_change_output_size);
    }

    /** Total cost of change (creation + future spend). */
    Amount GetCostOfChange() const
    {
        return GetChangeFee() + m_discard_feerate.GetFee(m_change_spend_size);
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

private:
    FeeRate m_effective_feerate;
    FeeRate m_long_term_feerate;
    FeeRate m_discard_feerate;
    size_t m_change_output_size;
    size_t m_change_spend_size;
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
    return "0.2.0";
}

/**
 * @brief Helper to create a txid from a seed value (for testing).
 */
inline std::array<unsigned char, 32> MakeTxid(uint32_t seed)
{
    std::array<unsigned char, 32> txid{};
    for (size_t i = 0; i < 4; ++i) {
        txid[i] = (seed >> (i * 8)) & 0xFF;
    }
    return txid;
}

} // namespace btccs

#endif // BITCOIN_COINSELECTION_BITCOINCOINSELECTION_WRAPPER_H

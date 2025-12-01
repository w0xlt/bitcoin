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
#include <outputtype.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>
#include <util/result.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/spend.h>

#include <array>
#include <functional>
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
using CoinsResult = wallet::CoinsResult;
using PreSelectedInputs = wallet::PreSelectedInputs;
using CoinSelectionParams = wallet::CoinSelectionParams;
using CoinEligibilityFilter = wallet::CoinEligibilityFilter;
using CCoinControl = wallet::CCoinControl;

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
// CoinSelectionOptions - Options for coin selection
// ==========================================================================

/**
 * @brief Options for coin selection behavior.
 *
 * Simple struct to configure coin selection without a wallet.
 */
struct CoinSelectionOptions {
    /** Whether to allow spending zero-confirmation change outputs. */
    bool spend_zero_conf_change{true};

    /** Whether to reject transactions with long mempool chains. */
    bool reject_long_chains{false};

    CoinSelectionOptions() = default;
    CoinSelectionOptions(bool spend_zero_conf, bool reject_long)
        : spend_zero_conf_change(spend_zero_conf), reject_long_chains(reject_long) {}

    /** Convert to internal type */
    wallet::CoinSelectionOptions ToInternal() const {
        return wallet::CoinSelectionOptions(spend_zero_conf_change, reject_long_chains);
    }
};

// ==========================================================================
// SimpleCoinSelectionSource - Wallet-independent source implementation
// ==========================================================================

/**
 * @brief A simple implementation of CoinSelectionSource for use without a wallet.
 *
 * This class provides callbacks for chain information needed during coin selection.
 * For simple use cases, the default implementation returns sensible defaults.
 * For more advanced use, custom callbacks can be provided.
 *
 * Example usage:
 * @code
 *   // Simple mode with defaults
 *   SimpleCoinSelectionSource source;
 *
 *   // With custom limits
 *   SimpleCoinSelectionSource source(50, 50);  // Higher limits
 *
 *   // With custom callbacks
 *   SimpleCoinSelectionSource source;
 *   source.SetAncestryCallback([&](const Txid& txid) -> std::pair<size_t, size_t> {
 *       return mempool.GetAncestry(txid);
 *   });
 * @endcode
 */
class SimpleCoinSelectionSource : public wallet::CoinSelectionSource {
public:
    using AncestryCallback = std::function<std::pair<size_t, size_t>(const Txid&)>;
    using BumpFeeCallback = std::function<std::optional<Amount>(const std::vector<COutPoint>&, const FeeRate&)>;
    using PackageLimitsCallback = std::function<std::pair<unsigned int, unsigned int>()>;

    /**
     * @brief Create a source with default/no-op behavior.
     *
     * Default behavior:
     * - Returns 0 ancestors/descendants (treats all UTXOs as confirmed)
     * - Returns 0 for bump fees
     * - Uses standard package limits (25/25)
     */
    SimpleCoinSelectionSource()
        : m_limit_ancestor_count(25), m_limit_descendant_count(25) {}

    /**
     * @brief Create a source with custom package limits.
     *
     * @param limit_ancestor_count Maximum number of ancestors.
     * @param limit_descendant_count Maximum number of descendants.
     */
    SimpleCoinSelectionSource(unsigned int limit_ancestor_count,
                               unsigned int limit_descendant_count)
        : m_limit_ancestor_count(limit_ancestor_count)
        , m_limit_descendant_count(limit_descendant_count) {}

    // Interface implementation
    void GetTransactionAncestry(const Txid& txid, size_t& ancestors, size_t& descendants) const override
    {
        if (m_ancestry_callback) {
            auto [anc, desc] = m_ancestry_callback(txid);
            ancestors = anc;
            descendants = desc;
        } else {
            ancestors = 0;
            descendants = 0;
        }
    }

    std::optional<Amount> CalculateCombinedBumpFee(
        const std::vector<COutPoint>& outpoints,
        const FeeRate& feerate) const override
    {
        if (m_bump_fee_callback) {
            return m_bump_fee_callback(outpoints, feerate);
        }
        return Amount{0};
    }

    void GetPackageLimits(unsigned int& limit_ancestor_count,
                         unsigned int& limit_descendant_count) const override
    {
        if (m_package_limits_callback) {
            auto [anc, desc] = m_package_limits_callback();
            limit_ancestor_count = anc;
            limit_descendant_count = desc;
        } else {
            limit_ancestor_count = m_limit_ancestor_count;
            limit_descendant_count = m_limit_descendant_count;
        }
    }

    // Callback setters
    void SetAncestryCallback(AncestryCallback callback) { m_ancestry_callback = std::move(callback); }
    void SetBumpFeeCallback(BumpFeeCallback callback) { m_bump_fee_callback = std::move(callback); }
    void SetPackageLimitsCallback(PackageLimitsCallback callback) { m_package_limits_callback = std::move(callback); }

    // Limit setters
    void SetPackageLimits(unsigned int ancestors, unsigned int descendants) {
        m_limit_ancestor_count = ancestors;
        m_limit_descendant_count = descendants;
    }

private:
    unsigned int m_limit_ancestor_count;
    unsigned int m_limit_descendant_count;
    AncestryCallback m_ancestry_callback;
    BumpFeeCallback m_bump_fee_callback;
    PackageLimitsCallback m_package_limits_callback;
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
    // Individual Coin Selection Methods
    // ======================================================================

    /**
     * @brief Select coins using Branch and Bound (changeless solutions).
     */
    std::optional<SelectionResult> SelectBnB(
        Amount target,
        Amount cost_of_change,
        int max_weight = MAX_STANDARD_TX_WEIGHT) const
    {
        auto groups = m_groups;
        auto result = wallet::SelectCoinsBnB(groups, target, cost_of_change, max_weight);
        if (!result) return std::nullopt;
        return std::move(*result);
    }

    /**
     * @brief Select coins using Single Random Draw.
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
// CoinsResultBuilder - Builder for creating CoinsResult
// ==========================================================================

/**
 * @brief Builder class for creating CoinsResult containers.
 *
 * Provides a convenient way to populate available coins for selection.
 *
 * Example usage:
 * @code
 *   CoinsResultBuilder builder;
 *   builder.Add(OutputType::BECH32, txid1, 0, 100000, 68, 6, true, true, 0, false, fee1);
 *   builder.Add(OutputType::BECH32, txid2, 1, 250000, 68, 3, true, true, 0, false, fee2);
 *
 *   CoinsResult coins = builder.Build();
 * @endcode
 */
class CoinsResultBuilder {
public:
    CoinsResultBuilder() = default;

    /**
     * @brief Add a coin to the result.
     */
    CoinsResultBuilder& Add(OutputType type,
                             const std::array<unsigned char, 32>& txid,
                             uint32_t vout,
                             Amount value,
                             int input_bytes,
                             int depth,
                             bool solvable,
                             bool safe,
                             int64_t time,
                             bool from_me,
                             Amount fee,
                             Amount long_term_fee = 0)
    {
        uint256 hash;
        std::memcpy(hash.begin(), txid.data(), 32);
        COutPoint outpoint(Txid::FromUint256(hash), vout);
        CTxOut txout(value, CScript());

        COutput output(outpoint, txout, depth, input_bytes, solvable, safe, time, from_me, fee);
        output.long_term_fee = long_term_fee;

        m_coins.Add(type, output);
        return *this;
    }

    /**
     * @brief Add a coin with feerate calculation.
     */
    CoinsResultBuilder& Add(OutputType type,
                             const std::array<unsigned char, 32>& txid,
                             uint32_t vout,
                             Amount value,
                             int input_bytes,
                             int depth,
                             bool solvable,
                             bool safe,
                             int64_t time,
                             bool from_me,
                             const FeeRate& feerate,
                             std::optional<FeeRate> lt_feerate = std::nullopt)
    {
        Amount fee = feerate.GetFee(input_bytes);
        Amount lt_fee = lt_feerate ? lt_feerate->GetFee(input_bytes)
                                   : FeeRate(feerate.GetFeePerK() / 3).GetFee(input_bytes);
        return Add(type, txid, vout, value, input_bytes, depth, solvable, safe, time, from_me, fee, lt_fee);
    }

    /** Get the number of coins. */
    size_t Size() const { return m_coins.Size(); }

    /** Build and return the CoinsResult. */
    CoinsResult Build() { return std::move(m_coins); }

    /** Get mutable reference to underlying CoinsResult. */
    CoinsResult& Coins() { return m_coins; }

private:
    CoinsResult m_coins;
};

// ==========================================================================
// PreSelectedInputsBuilder - Builder for creating PreSelectedInputs
// ==========================================================================

/**
 * @brief Builder class for creating PreSelectedInputs.
 */
class PreSelectedInputsBuilder {
public:
    PreSelectedInputsBuilder() = default;

    /**
     * @brief Add a pre-selected input.
     */
    PreSelectedInputsBuilder& Add(const std::array<unsigned char, 32>& txid,
                                   uint32_t vout,
                                   Amount value,
                                   int input_bytes,
                                   int depth,
                                   Amount fee,
                                   bool subtract_fee_outputs)
    {
        uint256 hash;
        std::memcpy(hash.begin(), txid.data(), 32);
        COutPoint outpoint(Txid::FromUint256(hash), vout);
        CTxOut txout(value, CScript());

        COutput output(outpoint, txout, depth, input_bytes,
                       /*solvable=*/true, /*safe=*/true, /*time=*/0, /*from_me=*/false, fee);

        m_inputs.Insert(output, subtract_fee_outputs);
        return *this;
    }

    /** Get the total amount. */
    Amount Total() const { return m_inputs.total_amount; }

    /** Build and return the PreSelectedInputs. */
    PreSelectedInputs Build() { return std::move(m_inputs); }

    /** Get mutable reference to underlying PreSelectedInputs. */
    PreSelectedInputs& Inputs() { return m_inputs; }

private:
    PreSelectedInputs m_inputs;
};

// ==========================================================================
// CoinSelectionParamsBuilder - Builder for CoinSelectionParams
// ==========================================================================

/**
 * @brief Builder class for creating CoinSelectionParams.
 *
 * Provides convenient methods to configure selection parameters.
 *
 * Example usage:
 * @code
 *   FastRandomContext rng;
 *   auto params = CoinSelectionParamsBuilder(rng)
 *       .SetEffectiveFeeRate(CFeeRate(10000))
 *       .SetChangeOutputSize(31)
 *       .SetChangeSpendSize(68)
 *       .Build();
 * @endcode
 */
class CoinSelectionParamsBuilder {
public:
    explicit CoinSelectionParamsBuilder(FastRandomContext& rng)
        : m_rng(rng)
        , m_change_output_size(31)  // P2WPKH
        , m_change_spend_size(68)   // P2WPKH
        , m_min_change_target(0)
        , m_effective_feerate(10000) // 10 sat/vB
        , m_long_term_feerate(3333)  // ~3.3 sat/vB (1/3 of effective)
        , m_discard_feerate(3000)    // 3 sat/vB
        , m_tx_noinputs_size(0)
        , m_avoid_partial_spends(false)
        , m_subtract_fee_outputs(false)
        , m_max_tx_weight(std::nullopt)
    {}

    CoinSelectionParamsBuilder& SetChangeOutputSize(int size) { m_change_output_size = size; return *this; }
    CoinSelectionParamsBuilder& SetChangeSpendSize(int size) { m_change_spend_size = size; return *this; }
    CoinSelectionParamsBuilder& SetMinChangeTarget(Amount target) { m_min_change_target = target; return *this; }
    CoinSelectionParamsBuilder& SetEffectiveFeeRate(const FeeRate& rate) { m_effective_feerate = rate; return *this; }
    CoinSelectionParamsBuilder& SetLongTermFeeRate(const FeeRate& rate) { m_long_term_feerate = rate; return *this; }
    CoinSelectionParamsBuilder& SetDiscardFeeRate(const FeeRate& rate) { m_discard_feerate = rate; return *this; }
    CoinSelectionParamsBuilder& SetTxNoInputsSize(int size) { m_tx_noinputs_size = size; return *this; }
    CoinSelectionParamsBuilder& SetAvoidPartialSpends(bool avoid) { m_avoid_partial_spends = avoid; return *this; }
    CoinSelectionParamsBuilder& SetSubtractFeeOutputs(bool subtract) { m_subtract_fee_outputs = subtract; return *this; }
    CoinSelectionParamsBuilder& SetMaxTxWeight(int weight) { m_max_tx_weight = weight; return *this; }

    CoinSelectionParams Build()
    {
        CoinSelectionParams params(
            m_rng,
            m_change_output_size,
            m_change_spend_size,
            m_min_change_target,
            m_effective_feerate,
            m_long_term_feerate,
            m_discard_feerate,
            m_tx_noinputs_size,
            m_avoid_partial_spends,
            m_max_tx_weight);

        params.m_subtract_fee_outputs = m_subtract_fee_outputs;
        return params;
    }

private:
    FastRandomContext& m_rng;
    int m_change_output_size;
    int m_change_spend_size;
    Amount m_min_change_target;
    FeeRate m_effective_feerate;
    FeeRate m_long_term_feerate;
    FeeRate m_discard_feerate;
    int m_tx_noinputs_size;
    bool m_avoid_partial_spends;
    bool m_subtract_fee_outputs;
    std::optional<int> m_max_tx_weight;
};

// ==========================================================================
// Main Coin Selection Functions
// ==========================================================================

/**
 * @brief Perform full coin selection.
 *
 * This is the main entry point for coin selection that:
 * - Uses pre-selected inputs if provided
 * - Calls AutomaticCoinSelection if more inputs are needed
 * - Tries multiple eligibility filters
 * - Picks the best result based on waste metric
 *
 * @param source            Chain interface for ancestry/bump fees.
 * @param options           Selection options.
 * @param available_coins   Available coins to select from.
 * @param pre_set_inputs    Pre-selected inputs (may be empty).
 * @param target_value      Target amount in satoshis.
 * @param coin_control      Coin control settings.
 * @param params            Selection parameters.
 * @return Selection result, or error.
 */
inline util::Result<SelectionResult> SelectCoins(
    const wallet::CoinSelectionSource& source,
    const CoinSelectionOptions& options,
    CoinsResult& available_coins,
    const PreSelectedInputs& pre_set_inputs,
    Amount target_value,
    const CCoinControl& coin_control,
    const CoinSelectionParams& params)
{
    return wallet::SelectCoins(
        source,
        options.ToInternal(),
        available_coins,
        pre_set_inputs,
        target_value,
        coin_control,
        params);
}

/**
 * @brief Perform automatic coin selection.
 *
 * Simplified version for cases without manual input selection.
 */
inline util::Result<SelectionResult> AutomaticCoinSelection(
    const wallet::CoinSelectionSource& source,
    const CoinSelectionOptions& options,
    CoinsResult& available_coins,
    Amount target_value,
    const CoinSelectionParams& params)
{
    return wallet::AutomaticCoinSelection(
        source,
        options.ToInternal(),
        available_coins,
        target_value,
        params);
}

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
    return "0.3.0";
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

/**
 * @brief Calculate cost of change (creation + future spend).
 */
inline Amount CalculateCostOfChange(const FeeRate& effective_feerate,
                                     const FeeRate& discard_feerate,
                                     size_t change_output_size,
                                     size_t change_spend_size)
{
    return effective_feerate.GetFee(change_output_size) +
           discard_feerate.GetFee(change_spend_size);
}

} // namespace btccs

#endif // BITCOIN_COINSELECTION_BITCOINCOINSELECTION_WRAPPER_H

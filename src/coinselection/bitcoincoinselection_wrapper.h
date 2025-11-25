// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSELECTION_BITCOINCOINSELECTION_WRAPPER_H
#define BITCOIN_COINSELECTION_BITCOINCOINSELECTION_WRAPPER_H

#include <coinselection/bitcoincoinselection.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace btccs {

// Type alias for amounts (satoshis)
using Amount = btccs_Amount;

// Enums wrapping C enum types
enum class SelectionStatus : btccs_SelectionStatus {
    SUCCESS = btccs_SelectionStatus_SUCCESS,
    INSUFFICIENT_FUNDS = btccs_SelectionStatus_INSUFFICIENT_FUNDS,
    MAX_WEIGHT_EXCEEDED = btccs_SelectionStatus_MAX_WEIGHT_EXCEEDED,
    NO_SOLUTION_FOUND = btccs_SelectionStatus_NO_SOLUTION_FOUND,
    INVALID_PARAMETER = btccs_SelectionStatus_INVALID_PARAMETER,
    INTERNAL_ERROR = btccs_SelectionStatus_INTERNAL_ERROR
};

enum class SelectionAlgorithm : btccs_SelectionAlgorithm {
    BNB = btccs_SelectionAlgorithm_BNB,
    SRD = btccs_SelectionAlgorithm_SRD,
    COINGRINDER = btccs_SelectionAlgorithm_COINGRINDER,
    KNAPSACK = btccs_SelectionAlgorithm_KNAPSACK,
    MANUAL = btccs_SelectionAlgorithm_MANUAL
};

// Forward declarations
class OutPoint;
class TxOut;
class CoinOutput;
class OutputGroup;
class SelectionResult;
class CoinSelectionParams;
class RandomContext;

// Exception thrown on errors
class CoinSelectionError : public std::runtime_error {
public:
    explicit CoinSelectionError(const std::string& msg, SelectionStatus status = SelectionStatus::INTERNAL_ERROR)
        : std::runtime_error(msg), m_status{status} {}
    SelectionStatus status() const { return m_status; }
private:
    SelectionStatus m_status;
};

// Helper to check pointers
template <typename T>
T* check(T* ptr, const char* msg = "Failed to create object") {
    if (ptr == nullptr) {
        throw CoinSelectionError(msg);
    }
    return ptr;
}

// ==========================================================================
// OutPoint - Transaction outpoint (txid + vout)
// ==========================================================================

class OutPoint {
public:
    OutPoint(const unsigned char txid[32], uint32_t vout)
        : m_ptr{check(btccs_outpoint_create(txid, vout), "Failed to create outpoint")} {}

    OutPoint(const std::array<unsigned char, 32>& txid, uint32_t vout)
        : OutPoint(txid.data(), vout) {}

    OutPoint(const OutPoint& other)
        : m_ptr{check(btccs_outpoint_copy(other.m_ptr.get()), "Failed to copy outpoint")} {}

    OutPoint(OutPoint&&) = default;
    OutPoint& operator=(OutPoint&&) = default;

    OutPoint& operator=(const OutPoint& other) {
        if (this != &other) {
            m_ptr.reset(check(btccs_outpoint_copy(other.m_ptr.get()), "Failed to copy outpoint"));
        }
        return *this;
    }

    std::array<unsigned char, 32> GetTxid() const {
        std::array<unsigned char, 32> txid;
        btccs_outpoint_get_txid(m_ptr.get(), txid.data());
        return txid;
    }

    uint32_t GetVout() const {
        return btccs_outpoint_get_vout(m_ptr.get());
    }

    bool operator==(const OutPoint& other) const {
        return btccs_outpoint_equals(m_ptr.get(), other.m_ptr.get()) != 0;
    }

    btccs_OutPoint* get() const { return m_ptr.get(); }

private:
    struct Deleter { void operator()(btccs_OutPoint* p) { btccs_outpoint_destroy(p); } };
    std::unique_ptr<btccs_OutPoint, Deleter> m_ptr;
};

// ==========================================================================
// TxOut - Transaction output
// ==========================================================================

class TxOut {
public:
    TxOut(Amount value, const std::vector<unsigned char>& script_pubkey)
        : m_ptr{check(btccs_txout_create(value, script_pubkey.data(), script_pubkey.size()),
                      "Failed to create txout")} {}

    TxOut(Amount value, std::span<const unsigned char> script_pubkey)
        : m_ptr{check(btccs_txout_create(value, script_pubkey.data(), script_pubkey.size()),
                      "Failed to create txout")} {}

    TxOut(const TxOut& other)
        : m_ptr{check(btccs_txout_copy(other.m_ptr.get()), "Failed to copy txout")} {}

    TxOut(TxOut&&) = default;
    TxOut& operator=(TxOut&&) = default;

    TxOut& operator=(const TxOut& other) {
        if (this != &other) {
            m_ptr.reset(check(btccs_txout_copy(other.m_ptr.get()), "Failed to copy txout"));
        }
        return *this;
    }

    Amount GetValue() const {
        return btccs_txout_get_value(m_ptr.get());
    }

    std::vector<unsigned char> GetScriptPubKey() const {
        size_t len = 0;
        btccs_txout_get_script_pubkey(m_ptr.get(), nullptr, &len);
        std::vector<unsigned char> script(len);
        btccs_txout_get_script_pubkey(m_ptr.get(), script.data(), &len);
        return script;
    }

    btccs_TxOut* get() const { return m_ptr.get(); }

private:
    struct Deleter { void operator()(btccs_TxOut* p) { btccs_txout_destroy(p); } };
    std::unique_ptr<btccs_TxOut, Deleter> m_ptr;
};

// ==========================================================================
// CoinOutput - UTXO with metadata
// ==========================================================================

class CoinOutput {
public:
    // Full constructor with all parameters
    CoinOutput(const OutPoint& outpoint, const TxOut& txout, int depth, int input_bytes,
               bool spendable, bool solvable, bool safe, int64_t time, bool from_me,
               Amount fee, Amount long_term_fee)
        : m_ptr{check(btccs_coin_output_create(
              outpoint.get(), txout.get(), depth, input_bytes,
              spendable ? 1 : 0, solvable ? 1 : 0, safe ? 1 : 0,
              time, from_me ? 1 : 0, fee, long_term_fee),
              "Failed to create coin output")} {}

    // Simple constructor
    CoinOutput(const OutPoint& outpoint, const TxOut& txout, int depth, int input_bytes)
        : m_ptr{check(btccs_coin_output_create_simple(outpoint.get(), txout.get(), depth, input_bytes),
                      "Failed to create coin output")} {}

    CoinOutput(const CoinOutput& other)
        : m_ptr{check(btccs_coin_output_copy(other.m_ptr.get()), "Failed to copy coin output")} {}

    CoinOutput(CoinOutput&&) = default;
    CoinOutput& operator=(CoinOutput&&) = default;

    CoinOutput& operator=(const CoinOutput& other) {
        if (this != &other) {
            m_ptr.reset(check(btccs_coin_output_copy(other.m_ptr.get()), "Failed to copy coin output"));
        }
        return *this;
    }

    Amount GetValue() const { return btccs_coin_output_get_value(m_ptr.get()); }
    Amount GetEffectiveValue() const { return btccs_coin_output_get_effective_value(m_ptr.get()); }
    int GetDepth() const { return btccs_coin_output_get_depth(m_ptr.get()); }
    int GetInputBytes() const { return btccs_coin_output_get_input_bytes(m_ptr.get()); }
    Amount GetFee() const { return btccs_coin_output_get_fee(m_ptr.get()); }
    Amount GetLongTermFee() const { return btccs_coin_output_get_long_term_fee(m_ptr.get()); }
    bool IsSpendable() const { return btccs_coin_output_is_spendable(m_ptr.get()) != 0; }
    bool IsSafe() const { return btccs_coin_output_is_safe(m_ptr.get()) != 0; }

    void SetFees(Amount fee, Amount long_term_fee) {
        btccs_coin_output_set_fees(m_ptr.get(), fee, long_term_fee);
    }

    btccs_CoinOutput* get() const { return m_ptr.get(); }

private:
    // Constructor from raw pointer (for views)
    explicit CoinOutput(btccs_CoinOutput* ptr) : m_ptr{ptr} {}
    friend class OutputGroup;
    friend class SelectionResult;

    struct Deleter { void operator()(btccs_CoinOutput* p) { btccs_coin_output_destroy(p); } };
    std::unique_ptr<btccs_CoinOutput, Deleter> m_ptr;
};

// ==========================================================================
// OutputGroup - Group of outputs (typically from same address)
// ==========================================================================

class OutputGroup {
public:
    OutputGroup()
        : m_ptr{check(btccs_output_group_create(), "Failed to create output group")} {}

    OutputGroup(const OutputGroup& other)
        : m_ptr{check(btccs_output_group_copy(other.m_ptr.get()), "Failed to copy output group")} {}

    OutputGroup(OutputGroup&&) = default;
    OutputGroup& operator=(OutputGroup&&) = default;

    OutputGroup& operator=(const OutputGroup& other) {
        if (this != &other) {
            m_ptr.reset(check(btccs_output_group_copy(other.m_ptr.get()), "Failed to copy output group"));
        }
        return *this;
    }

    void Insert(const CoinOutput& coin, size_t ancestors = 0, size_t descendants = 0) {
        btccs_output_group_insert(m_ptr.get(), coin.get(), ancestors, descendants);
    }

    size_t Size() const { return btccs_output_group_size(m_ptr.get()); }
    Amount GetValue() const { return btccs_output_group_get_value(m_ptr.get()); }
    Amount GetSelectionAmount() const { return btccs_output_group_get_selection_amount(m_ptr.get()); }
    Amount GetFee() const { return btccs_output_group_get_fee(m_ptr.get()); }
    Amount GetLongTermFee() const { return btccs_output_group_get_long_term_fee(m_ptr.get()); }
    int GetWeight() const { return btccs_output_group_get_weight(m_ptr.get()); }

    bool IsEligible(int required_confirms, size_t max_ancestors, size_t max_descendants) const {
        return btccs_output_group_is_eligible(m_ptr.get(), required_confirms, max_ancestors, max_descendants) != 0;
    }

    btccs_OutputGroup* get() const { return m_ptr.get(); }

private:
    struct Deleter { void operator()(btccs_OutputGroup* p) { btccs_output_group_destroy(p); } };
    std::unique_ptr<btccs_OutputGroup, Deleter> m_ptr;
};

// ==========================================================================
// CoinSelectionParams - Parameters for coin selection
// ==========================================================================

class CoinSelectionParams {
public:
    // Full constructor
    CoinSelectionParams(int64_t effective_feerate_sat_per_kvb,
                        int64_t long_term_feerate_sat_per_kvb,
                        int64_t discard_feerate_sat_per_kvb,
                        size_t change_output_size,
                        size_t change_spend_size,
                        Amount min_viable_change,
                        size_t tx_noinputs_size,
                        bool avoid_partial_spends)
        : m_ptr{check(btccs_coin_selection_params_create(
              effective_feerate_sat_per_kvb, long_term_feerate_sat_per_kvb,
              discard_feerate_sat_per_kvb, change_output_size, change_spend_size,
              min_viable_change, tx_noinputs_size, avoid_partial_spends ? 1 : 0),
              "Failed to create coin selection params")} {}

    // Simple constructor with defaults
    explicit CoinSelectionParams(int64_t effective_feerate_sat_per_kvb)
        : m_ptr{check(btccs_coin_selection_params_create_default(effective_feerate_sat_per_kvb),
                      "Failed to create coin selection params")} {}

    CoinSelectionParams(const CoinSelectionParams& other)
        : m_ptr{check(btccs_coin_selection_params_copy(other.m_ptr.get()),
                      "Failed to copy coin selection params")} {}

    CoinSelectionParams(CoinSelectionParams&&) = default;
    CoinSelectionParams& operator=(CoinSelectionParams&&) = default;

    CoinSelectionParams& operator=(const CoinSelectionParams& other) {
        if (this != &other) {
            m_ptr.reset(check(btccs_coin_selection_params_copy(other.m_ptr.get()),
                              "Failed to copy coin selection params"));
        }
        return *this;
    }

    Amount GetCostOfChange() const { return btccs_coin_selection_params_get_cost_of_change(m_ptr.get()); }
    Amount GetChangeFee() const { return btccs_coin_selection_params_get_change_fee(m_ptr.get()); }

    void SetSubtractFeeOutputs(bool subtract) {
        btccs_coin_selection_params_set_subtract_fee_outputs(m_ptr.get(), subtract ? 1 : 0);
    }

    btccs_CoinSelectionParams* get() const { return m_ptr.get(); }

private:
    struct Deleter { void operator()(btccs_CoinSelectionParams* p) { btccs_coin_selection_params_destroy(p); } };
    std::unique_ptr<btccs_CoinSelectionParams, Deleter> m_ptr;
};

// ==========================================================================
// RandomContext - Random number generator context
// ==========================================================================

class RandomContext {
public:
    RandomContext()
        : m_ptr{check(btccs_random_context_create(), "Failed to create random context")} {}

    explicit RandomContext(const std::array<unsigned char, 32>& seed)
        : m_ptr{check(btccs_random_context_create_seeded(seed.data()), "Failed to create seeded random context")} {}

    RandomContext(RandomContext&&) = default;
    RandomContext& operator=(RandomContext&&) = default;

    // Non-copyable (RNG state shouldn't be duplicated)
    RandomContext(const RandomContext&) = delete;
    RandomContext& operator=(const RandomContext&) = delete;

    btccs_RandomContext* get() const { return m_ptr.get(); }

private:
    struct Deleter { void operator()(btccs_RandomContext* p) { btccs_random_context_destroy(p); } };
    std::unique_ptr<btccs_RandomContext, Deleter> m_ptr;
};

// ==========================================================================
// SelectionResult - Result of coin selection
// ==========================================================================

class SelectionResult {
public:
    SelectionResult(Amount target, SelectionAlgorithm algorithm)
        : m_ptr{check(btccs_selection_result_create(target, static_cast<btccs_SelectionAlgorithm>(algorithm)),
                      "Failed to create selection result")} {}

    SelectionResult(const SelectionResult& other)
        : m_ptr{check(btccs_selection_result_copy(other.m_ptr.get()), "Failed to copy selection result")} {}

    SelectionResult(SelectionResult&&) = default;
    SelectionResult& operator=(SelectionResult&&) = default;

    SelectionResult& operator=(const SelectionResult& other) {
        if (this != &other) {
            m_ptr.reset(check(btccs_selection_result_copy(other.m_ptr.get()), "Failed to copy selection result"));
        }
        return *this;
    }

    void AddInput(const OutputGroup& group) {
        btccs_selection_result_add_input(m_ptr.get(), group.get());
    }

    size_t GetInputCount() const { return btccs_selection_result_get_input_count(m_ptr.get()); }
    Amount GetSelectedValue() const { return btccs_selection_result_get_selected_value(m_ptr.get()); }
    Amount GetSelectedEffectiveValue() const { return btccs_selection_result_get_selected_effective_value(m_ptr.get()); }
    Amount GetTarget() const { return btccs_selection_result_get_target(m_ptr.get()); }
    Amount GetWaste() const { return btccs_selection_result_get_waste(m_ptr.get()); }
    int GetWeight() const { return btccs_selection_result_get_weight(m_ptr.get()); }

    SelectionAlgorithm GetAlgorithm() const {
        return static_cast<SelectionAlgorithm>(btccs_selection_result_get_algorithm(m_ptr.get()));
    }

    Amount GetChange(Amount cost_of_change, Amount change_fee) const {
        return btccs_selection_result_get_change(m_ptr.get(), cost_of_change, change_fee);
    }

    void RecalculateWaste(Amount min_viable_change, Amount change_cost, Amount change_fee) {
        btccs_selection_result_recalculate_waste(m_ptr.get(), min_viable_change, change_cost, change_fee);
    }

    btccs_SelectionResult* get() const { return m_ptr.get(); }

private:
    // Constructor from raw pointer (for algorithm results)
    explicit SelectionResult(btccs_SelectionResult* ptr) : m_ptr{ptr} {}
    friend std::optional<SelectionResult> SelectCoinsBnB(std::vector<OutputGroup>&, Amount, Amount, int, SelectionStatus*);
    friend std::optional<SelectionResult> SelectCoinsSRD(const std::vector<OutputGroup>&, Amount, Amount, RandomContext&, int, SelectionStatus*);
    friend std::optional<SelectionResult> CoinGrinder(std::vector<OutputGroup>&, Amount, Amount, int, SelectionStatus*);
    friend std::optional<SelectionResult> KnapsackSolver(std::vector<OutputGroup>&, Amount, Amount, RandomContext&, int, SelectionStatus*);

    struct Deleter { void operator()(btccs_SelectionResult* p) { btccs_selection_result_destroy(p); } };
    std::unique_ptr<btccs_SelectionResult, Deleter> m_ptr;
};

// ==========================================================================
// Algorithm wrapper functions
// ==========================================================================

/**
 * Branch and Bound coin selection - finds changeless solutions.
 */
inline std::optional<SelectionResult> SelectCoinsBnB(
    std::vector<OutputGroup>& utxo_pool,
    Amount selection_target,
    Amount cost_of_change,
    int max_selection_weight = btccs_get_max_standard_tx_weight(),
    SelectionStatus* status_out = nullptr)
{
    std::vector<btccs_OutputGroup*> pool_ptrs;
    pool_ptrs.reserve(utxo_pool.size());
    for (auto& group : utxo_pool) {
        pool_ptrs.push_back(group.get());
    }

    btccs_SelectionStatus status;
    btccs_SelectionResult* result = btccs_select_coins_bnb(
        pool_ptrs.data(), pool_ptrs.size(),
        selection_target, cost_of_change, max_selection_weight, &status);

    if (status_out) *status_out = static_cast<SelectionStatus>(status);

    if (result == nullptr) {
        return std::nullopt;
    }
    return SelectionResult{result};
}

/**
 * Single Random Draw coin selection.
 */
inline std::optional<SelectionResult> SelectCoinsSRD(
    const std::vector<OutputGroup>& utxo_pool,
    Amount target_value,
    Amount change_fee,
    RandomContext& rng,
    int max_selection_weight = btccs_get_max_standard_tx_weight(),
    SelectionStatus* status_out = nullptr)
{
    std::vector<const btccs_OutputGroup*> pool_ptrs;
    pool_ptrs.reserve(utxo_pool.size());
    for (const auto& group : utxo_pool) {
        pool_ptrs.push_back(group.get());
    }

    btccs_SelectionStatus status;
    btccs_SelectionResult* result = btccs_select_coins_srd(
        pool_ptrs.data(), pool_ptrs.size(),
        target_value, change_fee, rng.get(), max_selection_weight, &status);

    if (status_out) *status_out = static_cast<SelectionStatus>(status);

    if (result == nullptr) {
        return std::nullopt;
    }
    return SelectionResult{result};
}

/**
 * CoinGrinder - minimizes input set weight.
 */
inline std::optional<SelectionResult> CoinGrinder(
    std::vector<OutputGroup>& utxo_pool,
    Amount selection_target,
    Amount change_target,
    int max_selection_weight = btccs_get_max_standard_tx_weight(),
    SelectionStatus* status_out = nullptr)
{
    std::vector<btccs_OutputGroup*> pool_ptrs;
    pool_ptrs.reserve(utxo_pool.size());
    for (auto& group : utxo_pool) {
        pool_ptrs.push_back(group.get());
    }

    btccs_SelectionStatus status;
    btccs_SelectionResult* result = btccs_select_coins_coingrinder(
        pool_ptrs.data(), pool_ptrs.size(),
        selection_target, change_target, max_selection_weight, &status);

    if (status_out) *status_out = static_cast<SelectionStatus>(status);

    if (result == nullptr) {
        return std::nullopt;
    }
    return SelectionResult{result};
}

/**
 * Knapsack solver - legacy randomized subset sum.
 */
inline std::optional<SelectionResult> KnapsackSolver(
    std::vector<OutputGroup>& groups,
    Amount target_value,
    Amount change_target,
    RandomContext& rng,
    int max_selection_weight = btccs_get_max_standard_tx_weight(),
    SelectionStatus* status_out = nullptr)
{
    std::vector<btccs_OutputGroup*> pool_ptrs;
    pool_ptrs.reserve(groups.size());
    for (auto& group : groups) {
        pool_ptrs.push_back(group.get());
    }

    btccs_SelectionStatus status;
    btccs_SelectionResult* result = btccs_select_coins_knapsack(
        pool_ptrs.data(), pool_ptrs.size(),
        target_value, change_target, rng.get(), max_selection_weight, &status);

    if (status_out) *status_out = static_cast<SelectionStatus>(status);

    if (result == nullptr) {
        return std::nullopt;
    }
    return SelectionResult{result};
}

// ==========================================================================
// Utility functions
// ==========================================================================

inline Amount GenerateChangeTarget(Amount payment_value, Amount change_fee, RandomContext& rng) {
    return btccs_generate_change_target(payment_value, change_fee, rng.get());
}

inline int GetMaxStandardTxWeight() {
    return btccs_get_max_standard_tx_weight();
}

inline int GetInputWeight(int input_bytes) {
    return btccs_get_input_weight(input_bytes);
}

inline std::string Version() {
    return btccs_version();
}

} // namespace btccs

#endif // BITCOIN_COINSELECTION_BITCOINCOINSELECTION_WRAPPER_H

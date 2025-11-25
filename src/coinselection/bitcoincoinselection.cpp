// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINCOINSELECTION_BUILD

#include <coinselection/bitcoincoinselection.h>

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>
#include <util/check.h>
#include <wallet/coinselection.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

// Library version
static const char* BTCCS_VERSION = "0.1.0";

namespace {

// ==========================================================================
// Handle template for type-safe casting between C and C++ types
// ==========================================================================

template <typename C, typename CPP>
struct Handle {
    static C* ref(CPP* cpp_type)
    {
        return reinterpret_cast<C*>(cpp_type);
    }

    static const C* ref(const CPP* cpp_type)
    {
        return reinterpret_cast<const C*>(cpp_type);
    }

    template <typename... Args>
    static C* create(Args&&... args)
    {
        auto cpp_obj{std::make_unique<CPP>(std::forward<Args>(args)...)};
        return reinterpret_cast<C*>(cpp_obj.release());
    }

    static C* copy(const C* ptr)
    {
        auto cpp_obj{std::make_unique<CPP>(get(ptr))};
        return reinterpret_cast<C*>(cpp_obj.release());
    }

    static const CPP& get(const C* ptr)
    {
        return *reinterpret_cast<const CPP*>(ptr);
    }

    static CPP& get(C* ptr)
    {
        return *reinterpret_cast<CPP*>(ptr);
    }

    static void destroy(void* ptr)
    {
        delete reinterpret_cast<CPP*>(ptr);
    }
};

// ==========================================================================
// Internal wrapper structures
// ==========================================================================

/**
 * Internal representation of a coin output with all metadata needed for
 * coin selection. This wraps the data needed to construct wallet::COutput.
 */
struct CoinOutputInternal {
    COutPoint outpoint;
    CTxOut txout;
    int depth{0};
    int input_bytes{-1};
    bool spendable{true};
    bool solvable{true};
    bool safe{true};
    int64_t time{0};
    bool from_me{false};
    CAmount fee{0};
    CAmount long_term_fee{0};

    CoinOutputInternal() = default;

    CoinOutputInternal(const COutPoint& op, const CTxOut& to, int d, int ib,
                       bool sp, bool so, bool sa, int64_t t, bool fm, CAmount f, CAmount ltf)
        : outpoint(op), txout(to), depth(d), input_bytes(ib),
          spendable(sp), solvable(so), safe(sa), time(t), from_me(fm),
          fee(f), long_term_fee(ltf) {}

    CAmount GetValue() const { return txout.nValue; }
    CAmount GetEffectiveValue() const { return txout.nValue - fee; }

    // Convert to wallet::COutput for use with internal algorithms
    std::shared_ptr<wallet::COutput> ToCOutput() const {
        auto output = std::make_shared<wallet::COutput>(
            outpoint, txout, depth, input_bytes, spendable, solvable, safe, time, from_me, fee);
        output->long_term_fee = long_term_fee;
        return output;
    }
};

/**
 * Internal representation of an output group.
 */
struct OutputGroupInternal {
    std::vector<std::shared_ptr<CoinOutputInternal>> coins;
    CAmount m_value{0};
    CAmount m_fee{0};
    CAmount m_long_term_fee{0};
    int m_weight{0};
    size_t m_ancestors{0};
    size_t m_descendants{0};
    int m_depth{std::numeric_limits<int>::max()};

    void Insert(const std::shared_ptr<CoinOutputInternal>& coin, size_t ancestors, size_t descendants) {
        coins.push_back(coin);
        m_value += coin->GetValue();
        m_fee += coin->fee;
        m_long_term_fee += coin->long_term_fee;
        if (coin->input_bytes > 0) {
            m_weight += coin->input_bytes * 4; // Convert vbytes to weight
        }
        m_ancestors = std::max(m_ancestors, ancestors);
        m_descendants = std::max(m_descendants, descendants);
        m_depth = std::min(m_depth, coin->depth);
    }

    CAmount GetSelectionAmount() const {
        return m_value - m_fee;
    }

    bool IsEligible(int required_confirms, size_t max_ancestors, size_t max_descendants) const {
        return m_depth >= required_confirms &&
               m_ancestors <= max_ancestors &&
               m_descendants <= max_descendants;
    }

    // Convert to wallet::OutputGroup for use with internal algorithms
    wallet::OutputGroup ToOutputGroup() const {
        wallet::OutputGroup group;
        for (const auto& coin : coins) {
            group.Insert(coin->ToCOutput(), m_ancestors, m_descendants);
        }
        return group;
    }
};

/**
 * Internal representation of coin selection parameters.
 */
struct CoinSelectionParamsInternal {
    CFeeRate m_effective_feerate;
    CFeeRate m_long_term_feerate;
    CFeeRate m_discard_feerate;
    size_t m_change_output_size;
    size_t m_change_spend_size;
    CAmount m_min_viable_change;
    size_t m_tx_noinputs_size;
    bool m_avoid_partial_spends;
    bool m_subtract_fee_outputs{false};

    CoinSelectionParamsInternal(int64_t effective_feerate_sat_per_kvb,
                                 int64_t long_term_feerate_sat_per_kvb,
                                 int64_t discard_feerate_sat_per_kvb,
                                 size_t change_output_size,
                                 size_t change_spend_size,
                                 CAmount min_viable_change,
                                 size_t tx_noinputs_size,
                                 bool avoid_partial_spends)
        : m_effective_feerate(effective_feerate_sat_per_kvb)
        , m_long_term_feerate(long_term_feerate_sat_per_kvb)
        , m_discard_feerate(discard_feerate_sat_per_kvb)
        , m_change_output_size(change_output_size)
        , m_change_spend_size(change_spend_size)
        , m_min_viable_change(min_viable_change)
        , m_tx_noinputs_size(tx_noinputs_size)
        , m_avoid_partial_spends(avoid_partial_spends) {}

    CAmount GetCostOfChange() const {
        return m_effective_feerate.GetFee(m_change_output_size) +
               m_discard_feerate.GetFee(m_change_spend_size);
    }

    CAmount GetChangeFee() const {
        return m_effective_feerate.GetFee(m_change_output_size);
    }
};

/**
 * Internal representation of a selection result.
 */
struct SelectionResultInternal {
    std::vector<std::shared_ptr<CoinOutputInternal>> m_selected_inputs;
    CAmount m_target{0};
    CAmount m_waste{0};
    btccs_SelectionAlgorithm m_algorithm{btccs_SelectionAlgorithm_MANUAL};
    bool m_use_effective{true};

    SelectionResultInternal(CAmount target, btccs_SelectionAlgorithm algo)
        : m_target(target), m_algorithm(algo) {}

    void AddInputs(const OutputGroupInternal& group) {
        for (const auto& coin : group.coins) {
            m_selected_inputs.push_back(coin);
        }
    }

    size_t GetInputCount() const { return m_selected_inputs.size(); }

    CAmount GetSelectedValue() const {
        CAmount value{0};
        for (const auto& coin : m_selected_inputs) {
            value += coin->GetValue();
        }
        return value;
    }

    CAmount GetSelectedEffectiveValue() const {
        CAmount value{0};
        for (const auto& coin : m_selected_inputs) {
            value += coin->GetEffectiveValue();
        }
        return value;
    }

    int GetWeight() const {
        int weight{0};
        for (const auto& coin : m_selected_inputs) {
            if (coin->input_bytes > 0) {
                weight += coin->input_bytes * 4;
            }
        }
        return weight;
    }

    CAmount GetChange(CAmount cost_of_change, CAmount change_fee) const {
        CAmount selected = m_use_effective ? GetSelectedEffectiveValue() : GetSelectedValue();
        CAmount excess = selected - m_target;
        if (excess > cost_of_change) {
            return excess - change_fee;
        }
        return 0;
    }

    void RecalculateWaste(CAmount min_viable_change, CAmount change_cost, CAmount change_fee) {
        // Calculate fee difference from long-term feerate
        CAmount fee_diff{0};
        for (const auto& coin : m_selected_inputs) {
            fee_diff += coin->fee - coin->long_term_fee;
        }

        CAmount change = GetChange(change_cost, change_fee);
        if (change > 0) {
            // With change, waste = fee difference + cost of change
            m_waste = fee_diff + change_cost;
        } else {
            // Without change, waste = fee difference + excess dropped to fees
            CAmount selected = m_use_effective ? GetSelectedEffectiveValue() : GetSelectedValue();
            m_waste = fee_diff + (selected - m_target);
        }
    }

    // Populate from wallet::SelectionResult
    void FromSelectionResult(const wallet::SelectionResult& result) {
        m_selected_inputs.clear();
        for (const auto& coin : result.GetInputSet()) {
            auto internal = std::make_shared<CoinOutputInternal>();
            internal->outpoint = coin->outpoint;
            internal->txout = coin->txout;
            internal->depth = coin->depth;
            internal->input_bytes = coin->input_bytes;
            internal->spendable = coin->spendable;
            internal->solvable = coin->solvable;
            internal->safe = coin->safe;
            internal->time = coin->time;
            internal->from_me = coin->from_me;
            internal->fee = coin->fee;
            internal->long_term_fee = coin->long_term_fee;
            m_selected_inputs.push_back(internal);
        }
        m_waste = result.GetWaste();
    }
};

// Helper to convert internal OutputGroup vector to wallet::OutputGroup vector
std::vector<wallet::OutputGroup> ConvertGroups(btccs_OutputGroup* const* groups, size_t count) {
    std::vector<wallet::OutputGroup> result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const auto& internal = Handle<btccs_OutputGroup, OutputGroupInternal>::get(groups[i]);
        result.push_back(internal.ToOutputGroup());
    }
    return result;
}

// Helper to convert const groups
std::vector<wallet::OutputGroup> ConvertConstGroups(const btccs_OutputGroup* const* groups, size_t count) {
    std::vector<wallet::OutputGroup> result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const auto& internal = Handle<btccs_OutputGroup, OutputGroupInternal>::get(groups[i]);
        result.push_back(internal.ToOutputGroup());
    }
    return result;
}

} // namespace

// ==========================================================================
// Type definitions for Handle mappings
// ==========================================================================

struct btccs_OutPoint : Handle<btccs_OutPoint, COutPoint> {};
struct btccs_TxOut : Handle<btccs_TxOut, CTxOut> {};
struct btccs_CoinOutput : Handle<btccs_CoinOutput, CoinOutputInternal> {};
struct btccs_OutputGroup : Handle<btccs_OutputGroup, OutputGroupInternal> {};
struct btccs_SelectionResult : Handle<btccs_SelectionResult, SelectionResultInternal> {};
struct btccs_CoinSelectionParams : Handle<btccs_CoinSelectionParams, CoinSelectionParamsInternal> {};
struct btccs_RandomContext : Handle<btccs_RandomContext, FastRandomContext> {};

// ==========================================================================
// OutPoint Implementation
// ==========================================================================

btccs_OutPoint* btccs_outpoint_create(const unsigned char txid[32], uint32_t vout)
{
    if (txid == nullptr) return nullptr;
    uint256 hash;
    std::memcpy(hash.begin(), txid, 32);
    return btccs_OutPoint::create(hash, vout);
}

btccs_OutPoint* btccs_outpoint_copy(const btccs_OutPoint* outpoint)
{
    return btccs_OutPoint::copy(outpoint);
}

void btccs_outpoint_get_txid(const btccs_OutPoint* outpoint, unsigned char txid_out[32])
{
    std::memcpy(txid_out, btccs_OutPoint::get(outpoint).hash.begin(), 32);
}

uint32_t btccs_outpoint_get_vout(const btccs_OutPoint* outpoint)
{
    return btccs_OutPoint::get(outpoint).n;
}

int btccs_outpoint_equals(const btccs_OutPoint* a, const btccs_OutPoint* b)
{
    return btccs_OutPoint::get(a) == btccs_OutPoint::get(b) ? 1 : 0;
}

void btccs_outpoint_destroy(btccs_OutPoint* outpoint)
{
    delete outpoint;
}

// ==========================================================================
// TxOut Implementation
// ==========================================================================

btccs_TxOut* btccs_txout_create(btccs_Amount value, const unsigned char* script_pubkey, size_t script_pubkey_len)
{
    CScript script;
    if (script_pubkey != nullptr && script_pubkey_len > 0) {
        script = CScript(script_pubkey, script_pubkey + script_pubkey_len);
    }
    return btccs_TxOut::create(value, script);
}

btccs_TxOut* btccs_txout_copy(const btccs_TxOut* txout)
{
    return btccs_TxOut::copy(txout);
}

btccs_Amount btccs_txout_get_value(const btccs_TxOut* txout)
{
    return btccs_TxOut::get(txout).nValue;
}

int btccs_txout_get_script_pubkey(const btccs_TxOut* txout, unsigned char* script_out, size_t* script_len)
{
    const CScript& script = btccs_TxOut::get(txout).scriptPubKey;
    if (script_out == nullptr) {
        *script_len = script.size();
        return 0;
    }
    if (*script_len < script.size()) {
        *script_len = script.size();
        return -1;
    }
    std::memcpy(script_out, script.data(), script.size());
    *script_len = script.size();
    return 0;
}

void btccs_txout_destroy(btccs_TxOut* txout)
{
    delete txout;
}

// ==========================================================================
// CoinOutput Implementation
// ==========================================================================

btccs_CoinOutput* btccs_coin_output_create(
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
    btccs_Amount long_term_fee)
{
    return btccs_CoinOutput::create(
        btccs_OutPoint::get(outpoint),
        btccs_TxOut::get(txout),
        depth, input_bytes,
        spendable != 0, solvable != 0, safe != 0,
        time, from_me != 0, fee, long_term_fee);
}

btccs_CoinOutput* btccs_coin_output_create_simple(
    const btccs_OutPoint* outpoint,
    const btccs_TxOut* txout,
    int depth,
    int input_bytes)
{
    return btccs_CoinOutput::create(
        btccs_OutPoint::get(outpoint),
        btccs_TxOut::get(txout),
        depth, input_bytes,
        true, true, true, 0, false, 0, 0);
}

btccs_CoinOutput* btccs_coin_output_copy(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::copy(coin);
}

const btccs_OutPoint* btccs_coin_output_get_outpoint(const btccs_CoinOutput* coin)
{
    return btccs_OutPoint::ref(&btccs_CoinOutput::get(coin).outpoint);
}

const btccs_TxOut* btccs_coin_output_get_txout(const btccs_CoinOutput* coin)
{
    return btccs_TxOut::ref(&btccs_CoinOutput::get(coin).txout);
}

btccs_Amount btccs_coin_output_get_value(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::get(coin).GetValue();
}

btccs_Amount btccs_coin_output_get_effective_value(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::get(coin).GetEffectiveValue();
}

int btccs_coin_output_get_depth(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::get(coin).depth;
}

int btccs_coin_output_get_input_bytes(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::get(coin).input_bytes;
}

btccs_Amount btccs_coin_output_get_fee(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::get(coin).fee;
}

btccs_Amount btccs_coin_output_get_long_term_fee(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::get(coin).long_term_fee;
}

int btccs_coin_output_is_spendable(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::get(coin).spendable ? 1 : 0;
}

int btccs_coin_output_is_safe(const btccs_CoinOutput* coin)
{
    return btccs_CoinOutput::get(coin).safe ? 1 : 0;
}

void btccs_coin_output_set_fees(btccs_CoinOutput* coin, btccs_Amount fee, btccs_Amount long_term_fee)
{
    btccs_CoinOutput::get(coin).fee = fee;
    btccs_CoinOutput::get(coin).long_term_fee = long_term_fee;
}

void btccs_coin_output_destroy(btccs_CoinOutput* coin)
{
    delete coin;
}

// ==========================================================================
// OutputGroup Implementation
// ==========================================================================

btccs_OutputGroup* btccs_output_group_create(void)
{
    return btccs_OutputGroup::create();
}

btccs_OutputGroup* btccs_output_group_copy(const btccs_OutputGroup* group)
{
    return btccs_OutputGroup::copy(group);
}

void btccs_output_group_insert(btccs_OutputGroup* group, const btccs_CoinOutput* coin,
                                size_t ancestors, size_t descendants)
{
    auto coin_copy = std::make_shared<CoinOutputInternal>(btccs_CoinOutput::get(coin));
    btccs_OutputGroup::get(group).Insert(coin_copy, ancestors, descendants);
}

size_t btccs_output_group_size(const btccs_OutputGroup* group)
{
    return btccs_OutputGroup::get(group).coins.size();
}

const btccs_CoinOutput* btccs_output_group_get_coin_at(const btccs_OutputGroup* group, size_t index)
{
    const auto& internal = btccs_OutputGroup::get(group);
    if (index >= internal.coins.size()) return nullptr;
    return btccs_CoinOutput::ref(internal.coins[index].get());
}

btccs_Amount btccs_output_group_get_value(const btccs_OutputGroup* group)
{
    return btccs_OutputGroup::get(group).m_value;
}

btccs_Amount btccs_output_group_get_selection_amount(const btccs_OutputGroup* group)
{
    return btccs_OutputGroup::get(group).GetSelectionAmount();
}

btccs_Amount btccs_output_group_get_fee(const btccs_OutputGroup* group)
{
    return btccs_OutputGroup::get(group).m_fee;
}

btccs_Amount btccs_output_group_get_long_term_fee(const btccs_OutputGroup* group)
{
    return btccs_OutputGroup::get(group).m_long_term_fee;
}

int btccs_output_group_get_weight(const btccs_OutputGroup* group)
{
    return btccs_OutputGroup::get(group).m_weight;
}

int btccs_output_group_is_eligible(const btccs_OutputGroup* group, int required_confirms,
                                    size_t max_ancestors, size_t max_descendants)
{
    return btccs_OutputGroup::get(group).IsEligible(required_confirms, max_ancestors, max_descendants) ? 1 : 0;
}

void btccs_output_group_destroy(btccs_OutputGroup* group)
{
    delete group;
}

// ==========================================================================
// CoinSelectionParams Implementation
// ==========================================================================

btccs_CoinSelectionParams* btccs_coin_selection_params_create(
    int64_t effective_feerate_sat_per_kvb,
    int64_t long_term_feerate_sat_per_kvb,
    int64_t discard_feerate_sat_per_kvb,
    size_t change_output_size,
    size_t change_spend_size,
    btccs_Amount min_viable_change,
    size_t tx_noinputs_size,
    int avoid_partial_spends)
{
    return btccs_CoinSelectionParams::create(
        effective_feerate_sat_per_kvb,
        long_term_feerate_sat_per_kvb,
        discard_feerate_sat_per_kvb,
        change_output_size,
        change_spend_size,
        min_viable_change,
        tx_noinputs_size,
        avoid_partial_spends != 0);
}

btccs_CoinSelectionParams* btccs_coin_selection_params_create_default(int64_t effective_feerate_sat_per_kvb)
{
    // Default values for P2WPKH
    // Change output: 8 (value) + 1 (script len) + 22 (P2WPKH script) = 31 bytes
    // Change spend: ~68 bytes for P2WPKH input
    constexpr size_t DEFAULT_CHANGE_OUTPUT_SIZE = 31;
    constexpr size_t DEFAULT_CHANGE_SPEND_SIZE = 68;
    constexpr CAmount DEFAULT_MIN_VIABLE_CHANGE = 1000; // 1000 sats
    constexpr size_t DEFAULT_TX_NOINPUTS_SIZE = 11; // version + locktime + in/out counts

    return btccs_CoinSelectionParams::create(
        effective_feerate_sat_per_kvb,
        effective_feerate_sat_per_kvb / 3, // Default long-term is 1/3 of effective
        3000, // Default discard rate: 3 sat/vB
        DEFAULT_CHANGE_OUTPUT_SIZE,
        DEFAULT_CHANGE_SPEND_SIZE,
        DEFAULT_MIN_VIABLE_CHANGE,
        DEFAULT_TX_NOINPUTS_SIZE,
        false);
}

btccs_CoinSelectionParams* btccs_coin_selection_params_copy(const btccs_CoinSelectionParams* params)
{
    return btccs_CoinSelectionParams::copy(params);
}

btccs_Amount btccs_coin_selection_params_get_cost_of_change(const btccs_CoinSelectionParams* params)
{
    return btccs_CoinSelectionParams::get(params).GetCostOfChange();
}

btccs_Amount btccs_coin_selection_params_get_change_fee(const btccs_CoinSelectionParams* params)
{
    return btccs_CoinSelectionParams::get(params).GetChangeFee();
}

void btccs_coin_selection_params_set_subtract_fee_outputs(btccs_CoinSelectionParams* params, int subtract_fee_outputs)
{
    btccs_CoinSelectionParams::get(params).m_subtract_fee_outputs = (subtract_fee_outputs != 0);
}

void btccs_coin_selection_params_destroy(btccs_CoinSelectionParams* params)
{
    delete params;
}

// ==========================================================================
// RandomContext Implementation
// ==========================================================================

btccs_RandomContext* btccs_random_context_create(void)
{
    return btccs_RandomContext::create();
}

btccs_RandomContext* btccs_random_context_create_seeded(const unsigned char seed[32])
{
    uint256 seed_hash;
    std::memcpy(seed_hash.begin(), seed, 32);
    return btccs_RandomContext::create(seed_hash);
}

void btccs_random_context_destroy(btccs_RandomContext* rng)
{
    delete rng;
}

// ==========================================================================
// SelectionResult Implementation
// ==========================================================================

btccs_SelectionResult* btccs_selection_result_create(btccs_Amount target, btccs_SelectionAlgorithm algorithm)
{
    return btccs_SelectionResult::create(target, algorithm);
}

btccs_SelectionResult* btccs_selection_result_copy(const btccs_SelectionResult* result)
{
    return btccs_SelectionResult::copy(result);
}

void btccs_selection_result_add_input(btccs_SelectionResult* result, const btccs_OutputGroup* group)
{
    btccs_SelectionResult::get(result).AddInputs(btccs_OutputGroup::get(group));
}

size_t btccs_selection_result_get_input_count(const btccs_SelectionResult* result)
{
    return btccs_SelectionResult::get(result).GetInputCount();
}

const btccs_CoinOutput* btccs_selection_result_get_input_at(const btccs_SelectionResult* result, size_t index)
{
    const auto& internal = btccs_SelectionResult::get(result);
    if (index >= internal.m_selected_inputs.size()) return nullptr;
    return btccs_CoinOutput::ref(internal.m_selected_inputs[index].get());
}

btccs_Amount btccs_selection_result_get_selected_value(const btccs_SelectionResult* result)
{
    return btccs_SelectionResult::get(result).GetSelectedValue();
}

btccs_Amount btccs_selection_result_get_selected_effective_value(const btccs_SelectionResult* result)
{
    return btccs_SelectionResult::get(result).GetSelectedEffectiveValue();
}

btccs_Amount btccs_selection_result_get_target(const btccs_SelectionResult* result)
{
    return btccs_SelectionResult::get(result).m_target;
}

btccs_Amount btccs_selection_result_get_waste(const btccs_SelectionResult* result)
{
    return btccs_SelectionResult::get(result).m_waste;
}

btccs_Amount btccs_selection_result_get_change(const btccs_SelectionResult* result, btccs_Amount cost_of_change, btccs_Amount change_fee)
{
    return btccs_SelectionResult::get(result).GetChange(cost_of_change, change_fee);
}

int btccs_selection_result_get_weight(const btccs_SelectionResult* result)
{
    return btccs_SelectionResult::get(result).GetWeight();
}

btccs_SelectionAlgorithm btccs_selection_result_get_algorithm(const btccs_SelectionResult* result)
{
    return btccs_SelectionResult::get(result).m_algorithm;
}

void btccs_selection_result_recalculate_waste(btccs_SelectionResult* result, btccs_Amount min_viable_change,
                                               btccs_Amount change_cost, btccs_Amount change_fee)
{
    btccs_SelectionResult::get(result).RecalculateWaste(min_viable_change, change_cost, change_fee);
}

void btccs_selection_result_destroy(btccs_SelectionResult* result)
{
    delete result;
}

// ==========================================================================
// Coin Selection Algorithm Implementations
// ==========================================================================

btccs_SelectionResult* btccs_select_coins_bnb(
    btccs_OutputGroup* const* utxo_pool,
    size_t utxo_pool_size,
    btccs_Amount selection_target,
    btccs_Amount cost_of_change,
    int max_selection_weight,
    btccs_SelectionStatus* status)
{
    if (utxo_pool == nullptr && utxo_pool_size > 0) {
        if (status) *status = btccs_SelectionStatus_INVALID_PARAMETER;
        return nullptr;
    }

    try {
        std::vector<wallet::OutputGroup> groups = ConvertGroups(utxo_pool, utxo_pool_size);

        auto result = wallet::SelectCoinsBnB(groups, selection_target, cost_of_change, max_selection_weight);

        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        auto internal_result = std::make_unique<SelectionResultInternal>(selection_target, btccs_SelectionAlgorithm_BNB);
        internal_result->FromSelectionResult(*result);

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return reinterpret_cast<btccs_SelectionResult*>(internal_result.release());

    } catch (const std::exception&) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

btccs_SelectionResult* btccs_select_coins_srd(
    const btccs_OutputGroup* const* utxo_pool,
    size_t utxo_pool_size,
    btccs_Amount target_value,
    btccs_Amount change_fee,
    btccs_RandomContext* rng,
    int max_selection_weight,
    btccs_SelectionStatus* status)
{
    if ((utxo_pool == nullptr && utxo_pool_size > 0) || rng == nullptr) {
        if (status) *status = btccs_SelectionStatus_INVALID_PARAMETER;
        return nullptr;
    }

    try {
        std::vector<wallet::OutputGroup> groups = ConvertConstGroups(utxo_pool, utxo_pool_size);
        FastRandomContext& rng_ctx = btccs_RandomContext::get(rng);

        auto result = wallet::SelectCoinsSRD(groups, target_value, change_fee, rng_ctx, max_selection_weight);

        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        auto internal_result = std::make_unique<SelectionResultInternal>(target_value, btccs_SelectionAlgorithm_SRD);
        internal_result->FromSelectionResult(*result);

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return reinterpret_cast<btccs_SelectionResult*>(internal_result.release());

    } catch (const std::exception&) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

btccs_SelectionResult* btccs_select_coins_coingrinder(
    btccs_OutputGroup* const* utxo_pool,
    size_t utxo_pool_size,
    btccs_Amount selection_target,
    btccs_Amount change_target,
    int max_selection_weight,
    btccs_SelectionStatus* status)
{
    if (utxo_pool == nullptr && utxo_pool_size > 0) {
        if (status) *status = btccs_SelectionStatus_INVALID_PARAMETER;
        return nullptr;
    }

    try {
        std::vector<wallet::OutputGroup> groups = ConvertGroups(utxo_pool, utxo_pool_size);

        auto result = wallet::CoinGrinder(groups, selection_target, change_target, max_selection_weight);

        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        auto internal_result = std::make_unique<SelectionResultInternal>(selection_target, btccs_SelectionAlgorithm_COINGRINDER);
        internal_result->FromSelectionResult(*result);

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return reinterpret_cast<btccs_SelectionResult*>(internal_result.release());

    } catch (const std::exception&) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

btccs_SelectionResult* btccs_select_coins_knapsack(
    btccs_OutputGroup* const* groups,
    size_t groups_size,
    btccs_Amount target_value,
    btccs_Amount change_target,
    btccs_RandomContext* rng,
    int max_selection_weight,
    btccs_SelectionStatus* status)
{
    if ((groups == nullptr && groups_size > 0) || rng == nullptr) {
        if (status) *status = btccs_SelectionStatus_INVALID_PARAMETER;
        return nullptr;
    }

    try {
        std::vector<wallet::OutputGroup> group_vec = ConvertGroups(groups, groups_size);
        FastRandomContext& rng_ctx = btccs_RandomContext::get(rng);

        auto result = wallet::KnapsackSolver(group_vec, target_value, change_target, rng_ctx, max_selection_weight);

        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        auto internal_result = std::make_unique<SelectionResultInternal>(target_value, btccs_SelectionAlgorithm_KNAPSACK);
        internal_result->FromSelectionResult(*result);

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return reinterpret_cast<btccs_SelectionResult*>(internal_result.release());

    } catch (const std::exception&) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

// ==========================================================================
// Utility Functions
// ==========================================================================

btccs_Amount btccs_generate_change_target(btccs_Amount payment_value, btccs_Amount change_fee, btccs_RandomContext* rng)
{
    FastRandomContext& rng_ctx = btccs_RandomContext::get(rng);
    return wallet::GenerateChangeTarget(payment_value, change_fee, rng_ctx);
}

btccs_Amount btccs_calculate_waste(
    const btccs_CoinOutput* const* inputs,
    size_t inputs_count,
    btccs_Amount change_cost,
    btccs_Amount target,
    int use_effective_value)
{
    CAmount fee_diff{0};
    CAmount selected_value{0};

    for (size_t i = 0; i < inputs_count; ++i) {
        const auto& coin = btccs_CoinOutput::get(inputs[i]);
        fee_diff += coin.fee - coin.long_term_fee;
        selected_value += use_effective_value ? coin.GetEffectiveValue() : coin.GetValue();
    }

    CAmount excess = selected_value - target;
    if (excess > change_cost) {
        return fee_diff + change_cost;
    } else {
        return fee_diff + excess;
    }
}

btccs_Amount btccs_calculate_input_fee(const btccs_CoinOutput* const* inputs, size_t inputs_count)
{
    CAmount total_fee{0};
    for (size_t i = 0; i < inputs_count; ++i) {
        total_fee += btccs_CoinOutput::get(inputs[i]).fee;
    }
    return total_fee;
}

int btccs_get_max_standard_tx_weight(void)
{
    return MAX_STANDARD_TX_WEIGHT;
}

int btccs_get_input_weight(int input_bytes)
{
    // Weight = size * 4 for non-witness data
    return input_bytes * WITNESS_SCALE_FACTOR;
}

const char* btccs_version(void)
{
    return BTCCS_VERSION;
}

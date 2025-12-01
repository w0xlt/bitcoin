// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINCOINSELECTION_BUILD

#include <coinselection/bitcoincoinselection.h>

#include <consensus/amount.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <uint256.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/spend.h>

#include <cstring>
#include <map>
#include <memory>
#include <vector>

// Required for translation function symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const char* BTCCS_VERSION = "0.3.0";

// ==========================================================================
// Helper: Convert btccs_OutputType to OutputType
// ==========================================================================

static OutputType ConvertOutputType(btccs_OutputType type)
{
    switch (type) {
    case btccs_OutputType_LEGACY:      return OutputType::LEGACY;
    case btccs_OutputType_P2SH_SEGWIT: return OutputType::P2SH_SEGWIT;
    case btccs_OutputType_BECH32:      return OutputType::BECH32;
    case btccs_OutputType_BECH32M:     return OutputType::BECH32M;
    default:                           return OutputType::BECH32; // Default to BECH32
    }
}

static btccs_SelectionAlgorithm ConvertAlgorithm(wallet::SelectionAlgorithm algo)
{
    switch (algo) {
    case wallet::SelectionAlgorithm::BNB:      return btccs_SelectionAlgorithm_BNB;
    case wallet::SelectionAlgorithm::SRD:      return btccs_SelectionAlgorithm_SRD;
    case wallet::SelectionAlgorithm::CG:       return btccs_SelectionAlgorithm_COINGRINDER;
    case wallet::SelectionAlgorithm::KNAPSACK: return btccs_SelectionAlgorithm_KNAPSACK;
    case wallet::SelectionAlgorithm::MANUAL:   return btccs_SelectionAlgorithm_MANUAL;
    default:                                   return btccs_SelectionAlgorithm_MANUAL;
    }
}

// ==========================================================================
// Internal: UTXO Pool - stores OutputGroups directly
// ==========================================================================

struct btccs_UtxoPool {
    struct CoinFeeData {
        CAmount fee;
        CAmount long_term_fee;
    };

    std::vector<wallet::OutputGroup> groups;
    std::map<COutPoint, CoinFeeData> fee_map;

    void AddUtxo(const COutPoint& outpoint, CAmount value, int input_bytes,
                 int depth, CAmount fee, CAmount long_term_fee)
    {
        // Create COutput (the shared_ptr is required by OutputGroup)
        CTxOut txout(value, CScript());
        auto coin = std::make_shared<wallet::COutput>(
            outpoint, txout, depth, input_bytes,
            /*solvable=*/true, /*safe=*/true, /*time=*/0, /*from_me=*/false, fee);
        coin->long_term_fee = long_term_fee;

        // Each UTXO gets its own group (single-coin groups)
        wallet::OutputGroup group;
        group.Insert(coin, /*ancestors=*/0, /*descendants=*/0);
        groups.push_back(std::move(group));

        // Record the fee information so we can later compute a C-API specific waste metric.
        fee_map.emplace(outpoint, CoinFeeData{fee, long_term_fee});
    }
};

// ==========================================================================
// Internal: Selection Result wrapper
// ==========================================================================

struct btccs_SelectionResult {
    wallet::SelectionResult result;
    btccs_SelectionAlgorithm algorithm;
    CAmount waste; //!< C-API specific waste metric, in satoshis

    btccs_SelectionResult(wallet::SelectionResult&& r,
                          btccs_SelectionAlgorithm algo,
                          CAmount waste_in)
        : result(std::move(r)), algorithm(algo), waste(waste_in) {}

    // Constructor from SelectionResult with auto-detected algorithm
    explicit btccs_SelectionResult(wallet::SelectionResult&& r)
        : result(std::move(r))
        , algorithm(ConvertAlgorithm(result.GetAlgo()))
        , waste(0)
    {
        // Try to get waste from the result if available
        try {
            waste = result.GetWaste();
        } catch (...) {
            waste = 0;
        }
    }
};

// ==========================================================================
// Internal: Random Context - wraps FastRandomContext
// ==========================================================================

struct btccs_RandomContext {
    FastRandomContext rng;

    btccs_RandomContext() : rng() {}
    explicit btccs_RandomContext(const uint256& seed) : rng(seed) {}
};

// ==========================================================================
// Internal: Coin Selection Source - implements CoinSelectionSource interface
// ==========================================================================

struct btccs_CoinSelectionSource : public wallet::CoinSelectionSource {
    btccs_CoinSelectionSourceCallbacks callbacks;
    void* user_data;
    bool is_simple;
    unsigned int simple_ancestor_limit;
    unsigned int simple_descendant_limit;

    btccs_CoinSelectionSource(const btccs_CoinSelectionSourceCallbacks& cb, void* ud)
        : callbacks(cb), user_data(ud), is_simple(false),
          simple_ancestor_limit(25), simple_descendant_limit(25) {}

    btccs_CoinSelectionSource(unsigned int ancestor_limit, unsigned int descendant_limit)
        : callbacks{}, user_data(nullptr), is_simple(true),
          simple_ancestor_limit(ancestor_limit), simple_descendant_limit(descendant_limit)
    {
        callbacks.get_transaction_ancestry = nullptr;
        callbacks.calculate_combined_bump_fee = nullptr;
        callbacks.get_package_limits = nullptr;
    }

    void GetTransactionAncestry(const Txid& txid, size_t& ancestors, size_t& descendants) const override
    {
        if (is_simple || !callbacks.get_transaction_ancestry) {
            ancestors = 0;
            descendants = 0;
            return;
        }
        callbacks.get_transaction_ancestry(user_data, reinterpret_cast<const unsigned char*>(txid.data()), &ancestors, &descendants);
    }

    std::optional<CAmount> CalculateCombinedBumpFee(
        const std::vector<COutPoint>& outpoints,
        const CFeeRate& feerate) const override
    {
        if (is_simple || !callbacks.calculate_combined_bump_fee) {
            return CAmount{0};
        }

        // Serialize outpoints: each is 32-byte txid + 4-byte vout
        std::vector<unsigned char> serialized;
        serialized.reserve(outpoints.size() * 36);
        for (const auto& op : outpoints) {
            const unsigned char* hash_begin = reinterpret_cast<const unsigned char*>(op.hash.begin());
            const unsigned char* hash_end = reinterpret_cast<const unsigned char*>(op.hash.end());
            serialized.insert(serialized.end(), hash_begin, hash_end);
            uint32_t vout = op.n;
            serialized.push_back(vout & 0xFF);
            serialized.push_back((vout >> 8) & 0xFF);
            serialized.push_back((vout >> 16) & 0xFF);
            serialized.push_back((vout >> 24) & 0xFF);
        }

        CAmount bump_fee = 0;
        bool success = callbacks.calculate_combined_bump_fee(
            user_data,
            serialized.data(),
            outpoints.size(),
            feerate.GetFeePerK(),
            &bump_fee);

        if (!success) {
            return std::nullopt;
        }
        return bump_fee;
    }

    void GetPackageLimits(unsigned int& limit_ancestor_count,
                         unsigned int& limit_descendant_count) const override
    {
        if (is_simple || !callbacks.get_package_limits) {
            limit_ancestor_count = simple_ancestor_limit;
            limit_descendant_count = simple_descendant_limit;
            return;
        }
        callbacks.get_package_limits(user_data, &limit_ancestor_count, &limit_descendant_count);
    }
};

// ==========================================================================
// Internal: Coins Result wrapper
// ==========================================================================

struct btccs_CoinsResult {
    wallet::CoinsResult coins;
};

// ==========================================================================
// Internal: Pre-Selected Inputs wrapper
// ==========================================================================

struct btccs_PreSelectedInputs {
    wallet::PreSelectedInputs inputs;
};

// ==========================================================================
// Internal: Coin Control wrapper
// ==========================================================================

struct btccs_CoinControl {
    wallet::CCoinControl control;
};

// ==========================================================================
// Internal: Coin Selection Params wrapper
// ==========================================================================

struct btccs_CoinSelectionParams {
    // We need to keep the RNG alive for the lifetime of params
    FastRandomContext* rng_ptr;
    std::unique_ptr<wallet::CoinSelectionParams> params;

    btccs_CoinSelectionParams(FastRandomContext* rng,
                               int change_output_size,
                               int change_spend_size,
                               CAmount min_change_target,
                               CFeeRate effective_feerate,
                               CFeeRate long_term_feerate,
                               CFeeRate discard_feerate,
                               int tx_noinputs_size,
                               bool avoid_partial_spends)
        : rng_ptr(rng)
    {
        params = std::make_unique<wallet::CoinSelectionParams>(
            *rng_ptr,
            change_output_size,
            change_spend_size,
            min_change_target,
            effective_feerate,
            long_term_feerate,
            discard_feerate,
            tx_noinputs_size,
            avoid_partial_spends);
    }
};

/**
 * Compute the C-API waste metric for a given SelectionResult using
 * the per-input fee information stored in the originating UTXO pool.
 */
static CAmount ComputeWasteFromPool(const wallet::SelectionResult& result,
                                    const btccs_UtxoPool* pool)
{
    CAmount waste = 0;
    if (pool == nullptr) return waste;

    for (const auto& coin : result.GetInputSet()) {
        auto it = pool->fee_map.find(coin->outpoint);
        if (it == pool->fee_map.end()) {
            continue;
        }
        const CAmount fee = it->second.fee;
        const CAmount lt_fee = it->second.long_term_fee;
        waste += fee - lt_fee;
    }
    return waste;
}

// ==========================================================================
// Coin Selection Options Implementation
// ==========================================================================

btccs_CoinSelectionOptions btccs_coin_selection_options_default(void)
{
    btccs_CoinSelectionOptions opts;
    opts.spend_zero_conf_change = true;
    opts.reject_long_chains = false;
    return opts;
}

// ==========================================================================
// Coin Selection Source Implementation
// ==========================================================================

btccs_CoinSelectionSource* btccs_coin_selection_source_create(
    const btccs_CoinSelectionSourceCallbacks* callbacks,
    void* user_data)
{
    try {
        return new btccs_CoinSelectionSource(*callbacks, user_data);
    } catch (...) {
        return nullptr;
    }
}

btccs_CoinSelectionSource* btccs_coin_selection_source_create_simple(
    unsigned int limit_ancestor_count,
    unsigned int limit_descendant_count)
{
    try {
        return new btccs_CoinSelectionSource(limit_ancestor_count, limit_descendant_count);
    } catch (...) {
        return nullptr;
    }
}

void btccs_coin_selection_source_destroy(btccs_CoinSelectionSource* source)
{
    delete source;
}

// ==========================================================================
// UTXO Pool Implementation
// ==========================================================================

btccs_UtxoPool* btccs_utxo_pool_create(void)
{
    return new btccs_UtxoPool();
}

void btccs_utxo_pool_add(
    btccs_UtxoPool* pool,
    const unsigned char txid[32],
    uint32_t vout,
    btccs_Amount value,
    int input_bytes,
    int depth,
    btccs_Amount fee,
    btccs_Amount long_term_fee)
{
    uint256 hash;
    std::memcpy(hash.begin(), txid, 32);
    COutPoint outpoint(Txid::FromUint256(hash), vout);

    pool->AddUtxo(outpoint, value, input_bytes, depth, fee, long_term_fee);
}

size_t btccs_utxo_pool_size(const btccs_UtxoPool* pool)
{
    return pool->groups.size();
}

void btccs_utxo_pool_destroy(btccs_UtxoPool* pool)
{
    delete pool;
}

// ==========================================================================
// Coins Result Implementation
// ==========================================================================

btccs_CoinsResult* btccs_coins_result_create(void)
{
    try {
        return new btccs_CoinsResult();
    } catch (...) {
        return nullptr;
    }
}

void btccs_coins_result_add(
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
    btccs_Amount long_term_fee)
{
    uint256 hash;
    std::memcpy(hash.begin(), txid, 32);
    COutPoint outpoint(Txid::FromUint256(hash), vout);
    CTxOut txout(value, CScript());

    wallet::COutput output(outpoint, txout, depth, input_bytes, solvable, safe, time, from_me, fee);
    output.long_term_fee = long_term_fee;

    coins->coins.Add(ConvertOutputType(output_type), output);
}

size_t btccs_coins_result_size(const btccs_CoinsResult* coins)
{
    return coins->coins.Size();
}

btccs_Amount btccs_coins_result_get_total_amount(const btccs_CoinsResult* coins)
{
    // Need to compute sum since GetTotalAmount is non-const
    CAmount total = 0;
    for (const auto& [type, outputs] : coins->coins.coins) {
        for (const auto& output : outputs) {
            total += output.txout.nValue;
        }
    }
    return total;
}

void btccs_coins_result_shuffle(btccs_CoinsResult* coins, btccs_RandomContext* rng)
{
    coins->coins.Shuffle(rng->rng);
}

void btccs_coins_result_destroy(btccs_CoinsResult* coins)
{
    delete coins;
}

// ==========================================================================
// Pre-Selected Inputs Implementation
// ==========================================================================

btccs_PreSelectedInputs* btccs_preselected_inputs_create(void)
{
    try {
        return new btccs_PreSelectedInputs();
    } catch (...) {
        return nullptr;
    }
}

void btccs_preselected_inputs_add(
    btccs_PreSelectedInputs* inputs,
    const unsigned char txid[32],
    uint32_t vout,
    btccs_Amount value,
    int input_bytes,
    int depth,
    btccs_Amount fee,
    bool subtract_fee_outputs)
{
    uint256 hash;
    std::memcpy(hash.begin(), txid, 32);
    COutPoint outpoint(Txid::FromUint256(hash), vout);
    CTxOut txout(value, CScript());

    wallet::COutput output(outpoint, txout, depth, input_bytes,
                           /*solvable=*/true, /*safe=*/true, /*time=*/0, /*from_me=*/false, fee);

    inputs->inputs.Insert(output, subtract_fee_outputs);
}

btccs_Amount btccs_preselected_inputs_get_total(const btccs_PreSelectedInputs* inputs)
{
    return inputs->inputs.total_amount;
}

void btccs_preselected_inputs_destroy(btccs_PreSelectedInputs* inputs)
{
    delete inputs;
}

// ==========================================================================
// Coin Control Implementation
// ==========================================================================

btccs_CoinControl* btccs_coin_control_create(void)
{
    try {
        return new btccs_CoinControl();
    } catch (...) {
        return nullptr;
    }
}

void btccs_coin_control_set_allow_other_inputs(btccs_CoinControl* coin_control, bool allow)
{
    coin_control->control.m_allow_other_inputs = allow;
}

void btccs_coin_control_set_include_unsafe_inputs(btccs_CoinControl* coin_control, bool include)
{
    coin_control->control.m_include_unsafe_inputs = include;
}

void btccs_coin_control_set_avoid_partial_spends(btccs_CoinControl* coin_control, bool avoid)
{
    coin_control->control.m_avoid_partial_spends = avoid;
}

void btccs_coin_control_destroy(btccs_CoinControl* coin_control)
{
    delete coin_control;
}

// ==========================================================================
// Coin Selection Params Implementation
// ==========================================================================

btccs_CoinSelectionParams* btccs_coin_selection_params_create(
    btccs_RandomContext* rng,
    int change_output_size,
    int change_spend_size,
    btccs_Amount min_change_target,
    int64_t effective_feerate_sat_per_kvb,
    int64_t long_term_feerate_sat_per_kvb,
    int64_t discard_feerate_sat_per_kvb,
    int tx_noinputs_size,
    bool avoid_partial_spends)
{
    try {
        return new btccs_CoinSelectionParams(
            &rng->rng,
            change_output_size,
            change_spend_size,
            min_change_target,
            CFeeRate(effective_feerate_sat_per_kvb),
            CFeeRate(long_term_feerate_sat_per_kvb),
            CFeeRate(discard_feerate_sat_per_kvb),
            tx_noinputs_size,
            avoid_partial_spends);
    } catch (...) {
        return nullptr;
    }
}

void btccs_coin_selection_params_set_subtract_fee_outputs(
    btccs_CoinSelectionParams* params,
    bool subtract)
{
    params->params->m_subtract_fee_outputs = subtract;
}

void btccs_coin_selection_params_set_max_tx_weight(
    btccs_CoinSelectionParams* params,
    int max_weight)
{
    params->params->m_max_tx_weight = max_weight;
}

void btccs_coin_selection_params_destroy(btccs_CoinSelectionParams* params)
{
    delete params;
}

// ==========================================================================
// Random Context Implementation
// ==========================================================================

btccs_RandomContext* btccs_random_context_create(void)
{
    return new btccs_RandomContext();
}

btccs_RandomContext* btccs_random_context_create_seeded(const unsigned char seed[32])
{
    uint256 hash;
    std::memcpy(hash.begin(), seed, 32);
    return new btccs_RandomContext(hash);
}

void btccs_random_context_destroy(btccs_RandomContext* rng)
{
    delete rng;
}

// ==========================================================================
// Individual Coin Selection Algorithms
// ==========================================================================

btccs_SelectionResult* btccs_select_coins_bnb(
    btccs_UtxoPool* pool,
    btccs_Amount selection_target,
    btccs_Amount cost_of_change,
    int max_weight,
    btccs_SelectionStatus* status)
{
    try {
        std::vector<wallet::OutputGroup> groups = pool->groups;

        auto result = wallet::SelectCoinsBnB(groups, selection_target, cost_of_change, max_weight);
        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        const CAmount waste = ComputeWasteFromPool(*result, pool);

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result), btccs_SelectionAlgorithm_BNB, waste);
    } catch (...) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

btccs_SelectionResult* btccs_select_coins_srd(
    btccs_UtxoPool* pool,
    btccs_Amount target_value,
    btccs_Amount change_fee,
    btccs_RandomContext* rng,
    int max_weight,
    btccs_SelectionStatus* status)
{
    try {
        std::vector<wallet::OutputGroup> groups = pool->groups;

        auto result = wallet::SelectCoinsSRD(groups, target_value, change_fee, rng->rng, max_weight);
        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        const CAmount waste = ComputeWasteFromPool(*result, pool);

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result), btccs_SelectionAlgorithm_SRD, waste);
    } catch (...) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

btccs_SelectionResult* btccs_select_coins_coingrinder(
    btccs_UtxoPool* pool,
    btccs_Amount selection_target,
    btccs_Amount change_target,
    int max_weight,
    btccs_SelectionStatus* status)
{
    try {
        std::vector<wallet::OutputGroup> groups = pool->groups;

        auto result = wallet::CoinGrinder(groups, selection_target, change_target, max_weight);
        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        const CAmount waste = ComputeWasteFromPool(*result, pool);

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result), btccs_SelectionAlgorithm_COINGRINDER, waste);
    } catch (...) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

btccs_SelectionResult* btccs_select_coins_knapsack(
    btccs_UtxoPool* pool,
    btccs_Amount target_value,
    btccs_Amount change_target,
    btccs_RandomContext* rng,
    int max_weight,
    btccs_SelectionStatus* status)
{
    try {
        std::vector<wallet::OutputGroup> groups = pool->groups;

        auto result = wallet::KnapsackSolver(groups, target_value, change_target, rng->rng, max_weight);
        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        const CAmount waste = ComputeWasteFromPool(*result, pool);

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result), btccs_SelectionAlgorithm_KNAPSACK, waste);
    } catch (...) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

// ==========================================================================
// Full Coin Selection (SelectCoins)
// ==========================================================================

btccs_SelectionResult* btccs_select_coins(
    btccs_CoinSelectionSource* source,
    btccs_CoinSelectionOptions options,
    btccs_CoinsResult* available_coins,
    btccs_PreSelectedInputs* pre_set_inputs,
    btccs_Amount target_value,
    btccs_CoinControl* coin_control,
    btccs_CoinSelectionParams* params,
    btccs_SelectionStatus* status)
{
    try {
        wallet::CoinSelectionOptions opts(options.spend_zero_conf_change, options.reject_long_chains);

        auto result = wallet::SelectCoins(
            *source,
            opts,
            available_coins->coins,
            pre_set_inputs->inputs,
            target_value,
            coin_control->control,
            *params->params);

        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result));
    } catch (...) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

btccs_SelectionResult* btccs_automatic_coin_selection(
    btccs_CoinSelectionSource* source,
    btccs_CoinSelectionOptions options,
    btccs_CoinsResult* available_coins,
    btccs_Amount target_value,
    btccs_CoinSelectionParams* params,
    btccs_SelectionStatus* status)
{
    try {
        wallet::CoinSelectionOptions opts(options.spend_zero_conf_change, options.reject_long_chains);

        auto result = wallet::AutomaticCoinSelection(
            *source,
            opts,
            available_coins->coins,
            target_value,
            *params->params);

        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result));
    } catch (...) {
        if (status) *status = btccs_SelectionStatus_INTERNAL_ERROR;
        return nullptr;
    }
}

// ==========================================================================
// Selection Result Implementation
// ==========================================================================

size_t btccs_selection_result_get_input_count(const btccs_SelectionResult* result)
{
    return result->result.GetInputSet().size();
}

btccs_Amount btccs_selection_result_get_selected_value(const btccs_SelectionResult* result)
{
    return result->result.GetSelectedValue();
}

btccs_Amount btccs_selection_result_get_selected_effective_value(const btccs_SelectionResult* result)
{
    return result->result.GetSelectedEffectiveValue();
}

btccs_Amount btccs_selection_result_get_waste(const btccs_SelectionResult* result)
{
    return result->waste;
}

int btccs_selection_result_get_weight(const btccs_SelectionResult* result)
{
    return result->result.GetWeight();
}

btccs_SelectionAlgorithm btccs_selection_result_get_algorithm(const btccs_SelectionResult* result)
{
    return result->algorithm;
}

btccs_Amount btccs_selection_result_get_change(
    const btccs_SelectionResult* result,
    btccs_Amount min_viable_change,
    btccs_Amount change_fee)
{
    return result->result.GetChange(min_viable_change, change_fee);
}

int btccs_selection_result_get_input_outpoint(
    const btccs_SelectionResult* result,
    size_t index,
    unsigned char txid_out[32],
    uint32_t* vout_out)
{
    const auto& inputs = result->result.GetInputSet();
    if (index >= inputs.size()) return -1;

    auto it = inputs.begin();
    std::advance(it, index);

    std::memcpy(txid_out, (*it)->outpoint.hash.begin(), 32);
    *vout_out = (*it)->outpoint.n;
    return 0;
}

void btccs_selection_result_destroy(btccs_SelectionResult* result)
{
    delete result;
}

// ==========================================================================
// Utility Functions
// ==========================================================================

int btccs_get_max_standard_tx_weight(void)
{
    return MAX_STANDARD_TX_WEIGHT;
}

int btccs_get_input_weight(int input_bytes)
{
    return input_bytes * WITNESS_SCALE_FACTOR;
}

btccs_Amount btccs_calculate_cost_of_change(
    int64_t feerate_sat_per_kvb,
    size_t change_output_size,
    size_t change_spend_size)
{
    CFeeRate feerate(feerate_sat_per_kvb);
    CFeeRate discard_rate(3000); // Default 3 sat/vB discard rate
    return feerate.GetFee(change_output_size) + discard_rate.GetFee(change_spend_size);
}

btccs_Amount btccs_calculate_cost_of_change_ex(
    int64_t feerate_sat_per_kvb,
    int64_t discard_feerate_sat_per_kvb,
    size_t change_output_size,
    size_t change_spend_size)
{
    CFeeRate feerate(feerate_sat_per_kvb);
    CFeeRate discard_rate(discard_feerate_sat_per_kvb);
    return feerate.GetFee(change_output_size) + discard_rate.GetFee(change_spend_size);
}

btccs_Amount btccs_generate_change_target(
    btccs_Amount payment_value,
    btccs_Amount change_fee,
    btccs_RandomContext* rng)
{
    return wallet::GenerateChangeTarget(payment_value, change_fee, rng->rng);
}

const char* btccs_version(void)
{
    return BTCCS_VERSION;
}

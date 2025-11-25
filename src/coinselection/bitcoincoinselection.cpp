// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINCOINSELECTION_BUILD

#include <coinselection/bitcoincoinselection.h>

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <uint256.h>
#include <wallet/coinselection.h>

#include <cstring>
#include <memory>
#include <vector>

// Required for translation function symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const char* BTCCS_VERSION = "0.2.0";

// ==========================================================================
// Internal: UTXO Pool - stores OutputGroups directly
// ==========================================================================

struct btccs_UtxoPool {
    std::vector<wallet::OutputGroup> groups;

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
    }
};

// ==========================================================================
// Internal: Selection Result wrapper
// ==========================================================================

struct btccs_SelectionResult {
    wallet::SelectionResult result;
    btccs_SelectionAlgorithm algorithm;

    btccs_SelectionResult(wallet::SelectionResult&& r, btccs_SelectionAlgorithm algo)
        : result(std::move(r)), algorithm(algo) {}
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
    // pool and txid are marked nonnull - caller must ensure they're valid
    uint256 hash;
    std::memcpy(hash.begin(), txid, 32);
    COutPoint outpoint(Txid::FromUint256(hash), vout);

    pool->AddUtxo(outpoint, value, input_bytes, depth, fee, long_term_fee);
}

size_t btccs_utxo_pool_size(const btccs_UtxoPool* pool)
{
    // pool is marked nonnull
    return pool->groups.size();
}

void btccs_utxo_pool_destroy(btccs_UtxoPool* pool)
{
    delete pool;
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
    // seed is marked nonnull
    uint256 hash;
    std::memcpy(hash.begin(), seed, 32);
    return new btccs_RandomContext(hash);
}

void btccs_random_context_destroy(btccs_RandomContext* rng)
{
    delete rng;
}

// ==========================================================================
// Coin Selection Algorithms
// ==========================================================================

btccs_SelectionResult* btccs_select_coins_bnb(
    btccs_UtxoPool* pool,
    btccs_Amount selection_target,
    btccs_Amount cost_of_change,
    int max_weight,
    btccs_SelectionStatus* status)
{
    // pool is marked nonnull
    try {
        // Make a copy since BnB may modify the groups
        std::vector<wallet::OutputGroup> groups = pool->groups;

        auto result = wallet::SelectCoinsBnB(groups, selection_target, cost_of_change, max_weight);
        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result), btccs_SelectionAlgorithm_BNB);
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
    // pool and rng are marked nonnull
    try {
        std::vector<wallet::OutputGroup> groups = pool->groups;

        auto result = wallet::SelectCoinsSRD(groups, target_value, change_fee, rng->rng, max_weight);
        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result), btccs_SelectionAlgorithm_SRD);
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
    // pool is marked nonnull
    try {
        std::vector<wallet::OutputGroup> groups = pool->groups;

        auto result = wallet::CoinGrinder(groups, selection_target, change_target, max_weight);
        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result), btccs_SelectionAlgorithm_COINGRINDER);
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
    // pool and rng are marked nonnull
    try {
        std::vector<wallet::OutputGroup> groups = pool->groups;

        auto result = wallet::KnapsackSolver(groups, target_value, change_target, rng->rng, max_weight);
        if (!result) {
            if (status) *status = btccs_SelectionStatus_NO_SOLUTION_FOUND;
            return nullptr;
        }

        if (status) *status = btccs_SelectionStatus_SUCCESS;
        return new btccs_SelectionResult(std::move(*result), btccs_SelectionAlgorithm_KNAPSACK);
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
    // result is marked nonnull
    return result->result.GetInputSet().size();
}

btccs_Amount btccs_selection_result_get_selected_value(const btccs_SelectionResult* result)
{
    // result is marked nonnull
    CAmount total = 0;
    for (const auto& coin : result->result.GetInputSet()) {
        total += coin->txout.nValue;
    }
    return total;
}

btccs_Amount btccs_selection_result_get_selected_effective_value(const btccs_SelectionResult* result)
{
    // result is marked nonnull
    CAmount total = 0;
    for (const auto& coin : result->result.GetInputSet()) {
        total += coin->GetEffectiveValue();
    }
    return total;
}

btccs_Amount btccs_selection_result_get_waste(const btccs_SelectionResult* result)
{
    // result is marked nonnull
    // Calculate basic waste: fee difference from long-term
    CAmount waste = 0;
    for (const auto& coin : result->result.GetInputSet()) {
        waste += coin->GetFee() - coin->long_term_fee;
    }
    return waste;
}

int btccs_selection_result_get_weight(const btccs_SelectionResult* result)
{
    // result is marked nonnull
    return result->result.GetWeight();
}

btccs_SelectionAlgorithm btccs_selection_result_get_algorithm(const btccs_SelectionResult* result)
{
    // result is marked nonnull
    return result->algorithm;
}

int btccs_selection_result_get_input_outpoint(
    const btccs_SelectionResult* result,
    size_t index,
    unsigned char txid_out[32],
    uint32_t* vout_out)
{
    // result, txid_out, vout_out are marked nonnull
    const auto& inputs = result->result.GetInputSet();
    if (index >= inputs.size()) return -1;

    // GetInputSet returns a set, need to iterate
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

btccs_Amount btccs_generate_change_target(
    btccs_Amount payment_value,
    btccs_Amount change_fee,
    btccs_RandomContext* rng)
{
    // rng is marked nonnull
    return wallet::GenerateChangeTarget(payment_value, change_fee, rng->rng);
}

const char* btccs_version(void)
{
    return BTCCS_VERSION;
}

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
#include <map>
#include <memory>
#include <vector>

// Required for translation function symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const char* BTCCS_VERSION = "0.2.0";

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
};

// ==========================================================================
// Internal: Random Context - wraps FastRandomContext
// ==========================================================================

struct btccs_RandomContext {
    FastRandomContext rng;

    btccs_RandomContext() : rng() {}
    explicit btccs_RandomContext(const uint256& seed) : rng(seed) {}
};

/**
 * Compute the C-API waste metric for a given SelectionResult using
 * the per-input fee information stored in the originating UTXO pool.
 *
 * The C-API defines waste as the sum over all selected inputs of
 * (fee_at_current_feerate - fee_at_long_term_feerate).
 *
 * This is intentionally a lightweight metric that does not try to
 * re-implement Bitcoin Core's internal SelectionResult::GetWaste()
 * logic (which may also account for change and other factors).
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
    // pool and rng are marked nonnull
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
    // pool is marked nonnull
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
    // pool and rng are marked nonnull
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

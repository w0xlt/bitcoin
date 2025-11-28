// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <common/args.h>
#include <common/messages.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <node/types.h>
#include <numeric>
#include <policy/policy.h>
#include <policy/truc_policy.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/trace.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

#include <cmath>

using common::StringForFeeReason;
using common::TransactionErrorString;
using interfaces::FoundBlock;
using node::TransactionError;

TRACEPOINT_SEMAPHORE(coin_selection, selected_coins);
TRACEPOINT_SEMAPHORE(coin_selection, normal_create_tx_internal);
TRACEPOINT_SEMAPHORE(coin_selection, attempting_aps_create_tx);
TRACEPOINT_SEMAPHORE(coin_selection, aps_create_tx_internal);

namespace wallet {
static constexpr size_t OUTPUT_GROUP_MAX_ENTRIES{100};

namespace {

/** Adapter to use interfaces::Chain as a CoinSelectionSource. */
class ChainCoinSelectionSource final : public CoinSelectionSource
{
    interfaces::Chain& m_chain;

public:
    explicit ChainCoinSelectionSource(interfaces::Chain& chain) : m_chain(chain) {}

    void GetTransactionAncestry(const Txid& txid,
                                size_t& ancestors,
                                size_t& descendants) const override
    {
        m_chain.getTransactionAncestry(txid, ancestors, descendants);
    }

    std::optional<CAmount> CalculateCombinedBumpFee(
        const std::vector<COutPoint>& outpoints,
        const CFeeRate& feerate) const override
    {
        return m_chain.calculateCombinedBumpFee(outpoints, feerate);
    }

    void GetPackageLimits(unsigned int& limit_ancestor_count,
                          unsigned int& limit_descendant_count) const override
    {
        m_chain.getPackageLimits(limit_ancestor_count, limit_descendant_count);
    }
};

// Returns true if the result contains an error and the message is not empty
static bool HasErrorMsg(const util::Result<SelectionResult>& res)
{
    return !util::ErrorString(res).empty();
}

} // namespace

/** Whether the descriptor represents, directly or not, a witness program. */
static bool IsSegwit(const Descriptor& desc)
{
    if (const auto typ = desc.GetOutputType()) return *typ != OutputType::LEGACY;
    return false;
}

/** Whether to assume ECDSA signatures' will be high-r. */
static bool UseMaxSig(const std::optional<CTxIn>& txin, const CCoinControl* coin_control)
{
    return coin_control && txin && coin_control->IsExternalSelected(txin->prevout);
}

static std::optional<int64_t> MaxInputWeight(const Descriptor& desc,
                                             const std::optional<CTxIn>& txin,
                                             const CCoinControl* coin_control,
                                             const bool tx_is_segwit,
                                             const bool can_grind_r)
{
    if (const auto sat_weight =
            desc.MaxSatisfactionWeight(!can_grind_r || UseMaxSig(txin, coin_control))) {
        if (const auto elems_count = desc.MaxSatisfactionElems()) {
            const bool is_segwit = IsSegwit(desc);
            const int64_t scriptsig_len =
                is_segwit ? 1 : GetSizeOfCompactSize(*sat_weight / WITNESS_SCALE_FACTOR);
            const int64_t witstack_len =
                is_segwit ? GetSizeOfCompactSize(*elems_count) : (tx_is_segwit ? 1 : 0);
            return (32 + 4 + 4 + scriptsig_len) * WITNESS_SCALE_FACTOR + witstack_len +
                   *sat_weight;
        }
    }

    return {};
}

int CalculateMaximumSignedInputSize(const CTxOut& txout,
                                    const COutPoint outpoint,
                                    const SigningProvider* provider,
                                    bool can_grind_r,
                                    const CCoinControl* coin_control)
{
    if (!provider) return -1;

    if (const auto desc = InferDescriptor(txout.scriptPubKey, *provider)) {
        if (const auto weight =
                MaxInputWeight(*desc, {}, coin_control, true, can_grind_r)) {
            return static_cast<int>(GetVirtualTransactionSize(*weight, 0, 0));
        }
    }

    return -1;
}

int CalculateMaximumSignedInputSize(const CTxOut& txout,
                                    const CWallet* wallet,
                                    const CCoinControl* coin_control)
{
    if (!wallet) return -1;
    const std::unique_ptr<SigningProvider> provider =
        wallet->GetSolvingProvider(txout.scriptPubKey);
    return CalculateMaximumSignedInputSize(txout, COutPoint(), provider.get(),
                                           wallet->CanGrindR(), coin_control);
}

/** Infer a descriptor for the given output script. */
static std::unique_ptr<Descriptor> GetDescriptor(const CWallet* wallet,
                                                 const CCoinControl* coin_control,
                                                 const CScript script_pubkey)
{
    MultiSigningProvider providers;
    for (const auto spkman : wallet->GetScriptPubKeyMans(script_pubkey)) {
        providers.AddProvider(spkman->GetSolvingProvider(script_pubkey));
    }
    if (coin_control) {
        providers.AddProvider(
            std::make_unique<FlatSigningProvider>(coin_control->m_external_provider));
    }
    return InferDescriptor(script_pubkey, providers);
}

/** Infer the maximum size of this input after it will be signed. */
static std::optional<int64_t> GetSignedTxinWeight(const CWallet* wallet,
                                                  const CCoinControl* coin_control,
                                                  const CTxIn& txin,
                                                  const CTxOut& txo,
                                                  const bool tx_is_segwit,
                                                  const bool can_grind_r)
{
    std::optional<int64_t> weight;
    if (coin_control && (weight = coin_control->GetInputWeight(txin.prevout))) {
        return weight.value();
    }

    std::unique_ptr<Descriptor> desc{
        GetDescriptor(wallet, coin_control, txo.scriptPubKey)};
    if (desc) return MaxInputWeight(*desc, {txin}, coin_control, tx_is_segwit, can_grind_r);

    return {};
}

TxSize CalculateMaximumSignedTxSize(const CTransaction& tx,
                                    const CWallet* wallet,
                                    const std::vector<CTxOut>& txouts,
                                    const CCoinControl* coin_control)
{
    int64_t weight = (4 + 4 + GetSizeOfCompactSize(tx.vin.size()) +
                      GetSizeOfCompactSize(tx.vout.size())) *
                     WITNESS_SCALE_FACTOR;

    bool is_segwit = std::any_of(
        txouts.begin(), txouts.end(), [&](const CTxOut& txo) {
            std::unique_ptr<Descriptor> desc{
                GetDescriptor(wallet, coin_control, txo.scriptPubKey)};
            if (desc) return IsSegwit(*desc);
            return false;
        });
    if (is_segwit) weight += 2;

    for (const auto& txo : tx.vout) {
        weight += GetSerializeSize(txo) * WITNESS_SCALE_FACTOR;
    }

    for (uint32_t i = 0; i < txouts.size(); i++) {
        const auto txin_weight =
            GetSignedTxinWeight(wallet, coin_control, tx.vin[i], txouts[i],
                                is_segwit, wallet->CanGrindR());
        if (!txin_weight) return TxSize{-1, -1};
        assert(*txin_weight > -1);
        weight += *txin_weight;
    }

    return TxSize{GetVirtualTransactionSize(weight, 0, 0), weight};
}

TxSize CalculateMaximumSignedTxSize(const CTransaction& tx,
                                    const CWallet* wallet,
                                    const CCoinControl* coin_control)
{
    std::vector<CTxOut> txouts;
    for (const CTxIn& input : tx.vin) {
        const auto mi = wallet->mapWallet.find(input.prevout.hash);
        if (mi != wallet->mapWallet.end()) {
            assert(input.prevout.n < mi->second.tx->vout.size());
            txouts.emplace_back(mi->second.tx->vout.at(input.prevout.n));
        } else if (coin_control) {
            const auto& txout{coin_control->GetExternalOutput(input.prevout)};
            if (!txout) return TxSize{-1, -1};
            txouts.emplace_back(*txout);
        } else {
            return TxSize{-1, -1};
        }
    }
    return CalculateMaximumSignedTxSize(tx, wallet, txouts, coin_control);
}

size_t CoinsResult::Size() const
{
    size_t size{0};
    for (const auto& it : coins) {
        size += it.second.size();
    }
    return size;
}

std::vector<COutput> CoinsResult::All() const
{
    std::vector<COutput> all;
    for (const auto& it : coins) {
        all.insert(all.end(), it.second.begin(), it.second.end());
    }
    return all;
}

void CoinsResult::Clear()
{
    coins.clear();
}

void CoinsResult::Erase(const std::unordered_set<COutPoint, SaltedOutpointHasher>& coins_to_remove)
{
    for (auto& [type, vec] : coins) {
        auto remove_it = std::remove_if(vec.begin(), vec.end(),
                                        [&](const COutput& coin) {
                                            if (coins_to_remove.count(coin.outpoint) == 0)
                                                return false;

                                            total_amount -= coin.txout.nValue;
                                            if (coin.HasEffectiveValue()) {
                                                total_effective_amount =
                                                    *total_effective_amount -
                                                    coin.GetEffectiveValue();
                                            }
                                            return true;
                                        });
        vec.erase(remove_it, vec.end());
    }
}

void CoinsResult::Shuffle(FastRandomContext& rng_fast)
{
    for (auto& it : coins) {
        std::shuffle(it.second.begin(), it.second.end(), rng_fast);
    }
}

void CoinsResult::Add(OutputType type, const COutput& out)
{
    coins[type].emplace_back(out);
    total_amount += out.txout.nValue;
    if (out.HasEffectiveValue()) {
        total_effective_amount = total_effective_amount.has_value()
                                     ? *total_effective_amount + out.GetEffectiveValue()
                                     : out.GetEffectiveValue();
    }
}

static OutputType GetOutputType(TxoutType type, bool is_from_p2sh)
{
    switch (type) {
    case TxoutType::WITNESS_V1_TAPROOT:
        return OutputType::BECH32M;
    case TxoutType::WITNESS_V0_KEYHASH:
    case TxoutType::WITNESS_V0_SCRIPTHASH:
        return is_from_p2sh ? OutputType::P2SH_SEGWIT : OutputType::BECH32;
    case TxoutType::SCRIPTHASH:
    case TxoutType::PUBKEYHASH:
        return OutputType::LEGACY;
    default:
        return OutputType::UNKNOWN;
    }
}

util::Result<PreSelectedInputs> FetchSelectedInputs(const CWallet& wallet,
                                                    const CCoinControl& coin_control,
                                                    const CoinSelectionParams& coin_selection_params)
{
    PreSelectedInputs result;
    const bool can_grind_r = wallet.CanGrindR();
    std::map<COutPoint, CAmount> map_of_bump_fees =
        wallet.chain().calculateIndividualBumpFees(
            coin_control.ListSelected(),
            coin_selection_params.m_effective_feerate);

    for (const COutPoint& outpoint : coin_control.ListSelected()) {
        int64_t input_bytes = coin_control.GetInputWeight(outpoint).value_or(-1);
        if (input_bytes != -1) {
            input_bytes = GetVirtualTransactionSize(input_bytes, 0, 0);
        }
        CTxOut txout;
        if (auto txo = wallet.GetTXO(outpoint)) {
            txout = txo->GetTxOut();
            if (input_bytes == -1) {
                input_bytes =
                    CalculateMaximumSignedInputSize(txout, &wallet, &coin_control);
            }
            const CWalletTx& parent_tx = txo->GetWalletTx();
            if (wallet.GetTxDepthInMainChain(parent_tx) == 0) {
                if (parent_tx.tx->version == TRUC_VERSION &&
                    coin_control.m_version != TRUC_VERSION) {
                    return util::Error{strprintf(
                        _("Can't spend unconfirmed version 3 pre-selected input with a "
                          "version %d tx"),
                        coin_control.m_version)};
                } else if (coin_control.m_version == TRUC_VERSION &&
                           parent_tx.tx->version != TRUC_VERSION) {
                    return util::Error{strprintf(
                        _("Can't spend unconfirmed version %d pre-selected input with a "
                          "version 3 tx"),
                        parent_tx.tx->version)};
                }
            }
        } else {
            const auto out{coin_control.GetExternalOutput(outpoint)};
            if (!out) {
                return util::Error{strprintf(
                    _("Not found pre-selected input %s"), outpoint.ToString())};
            }

            txout = *out;
        }

        if (input_bytes == -1) {
            input_bytes = CalculateMaximumSignedInputSize(
                txout, outpoint, &coin_control.m_external_provider,
                can_grind_r, &coin_control);
        }

        if (input_bytes == -1) {
            return util::Error{
                strprintf(_("Not solvable pre-selected input %s"),
                          outpoint.ToString())};
        }

        COutput output(outpoint, txout, /*depth=*/0, input_bytes,
                       /*solvable=*/true, /*safe=*/true,
                       /*time=*/0, /*from_me=*/false,
                       coin_selection_params.m_effective_feerate);
        output.ApplyBumpFee(map_of_bump_fees.at(output.outpoint));
        result.Insert(output, coin_selection_params.m_subtract_fee_outputs);
    }
    return result;
}

CoinsResult AvailableCoins(const CWallet& wallet,
                           const CCoinControl* coinControl,
                           std::optional<CFeeRate> feerate,
                           const CoinFilterParams& params)
{
    AssertLockHeld(wallet.cs_wallet);

    CoinsResult result;
    std::vector<std::pair<OutputType, COutput>> unconfirmed_truc_coins;
    std::unordered_map<Txid, CAmount, SaltedTxidHasher> truc_txid_by_value;

    bool allow_used_addresses =
        !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE) ||
        (coinControl && !coinControl->m_avoid_address_reuse);
    const int min_depth{coinControl ? coinControl->m_min_depth
                                    : DEFAULT_MIN_DEPTH};
    const int max_depth{coinControl ? coinControl->m_max_depth
                                    : DEFAULT_MAX_DEPTH};
    const bool only_safe{coinControl ? !coinControl->m_include_unsafe_inputs
                                     : true};
    const bool can_grind_r = wallet.CanGrindR();
    std::vector<COutPoint> outpoints;

    std::set<Txid> trusted_parents;
    std::unordered_map<Txid, std::pair<bool, bool>, SaltedTxidHasher> tx_safe_cache;

    for (const auto& [outpoint, txo] : wallet.GetTXOs()) {
        const CWalletTx& wtx = txo.GetWalletTx();
        const CTxOut& output = txo.GetTxOut();

        if (tx_safe_cache.contains(outpoint.hash) &&
            !tx_safe_cache.at(outpoint.hash).first) {
            continue;
        }

        int nDepth = wallet.GetTxDepthInMainChain(wtx);

        if (!tx_safe_cache.contains(outpoint.hash)) {
            tx_safe_cache[outpoint.hash] = {false, false};

            if (wallet.IsTxImmatureCoinBase(wtx) &&
                !params.include_immature_coinbase) {
                continue;
            }

            if (nDepth < 0) continue;

            if (nDepth == 0 && !wtx.InMempool()) continue;

            bool safeTx = CachedTxIsTrusted(wallet, wtx, trusted_parents);

            if (nDepth == 0 && wtx.mapValue.count("replaces_txid")) {
                safeTx = false;
            }

            if (nDepth == 0 && wtx.mapValue.count("replaced_by_txid")) {
                safeTx = false;
            }

            if (nDepth == 0 && params.check_version_trucness) {
                if (coinControl->m_version == TRUC_VERSION) {
                    if (wtx.tx->version != TRUC_VERSION) continue;
                    if (wtx.truc_child_in_mempool.has_value()) continue;
                } else {
                    if (wtx.tx->version == TRUC_VERSION) continue;
                    Assume(!wtx.truc_child_in_mempool.has_value());
                }
            }

            if (only_safe && !safeTx) {
                continue;
            }

            if (nDepth < min_depth || nDepth > max_depth) {
                continue;
            }

            tx_safe_cache[outpoint.hash] = {true, safeTx};
        }
        const auto& [tx_ok, tx_safe] = tx_safe_cache.at(outpoint.hash);
        if (!Assume(tx_ok)) continue;

        if (output.nValue < params.min_amount ||
            output.nValue > params.max_amount) {
            continue;
        }

        if (coinControl && coinControl->HasSelected() &&
            coinControl->IsSelected(outpoint)) {
            continue;
        }

        if (wallet.IsLockedCoin(outpoint) && params.skip_locked) continue;
        if (wallet.IsSpent(outpoint)) continue;
        if (!allow_used_addresses && wallet.IsSpentKey(output.scriptPubKey)) {
            continue;
        }

        bool tx_from_me = CachedTxIsFromMe(wallet, wtx);

        std::unique_ptr<SigningProvider> provider =
            wallet.GetSolvingProvider(output.scriptPubKey);

        int input_bytes = CalculateMaximumSignedInputSize(
            output, COutPoint(), provider.get(), can_grind_r, coinControl);
        bool solvable = input_bytes > -1;

        std::vector<std::vector<uint8_t>> script_solutions;
        TxoutType type = Solver(output.scriptPubKey, script_solutions);

        bool is_from_p2sh{false};
        if (type == TxoutType::SCRIPTHASH && solvable) {
            CScript script;
            if (!provider->GetCScript(
                    CScriptID(uint160(script_solutions[0])), script)) {
                continue;
            }
            type = Solver(script, script_solutions);
            is_from_p2sh = true;
        }

        auto available_output_type = GetOutputType(type, is_from_p2sh);
        auto available_output =
            COutput(outpoint, output, nDepth, input_bytes, solvable, tx_safe,
                    wtx.GetTxTime(), tx_from_me, feerate);

        if (wtx.tx->version == TRUC_VERSION && nDepth == 0 &&
            params.check_version_trucness) {
            unconfirmed_truc_coins.emplace_back(available_output_type,
                                                available_output);
            auto [it, _] = truc_txid_by_value.try_emplace(wtx.tx->GetHash(), 0);
            it->second += output.nValue;
        } else {
            result.Add(available_output_type, available_output);
        }

        outpoints.push_back(outpoint);

        if (params.min_sum_amount != MAX_MONEY) {
            if (result.GetTotalAmount() >= params.min_sum_amount) {
                return result;
            }
        }

        if (params.max_count > 0 && result.Size() >= params.max_count) {
            return result;
        }
    }

    if (params.check_version_trucness && !unconfirmed_truc_coins.empty()) {
        auto highest_value_truc_tx = std::max_element(
            truc_txid_by_value.begin(), truc_txid_by_value.end(),
            [](const auto& tx1, const auto& tx2) {
                return tx1.second < tx2.second;
            });

        const Txid& truc_txid = highest_value_truc_tx->first;
        for (const auto& [type, output] : unconfirmed_truc_coins) {
            if (output.outpoint.hash == truc_txid) {
                result.Add(type, output);
            }
        }
    }

    if (feerate.has_value()) {
        std::map<COutPoint, CAmount> map_of_bump_fees =
            wallet.chain().calculateIndividualBumpFees(outpoints, *feerate);

        for (auto& [_, outputs] : result.coins) {
            for (auto& output : outputs) {
                output.ApplyBumpFee(map_of_bump_fees.at(output.outpoint));
            }
        }
    }

    return result;
}

const CTxOut& FindNonChangeParentOutput(const CWallet& wallet,
                                        const COutPoint& outpoint)
{
    AssertLockHeld(wallet.cs_wallet);
    const CWalletTx* wtx{Assert(wallet.GetWalletTx(outpoint.hash))};

    const CTransaction* ptx = wtx->tx.get();
    int n = outpoint.n;
    while (OutputIsChange(wallet, ptx->vout[n]) && !ptx->vin.empty()) {
        const COutPoint& prevout = ptx->vin[0].prevout;
        const CWalletTx* it = wallet.GetWalletTx(prevout.hash);
        if (!it || it->tx->vout.size() <= prevout.n ||
            !wallet.IsMine(it->tx->vout[prevout.n])) {
            break;
        }
        ptx = it->tx.get();
        n = prevout.n;
    }
    return ptx->vout[n];
}

std::map<CTxDestination, std::vector<COutput>> ListCoins(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    std::map<CTxDestination, std::vector<COutput>> result;

    CCoinControl coin_control;
    CoinFilterParams coins_params;
    coins_params.skip_locked = false;
    for (const COutput& coin :
         AvailableCoins(wallet, &coin_control, /*feerate=*/std::nullopt,
                        coins_params)
             .All()) {
        CTxDestination address;
        if (!ExtractDestination(
                FindNonChangeParentOutput(wallet, coin.outpoint).scriptPubKey,
                address)) {
            if (auto pk_dest = std::get_if<PubKeyDestination>(&address)) {
                address = PKHash(pk_dest->GetPubKey());
            } else {
                continue;
            }
        }
        result[address].emplace_back(coin);
    }
    return result;
}

FilteredOutputGroups GroupOutputs(const CoinSelectionSource& source,
                                  const CoinsResult& coins,
                                  const CoinSelectionParams& coin_sel_params,
                                  const std::vector<SelectionFilter>& filters,
                                  std::vector<OutputGroup>& ret_discarded_groups)
{
    FilteredOutputGroups filtered_groups;

    if (!coin_sel_params.m_avoid_partial_spends) {
        // No partial-spend avoidance: each COutput gets its own OutputGroup
        for (const auto& [type, outputs] : coins.coins) {
            for (const COutput& output : outputs) {
                size_t ancestors{0}, descendants{0};
                source.GetTransactionAncestry(output.outpoint.hash,
                                              ancestors, descendants);

                OutputGroup group(coin_sel_params);
                group.Insert(std::make_shared<COutput>(output),
                             ancestors, descendants);

                bool accepted = false;
                for (const auto& sel_filter : filters) {
                    const auto& filter = sel_filter.filter;
                    if (!group.EligibleForSpending(filter)) continue;
                    filtered_groups[filter].Push(
                        group, type,
                        /*insert_positive=*/true,
                        /*insert_mixed=*/true);
                    accepted = true;
                }
                if (!accepted) ret_discarded_groups.emplace_back(group);
            }
        }
        return filtered_groups;
    }

    using ScriptPubKeyToOutgroup =
        std::map<std::pair<CScript, OutputType>, std::vector<OutputGroup>>;

    const auto insert_output =
        [&](const std::shared_ptr<COutput>& output,
            OutputType type,
            size_t ancestors,
            size_t descendants,
            ScriptPubKeyToOutgroup& groups_map) {
            std::vector<OutputGroup>& groups =
                groups_map[std::make_pair(output->txout.scriptPubKey, type)];

            if (groups.empty()) {
                groups.emplace_back(coin_sel_params);
            }

            OutputGroup* group = &groups.back();

            if (group->m_outputs.size() >= OUTPUT_GROUP_MAX_ENTRIES) {
                groups.emplace_back(coin_sel_params);
                group = &groups.back();
            }

            group->Insert(output, ancestors, descendants);
        };

    ScriptPubKeyToOutgroup spk_to_groups_map;
    ScriptPubKeyToOutgroup spk_to_positive_groups_map;

    for (const auto& [type, outs] : coins.coins) {
        for (const COutput& output : outs) {
            size_t ancestors{0}, descendants{0};
            source.GetTransactionAncestry(output.outpoint.hash,
                                          ancestors, descendants);

            const auto shared_output = std::make_shared<COutput>(output);

            if (output.GetEffectiveValue() > 0) {
                insert_output(shared_output, type, ancestors, descendants,
                              spk_to_positive_groups_map);
            }

            insert_output(shared_output, type, ancestors, descendants,
                          spk_to_groups_map);
        }
    }

    const auto push_output_groups =
        [&](const ScriptPubKeyToOutgroup& groups_map, bool positive_only) {
            for (const auto& [script_and_type, groups] : groups_map) {
                const OutputType type = script_and_type.second;

                for (auto group_it = groups.rbegin();
                     group_it != groups.rend(); ++group_it) {
                    const OutputGroup& group = *group_it;

                    bool accepted = false;
                    for (const auto& sel_filter : filters) {
                        const auto& filter = sel_filter.filter;
                        if (!group.EligibleForSpending(filter)) continue;

                        if (group_it == groups.rbegin() &&
                            groups.size() > 1 &&
                            !filter.m_include_partial_groups) {
                            continue;
                        }

                        filtered_groups[filter].Push(
                            group, type,
                            /*insert_positive=*/positive_only,
                            /*insert_mixed=*/!positive_only);
                        accepted = true;
                    }
                    if (!accepted) ret_discarded_groups.emplace_back(group);
                }
            }
        };

    // Order matches original behaviour: mixed groups first, then positive-only.
    push_output_groups(spk_to_groups_map, /*positive_only=*/false);
    push_output_groups(spk_to_positive_groups_map, /*positive_only=*/true);

    return filtered_groups;
}

FilteredOutputGroups GroupOutputs(const CoinSelectionSource& source,
                                  const CoinsResult& coins,
                                  const CoinSelectionParams& coin_sel_params,
                                  const std::vector<SelectionFilter>& filters)
{
    std::vector<OutputGroup> unused;
    return GroupOutputs(source, coins, coin_sel_params, filters, unused);
}

FilteredOutputGroups GroupOutputs(const CWallet& wallet,
                                  const CoinsResult& coins,
                                  const CoinSelectionParams& coin_sel_params,
                                  const std::vector<SelectionFilter>& filters)
{
    CWalletCoinSelectionSource source(wallet);
    return GroupOutputs(source, coins, coin_sel_params, filters);
}

util::Result<SelectionResult> AttemptSelection(const CoinSelectionSource& source,
                                               const CAmount& nTargetValue,
                                               OutputGroupTypeMap& groups,
                                               const CoinSelectionParams& coin_selection_params,
                                               bool allow_mixed_output_types)
{
    std::vector<SelectionResult> results;

    for (auto& [type, group] : groups.groups_by_type) {
        auto result =
            ChooseSelectionResult(source, nTargetValue, group, coin_selection_params);
        if (HasErrorMsg(result)) return result;
        if (result) results.push_back(*result);
    }

    if (!results.empty()) {
        return *std::min_element(results.begin(), results.end());
    }

    if (allow_mixed_output_types && groups.TypesCount() > 1) {
        return ChooseSelectionResult(source, nTargetValue,
                                     groups.all_groups, coin_selection_params);
    }

    return util::Error();
}

util::Result<SelectionResult> AttemptSelection(interfaces::Chain& chain,
                                               const CAmount& nTargetValue,
                                               OutputGroupTypeMap& groups,
                                               const CoinSelectionParams& coin_selection_params,
                                               bool allow_mixed_output_types)
{
    ChainCoinSelectionSource source(chain);
    return AttemptSelection(source, nTargetValue, groups,
                            coin_selection_params, allow_mixed_output_types);
}

util::Result<SelectionResult> ChooseSelectionResult(const CoinSelectionSource& source,
                                                    const CAmount& nTargetValue,
                                                    Groups& groups,
                                                    const CoinSelectionParams& coin_selection_params)
{
    std::vector<SelectionResult> results;
    std::vector<util::Result<SelectionResult>> errors;

    auto append_error = [&](util::Result<SelectionResult>&& result) {
        if (HasErrorMsg(result)) {
            errors.emplace_back(std::move(result));
        }
    };

    int max_transaction_weight =
        coin_selection_params.m_max_tx_weight.value_or(MAX_STANDARD_TX_WEIGHT);
    int tx_weight_no_input =
        coin_selection_params.tx_noinputs_size * WITNESS_SCALE_FACTOR;
    int max_selection_weight = max_transaction_weight - tx_weight_no_input;
    if (max_selection_weight <= 0) {
        return util::Error{
            _("Maximum transaction weight is less than transaction weight "
              "without inputs")};
    }

    if (!coin_selection_params.m_subtract_fee_outputs) {
        auto bnb_result = SelectCoinsBnB(
            groups.positive_group,
            nTargetValue,
            coin_selection_params.m_cost_of_change,
            max_selection_weight);
        if (bnb_result) {
            results.push_back(*bnb_result);
        } else {
            append_error(std::move(bnb_result));
        }
    }

    int change_outputs_weight =
        coin_selection_params.change_output_size * WITNESS_SCALE_FACTOR;
    max_selection_weight -= change_outputs_weight;
    if (max_selection_weight < 0 && results.empty()) {
        return util::Error{
            _("Maximum transaction weight is too low, can not accommodate "
              "change output")};
    }

    {
        auto knapsack_result = KnapsackSolver(
            groups.mixed_group, nTargetValue,
            coin_selection_params.m_min_change_target,
            coin_selection_params.rng_fast,
            max_selection_weight);
        if (knapsack_result) {
            results.push_back(*knapsack_result);
        } else {
            append_error(std::move(knapsack_result));
        }
    }

    if (coin_selection_params.m_effective_feerate >
        CFeeRate{3 * coin_selection_params.m_long_term_feerate}) {
        auto cg_result = CoinGrinder(
            groups.positive_group, nTargetValue,
            coin_selection_params.m_min_change_target,
            max_selection_weight);
        if (cg_result) {
            cg_result->RecalculateWaste(
                coin_selection_params.min_viable_change,
                coin_selection_params.m_cost_of_change,
                coin_selection_params.m_change_fee);
            results.push_back(*cg_result);
        } else {
            append_error(std::move(cg_result));
        }
    }

    {
        auto srd_result = SelectCoinsSRD(
            groups.positive_group, nTargetValue,
            coin_selection_params.m_change_fee,
            coin_selection_params.rng_fast,
            max_selection_weight);
        if (srd_result) {
            results.push_back(*srd_result);
        } else {
            append_error(std::move(srd_result));
        }
    }

    if (results.empty()) {
        return errors.empty() ? util::Error() : std::move(errors.front());
    }

    for (auto& result : results) {
        std::vector<COutPoint> outpoints;
        std::set<std::shared_ptr<COutput>> coins = result.GetInputSet();
        CAmount summed_bump_fees{0};
        for (auto& coin : coins) {
            if (coin->depth > 0) continue;
            outpoints.push_back(coin->outpoint);
            summed_bump_fees += coin->ancestor_bump_fees;
        }

        std::optional<CAmount> combined_bump_fee =
            source.CalculateCombinedBumpFee(outpoints,
                                            coin_selection_params.m_effective_feerate);
        if (!combined_bump_fee.has_value()) {
            return util::Error{
                _("Failed to calculate bump fees, because unconfirmed UTXOs "
                  "depend on an enormous cluster of unconfirmed transactions.")};
        }
        CAmount bump_fee_overestimate =
            summed_bump_fees - combined_bump_fee.value();
        if (bump_fee_overestimate) {
            result.SetBumpFeeDiscount(bump_fee_overestimate);
        }
        result.RecalculateWaste(coin_selection_params.min_viable_change,
                                coin_selection_params.m_cost_of_change,
                                coin_selection_params.m_change_fee);
    }

    return *std::min_element(results.begin(), results.end());
}

util::Result<SelectionResult> ChooseSelectionResult(interfaces::Chain& chain,
                                                    const CAmount& nTargetValue,
                                                    Groups& groups,
                                                    const CoinSelectionParams& coin_selection_params)
{
    ChainCoinSelectionSource source(chain);
    return ChooseSelectionResult(source, nTargetValue, groups, coin_selection_params);
}

util::Result<SelectionResult> AutomaticCoinSelection(const CoinSelectionSource& source,
                                                     const CoinSelectionOptions& options,
                                                     CoinsResult& available_coins,
                                                     const CAmount& value_to_select,
                                                     const CoinSelectionParams& coin_selection_params)
{
    unsigned int limit_ancestor_count{0};
    unsigned int limit_descendant_count{0};
    source.GetPackageLimits(limit_ancestor_count, limit_descendant_count);
    const size_t max_ancestors =
        static_cast<size_t>(std::max<int64_t>(1, limit_ancestor_count));
    const size_t max_descendants =
        static_cast<size_t>(std::max<int64_t>(1, limit_descendant_count));
    const bool fRejectLongChains = options.reject_long_chains;

    if (coin_selection_params.m_avoid_partial_spends &&
        available_coins.Size() > OUTPUT_GROUP_MAX_ENTRIES) {
        available_coins.Shuffle(coin_selection_params.rng_fast);
    }

    std::vector<SelectionFilter> ordered_filters{
        {CoinEligibilityFilter(1, 6, 0), /*allow_mixed_output_types=*/false},
        {CoinEligibilityFilter(1, 1, 0)},
    };

    if (options.spend_zero_conf_change) {
        ordered_filters.push_back({CoinEligibilityFilter(0, 1, 2)});
        ordered_filters.push_back({CoinEligibilityFilter(
            0, 1,
            std::min<size_t>(4, max_ancestors / 3),
            std::min<size_t>(4, max_descendants / 3))});
        ordered_filters.push_back({CoinEligibilityFilter(
            0, 1, max_ancestors / 2, max_descendants / 2)});
        ordered_filters.push_back({CoinEligibilityFilter(
            0, 1, max_ancestors - 1, max_descendants - 1,
            /*include_partial=*/true)});
        if (coin_selection_params.m_include_unsafe_inputs) {
            ordered_filters.push_back({CoinEligibilityFilter(
                /*conf_mine=*/0,
                /*conf_theirs=*/0,
                max_ancestors - 1,
                max_descendants - 1,
                /*include_partial=*/true)});
        }
        if (!fRejectLongChains) {
            ordered_filters.push_back({CoinEligibilityFilter(
                0, 1,
                std::numeric_limits<uint64_t>::max(),
                std::numeric_limits<uint64_t>::max(),
                /*include_partial=*/true)});
        }
    }

    std::vector<OutputGroup> discarded_groups;
    FilteredOutputGroups filtered_groups =
        GroupOutputs(source, available_coins, coin_selection_params,
                     ordered_filters, discarded_groups);

    CAmount total_discarded{0};
    CAmount total_unconf_long_chain{0};
    for (const auto& group : discarded_groups) {
        total_discarded += group.GetSelectionAmount();
        if (group.m_ancestors >= max_ancestors ||
            group.m_descendants >= max_descendants) {
            total_unconf_long_chain += group.GetSelectionAmount();
        }
    }

    const CAmount total_amount =
        available_coins.GetTotalAmount() - total_discarded;
    if (total_amount < value_to_select) {
        if (total_amount + total_unconf_long_chain > value_to_select) {
            return util::Error{
                _("Unconfirmed UTXOs are available, but spending them creates a "
                  "chain of transactions that will be rejected by the mempool")};
        }
        return util::Error();
    }

    std::vector<util::Result<SelectionResult>> res_detailed_errors;
    CoinSelectionParams updated_selection_params = coin_selection_params;

    for (const auto& select_filter : ordered_filters) {
        auto it = filtered_groups.find(select_filter.filter);
        if (it == filtered_groups.end()) continue;

        if (updated_selection_params.m_version == TRUC_VERSION &&
            (select_filter.filter.conf_mine == 0 ||
             select_filter.filter.conf_theirs == 0)) {
            if (!updated_selection_params.m_max_tx_weight ||
                *updated_selection_params.m_max_tx_weight > TRUC_CHILD_MAX_WEIGHT) {
                updated_selection_params.m_max_tx_weight = TRUC_CHILD_MAX_WEIGHT;
            }
        }

        auto res = AttemptSelection(source, value_to_select, it->second,
                                    updated_selection_params,
                                    select_filter.allow_mixed_output_types);
        if (res) {
            return res;
        }

        if (HasErrorMsg(res)) {
            res_detailed_errors.emplace_back(std::move(res));
        }
    }

    if (!res_detailed_errors.empty()) {
        return std::move(res_detailed_errors.front());
    }

    return util::Error();
}

util::Result<SelectionResult> AutomaticCoinSelection(const CWallet& wallet,
                                                     CoinsResult& available_coins,
                                                     const CAmount& nTargetValue,
                                                     const CoinSelectionParams& coin_selection_params)
{
    CWalletCoinSelectionSource source(wallet);
    CoinSelectionOptions options(
        wallet.m_spend_zero_conf_change,
        gArgs.GetBoolArg("-walletrejectlongchains",
                         DEFAULT_WALLET_REJECT_LONG_CHAINS));
    return AutomaticCoinSelection(source, options, available_coins,
                                  nTargetValue, coin_selection_params);
}

util::Result<SelectionResult> SelectCoins(const CoinSelectionSource& source,
                                          const CoinSelectionOptions& options,
                                          CoinsResult& available_coins,
                                          const PreSelectedInputs& pre_set_inputs,
                                          const CAmount& nTargetValue,
                                          const CCoinControl& coin_control,
                                          const CoinSelectionParams& coin_selection_params)
{
    CAmount selection_target = nTargetValue - pre_set_inputs.total_amount;

    if (!coin_control.m_allow_other_inputs && selection_target > 0) {
        return util::Error{
            _("The preselected coins total amount does not cover the "
              "transaction target. Please allow other inputs to be "
              "automatically selected or include more coins manually")};
    }

    if (selection_target <= 0) {
        SelectionResult result(nTargetValue, SelectionAlgorithm::MANUAL);
        result.AddInputs(pre_set_inputs.coins,
                         coin_selection_params.m_subtract_fee_outputs);
        result.RecalculateWaste(coin_selection_params.min_viable_change,
                                coin_selection_params.m_cost_of_change,
                                coin_selection_params.m_change_fee);
        return result;
    }

    const CAmount available_coins_total_amount =
        coin_selection_params.m_subtract_fee_outputs
            ? available_coins.GetTotalAmount()
            : (available_coins.GetEffectiveTotalAmount().has_value()
                   ? *available_coins.GetEffectiveTotalAmount()
                   : 0);

    if (selection_target > available_coins_total_amount) {
        return util::Error();
    }

    auto op_selection_result =
        AutomaticCoinSelection(source, options, available_coins,
                               selection_target, coin_selection_params);
    if (!op_selection_result) return op_selection_result;

    if (!pre_set_inputs.coins.empty()) {
        SelectionResult preselected(pre_set_inputs.total_amount,
                                    SelectionAlgorithm::MANUAL);
        preselected.AddInputs(pre_set_inputs.coins,
                              coin_selection_params.m_subtract_fee_outputs);
        op_selection_result->Merge(preselected);
        op_selection_result->RecalculateWaste(
            coin_selection_params.min_viable_change,
            coin_selection_params.m_cost_of_change,
            coin_selection_params.m_change_fee);

        int max_inputs_weight =
            coin_selection_params.m_max_tx_weight.value_or(
                MAX_STANDARD_TX_WEIGHT) -
            (coin_selection_params.tx_noinputs_size * WITNESS_SCALE_FACTOR);
        if (op_selection_result->GetWeight() > max_inputs_weight) {
            return util::Error{_("The combination of the pre-selected inputs and the wallet automatic inputs selection exceeds the transaction maximum weight. "
                "Please try sending a smaller amount or manually consolidating your wallet's UTXOs")};
        }
    }

    return op_selection_result;
}

util::Result<SelectionResult> SelectCoins(const CWallet& wallet,
                                          CoinsResult& available_coins,
                                          const PreSelectedInputs& pre_set_inputs,
                                          const CAmount& nTargetValue,
                                          const CCoinControl& coin_control,
                                          const CoinSelectionParams& coin_selection_params)
{
    CWalletCoinSelectionSource source(wallet);
    CoinSelectionOptions options(
        wallet.m_spend_zero_conf_change,
        gArgs.GetBoolArg("-walletrejectlongchains",
                         DEFAULT_WALLET_REJECT_LONG_CHAINS));
    return SelectCoins(source, options, available_coins, pre_set_inputs,
                       nTargetValue, coin_control, coin_selection_params);
}

static bool IsCurrentForAntiFeeSniping(interfaces::Chain& chain,
                                       const uint256& block_hash)
{
    if (chain.isInitialBlockDownload()) {
        return false;
    }
    constexpr int64_t MAX_ANTI_FEE_SNIPING_TIP_AGE = 8 * 60 * 60;
    int64_t block_time;
    CHECK_NONFATAL(
        chain.findBlock(block_hash, FoundBlock().time(block_time)));
    if (block_time < (GetTime() - MAX_ANTI_FEE_SNIPING_TIP_AGE)) {
        return false;
    }
    return true;
}

void DiscourageFeeSniping(CMutableTransaction& tx,
                          FastRandomContext& rng_fast,
                          interfaces::Chain& chain,
                          const uint256& block_hash,
                          int block_height)
{
    assert(!tx.vin.empty());

    if (IsCurrentForAntiFeeSniping(chain, block_hash)) {
        tx.nLockTime = block_height;

        if (rng_fast.randrange(10) == 0) {
            tx.nLockTime =
                std::max(0, int(tx.nLockTime) - int(rng_fast.randrange(100)));
        }
    } else {
        tx.nLockTime = 0;
    }
    assert(tx.nLockTime < LOCKTIME_THRESHOLD);
    assert(tx.nLockTime <= uint64_t(block_height));
    for (const auto& in : tx.vin) {
        assert(in.nSequence != CTxIn::SEQUENCE_FINAL);
        if (in.nSequence == CTxIn::MAX_SEQUENCE_NONFINAL) continue;
        if (in.nSequence == MAX_BIP125_RBF_SEQUENCE) continue;
        assert(false);
    }
}

uint64_t GetSerializeSizeForRecipient(const CRecipient& recipient)
{
    return ::GetSerializeSize(
        CTxOut(recipient.nAmount, GetScriptForDestination(recipient.dest)));
}

bool IsDust(const CRecipient& recipient, const CFeeRate& dustRelayFee)
{
    return ::IsDust(
        CTxOut(recipient.nAmount, GetScriptForDestination(recipient.dest)),
        dustRelayFee);
}

static util::Result<CreatedTransactionResult> CreateTransactionInternal(
    CWallet& wallet,
    const std::vector<CRecipient>& vecSend,
    std::optional<unsigned int> change_pos,
    const CCoinControl& coin_control,
    bool sign) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    FastRandomContext rng_fast;
    CMutableTransaction txNew;

    txNew.version = coin_control.m_version;

    CoinSelectionParams coin_selection_params{rng_fast};
    coin_selection_params.m_avoid_partial_spends =
        coin_control.m_avoid_partial_spends;
    coin_selection_params.m_include_unsafe_inputs =
        coin_control.m_include_unsafe_inputs;
    coin_selection_params.m_max_tx_weight =
        coin_control.m_max_tx_weight.value_or(MAX_STANDARD_TX_WEIGHT);
    coin_selection_params.m_version = coin_control.m_version;
    int minimum_tx_weight = MIN_STANDARD_TX_NONWITNESS_SIZE *
                            WITNESS_SCALE_FACTOR;
    if (coin_selection_params.m_max_tx_weight.value() < minimum_tx_weight ||
        coin_selection_params.m_max_tx_weight.value() >
            MAX_STANDARD_TX_WEIGHT) {
        return util::Error{strprintf(
            _("Maximum transaction weight must be between %d and %d"),
            minimum_tx_weight, MAX_STANDARD_TX_WEIGHT)};
    }

    coin_selection_params.m_long_term_feerate = wallet.m_consolidate_feerate;
    coin_selection_params.tx_noinputs_size =
        10 + GetSizeOfCompactSize(vecSend.size());

    CAmount recipients_sum{0};
    const OutputType change_type = wallet.TransactionChangeType(
        coin_control.m_change_type
            ? *coin_control.m_change_type
            : wallet.m_default_change_type,
        vecSend);
    ReserveDestination reservedest(&wallet, change_type);
    unsigned int outputs_to_subtract_fee_from{0};

    for (const auto& recipient : vecSend) {
        if (IsDust(recipient, wallet.chain().relayDustFee())) {
            return util::Error{_("Transaction amount too small")};
        }

        coin_selection_params.tx_noinputs_size +=
            GetSerializeSizeForRecipient(recipient);
        recipients_sum += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount) {
            outputs_to_subtract_fee_from++;
            coin_selection_params.m_subtract_fee_outputs = true;
        }
    }

    CScript scriptChange;
    bilingual_str error;

    if (!std::get_if<CNoDestination>(&coin_control.destChange)) {
        scriptChange = GetScriptForDestination(coin_control.destChange);
    } else {
        CTxDestination dest;
        auto op_dest = reservedest.GetReservedDestination(true);
        if (!op_dest) {
            error = _("Transaction needs a change address, but we can't "
                      "generate it.") +
                    Untranslated(" ") + util::ErrorString(op_dest);
        } else {
            dest = *op_dest;
            scriptChange = GetScriptForDestination(dest);
        }
        CHECK_NONFATAL(IsValidDestination(dest) != scriptChange.empty());
    }

    CTxOut change_prototype_txout(0, scriptChange);
    coin_selection_params.change_output_size =
        GetSerializeSize(change_prototype_txout);

    int change_spend_size =
        CalculateMaximumSignedInputSize(change_prototype_txout, &wallet,
                                        /*coin_control=*/nullptr);
    if (change_spend_size == -1) {
        coin_selection_params.change_spend_size =
            DUMMY_NESTED_P2WPKH_INPUT_SIZE;
    } else {
        coin_selection_params.change_spend_size = change_spend_size;
    }

    coin_selection_params.m_discard_feerate = GetDiscardRate(wallet);

    FeeCalculation feeCalc;
    coin_selection_params.m_effective_feerate =
        GetMinimumFeeRate(wallet, coin_control, &feeCalc);

    if (coin_control.m_feerate &&
        coin_selection_params.m_effective_feerate >
            *coin_control.m_feerate) {
        return util::Error{strprintf(
            _("Fee rate (%s) is lower than the minimum fee rate setting (%s)"),
            coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB),
            coin_selection_params.m_effective_feerate.ToString(
                FeeEstimateMode::SAT_VB))};
    }
    if (feeCalc.reason == FeeReason::FALLBACK &&
        !wallet.m_allow_fallback_fee) {
        return util::Error{strprintf(
            _("Fee estimation failed. Fallbackfee is disabled. Wait a few "
              "blocks or enable %s."),
            "-fallbackfee")};
    }

    coin_selection_params.m_change_fee =
        coin_selection_params.m_effective_feerate.GetFee(
            coin_selection_params.change_output_size);
    coin_selection_params.m_cost_of_change =
        coin_selection_params.m_discard_feerate.GetFee(
            coin_selection_params.change_spend_size) +
        coin_selection_params.m_change_fee;

    coin_selection_params.m_min_change_target = GenerateChangeTarget(
        std::floor(recipients_sum / vecSend.size()),
        coin_selection_params.m_change_fee, rng_fast);

    const auto dust =
        GetDustThreshold(change_prototype_txout,
                         coin_selection_params.m_discard_feerate);
    const auto change_spend_fee =
        coin_selection_params.m_discard_feerate.GetFee(
            coin_selection_params.change_spend_size);
    coin_selection_params.min_viable_change =
        std::max(change_spend_fee + 1, dust);

    const CAmount not_input_fees =
        coin_selection_params.m_effective_feerate.GetFee(
            coin_selection_params.m_subtract_fee_outputs
                ? 0
                : coin_selection_params.tx_noinputs_size);
    CAmount selection_target = recipients_sum + not_input_fees;

    if (selection_target == 0 && !coin_control.HasSelected()) {
        return util::Error{_("Transaction requires one destination of "
                             "non-zero value, a non-zero feerate, or a "
                             "pre-selected input")};
    }

    PreSelectedInputs preset_inputs;
    if (coin_control.HasSelected()) {
        auto res_fetch_inputs =
            FetchSelectedInputs(wallet, coin_control, coin_selection_params);
        if (!res_fetch_inputs) {
            return util::Error{util::ErrorString(res_fetch_inputs)};
        }
        preset_inputs = *res_fetch_inputs;
    }

    CoinsResult available_coins;
    if (coin_control.m_allow_other_inputs) {
        available_coins =
            AvailableCoins(wallet, &coin_control,
                           coin_selection_params.m_effective_feerate);
    }

    auto select_coins_res = SelectCoins(wallet, available_coins, preset_inputs,
                                        /*nTargetValue=*/selection_target,
                                        coin_control, coin_selection_params);
    if (!select_coins_res) {
        const bilingual_str& err = util::ErrorString(select_coins_res);
        return util::Error{err.empty() ? _("Insufficient funds") : err};
    }
    const SelectionResult& result = *select_coins_res;
    TRACEPOINT(coin_selection, selected_coins,
               wallet.GetName().c_str(),
               GetAlgorithmName(result.GetAlgo()).c_str(), result.GetTarget(),
               result.GetWaste(), result.GetSelectedValue());

    txNew.vout.reserve(vecSend.size() + 1);
    for (const auto& recipient : vecSend) {
        txNew.vout.emplace_back(recipient.nAmount,
                                GetScriptForDestination(recipient.dest));
    }
    const CAmount change_amount =
        result.GetChange(coin_selection_params.min_viable_change,
                         coin_selection_params.m_change_fee);
    if (change_amount > 0) {
        CTxOut newTxOut(change_amount, scriptChange);
        if (!change_pos) {
            change_pos = rng_fast.randrange(txNew.vout.size() + 1);
        } else if (*change_pos > txNew.vout.size()) {
            return util::Error{_("Transaction change output index out of range")};
        }
        txNew.vout.insert(txNew.vout.begin() + *change_pos, newTxOut);
    } else {
        change_pos = std::nullopt;
    }

    std::vector<std::shared_ptr<COutput>> selected_coins =
        result.GetShuffledInputVector();

    if (coin_control.HasSelected() && coin_control.HasSelectedOrder()) {
        std::stable_sort(
            selected_coins.begin(), selected_coins.end(),
            [&coin_control](const std::shared_ptr<COutput>& a,
                            const std::shared_ptr<COutput>& b) {
                auto a_pos = coin_control.GetSelectionPos(a->outpoint);
                auto b_pos = coin_control.GetSelectionPos(b->outpoint);
                if (a_pos.has_value() && b_pos.has_value()) {
                    return a_pos.value() < b_pos.value();
                } else if (a_pos.has_value() && !b_pos.has_value()) {
                    return true;
                } else {
                    return false;
                }
            });
    }

    bool use_anti_fee_sniping = true;
    const uint32_t default_sequence{
        coin_control.m_signal_bip125_rbf.value_or(wallet.m_signal_rbf)
            ? MAX_BIP125_RBF_SEQUENCE
            : CTxIn::MAX_SEQUENCE_NONFINAL};
    txNew.vin.reserve(selected_coins.size());
    for (const auto& coin : selected_coins) {
        std::optional<uint32_t> sequence =
            coin_control.GetSequence(coin->outpoint);
        if (sequence) {
            use_anti_fee_sniping = false;
        }
        txNew.vin.emplace_back(coin->outpoint, CScript{},
                               sequence.value_or(default_sequence));

        auto scripts = coin_control.GetScripts(coin->outpoint);
        if (scripts.first) {
            txNew.vin.back().scriptSig = *scripts.first;
        }
        if (scripts.second) {
            txNew.vin.back().scriptWitness = *scripts.second;
        }
    }
    if (coin_control.m_locktime) {
        txNew.nLockTime = coin_control.m_locktime.value();
        use_anti_fee_sniping = false;
    }
    if (use_anti_fee_sniping) {
        DiscourageFeeSniping(txNew, rng_fast, wallet.chain(),
                             wallet.GetLastBlockHash(),
                             wallet.GetLastBlockHeight());
    }

    TxSize tx_sizes =
        CalculateMaximumSignedTxSize(CTransaction(txNew), &wallet, &coin_control);
    int nBytes = tx_sizes.vsize;
    if (nBytes == -1) {
        return util::Error{
            _("Missing solving data for estimating transaction size")};
    }
    CAmount fee_needed =
        coin_selection_params.m_effective_feerate.GetFee(nBytes) +
        result.GetTotalBumpFees();
    const CAmount output_value = CalculateOutputValue(txNew);
    Assume(recipients_sum + change_amount == output_value);
    CAmount current_fee = result.GetSelectedValue() - output_value;

    if (current_fee < 0) {
        return util::Error{Untranslated(STR_INTERNAL_BUG("Fee paid < 0"))};
    }

    if (change_pos && fee_needed < current_fee) {
        auto& change = txNew.vout.at(*change_pos);
        change.nValue += current_fee - fee_needed;
        current_fee = result.GetSelectedValue() - CalculateOutputValue(txNew);
        if (fee_needed != current_fee) {
            return util::Error{Untranslated(
                STR_INTERNAL_BUG("Change adjustment: Fee needed != fee paid"))};
        }
    }

    if (coin_selection_params.m_subtract_fee_outputs) {
        CAmount to_reduce = fee_needed - current_fee;
        unsigned int i{0};
        bool fFirst{true};
        for (const auto& recipient : vecSend) {
            if (change_pos && i == *change_pos) ++i;
            CTxOut& txout = txNew.vout[i];

            if (recipient.fSubtractFeeFromAmount) {
                txout.nValue -=
                    to_reduce / outputs_to_subtract_fee_from;

                if (fFirst) {
                    fFirst = false;
                    txout.nValue -=
                        to_reduce % outputs_to_subtract_fee_from;
                }

                if (IsDust(txout, wallet.chain().relayDustFee())) {
                    if (txout.nValue < 0) {
                        return util::Error{
                            _("The transaction amount is too small to pay "
                              "the fee")};
                    } else {
                        return util::Error{
                            _("The transaction amount is too small to send "
                              "after the fee has been deducted")};
                    }
                }
            }
            ++i;
        }
        current_fee = result.GetSelectedValue() - CalculateOutputValue(txNew);
        if (fee_needed != current_fee) {
            return util::Error{Untranslated(
                STR_INTERNAL_BUG("SFFO: Fee needed != fee paid"))};
        }
    }

    if (fee_needed > current_fee) {
        return util::Error{
            Untranslated(STR_INTERNAL_BUG("Fee needed > fee paid"))};
    }

    if (scriptChange.empty() && change_pos) {
        return util::Error{error};
    }

    if (sign && !wallet.SignTransaction(txNew)) {
        return util::Error{_("Signing transaction failed")};
    }

    CTransactionRef tx = MakeTransactionRef(std::move(txNew));

    if ((sign && GetTransactionWeight(*tx) > MAX_STANDARD_TX_WEIGHT) ||
        (!sign && tx_sizes.weight > MAX_STANDARD_TX_WEIGHT)) {
        return util::Error{_("Transaction too large")};
    }

    if (current_fee > wallet.m_default_max_tx_fee) {
        return util::Error{
            TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED)};
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains",
                         DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        auto result = wallet.chain().checkChainLimits(tx);
        if (!result) {
            return util::Error{util::ErrorString(result)};
        }
    }

    reservedest.KeepDestination();

    wallet.WalletLogPrintf("Coin Selection: Algorithm:%s, Waste Metric "
                           "Score:%d\n",
                           GetAlgorithmName(result.GetAlgo()),
                           result.GetWaste());
    wallet.WalletLogPrintf(
        "Fee Calculation: Fee:%d Bytes:%u Tgt:%d (requested %d) Reason:\"%s\" "
        "Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) "
        "Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
        current_fee, nBytes, feeCalc.returnedTarget, feeCalc.desiredTarget,
        StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
        feeCalc.est.pass.start, feeCalc.est.pass.end,
        (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool +
         feeCalc.est.pass.leftMempool) > 0.0
            ? 100 * feeCalc.est.pass.withinTarget /
                  (feeCalc.est.pass.totalConfirmed +
                   feeCalc.est.pass.inMempool +
                   feeCalc.est.pass.leftMempool)
            : 0.0,
        feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed,
        feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
        feeCalc.est.fail.start, feeCalc.est.fail.end,
        (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool +
         feeCalc.est.fail.leftMempool) > 0.0
            ? 100 * feeCalc.est.fail.withinTarget /
                  (feeCalc.est.fail.totalConfirmed +
                   feeCalc.est.fail.inMempool +
                   feeCalc.est.fail.leftMempool)
            : 0.0,
        feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed,
        feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);

    return CreatedTransactionResult(tx, current_fee, change_pos, feeCalc);
}

util::Result<CreatedTransactionResult> CreateTransaction(
    CWallet& wallet,
    const std::vector<CRecipient>& vecSend,
    std::optional<unsigned int> change_pos,
    const CCoinControl& coin_control,
    bool sign)
{
    if (vecSend.empty()) {
        return util::Error{_("Transaction must have at least one recipient")};
    }

    if (std::any_of(vecSend.cbegin(), vecSend.cend(),
                    [](const auto& recipient) {
                        return recipient.nAmount < 0;
                    })) {
        return util::Error{_("Transaction amounts must not be negative")};
    }

    LOCK(wallet.cs_wallet);

    auto res =
        CreateTransactionInternal(wallet, vecSend, change_pos, coin_control, sign);
    TRACEPOINT(coin_selection, normal_create_tx_internal,
               wallet.GetName().c_str(), bool(res),
               res ? res->fee : 0,
               res && res->change_pos.has_value()
                   ? int32_t(*res->change_pos)
                   : -1);
    if (!res) return res;
    const auto& txr_ungrouped = *res;

    if (txr_ungrouped.fee > 0 &&
        wallet.m_max_aps_fee > -1 &&
        !coin_control.m_avoid_partial_spends) {
        TRACEPOINT(coin_selection, attempting_aps_create_tx,
                   wallet.GetName().c_str());
        CCoinControl tmp_cc = coin_control;
        tmp_cc.m_avoid_partial_spends = true;

        if (txr_ungrouped.change_pos) {
            ExtractDestination(
                txr_ungrouped.tx->vout[*txr_ungrouped.change_pos].scriptPubKey,
                tmp_cc.destChange);
        }

        auto txr_grouped =
            CreateTransactionInternal(wallet, vecSend, change_pos, tmp_cc, sign);
        const bool use_aps{txr_grouped.has_value()
                               ? (txr_grouped->fee <=
                                  txr_ungrouped.fee + wallet.m_max_aps_fee)
                               : false};
        TRACEPOINT(coin_selection, aps_create_tx_internal,
                   wallet.GetName().c_str(), use_aps,
                   txr_grouped.has_value(),
                   txr_grouped.has_value() ? txr_grouped->fee : 0,
                   txr_grouped.has_value() &&
                           txr_grouped->change_pos.has_value()
                       ? int32_t(*txr_grouped->change_pos)
                       : -1);
        if (txr_grouped) {
            wallet.WalletLogPrintf(
                "Fee non-grouped = %lld, grouped = %lld, using %s\n",
                txr_ungrouped.fee, txr_grouped->fee,
                use_aps ? "grouped" : "non-grouped");
            if (use_aps) return txr_grouped;
        }
    }
    return res;
}

util::Result<CreatedTransactionResult> FundTransaction(
    CWallet& wallet,
    const CMutableTransaction& tx,
    const std::vector<CRecipient>& vecSend,
    std::optional<unsigned int> change_pos,
    bool lockUnspents,
    CCoinControl coinControl)
{
    assert(tx.vout.empty());

    coinControl.m_locktime = tx.nLockTime;
    coinControl.m_version = tx.version;

    LOCK(wallet.cs_wallet);

    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : tx.vin) {
        coins[txin.prevout];
    }
    wallet.chain().findCoins(coins);

    for (const CTxIn& txin : tx.vin) {
        const auto& outPoint = txin.prevout;
        PreselectedInput& preset_txin = coinControl.Select(outPoint);
        if (!wallet.IsMine(outPoint)) {
            if (coins[outPoint].out.IsNull()) {
                return util::Error{_("Unable to find UTXO for external input")};
            }
            preset_txin.SetTxOut(coins[outPoint].out);
        }
        preset_txin.SetSequence(txin.nSequence);
        preset_txin.SetScriptSig(txin.scriptSig);
        preset_txin.SetScriptWitness(txin.scriptWitness);
    }

    auto res =
        CreateTransaction(wallet, vecSend, change_pos, coinControl, false);
    if (!res) {
        return res;
    }

    if (lockUnspents) {
        for (const CTxIn& txin : res->tx->vin) {
            wallet.LockCoin(txin.prevout, /*persist=*/false);
        }
    }

    return res;
}

/** CWalletCoinSelectionSource implementation **/

void CWalletCoinSelectionSource::GetTransactionAncestry(const Txid& txid,
                                                        size_t& ancestors,
                                                        size_t& descendants) const
{
    m_wallet.chain().getTransactionAncestry(txid, ancestors, descendants);
}

std::optional<CAmount> CWalletCoinSelectionSource::CalculateCombinedBumpFee(
    const std::vector<COutPoint>& outpoints,
    const CFeeRate& feerate) const
{
    return m_wallet.chain().calculateCombinedBumpFee(outpoints, feerate);
}

void CWalletCoinSelectionSource::GetPackageLimits(
    unsigned int& limit_ancestor_count,
    unsigned int& limit_descendant_count) const
{
    m_wallet.chain().getPackageLimits(limit_ancestor_count,
                                      limit_descendant_count);
}

} // namespace wallet

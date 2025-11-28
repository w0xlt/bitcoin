// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/coinselection.h>

#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <logging.h>
#include <policy/feerate.h>
#include <util/check.h>
#include <util/moneystr.h>

#include <numeric>
#include <optional>
#include <queue>

namespace wallet {

static util::Result<SelectionResult> ErrorMaxWeightExceeded()
{
    return util::Error{_("The inputs size exceeds the maximum weight. "
                         "Please try sending a smaller amount or manually consolidating your wallet's UTXOs")};
}

// Sort by descending (effective) value prefer lower waste on tie
struct {
    bool operator()(const OutputGroup& a, const OutputGroup& b) const
    {
        if (a.GetSelectionAmount() == b.GetSelectionAmount()) {
            // Lower waste is better when effective_values are tied
            return (a.fee - a.long_term_fee) < (b.fee - b.long_term_fee);
        }
        return a.GetSelectionAmount() > b.GetSelectionAmount();
    }
} descending;

// Sort by descending (effective) value prefer lower weight on tie
struct {
    bool operator()(const OutputGroup& a, const OutputGroup& b) const
    {
        if (a.GetSelectionAmount() == b.GetSelectionAmount()) {
            // Sort lower weight to front on tied effective_value
            return a.m_weight < b.m_weight;
        }
        return a.GetSelectionAmount() > b.GetSelectionAmount();
    }
} descending_effval_weight;

static const size_t TOTAL_TRIES = 100000;

util::Result<SelectionResult> SelectCoinsBnB(std::vector<OutputGroup>& utxo_pool,
                                             const CAmount& selection_target,
                                             const CAmount& cost_of_change,
                                             int max_selection_weight)
{
    SelectionResult result(selection_target, SelectionAlgorithm::BNB);
    CAmount curr_value = 0;
    std::vector<size_t> curr_selection;
    int curr_selection_weight = 0;

    CAmount curr_available_value = 0;
    for (const OutputGroup& utxo : utxo_pool) {
        assert(utxo.GetSelectionAmount() > 0);
        curr_available_value += utxo.GetSelectionAmount();
    }
    if (curr_available_value < selection_target) {
        return util::Error();
    }

    std::sort(utxo_pool.begin(), utxo_pool.end(), descending);

    CAmount curr_waste = 0;
    std::vector<size_t> best_selection;
    CAmount best_waste = MAX_MONEY;

    bool is_feerate_high = utxo_pool.at(0).fee > utxo_pool.at(0).long_term_fee;
    bool max_tx_weight_exceeded = false;

    for (size_t curr_try = 0, utxo_pool_index = 0; curr_try < TOTAL_TRIES; ++curr_try, ++utxo_pool_index) {
        bool backtrack = false;
        if (curr_value + curr_available_value < selection_target ||
            curr_value > selection_target + cost_of_change ||
            (curr_waste > best_waste && is_feerate_high)) {
            backtrack = true;
        } else if (curr_selection_weight > max_selection_weight) {
            max_tx_weight_exceeded = true;
            backtrack = true;
        } else if (curr_value >= selection_target) {
            curr_waste += (curr_value - selection_target);
            if (curr_waste <= best_waste) {
                best_selection = curr_selection;
                best_waste = curr_waste;
            }
            curr_waste -= (curr_value - selection_target);
            backtrack = true;
        }

        if (backtrack) {
            if (curr_selection.empty()) {
                break;
            }

            for (--utxo_pool_index; utxo_pool_index > curr_selection.back(); --utxo_pool_index) {
                curr_available_value += utxo_pool.at(utxo_pool_index).GetSelectionAmount();
            }

            assert(utxo_pool_index == curr_selection.back());
            OutputGroup& utxo = utxo_pool.at(utxo_pool_index);
            curr_value -= utxo.GetSelectionAmount();
            curr_waste -= utxo.fee - utxo.long_term_fee;
            curr_selection_weight -= utxo.m_weight;
            curr_selection.pop_back();
        } else {
            OutputGroup& utxo = utxo_pool.at(utxo_pool_index);

            curr_available_value -= utxo.GetSelectionAmount();

            if (curr_selection.empty() ||
                (utxo_pool_index - 1) == curr_selection.back() ||
                utxo.GetSelectionAmount() != utxo_pool.at(utxo_pool_index - 1).GetSelectionAmount() ||
                utxo.fee != utxo_pool.at(utxo_pool_index - 1).fee) {

                curr_selection.push_back(utxo_pool_index);
                curr_value += utxo.GetSelectionAmount();
                curr_waste += utxo.fee - utxo.long_term_fee;
                curr_selection_weight += utxo.m_weight;
            }
        }
    }

    if (best_selection.empty()) {
        return max_tx_weight_exceeded ? ErrorMaxWeightExceeded() : util::Error();
    }

    for (const size_t& i : best_selection) {
        result.AddInput(utxo_pool.at(i));
    }
    result.RecalculateWaste(cost_of_change, cost_of_change, CAmount{0});
    assert(best_waste == result.GetWaste());

    return result;
}

util::Result<SelectionResult> CoinGrinder(std::vector<OutputGroup>& utxo_pool,
                                          const CAmount& selection_target,
                                          CAmount change_target,
                                          int max_selection_weight)
{
    std::sort(utxo_pool.begin(), utxo_pool.end(), descending_effval_weight);

    std::vector<CAmount> lookahead(utxo_pool.size());
    std::vector<int> min_tail_weight(utxo_pool.size());

    CAmount total_available = 0;
    int min_group_weight = std::numeric_limits<int>::max();
    for (size_t i = 0; i < utxo_pool.size(); ++i) {
        size_t index = utxo_pool.size() - 1 - i;
        lookahead[index] = total_available;
        min_tail_weight[index] = min_group_weight;
        Assume(utxo_pool[index].GetSelectionAmount() > 0);
        total_available += utxo_pool[index].GetSelectionAmount();
        min_group_weight = std::min(min_group_weight, utxo_pool[index].m_weight);
    }

    const CAmount total_target = selection_target + change_target;
    if (total_available < total_target) {
        // Insufficient funds
        return util::Error();
    }

    // The current selection and the best input set found so far, stored as the utxo_pool indices of the UTXOs forming them
    std::vector<size_t> curr_selection;
    std::vector<size_t> best_selection;

    CAmount curr_amount = 0;
    CAmount best_selection_amount = MAX_MONEY;

    int curr_weight = 0;
    int best_selection_weight = max_selection_weight;

    bool max_tx_weight_exceeded = false;

    size_t next_utxo = 0;

    auto deselect_last = [&]() {
        OutputGroup& utxo = utxo_pool[curr_selection.back()];
        curr_amount -= utxo.GetSelectionAmount();
        curr_weight -= utxo.m_weight;
        curr_selection.pop_back();
    };

    SelectionResult result(selection_target, SelectionAlgorithm::CG);
    bool is_done = false;
    size_t curr_try = 0;
    while (!is_done) {
        bool should_shift{false}, should_cut{false};

        OutputGroup& utxo = utxo_pool[next_utxo];
        curr_amount += utxo.GetSelectionAmount();
        curr_weight += utxo.m_weight;
        curr_selection.push_back(next_utxo);
        ++next_utxo;
        ++curr_try;

        auto curr_tail = curr_selection.back();
        if (curr_amount + lookahead[curr_tail] < total_target) {
            should_cut = true;
        } else if (curr_weight > best_selection_weight) {
            if (curr_weight > max_selection_weight) max_tx_weight_exceeded = true;
            if (utxo_pool[curr_tail].m_weight <= min_tail_weight[curr_tail]) {
                should_cut = true;
            } else {
                should_shift  = true;
            }
        } else if (curr_amount >= total_target) {
            should_shift  = true;
            if (curr_weight < best_selection_weight ||
                (curr_weight == best_selection_weight && curr_amount < best_selection_amount)) {
                best_selection = curr_selection;
                best_selection_weight = curr_weight;
                best_selection_amount = curr_amount;
            }
        } else if (!best_selection.empty() &&
                   curr_weight + int64_t{min_tail_weight[curr_tail]} *
                       ((total_target - curr_amount + utxo_pool[curr_tail].GetSelectionAmount() - 1) /
                        utxo_pool[curr_tail].GetSelectionAmount()) > best_selection_weight) {

            if (utxo_pool[curr_tail].m_weight <= min_tail_weight[curr_tail]) {
                should_cut = true;
            } else {
                should_shift = true;
            }
        }

        if (curr_try >= TOTAL_TRIES) {
            result.SetAlgoCompleted(false);
            break;
        }

        if (next_utxo == utxo_pool.size()) {
            should_cut = true;
        }

        if (should_cut) {
            deselect_last();
            should_shift  = true;
        }

        while (should_shift) {
            if (curr_selection.empty()) {
                is_done = true;
                result.SetAlgoCompleted(true);
                break;
            }
            next_utxo = curr_selection.back() + 1;
            deselect_last();
            should_shift  = false;

            while (utxo_pool[next_utxo - 1].GetSelectionAmount() == utxo_pool[next_utxo].GetSelectionAmount()) {
                if (next_utxo >= utxo_pool.size() - 1) {
                    should_shift = true;
                    break;
                }
                ++next_utxo;
            }
        }
    }

    result.SetSelectionsEvaluated(curr_try);

    if (best_selection.empty()) {
        return max_tx_weight_exceeded ? ErrorMaxWeightExceeded() : util::Error();
    }

    for (const size_t& i : best_selection) {
        result.AddInput(utxo_pool[i]);
    }

    return result;
}

class MinOutputGroupComparator
{
public:
    int operator() (const OutputGroup& group1, const OutputGroup& group2) const
    {
        return group1.GetSelectionAmount() > group2.GetSelectionAmount();
    }
};

util::Result<SelectionResult> SelectCoinsSRD(const std::vector<OutputGroup>& utxo_pool,
                                             CAmount target_value,
                                             CAmount change_fee,
                                             FastRandomContext& rng,
                                             int max_selection_weight)
{
    SelectionResult result(target_value, SelectionAlgorithm::SRD);
    std::priority_queue<OutputGroup, std::vector<OutputGroup>, MinOutputGroupComparator> heap;

    target_value += CHANGE_LOWER + change_fee;

    std::vector<size_t> indexes(utxo_pool.size());
    std::iota(indexes.begin(), indexes.end(), 0);
    std::shuffle(indexes.begin(), indexes.end(), rng);

    CAmount selected_eff_value = 0;
    int weight = 0;
    bool max_tx_weight_exceeded = false;
    for (const size_t i : indexes) {
        const OutputGroup& group = utxo_pool.at(i);
        Assume(group.GetSelectionAmount() > 0);

        heap.push(group);
        selected_eff_value += group.GetSelectionAmount();
        weight += group.m_weight;

        if (weight > max_selection_weight) {
            max_tx_weight_exceeded = true;
            do {
                const OutputGroup& to_remove_group = heap.top();
                selected_eff_value -= to_remove_group.GetSelectionAmount();
                weight -= to_remove_group.m_weight;
                heap.pop();
            } while (!heap.empty() && weight > max_selection_weight);
        }

        if (selected_eff_value >= target_value) {
            while (!heap.empty()) {
                result.AddInput(heap.top());
                heap.pop();
            }
            return result;
        }
    }
    return max_tx_weight_exceeded ? ErrorMaxWeightExceeded() : util::Error();
}

static void ApproximateBestSubset(FastRandomContext& insecure_rand,
                                  const std::vector<OutputGroup>& groups,
                                  const CAmount& nTotalLower,
                                  const CAmount& nTargetValue,
                                  std::vector<char>& vfBest,
                                  CAmount& nBest,
                                  int max_selection_weight,
                                  int iterations = 1000)
{
    std::vector<char> vfIncluded;

    vfBest.assign(groups.size(), true);
    nBest = nTotalLower;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++) {
        vfIncluded.assign(groups.size(), false);
        CAmount nTotal = 0;
        int selected_coins_weight{0};
        bool fReachedTarget = false;

        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++) {
            for (unsigned int i = 0; i < groups.size(); i++) {
                if (nPass == 0 ? insecure_rand.randbool() : !vfIncluded[i]) {
                    nTotal += groups[i].GetSelectionAmount();
                    selected_coins_weight += groups[i].m_weight;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue && selected_coins_weight <= max_selection_weight) {
                        fReachedTarget = true;
                        if (nTotal < nBest) {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= groups[i].GetSelectionAmount();
                        selected_coins_weight -= groups[i].m_weight;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

util::Result<SelectionResult> KnapsackSolver(std::vector<OutputGroup>& groups,
                                             const CAmount& nTargetValue,
                                             CAmount change_target,
                                             FastRandomContext& rng,
                                             int max_selection_weight)
{
    SelectionResult result(nTargetValue, SelectionAlgorithm::KNAPSACK);

    bool max_weight_exceeded{false};
    std::optional<OutputGroup> lowest_larger;
    std::vector<OutputGroup> applicable_groups;
    CAmount nTotalLower = 0;

    std::shuffle(groups.begin(), groups.end(), rng);

    for (const OutputGroup& group : groups) {
        if (group.m_weight > max_selection_weight) {
            max_weight_exceeded = true;
            continue;
        }
        if (group.GetSelectionAmount() == nTargetValue) {
            result.AddInput(group);
            return result;
        } else if (group.GetSelectionAmount() < nTargetValue + change_target) {
            applicable_groups.push_back(group);
            nTotalLower += group.GetSelectionAmount();
        } else if (!lowest_larger || group.GetSelectionAmount() < lowest_larger->GetSelectionAmount()) {
            lowest_larger = group;
        }
    }

    if (nTotalLower == nTargetValue) {
        for (const auto& group : applicable_groups) {
            result.AddInput(group);
        }
        if (result.GetWeight() <= max_selection_weight) {
            return result;
        }
        max_weight_exceeded = true;
        result.Clear();
    }

    if (nTotalLower < nTargetValue) {
        if (!lowest_larger) {
            return max_weight_exceeded ? ErrorMaxWeightExceeded() : util::Error();
        }
        result.AddInput(*lowest_larger);
        return result;
    }

    std::sort(applicable_groups.begin(), applicable_groups.end(), descending);
    std::vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(rng, applicable_groups, nTotalLower, nTargetValue,
                          vfBest, nBest, max_selection_weight);
    if (nBest != nTargetValue &&
        nTotalLower >= nTargetValue + change_target) {
        ApproximateBestSubset(rng, applicable_groups, nTotalLower,
                              nTargetValue + change_target,
                              vfBest, nBest, max_selection_weight);
    }

    if (lowest_larger &&
        ((nBest != nTargetValue && nBest < nTargetValue + change_target) ||
         lowest_larger->GetSelectionAmount() <= nBest)) {
        result.AddInput(*lowest_larger);
    } else {
        for (unsigned int i = 0; i < applicable_groups.size(); i++) {
            if (vfBest[i]) {
                result.AddInput(applicable_groups[i]);
            }
        }

        if (result.GetWeight() > max_selection_weight) {
            if (!lowest_larger) return ErrorMaxWeightExceeded();
            result.Clear();
            result.AddInput(*lowest_larger);
        }

        if (LogAcceptCategory(BCLog::SELECTCOINS, BCLog::Level::Debug)) {
            std::string log_message{"Coin selection best subset: "};
            for (unsigned int i = 0; i < applicable_groups.size(); i++) {
                if (vfBest[i]) {
                    log_message += strprintf("%s ", FormatMoney(applicable_groups[i].m_value));
                }
            }
            LogDebug(BCLog::SELECTCOINS, "%stotal %s\n", log_message, FormatMoney(nBest));
        }
    }
    Assume(result.GetWeight() <= max_selection_weight);
    return result;
}

/******************************************************************************

 OutputGroup

 ******************************************************************************/

void OutputGroup::Insert(const std::shared_ptr<COutput>& output,
                         size_t ancestors,
                         size_t descendants)
{
    m_outputs.push_back(output);
    auto& coin = *m_outputs.back();

    fee += coin.GetFee();

    coin.long_term_fee = coin.input_bytes < 0 ? 0 : m_long_term_feerate.GetFee(coin.input_bytes);
    long_term_fee += coin.long_term_fee;

    effective_value += coin.GetEffectiveValue();

    m_from_me &= coin.from_me;
    m_value += coin.txout.nValue;
    m_depth = std::min(m_depth, coin.depth);
    m_ancestors += ancestors;
    m_descendants = std::max(m_descendants, descendants);

    if (output->input_bytes > 0) {
        m_weight += output->input_bytes * WITNESS_SCALE_FACTOR;
    }
}

bool OutputGroup::EligibleForSpending(const CoinEligibilityFilter& eligibility_filter) const
{
    return m_depth >= (m_from_me ? eligibility_filter.conf_mine : eligibility_filter.conf_theirs)
        && m_ancestors <= eligibility_filter.max_ancestors
        && m_descendants <= eligibility_filter.max_descendants;
}

CAmount OutputGroup::GetSelectionAmount() const
{
    return m_subtract_fee_outputs ? m_value : effective_value;
}

void OutputGroupTypeMap::Push(const OutputGroup& group,
                              OutputType type,
                              bool insert_positive,
                              bool insert_mixed)
{
    if (group.m_outputs.empty()) return;

    Groups& groups = groups_by_type[type];
    if (insert_positive && group.GetSelectionAmount() > 0) {
        groups.positive_group.emplace_back(group);
        all_groups.positive_group.emplace_back(group);
    }
    if (insert_mixed) {
        groups.mixed_group.emplace_back(group);
        all_groups.mixed_group.emplace_back(group);
    }
}

CAmount GenerateChangeTarget(const CAmount payment_value,
                             const CAmount change_fee,
                             FastRandomContext& rng)
{
    if (payment_value <= CHANGE_LOWER / 2) {
        return change_fee + CHANGE_LOWER;
    }

    const auto upper_bound = std::min(payment_value * 2, CHANGE_UPPER);
    return change_fee + rng.randrange(upper_bound - CHANGE_LOWER) + CHANGE_LOWER;
}

void SelectionResult::SetBumpFeeDiscount(const CAmount discount)
{
    assert(discount >= 0);
    bump_fee_group_discount = discount;
}

void SelectionResult::RecalculateWaste(const CAmount min_viable_change,
                                       const CAmount change_cost,
                                       const CAmount change_fee)
{
    assert(!m_selected_inputs.empty());

    CAmount waste = 0;
    for (const auto& coin_ptr : m_selected_inputs) {
        const COutput& coin = *coin_ptr;
        waste += coin.GetFee() - coin.long_term_fee;
    }

    waste -= bump_fee_group_discount;

    if (GetChange(min_viable_change, change_fee)) {
        waste += change_cost;
    } else {
        CAmount selected_effective_value =
            m_use_effective ? GetSelectedEffectiveValue() : GetSelectedValue();
        assert(selected_effective_value >= m_target);
        waste += selected_effective_value - m_target;
    }

    m_waste = waste;
}

void SelectionResult::SetAlgoCompleted(bool algo_completed)
{
    m_algo_completed = algo_completed;
}

bool SelectionResult::GetAlgoCompleted() const
{
    return m_algo_completed;
}

void SelectionResult::SetSelectionsEvaluated(size_t attempts)
{
    m_selections_evaluated = attempts;
}

size_t SelectionResult::GetSelectionsEvaluated() const
{
    return m_selections_evaluated;
}

CAmount SelectionResult::GetWaste() const
{
    return *Assert(m_waste);
}

CAmount SelectionResult::GetSelectedValue() const
{
    return std::accumulate(
        m_selected_inputs.cbegin(), m_selected_inputs.cend(), CAmount{0},
        [](CAmount sum, const auto& coin) { return sum + coin->txout.nValue; });
}

CAmount SelectionResult::GetSelectedEffectiveValue() const
{
    return std::accumulate(
               m_selected_inputs.cbegin(), m_selected_inputs.cend(), CAmount{0},
               [](CAmount sum, const auto& coin) {
                   return sum + coin->GetEffectiveValue();
               }) +
           bump_fee_group_discount;
}

CAmount SelectionResult::GetTotalBumpFees() const
{
    return std::accumulate(
               m_selected_inputs.cbegin(), m_selected_inputs.cend(), CAmount{0},
               [](CAmount sum, const auto& coin) {
                   return sum + coin->ancestor_bump_fees;
               }) -
           bump_fee_group_discount;
}

void SelectionResult::Clear()
{
    m_selected_inputs.clear();
    m_waste.reset();
    m_weight = 0;
}

void SelectionResult::AddInput(const OutputGroup& group)
{
    InsertInputs(group.m_outputs);
    m_use_effective = !group.m_subtract_fee_outputs;

    m_weight += group.m_weight;
}

void SelectionResult::AddInputs(const std::set<std::shared_ptr<COutput>>& inputs,
                                bool subtract_fee_outputs)
{
    InsertInputs(inputs);
    m_use_effective = !subtract_fee_outputs;

    m_weight += std::accumulate(
        inputs.cbegin(), inputs.cend(), 0,
        [](int sum, const auto& coin) {
            return sum + std::max(coin->input_bytes, 0) * WITNESS_SCALE_FACTOR;
        });
}

void SelectionResult::Merge(const SelectionResult& other)
{
    InsertInputs(other.m_selected_inputs);

    m_target += other.m_target;
    m_use_effective |= other.m_use_effective;
    if (m_algo == SelectionAlgorithm::MANUAL) {
        m_algo = other.m_algo;
    }

    m_weight += other.m_weight;
}

const std::set<std::shared_ptr<COutput>>& SelectionResult::GetInputSet() const
{
    return m_selected_inputs;
}

std::vector<std::shared_ptr<COutput>> SelectionResult::GetShuffledInputVector() const
{
    std::vector<std::shared_ptr<COutput>> coins(m_selected_inputs.begin(),
                                                m_selected_inputs.end());
    std::shuffle(coins.begin(), coins.end(), FastRandomContext());
    return coins;
}

bool SelectionResult::operator<(SelectionResult other) const
{
    Assert(m_waste.has_value());
    Assert(other.m_waste.has_value());
    return *m_waste < *other.m_waste ||
           (*m_waste == *other.m_waste &&
            m_selected_inputs.size() > other.m_selected_inputs.size());
}

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", outpoint.hash.ToString(),
                     outpoint.n, depth, FormatMoney(txout.nValue));
}

std::string GetAlgorithmName(const SelectionAlgorithm algo)
{
    switch (algo)
    {
    case SelectionAlgorithm::BNB: return "bnb";
    case SelectionAlgorithm::KNAPSACK: return "knapsack";
    case SelectionAlgorithm::SRD: return "srd";
    case SelectionAlgorithm::CG: return "cg";
    case SelectionAlgorithm::MANUAL: return "manual";
    // No default case to allow for compiler to warn
    }
    assert(false);
}

CAmount SelectionResult::GetChange(const CAmount min_viable_change,
                                   const CAmount change_fee) const
{
    const CAmount change = m_use_effective
                           ? GetSelectedEffectiveValue() - m_target - change_fee
                           : GetSelectedValue() - m_target;

    if (change < min_viable_change) {
        return 0;
    }

    return change;
}

} // namespace wallet

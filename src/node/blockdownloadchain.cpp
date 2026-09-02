// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/blockdownloadchain.h>
#include <node/blockdownloadchain_impl.h>

#include <chain.h>
#include <consensus/validation.h>
#include <sync.h>
#include <validation.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <ranges>
#include <vector>

namespace node {
namespace {

static constexpr int PATH_BATCH_SIZE{128};

BlockDownloadBlock MakeBlock(const CBlockIndex& block)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    return {block.GetBlockHash(), block.nHeight, block.nChainWork};
}

BlockDownloadCandidate MakeCandidate(
    const CBlockIndex& block,
    const ChainstateManager& chainman)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    return {
        .m_block = MakeBlock(block),
        .m_valid_tree = block.IsValid(BLOCK_VALID_TREE),
        .m_have_data = bool(block.nStatus & BLOCK_HAVE_DATA),
        .m_in_active_chain = chainman.ActiveChain().Contains(block),
        .m_have_chain_txs = block.HaveNumChainTxs(),
        .m_segwit_active = DeploymentActiveAt(block, chainman, Consensus::DEPLOYMENT_SEGWIT),
    };
}

BlockDownloadAssumeutxoState GetAssumeutxoState(const Chainstate& chainstate)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    if (!chainstate.SnapshotBase()) return BlockDownloadAssumeutxoState::NONE;
    return chainstate.m_assumeutxo == Assumeutxo::UNVALIDATED
        ? BlockDownloadAssumeutxoState::UNVALIDATED
        : BlockDownloadAssumeutxoState::VALIDATED;
}

void AppendPath(
    const CBlockIndex& start,
    const CBlockIndex& best_known,
    int max_height,
    const ChainstateManager& chainman,
    std::vector<BlockDownloadCandidate>& output)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    const CBlockIndex* walk{&start};
    std::vector<const CBlockIndex*> batch;
    while (walk->nHeight < max_height) {
        const int count{std::min(max_height - walk->nHeight, PATH_BATCH_SIZE)};
        batch.resize(count);
        walk = best_known.GetAncestor(walk->nHeight + count);
        if (!walk) return;
        batch[count - 1] = walk;
        for (int pos{count - 1}; pos > 0; --pos) batch[pos - 1] = batch[pos]->pprev;
        for (const CBlockIndex* block : batch) output.push_back(MakeCandidate(*block, chainman));
    }
}

class ValidationBlockDownloadChain final : public BlockDownloadChain
{
    ChainstateManager& m_chainman;

    const CBlockIndex* Lookup(const std::optional<uint256>& hash) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return hash ? m_chainman.m_blockman.LookupBlockIndex(*hash) : nullptr;
    }

    BlockDownloadChainSnapshot CaptureLocked(const BlockDownloadChainQuery& query) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        const CBlockIndex* pending{Lookup(query.m_pending_hash)};
        const CBlockIndex* announced{Lookup(query.m_announced_hash)};
        const CBlockIndex* ancestor{Lookup(query.m_ancestor_hash)};
        const CBlockIndex* best_known{Lookup(query.m_best_known_hash)};
        const CBlockIndex* best_header_sent{Lookup(query.m_best_header_sent_hash)};

        BlockDownloadChainSnapshot snapshot;
        if (pending) snapshot.m_pending_block = MakeBlock(*pending);
        if (announced) snapshot.m_announced_block = MakeBlock(*announced);
        if (ancestor && best_known && ancestor->nHeight <= best_known->nHeight) {
            snapshot.m_ancestor_of_best_known = best_known->GetAncestor(ancestor->nHeight) == ancestor;
        }
        if (ancestor && best_header_sent && ancestor->nHeight <= best_header_sent->nHeight) {
            snapshot.m_ancestor_of_best_header_sent = best_header_sent->GetAncestor(ancestor->nHeight) == ancestor;
        }
        if (!query.m_plan_blocks) return snapshot;

        const CBlockIndex* active_tip{m_chainman.ActiveTip()};
        const Chainstate& current_chainstate{m_chainman.CurrentChainstate()};
        const CBlockIndex* current_tip{current_chainstate.m_chain.Tip()};
        const CBlockIndex* snapshot_base{current_chainstate.SnapshotBase()};
        snapshot.m_active_tip = active_tip ? std::optional{MakeBlock(*active_tip)} : std::nullopt;
        snapshot.m_minimum_chain_work = m_chainman.MinimumChainWork();
        snapshot.m_current_chainstate_tip_hash = current_tip ? std::optional{current_tip->GetBlockHash()} : std::nullopt;
        snapshot.m_snapshot_base = snapshot_base ? std::optional{MakeBlock(*snapshot_base)} : std::nullopt;
        snapshot.m_assumeutxo_state = GetAssumeutxoState(current_chainstate);
        snapshot.m_resolved_best_known = best_known ? std::optional{MakeBlock(*best_known)} : std::nullopt;
        snapshot.m_input_last_common_hash = query.m_last_common_hash;

        if (best_known && active_tip) {
            const CBlockIndex* fork{LastCommonAncestor(best_known, active_tip)};
            snapshot.m_fork_block = MakeBlock(*fork);
            const CBlockIndex* last_common{Lookup(query.m_last_common_hash)};
            if (!last_common ||
                fork->nChainWork > last_common->nChainWork ||
                last_common->nHeight > best_known->nHeight ||
                best_known->GetAncestor(last_common->nHeight) != last_common) {
                last_common = fork;
            }
            snapshot.m_last_common_block = MakeBlock(*last_common);
            snapshot.m_last_common_candidate = MakeCandidate(*last_common, m_chainman);
            if (snapshot_base && snapshot_base->nHeight <= best_known->nHeight) {
                snapshot.m_best_known_has_snapshot_base =
                    best_known->GetAncestor(snapshot_base->nHeight) == snapshot_base;
            }
            snapshot.m_normal_window_end = last_common->nHeight + static_cast<int>(query.m_download_window);
            const int max_height{std::min(best_known->nHeight, snapshot.m_normal_window_end + 1)};
            AppendPath(*last_common, *best_known, max_height, m_chainman, snapshot.m_normal_path);
        }

        snapshot.m_historical_requested = query.m_include_historical;
        if (!query.m_include_historical) return snapshot;
        const auto historical{m_chainman.GetHistoricalBlockRange()};
        if (!historical) return snapshot;
        const auto [historical_start, historical_target]{*historical};
        const CBlockIndex* historical_common{LastCommonAncestor(historical_start, historical_target)};
        snapshot.m_historical_start = MakeBlock(*historical_start);
        snapshot.m_historical_target = MakeBlock(*historical_target);
        snapshot.m_historical_last_common = MakeBlock(*historical_common);
        if (!best_known || historical_target->nHeight > best_known->nHeight ||
            best_known->GetAncestor(historical_target->nHeight) != historical_target) {
            return snapshot;
        }
        snapshot.m_best_known_has_historical_target = true;
        snapshot.m_historical_window_end = std::min(
            historical_common->nHeight + static_cast<int>(query.m_download_window),
            historical_target->nHeight);
        const int max_height{std::min(best_known->nHeight, snapshot.m_historical_window_end + 1)};
        AppendPath(*historical_common, *best_known, max_height, m_chainman, snapshot.m_historical_path);
        return snapshot;
    }

    bool PlanningIdentityMatches(const BlockDownloadChainSnapshot& snapshot) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        const CBlockIndex* active_tip{m_chainman.ActiveTip()};
        if ((active_tip ? std::optional{MakeBlock(*active_tip)} : std::nullopt) != snapshot.m_active_tip ||
            m_chainman.MinimumChainWork() != snapshot.m_minimum_chain_work) {
            return false;
        }

        const Chainstate& current_chainstate{m_chainman.CurrentChainstate()};
        const CBlockIndex* current_tip{current_chainstate.m_chain.Tip()};
        const CBlockIndex* snapshot_base{current_chainstate.SnapshotBase()};
        if ((current_tip ? std::optional{current_tip->GetBlockHash()} : std::nullopt) != snapshot.m_current_chainstate_tip_hash ||
            (snapshot_base ? std::optional{MakeBlock(*snapshot_base)} : std::nullopt) != snapshot.m_snapshot_base ||
            GetAssumeutxoState(current_chainstate) != snapshot.m_assumeutxo_state) {
            return false;
        }

        const CBlockIndex* best_known{snapshot.m_resolved_best_known
            ? m_chainman.m_blockman.LookupBlockIndex(snapshot.m_resolved_best_known->m_hash)
            : nullptr};
        if ((best_known ? std::optional{MakeBlock(*best_known)} : std::nullopt) != snapshot.m_resolved_best_known) return false;

        if (best_known && active_tip) {
            const CBlockIndex* fork{LastCommonAncestor(best_known, active_tip)};
            if (!snapshot.m_fork_block || MakeBlock(*fork) != *snapshot.m_fork_block) return false;
            const CBlockIndex* last_common{Lookup(snapshot.m_input_last_common_hash)};
            if (!last_common ||
                fork->nChainWork > last_common->nChainWork ||
                last_common->nHeight > best_known->nHeight ||
                best_known->GetAncestor(last_common->nHeight) != last_common) {
                last_common = fork;
            }
            if (!snapshot.m_last_common_block ||
                !snapshot.m_last_common_candidate ||
                MakeBlock(*last_common) != *snapshot.m_last_common_block) {
                return false;
            }
            const bool has_snapshot_base{
                snapshot_base && snapshot_base->nHeight <= best_known->nHeight &&
                best_known->GetAncestor(snapshot_base->nHeight) == snapshot_base};
            if (has_snapshot_base != snapshot.m_best_known_has_snapshot_base) return false;
        } else if (snapshot.m_fork_block || snapshot.m_last_common_block ||
                   snapshot.m_last_common_candidate || snapshot.m_best_known_has_snapshot_base) {
            return false;
        }

        if (!snapshot.m_revalidate_historical_identity) return true;
        const auto historical{m_chainman.GetHistoricalBlockRange()};
        if (!historical) return !snapshot.m_historical_start && !snapshot.m_historical_target;
        const auto [historical_start, historical_target]{*historical};
        const CBlockIndex* historical_common{LastCommonAncestor(historical_start, historical_target)};
        if (snapshot.m_historical_start != std::optional{MakeBlock(*historical_start)} ||
            snapshot.m_historical_target != std::optional{MakeBlock(*historical_target)} ||
            snapshot.m_historical_last_common != std::optional{MakeBlock(*historical_common)}) {
            return false;
        }
        const bool has_target{
            best_known && historical_target->nHeight <= best_known->nHeight &&
            best_known->GetAncestor(historical_target->nHeight) == historical_target};
        return has_target == snapshot.m_best_known_has_historical_target;
    }

public:
    explicit ValidationBlockDownloadChain(ChainstateManager& chainman) : m_chainman{chainman} {}

    BlockDownloadChainSnapshot Capture(const BlockDownloadChainQuery& query) const override
    {
        LOCK(::cs_main);
        return CaptureLocked(query);
    }

    bool Revalidate(
        const BlockDownloadChainSnapshot& snapshot,
        std::span<const BlockDownloadBlock> proposal,
        const std::function<bool()>& commit) const override
    {
        LOCK(::cs_main);
        if (!PlanningIdentityMatches(snapshot)) return false;
        for (const auto& block : snapshot.m_revalidation_blocks) {
            const auto expected = [&]() -> std::optional<BlockDownloadCandidate> {
                const auto find_block = [&](const auto& path) -> std::optional<BlockDownloadCandidate> {
                    const auto it{std::ranges::find(path, block.m_hash, [](const auto& candidate) {
                        return candidate.m_block.m_hash;
                    })};
                    return it == path.end() ? std::nullopt : std::optional{*it};
                };
                if (snapshot.m_last_common_candidate &&
                    snapshot.m_last_common_candidate->m_block.m_hash == block.m_hash) {
                    return snapshot.m_last_common_candidate;
                }
                if (auto candidate{find_block(snapshot.m_normal_path)}) return candidate;
                return find_block(snapshot.m_historical_path);
            }();
            const CBlockIndex* current{m_chainman.m_blockman.LookupBlockIndex(block.m_hash)};
            if (!expected || !current || MakeCandidate(*current, m_chainman) != *expected) return false;
        }
        for (const auto& block : proposal) {
            if (std::ranges::none_of(snapshot.m_revalidation_blocks, [&](const auto& revalidated) {
                    return revalidated == block;
                })) {
                return false;
            }
        }
        return commit();
    }
};

} // namespace

std::unique_ptr<BlockDownloadChain> MakeValidationBlockDownloadChain(ChainstateManager& chainman)
{
    return std::make_unique<ValidationBlockDownloadChain>(chainman);
}

} // namespace node

// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_BLOCKDOWNLOADCHAIN_H
#define BITCOIN_TEST_UTIL_BLOCKDOWNLOADCHAIN_H

#include <node/blockdownloadchain.h>

#include <algorithm>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace node::test {

/** Value-based mutable chain model for manager tests and fuzzing. */
class FakeBlockDownloadChain final : public BlockDownloadChain
{
    struct Entry {
        BlockDownloadCandidate m_candidate;
        std::optional<uint256> m_parent;
    };

    mutable std::mutex m_mutex;
    std::map<uint256, Entry> m_blocks;
    std::optional<uint256> m_active_tip;
    arith_uint256 m_minimum_chain_work;
    std::optional<uint256> m_current_chainstate_tip;
    std::optional<uint256> m_snapshot_base;
    BlockDownloadAssumeutxoState m_assumeutxo_state{BlockDownloadAssumeutxoState::NONE};
    std::optional<std::pair<uint256, uint256>> m_historical_range;
    mutable std::function<void()> m_capture_hook;
    mutable std::function<void()> m_revalidate_hook;
    mutable int m_forced_revalidation_failures{0};
    mutable int m_revalidation_count{0};

    const Entry* Lookup(const std::optional<uint256>& hash) const
    {
        if (!hash) return nullptr;
        const auto it{m_blocks.find(*hash)};
        return it == m_blocks.end() ? nullptr : &it->second;
    }

    bool IsAncestor(const uint256& ancestor, const uint256& descendant) const
    {
        auto it{m_blocks.find(descendant)};
        const auto ancestor_it{m_blocks.find(ancestor)};
        if (it == m_blocks.end() || ancestor_it == m_blocks.end() ||
            ancestor_it->second.m_candidate.m_block.m_height > it->second.m_candidate.m_block.m_height) {
            return false;
        }
        while (it->second.m_candidate.m_block.m_height > ancestor_it->second.m_candidate.m_block.m_height) {
            if (!it->second.m_parent) return false;
            it = m_blocks.find(*it->second.m_parent);
            if (it == m_blocks.end()) return false;
        }
        return it->first == ancestor;
    }

    const Entry* LastCommon(const Entry& first, const Entry& second) const
    {
        const Entry* left{&first};
        const Entry* right{&second};
        while (left->m_candidate.m_block.m_height > right->m_candidate.m_block.m_height) {
            left = Lookup(left->m_parent);
            if (!left) return nullptr;
        }
        while (right->m_candidate.m_block.m_height > left->m_candidate.m_block.m_height) {
            right = Lookup(right->m_parent);
            if (!right) return nullptr;
        }
        while (left->m_candidate.m_block.m_hash != right->m_candidate.m_block.m_hash) {
            left = Lookup(left->m_parent);
            right = Lookup(right->m_parent);
            if (!left || !right) return nullptr;
        }
        return left;
    }

    void AppendPath(const Entry& start, const Entry& best_known, int max_height, std::vector<BlockDownloadCandidate>& output) const
    {
        std::vector<const Entry*> reverse;
        const Entry* walk{&best_known};
        while (walk && walk->m_candidate.m_block.m_height > start.m_candidate.m_block.m_height) {
            if (walk->m_candidate.m_block.m_height <= max_height) reverse.push_back(walk);
            walk = Lookup(walk->m_parent);
        }
        if (!walk || walk->m_candidate.m_block.m_hash != start.m_candidate.m_block.m_hash) return;
        for (auto it{reverse.rbegin()}; it != reverse.rend(); ++it) output.push_back((*it)->m_candidate);
    }

    BlockDownloadChainSnapshot CaptureLocked(const BlockDownloadChainQuery& query) const
    {
        BlockDownloadChainSnapshot snapshot;
        const Entry* pending{Lookup(query.m_pending_hash)};
        const Entry* announced{Lookup(query.m_announced_hash)};
        const Entry* ancestor{Lookup(query.m_ancestor_hash)};
        const Entry* best_known{Lookup(query.m_best_known_hash)};
        const Entry* best_header_sent{Lookup(query.m_best_header_sent_hash)};
        if (pending) snapshot.m_pending_block = pending->m_candidate.m_block;
        if (announced) snapshot.m_announced_block = announced->m_candidate.m_block;
        if (ancestor && best_known) {
            snapshot.m_ancestor_of_best_known = IsAncestor(
                ancestor->m_candidate.m_block.m_hash, best_known->m_candidate.m_block.m_hash);
        }
        if (ancestor && best_header_sent) {
            snapshot.m_ancestor_of_best_header_sent = IsAncestor(
                ancestor->m_candidate.m_block.m_hash, best_header_sent->m_candidate.m_block.m_hash);
        }
        if (!query.m_plan_blocks) return snapshot;

        const Entry* active_tip{Lookup(m_active_tip)};
        const Entry* current_tip{Lookup(m_current_chainstate_tip)};
        const Entry* snapshot_base{Lookup(m_snapshot_base)};
        if (active_tip) snapshot.m_active_tip = active_tip->m_candidate.m_block;
        snapshot.m_minimum_chain_work = m_minimum_chain_work;
        if (current_tip) snapshot.m_current_chainstate_tip_hash = current_tip->m_candidate.m_block.m_hash;
        if (snapshot_base) snapshot.m_snapshot_base = snapshot_base->m_candidate.m_block;
        snapshot.m_assumeutxo_state = m_assumeutxo_state;
        if (best_known) snapshot.m_resolved_best_known = best_known->m_candidate.m_block;
        snapshot.m_input_last_common_hash = query.m_last_common_hash;

        if (best_known && active_tip) {
            const Entry* fork{LastCommon(*best_known, *active_tip)};
            if (fork) {
                snapshot.m_fork_block = fork->m_candidate.m_block;
                const Entry* last_common{Lookup(query.m_last_common_hash)};
                if (!last_common ||
                    fork->m_candidate.m_block.m_chain_work > last_common->m_candidate.m_block.m_chain_work ||
                    !IsAncestor(last_common->m_candidate.m_block.m_hash, best_known->m_candidate.m_block.m_hash)) {
                    last_common = fork;
                }
                snapshot.m_last_common_block = last_common->m_candidate.m_block;
                snapshot.m_last_common_candidate = last_common->m_candidate;
                snapshot.m_best_known_has_snapshot_base = snapshot_base && IsAncestor(
                    snapshot_base->m_candidate.m_block.m_hash, best_known->m_candidate.m_block.m_hash);
                snapshot.m_normal_window_end =
                    last_common->m_candidate.m_block.m_height + static_cast<int>(query.m_download_window);
                AppendPath(
                    *last_common,
                    *best_known,
                    std::min(best_known->m_candidate.m_block.m_height, snapshot.m_normal_window_end + 1),
                    snapshot.m_normal_path);
            }
        }

        snapshot.m_historical_requested = query.m_include_historical;
        if (!query.m_include_historical || !m_historical_range) return snapshot;
        const Entry* historical_start{Lookup(m_historical_range->first)};
        const Entry* historical_target{Lookup(m_historical_range->second)};
        if (!historical_start || !historical_target) return snapshot;
        const Entry* historical_common{LastCommon(*historical_start, *historical_target)};
        if (!historical_common) return snapshot;
        snapshot.m_historical_start = historical_start->m_candidate.m_block;
        snapshot.m_historical_target = historical_target->m_candidate.m_block;
        snapshot.m_historical_last_common = historical_common->m_candidate.m_block;
        if (!best_known || !IsAncestor(
                historical_target->m_candidate.m_block.m_hash,
                best_known->m_candidate.m_block.m_hash)) {
            return snapshot;
        }
        snapshot.m_best_known_has_historical_target = true;
        snapshot.m_historical_window_end = std::min(
            historical_common->m_candidate.m_block.m_height + static_cast<int>(query.m_download_window),
            historical_target->m_candidate.m_block.m_height);
        AppendPath(
            *historical_common,
            *best_known,
            std::min(best_known->m_candidate.m_block.m_height, snapshot.m_historical_window_end + 1),
            snapshot.m_historical_path);
        return snapshot;
    }

    bool IdentityMatches(const BlockDownloadChainSnapshot& snapshot) const
    {
        const Entry* active_tip{Lookup(m_active_tip)};
        const Entry* current_tip{Lookup(m_current_chainstate_tip)};
        const Entry* snapshot_base{Lookup(m_snapshot_base)};
        if ((active_tip ? std::optional{active_tip->m_candidate.m_block} : std::nullopt) != snapshot.m_active_tip ||
            m_minimum_chain_work != snapshot.m_minimum_chain_work ||
            (current_tip ? std::optional{current_tip->m_candidate.m_block.m_hash} : std::nullopt) != snapshot.m_current_chainstate_tip_hash ||
            (snapshot_base ? std::optional{snapshot_base->m_candidate.m_block} : std::nullopt) != snapshot.m_snapshot_base ||
            m_assumeutxo_state != snapshot.m_assumeutxo_state) {
            return false;
        }

        const Entry* best_known{Lookup(snapshot.m_resolved_best_known
            ? std::optional{snapshot.m_resolved_best_known->m_hash}
            : std::nullopt)};
        if ((best_known ? std::optional{best_known->m_candidate.m_block} : std::nullopt) != snapshot.m_resolved_best_known) {
            return false;
        }
        if (best_known && active_tip) {
            const Entry* fork{LastCommon(*best_known, *active_tip)};
            if (!fork || snapshot.m_fork_block != std::optional{fork->m_candidate.m_block}) return false;
            const Entry* last_common{Lookup(snapshot.m_input_last_common_hash)};
            if (!last_common ||
                fork->m_candidate.m_block.m_chain_work > last_common->m_candidate.m_block.m_chain_work ||
                !IsAncestor(last_common->m_candidate.m_block.m_hash, best_known->m_candidate.m_block.m_hash)) {
                last_common = fork;
            }
            if (!snapshot.m_last_common_candidate ||
                snapshot.m_last_common_block != std::optional{last_common->m_candidate.m_block}) {
                return false;
            }
            const bool has_snapshot_base{snapshot_base && IsAncestor(
                snapshot_base->m_candidate.m_block.m_hash, best_known->m_candidate.m_block.m_hash)};
            if (has_snapshot_base != snapshot.m_best_known_has_snapshot_base) return false;
        } else if (snapshot.m_fork_block || snapshot.m_last_common_block ||
                   snapshot.m_last_common_candidate || snapshot.m_best_known_has_snapshot_base) {
            return false;
        }

        if (!snapshot.m_revalidate_historical_identity) return true;
        if (!m_historical_range) return !snapshot.m_historical_start && !snapshot.m_historical_target;
        const Entry* historical_start{Lookup(m_historical_range->first)};
        const Entry* historical_target{Lookup(m_historical_range->second)};
        if (!historical_start || !historical_target) return false;
        const Entry* historical_common{LastCommon(*historical_start, *historical_target)};
        if (!historical_common ||
            snapshot.m_historical_start != std::optional{historical_start->m_candidate.m_block} ||
            snapshot.m_historical_target != std::optional{historical_target->m_candidate.m_block} ||
            snapshot.m_historical_last_common != std::optional{historical_common->m_candidate.m_block}) {
            return false;
        }
        const bool has_target{best_known && IsAncestor(
            historical_target->m_candidate.m_block.m_hash,
            best_known->m_candidate.m_block.m_hash)};
        return has_target == snapshot.m_best_known_has_historical_target;
    }

public:
    void SetBlock(BlockDownloadBlock block, std::optional<uint256> parent = std::nullopt)
    {
        SetCandidate({.m_block = std::move(block), .m_valid_tree = true}, std::move(parent));
    }

    void SetCandidate(BlockDownloadCandidate candidate, std::optional<uint256> parent = std::nullopt)
    {
        std::lock_guard lock{m_mutex};
        m_blocks.insert_or_assign(candidate.m_block.m_hash, Entry{std::move(candidate), std::move(parent)});
    }

    void RemoveBlock(const uint256& hash)
    {
        std::lock_guard lock{m_mutex};
        m_blocks.erase(hash);
    }

    void SetActiveTip(std::optional<uint256> hash)
    {
        std::lock_guard lock{m_mutex};
        m_active_tip = std::move(hash);
    }

    void SetMinimumChainWork(arith_uint256 work)
    {
        std::lock_guard lock{m_mutex};
        m_minimum_chain_work = std::move(work);
    }

    void SetCurrentChainstate(
        std::optional<uint256> tip,
        std::optional<uint256> snapshot_base = std::nullopt,
        BlockDownloadAssumeutxoState state = BlockDownloadAssumeutxoState::NONE)
    {
        std::lock_guard lock{m_mutex};
        m_current_chainstate_tip = std::move(tip);
        m_snapshot_base = std::move(snapshot_base);
        m_assumeutxo_state = state;
    }

    void SetHistoricalRange(std::optional<std::pair<uint256, uint256>> range)
    {
        std::lock_guard lock{m_mutex};
        m_historical_range = std::move(range);
    }

    /** Run once after a snapshot is copied but before Capture returns. */
    void SetCaptureHook(std::function<void()> hook)
    {
        std::lock_guard lock{m_mutex};
        m_capture_hook = std::move(hook);
    }

    /** Run once after Capture and immediately before the fake validation transaction. */
    void SetRevalidateHook(std::function<void()> hook)
    {
        std::lock_guard lock{m_mutex};
        m_revalidate_hook = std::move(hook);
    }

    void FailRevalidations(int count)
    {
        std::lock_guard lock{m_mutex};
        m_forced_revalidation_failures = count;
    }

    int RevalidationCount() const
    {
        std::lock_guard lock{m_mutex};
        return m_revalidation_count;
    }

    BlockDownloadChainSnapshot Capture(const BlockDownloadChainQuery& query) const override
    {
        BlockDownloadChainSnapshot snapshot;
        std::function<void()> hook;
        {
            std::lock_guard lock{m_mutex};
            snapshot = CaptureLocked(query);
            hook = std::move(m_capture_hook);
            m_capture_hook = {};
        }
        if (hook) hook();
        return snapshot;
    }

    bool Revalidate(
        const BlockDownloadChainSnapshot& snapshot,
        std::span<const BlockDownloadBlock> proposal,
        const std::function<bool()>& commit) const override
    {
        std::function<void()> hook;
        {
            std::lock_guard lock{m_mutex};
            hook = std::move(m_revalidate_hook);
            m_revalidate_hook = {};
        }
        if (hook) hook();

        std::lock_guard lock{m_mutex};
        ++m_revalidation_count;
        if (m_forced_revalidation_failures > 0) {
            --m_forced_revalidation_failures;
            return false;
        }
        if (!IdentityMatches(snapshot)) return false;

        for (const auto& block : snapshot.m_revalidation_blocks) {
            const auto current{m_blocks.find(block.m_hash)};
            if (current == m_blocks.end()) return false;
            const auto find_expected = [&](const auto& path) -> std::optional<BlockDownloadCandidate> {
                const auto it{std::find_if(path.begin(), path.end(), [&](const auto& candidate) {
                    return candidate.m_block.m_hash == block.m_hash;
                })};
                return it == path.end() ? std::nullopt : std::optional{*it};
            };
            std::optional<BlockDownloadCandidate> expected;
            if (snapshot.m_last_common_candidate && snapshot.m_last_common_candidate->m_block.m_hash == block.m_hash) {
                expected = snapshot.m_last_common_candidate;
            } else if (!(expected = find_expected(snapshot.m_normal_path))) {
                expected = find_expected(snapshot.m_historical_path);
            }
            if (!expected || current->second.m_candidate != *expected) return false;
        }
        for (const auto& block : proposal) {
            if (std::none_of(
                    snapshot.m_revalidation_blocks.begin(),
                    snapshot.m_revalidation_blocks.end(),
                    [&](const auto& revalidated) { return revalidated == block; })) {
                return false;
            }
        }
        return commit();
    }
};

} // namespace node::test

#endif // BITCOIN_TEST_UTIL_BLOCKDOWNLOADCHAIN_H

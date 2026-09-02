// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_BLOCKDOWNLOADCHAIN_H
#define BITCOIN_TEST_UTIL_BLOCKDOWNLOADCHAIN_H

#include <node/blockdownloadchain.h>

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <utility>

namespace node::test {

/** Value-based mutable chain model for manager tests and fuzzing. */
class FakeBlockDownloadChain final : public BlockDownloadChain
{
    struct Entry {
        BlockDownloadBlock m_block;
        std::optional<uint256> m_parent;
    };

    mutable std::mutex m_mutex;
    std::map<uint256, Entry> m_blocks;
    mutable std::function<void()> m_capture_hook;

    bool IsAncestor(const uint256& ancestor, const uint256& descendant) const
    {
        auto it{m_blocks.find(descendant)};
        const auto ancestor_it{m_blocks.find(ancestor)};
        if (it == m_blocks.end() || ancestor_it == m_blocks.end() ||
            ancestor_it->second.m_block.m_height > it->second.m_block.m_height) {
            return false;
        }
        while (it->second.m_block.m_height > ancestor_it->second.m_block.m_height) {
            if (!it->second.m_parent) return false;
            it = m_blocks.find(*it->second.m_parent);
            if (it == m_blocks.end()) return false;
        }
        return it->first == ancestor;
    }

public:
    void SetBlock(BlockDownloadBlock block, std::optional<uint256> parent = std::nullopt)
    {
        std::lock_guard lock{m_mutex};
        m_blocks.insert_or_assign(block.m_hash, Entry{std::move(block), std::move(parent)});
    }

    void RemoveBlock(const uint256& hash)
    {
        std::lock_guard lock{m_mutex};
        m_blocks.erase(hash);
    }

    /** Run once after a snapshot is copied but before Capture returns. */
    void SetCaptureHook(std::function<void()> hook)
    {
        std::lock_guard lock{m_mutex};
        m_capture_hook = std::move(hook);
    }

    BlockDownloadChainSnapshot Capture(const BlockDownloadChainQuery& query) const override
    {
        BlockDownloadChainSnapshot snapshot;
        std::function<void()> hook;
        {
            std::lock_guard lock{m_mutex};
            const auto lookup = [this](const std::optional<uint256>& hash) -> std::optional<BlockDownloadBlock> {
                if (!hash) return std::nullopt;
                const auto it{m_blocks.find(*hash)};
                return it == m_blocks.end() ? std::nullopt : std::optional{it->second.m_block};
            };
            snapshot.m_pending_block = lookup(query.m_pending_hash);
            snapshot.m_announced_block = lookup(query.m_announced_hash);
            if (query.m_ancestor_hash && query.m_best_known_hash) {
                snapshot.m_ancestor_of_best_known = IsAncestor(*query.m_ancestor_hash, *query.m_best_known_hash);
            }
            if (query.m_ancestor_hash && query.m_best_header_sent_hash) {
                snapshot.m_ancestor_of_best_header_sent = IsAncestor(*query.m_ancestor_hash, *query.m_best_header_sent_hash);
            }
            hook = std::move(m_capture_hook);
            m_capture_hook = {};
        }
        if (hook) hook();
        return snapshot;
    }
};

} // namespace node::test

#endif // BITCOIN_TEST_UTIL_BLOCKDOWNLOADCHAIN_H

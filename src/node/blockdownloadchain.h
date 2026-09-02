// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADCHAIN_H
#define BITCOIN_NODE_BLOCKDOWNLOADCHAIN_H

#include <arith_uint256.h>
#include <span.h>
#include <uint256.h>

#include <functional>
#include <optional>
#include <vector>

namespace node {

/** Block identity and work copied from a coherent chain read transaction. */
struct BlockDownloadBlock {
    uint256 m_hash;
    int m_height;
    arith_uint256 m_chain_work;

    friend bool operator==(const BlockDownloadBlock&, const BlockDownloadBlock&) = default;
};

/** Validation-owned facts copied for one scheduling candidate. */
struct BlockDownloadCandidate {
    BlockDownloadBlock m_block;
    bool m_valid_tree{false};
    bool m_have_data{false};
    bool m_in_active_chain{false};
    bool m_have_chain_txs{false};
    bool m_segwit_active{false};

    friend bool operator==(const BlockDownloadCandidate&, const BlockDownloadCandidate&) = default;
};

/** Owned state of the current chainstate relevant to AssumeUTXO gating. */
enum class BlockDownloadAssumeutxoState {
    NONE,
    UNVALIDATED,
    VALIDATED,
};

/** Coherent availability and ancestry facts requested by the download manager. */
struct BlockDownloadChainQuery {
    std::optional<uint256> m_pending_hash;
    std::optional<uint256> m_announced_hash;
    std::optional<uint256> m_ancestor_hash;
    std::optional<uint256> m_best_known_hash;
    std::optional<uint256> m_best_header_sent_hash;
    std::optional<uint256> m_last_common_hash;
    bool m_plan_blocks{false};
    bool m_include_historical{false};
    unsigned int m_download_window{0};
};

/** Owned result of one coherent chain read transaction. */
struct BlockDownloadChainSnapshot {
    std::optional<BlockDownloadBlock> m_pending_block;
    std::optional<BlockDownloadBlock> m_announced_block;
    bool m_ancestor_of_best_known{false};
    bool m_ancestor_of_best_header_sent{false};

    /** Identity and policy facts for an automatic scheduling attempt. */
    std::optional<BlockDownloadBlock> m_active_tip;
    arith_uint256 m_minimum_chain_work;
    std::optional<uint256> m_current_chainstate_tip_hash;
    std::optional<BlockDownloadBlock> m_snapshot_base;
    BlockDownloadAssumeutxoState m_assumeutxo_state{BlockDownloadAssumeutxoState::NONE};
    std::optional<BlockDownloadBlock> m_resolved_best_known;
    std::optional<BlockDownloadBlock> m_fork_block;
    std::optional<uint256> m_input_last_common_hash;
    std::optional<BlockDownloadBlock> m_last_common_block;
    std::optional<BlockDownloadCandidate> m_last_common_candidate;
    bool m_best_known_has_snapshot_base{false};
    int m_normal_window_end{-1};
    std::vector<BlockDownloadCandidate> m_normal_path;

    /** Bounded background-chain range, when one exists and was requested. */
    std::optional<BlockDownloadBlock> m_historical_start;
    std::optional<BlockDownloadBlock> m_historical_target;
    std::optional<BlockDownloadBlock> m_historical_last_common;
    bool m_best_known_has_historical_target{false};
    bool m_historical_requested{false};
    /** Set by pure planning only when historical identity affected the result. */
    bool m_revalidate_historical_identity{false};
    int m_historical_window_end{-1};
    std::vector<BlockDownloadCandidate> m_historical_path;

    /** Bounded candidate identities selected by pure planning for revalidation. */
    std::vector<BlockDownloadBlock> m_revalidation_blocks;
};

class BlockDownloadChain
{
public:
    virtual ~BlockDownloadChain() = default;

    virtual BlockDownloadChainSnapshot Capture(const BlockDownloadChainQuery& query) const = 0;

    /**
     * Recheck one bounded proposal and invoke commit only while the captured
     * planning view is still coherent. Commit must not call this provider.
     */
    virtual bool Revalidate(
        const BlockDownloadChainSnapshot& snapshot,
        std::span<const BlockDownloadBlock> proposal,
        const std::function<bool()>& commit) const = 0;
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADCHAIN_H

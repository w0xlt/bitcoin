// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADCHAIN_H
#define BITCOIN_NODE_BLOCKDOWNLOADCHAIN_H

#include <arith_uint256.h>
#include <uint256.h>

#include <optional>

namespace node {

/** Block identity and work copied from a coherent chain read transaction. */
struct BlockDownloadBlock {
    uint256 m_hash;
    int m_height;
    arith_uint256 m_chain_work;

    friend bool operator==(const BlockDownloadBlock&, const BlockDownloadBlock&) = default;
};

/** Coherent availability and ancestry facts requested by the download manager. */
struct BlockDownloadChainQuery {
    std::optional<uint256> m_pending_hash;
    std::optional<uint256> m_announced_hash;
    std::optional<uint256> m_ancestor_hash;
    std::optional<uint256> m_best_known_hash;
    std::optional<uint256> m_best_header_sent_hash;
};

/** Owned result of one coherent chain read transaction. */
struct BlockDownloadChainSnapshot {
    std::optional<BlockDownloadBlock> m_pending_block;
    std::optional<BlockDownloadBlock> m_announced_block;
    bool m_ancestor_of_best_known{false};
    bool m_ancestor_of_best_header_sent{false};
};

class BlockDownloadChain
{
public:
    virtual ~BlockDownloadChain() = default;

    virtual BlockDownloadChainSnapshot Capture(const BlockDownloadChainQuery& query) const = 0;
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADCHAIN_H

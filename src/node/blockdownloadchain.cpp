// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/blockdownloadchain.h>
#include <node/blockdownloadchain_impl.h>

#include <chain.h>
#include <sync.h>
#include <validation.h>

#include <memory>
#include <optional>

namespace node {
namespace {

BlockDownloadBlock MakeBlock(const CBlockIndex& block)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    return {block.GetBlockHash(), block.nHeight, block.nChainWork};
}

class ValidationBlockDownloadChain final : public BlockDownloadChain
{
    ChainstateManager& m_chainman;

public:
    explicit ValidationBlockDownloadChain(ChainstateManager& chainman) : m_chainman{chainman} {}

    BlockDownloadChainSnapshot Capture(const BlockDownloadChainQuery& query) const override
    {
        LOCK(::cs_main);

        const auto lookup = [this](const std::optional<uint256>& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) -> const CBlockIndex* {
            return hash ? m_chainman.m_blockman.LookupBlockIndex(*hash) : nullptr;
        };
        const CBlockIndex* pending{lookup(query.m_pending_hash)};
        const CBlockIndex* announced{lookup(query.m_announced_hash)};
        const CBlockIndex* ancestor{lookup(query.m_ancestor_hash)};
        const CBlockIndex* best_known{lookup(query.m_best_known_hash)};
        const CBlockIndex* best_header_sent{lookup(query.m_best_header_sent_hash)};

        BlockDownloadChainSnapshot snapshot;
        if (pending) snapshot.m_pending_block = MakeBlock(*pending);
        if (announced) snapshot.m_announced_block = MakeBlock(*announced);
        if (ancestor && best_known && ancestor->nHeight <= best_known->nHeight) {
            snapshot.m_ancestor_of_best_known = best_known->GetAncestor(ancestor->nHeight) == ancestor;
        }
        if (ancestor && best_header_sent && ancestor->nHeight <= best_header_sent->nHeight) {
            snapshot.m_ancestor_of_best_header_sent = best_header_sent->GetAncestor(ancestor->nHeight) == ancestor;
        }
        return snapshot;
    }
};

} // namespace

std::unique_ptr<BlockDownloadChain> MakeValidationBlockDownloadChain(ChainstateManager& chainman)
{
    return std::make_unique<ValidationBlockDownloadChain>(chainman);
}

} // namespace node

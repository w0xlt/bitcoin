// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <staletips.h>

#include <chain.h>
#include <util/check.h>

#include <vector>

namespace {

/** Whether `ancestor` is an ancestor of `block`, or `block` itself. */
bool HasAncestor(const CBlockIndex& block, const CBlockIndex& ancestor)
{
    return block.nHeight >= ancestor.nHeight && block.GetAncestor(ancestor.nHeight) == &ancestor;
}

} // namespace

StaleTipMessage::StaleTipMessage(const StaleFork& fork, bool have_block)
{
    AssertLockHeld(::cs_main);
    Assume(fork.fork_point != nullptr);
    Assume(fork.tip != nullptr);
    Assume(HasAncestor(*fork.tip, *fork.fork_point));

    m_fork_point = fork.fork_point->GetBlockHash();
    m_have_block = have_block;

    const int fork_length{fork.tip->nHeight - fork.fork_point->nHeight};
    if (fork_length <= 0) return;

    const CBlockIndex* pindex{fork.tip};
    m_headers.resize(fork_length);
    for (int i{fork_length - 1}; i >= 0; --i) {
        m_headers.at(i) = {
            .version = pindex->nVersion,
            .merkle_root = pindex->hashMerkleRoot,
            .time = pindex->nTime,
            .bits = pindex->nBits,
            .nonce = pindex->nNonce,
        };
        pindex = pindex->pprev;
    }
}

std::pair<uint256, std::vector<CBlockHeader>> StaleTipMessage::ReconstructHeaders() const
{
    std::vector<CBlockHeader> headers;
    headers.reserve(m_headers.size());

    uint256 prev_hash{m_fork_point};
    for (const auto& compressed : m_headers) {
        CBlockHeader header;
        header.nVersion = compressed.version;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = compressed.merkle_root;
        header.nTime = compressed.time;
        header.nBits = compressed.bits;
        header.nNonce = compressed.nonce;
        headers.push_back(header);
        prev_hash = headers.back().GetHash();
    }

    return {prev_hash, headers};
}

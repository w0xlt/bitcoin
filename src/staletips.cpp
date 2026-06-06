// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <staletips.h>

#include <arith_uint256.h>
#include <chain.h>
#include <node/blockstorage.h>
#include <util/check.h>

#include <algorithm>
#include <set>
#include <vector>

const uint256 StaleTipCache::TESTNET_MAX_TARGET{uint256::FromHex("0000000000000fffffffffffffffffffffffffffffffffffffffffffffffffff").value()};

namespace {

/** Whether `ancestor` is an ancestor of `block`, or `block` itself. */
bool HasAncestor(const CBlockIndex& block, const CBlockIndex& ancestor)
{
    return block.nHeight >= ancestor.nHeight && block.GetAncestor(ancestor.nHeight) == &ancestor;
}

enum class VariantHeaderResult {
    //! The tips are not variants of each other; track both.
    PREFER_BOTH,
    //! The existing tip's branch extends a variant of the candidate; keep it.
    PREFER_OLD,
    //! The candidate's branch extends a variant of the existing tip; replace it.
    PREFER_NEW,
};

/** Determine which of two stale tips to keep when their branches may contain
 *  variant headers: headers with the same previous block and merkle root that
 *  differ in other fields. On low-difficulty networks such as signet, valid
 *  variants of a block are cheap to produce by grinding such fields, so only
 *  the first seen variant is tracked and advertised to avoid amplifying
 *  header spam. */
VariantHeaderResult CompareVariantHeaders(const CBlockIndex& candidate, const CBlockIndex& existing)
{
    auto same_variant = [](const CBlockIndex* a, const CBlockIndex* b) {
        return a != nullptr && b != nullptr && a->pprev == b->pprev && a->hashMerkleRoot == b->hashMerkleRoot;
    };

    if (candidate.nHeight > existing.nHeight) {
        return same_variant(&existing, candidate.GetAncestor(existing.nHeight)) ? VariantHeaderResult::PREFER_NEW : VariantHeaderResult::PREFER_BOTH;
    }

    return same_variant(existing.GetAncestor(candidate.nHeight), &candidate) ? VariantHeaderResult::PREFER_OLD : VariantHeaderResult::PREFER_BOTH;
}

} // namespace

StaleTipMessage::StaleTipMessage(const StaleFork& fork)
{
    AssertLockHeld(::cs_main);
    Assume(fork.fork_point != nullptr);
    Assume(fork.tip != nullptr);
    Assume(HasAncestor(*fork.tip, *fork.fork_point));

    m_fork_point = fork.fork_point->GetBlockHash();
    m_have_block = fork.tip->nStatus & BLOCK_HAVE_DATA;

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

const CBlockIndex* StaleTipCache::GetEligibleForkPoint(const CChain& chain, const CBlockIndex& stale_tip) const
{
    const CBlockIndex* active_tip{chain.Tip()};
    if (active_tip == nullptr) return nullptr;
    if (chain.Contains(stale_tip)) return nullptr;
    if (stale_tip.nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)) return nullptr;
    if (stale_tip.nHeight < active_tip->nHeight - m_recent_window) return nullptr;
    if (stale_tip.nChainWork > active_tip->nChainWork) return nullptr;

    if (m_chain_type == ChainType::SIGNET && !(stale_tip.nStatus & BLOCK_HAVE_DATA)) return nullptr;

    if (m_chain_type == ChainType::TESTNET || m_chain_type == ChainType::TESTNET4) {
        arith_uint256 target;
        target.SetCompact(stale_tip.nBits);
        if (target > UintToArith256(TESTNET_MAX_TARGET)) return nullptr;
    }

    const CBlockIndex* fork_point{chain.FindFork(stale_tip)};
    if (fork_point == nullptr) return nullptr;

    const int fork_length{stale_tip.nHeight - fork_point->nHeight};
    if (fork_length <= 0 || static_cast<size_t>(fork_length) > m_max_headers) return nullptr;

    return fork_point;
}

bool StaleTipCache::Add(const CBlockIndex& stale_tip)
{
    AssertLockHeld(::cs_main);

    const bool have_block{(stale_tip.nStatus & BLOCK_HAVE_DATA) != 0};
    Entry* available{nullptr};
    Entry* evict{nullptr};
    std::vector<Entry*> replace;

    auto better_evict_candidate = [](const Entry* current, const Entry& candidate) {
        return current == nullptr || candidate.tip->nHeight < current->tip->nHeight ||
               (candidate.tip->nHeight == current->tip->nHeight && candidate.header_seqno < current->header_seqno);
    };

    for (auto& entry : m_tips) {
        if (entry.tip == nullptr) {
            if (available == nullptr) available = &entry;
            continue;
        }

        if (entry.tip == &stale_tip) {
            if (have_block && entry.block_seqno == 0) {
                entry.block_seqno = m_next_seqno++;
                return true;
            }
            return false;
        }

        if (HasAncestor(stale_tip, *entry.tip)) {
            replace.push_back(&entry);
            continue;
        }
        if (HasAncestor(*entry.tip, stale_tip)) return false;

        if (m_chain_type == ChainType::SIGNET) {
            const auto variant_result{CompareVariantHeaders(stale_tip, *entry.tip)};
            if (variant_result == VariantHeaderResult::PREFER_OLD) return false;
            if (variant_result == VariantHeaderResult::PREFER_NEW) {
                replace.push_back(&entry);
                continue;
            }
        }

        if (entry.tip->nHeight < stale_tip.nHeight && better_evict_candidate(evict, entry)) {
            evict = &entry;
        }
    }

    Entry* target{!replace.empty() ? replace.front() : available != nullptr ? available : evict};
    if (target == nullptr) return false;

    for (Entry* entry : replace) {
        *entry = {};
    }
    target->tip = &stale_tip;
    target->header_seqno = m_next_seqno++;
    target->block_seqno = have_block ? target->header_seqno : 0;
    return true;
}

void StaleTipCache::Initialize(node::BlockManager& blockman, const CChain& chain)
{
    AssertLockHeld(::cs_main);

    const CBlockIndex* active_tip{chain.Tip()};
    if (active_tip == nullptr) return;

    const int min_height{std::max<int>(active_tip->nHeight - m_recent_window, 0)};
    std::vector<const CBlockIndex*> candidates;
    std::set<const CBlockIndex*> parents;

    for (const auto& [_, block_index] : blockman.m_block_index) {
        if (!block_index.IsValid(BLOCK_VALID_TREE)) continue;
        if (block_index.nHeight < min_height) continue;
        if (GetEligibleForkPoint(chain, block_index) == nullptr) continue;
        candidates.push_back(&block_index);
        if (block_index.pprev != nullptr) parents.insert(block_index.pprev);
    }

    std::ranges::sort(candidates, [](const CBlockIndex* a, const CBlockIndex* b) {
        if (a->nHeight != b->nHeight) return a->nHeight > b->nHeight;
        return a->GetBlockHash() < b->GetBlockHash();
    });

    for (const CBlockIndex* candidate : candidates) {
        if (!parents.contains(candidate)) (void)Add(*candidate);
    }
}

bool StaleTipCache::AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip)
{
    AssertLockHeld(::cs_main);
    if (stale_tip == nullptr) return false;
    if (GetEligibleForkPoint(chain, *stale_tip) == nullptr) return false;

    if (m_chain_type == ChainType::SIGNET && chain.Tip() != nullptr) {
        if (CompareVariantHeaders(*stale_tip, *chain.Tip()) == VariantHeaderResult::PREFER_OLD) return false;
    }

    return Add(*stale_tip);
}

bool StaleTipCache::CanServeStaleBranchBlock(const CChain& chain, const CBlockIndex* block) const
{
    AssertLockHeld(::cs_main);
    if (block == nullptr) return false;
    if (!(block->nStatus & BLOCK_HAVE_DATA)) return false;

    for (const auto& entry : m_tips) {
        if (entry.tip == nullptr) continue;
        if (!(entry.tip->nStatus & BLOCK_HAVE_DATA)) continue;

        const CBlockIndex* fork_point{GetEligibleForkPoint(chain, *entry.tip)};
        if (fork_point == nullptr) continue;
        if (block->nHeight <= fork_point->nHeight || block->nHeight > entry.tip->nHeight) continue;
        if (entry.tip->GetAncestor(block->nHeight) == block) return true;
    }
    return false;
}

std::vector<StaleFork> StaleTipCache::GetStaleTips(const CChain& chain) const
{
    AssertLockHeld(::cs_main);

    std::vector<StaleFork> tips;
    tips.reserve(m_tips.size());

    for (const auto& entry : m_tips) {
        if (entry.tip == nullptr) continue;
        const CBlockIndex* fork_point{GetEligibleForkPoint(chain, *entry.tip)};
        if (fork_point == nullptr) continue;
        tips.push_back({.fork_point = fork_point, .tip = entry.tip});
    }

    return tips;
}

std::vector<StaleTipInfo> StaleTipCache::GetStaleTipInfo(const CChain& chain) const
{
    AssertLockHeld(::cs_main);

    std::vector<StaleTipInfo> info;
    for (const auto& fork : GetStaleTips(chain)) {
        info.push_back({
            .hash = fork.tip->GetBlockHash(),
            .height = fork.tip->nHeight,
            .have_block = (fork.tip->nStatus & BLOCK_HAVE_DATA) != 0,
            .fork_point = fork.fork_point->GetBlockHash(),
            .fork_length = fork.tip->nHeight - fork.fork_point->nHeight,
        });
    }
    return info;
}

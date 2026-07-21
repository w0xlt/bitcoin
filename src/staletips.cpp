// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <staletips.h>

#include <chain.h>
#include <util/check.h>

#include <utility>
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

    const int fork_length{fork.tip->nHeight - fork.fork_point->nHeight};
    Assert(fork_length > 0);
    Assert(static_cast<size_t>(fork_length) <= MAX_STALETIP_HEADERS);

    m_fork_point = fork.fork_point->GetBlockHash();
    m_have_block = have_block;

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

StaleTipMessage::HeaderDecompressionResult StaleTipMessage::DecompressHeaders() const
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

    return {
        .tip_hash = prev_hash,
        .headers = std::move(headers),
    };
}

bool StaleTipCache::IsRecentHeight(const CChain& chain, int height) const
{
    AssertLockHeld(::cs_main);
    const CBlockIndex* active_tip{chain.Tip()};
    return active_tip != nullptr && height >= active_tip->nHeight - m_recent_window;
}

const CBlockIndex* StaleTipCache::GetEligibleForkPoint(const CChain& chain, const CBlockIndex& stale_tip) const
{
    const CBlockIndex* active_tip{chain.Tip()};
    if (active_tip == nullptr) return nullptr;
    if (chain.Contains(stale_tip)) return nullptr;
    if (stale_tip.nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)) return nullptr;
    if (!IsRecentHeight(chain, stale_tip.nHeight)) return nullptr;
    if (stale_tip.nChainWork > active_tip->nChainWork) return nullptr;

    const CBlockIndex* fork_point{chain.FindFork(stale_tip)};
    if (fork_point == nullptr) return nullptr;

    const int fork_length{stale_tip.nHeight - fork_point->nHeight};
    if (fork_length <= 0 || static_cast<size_t>(fork_length) > m_max_headers) return nullptr;

    return fork_point;
}

bool StaleTipCache::IsLongBranchTip(const CChain& chain, const CBlockIndex& block) const
{
    AssertLockHeld(::cs_main);
    const CBlockIndex* active_tip{chain.Tip()};
    if (active_tip == nullptr || chain.Contains(block)) return false;
    if (block.nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)) return false;
    if (!IsRecentHeight(chain, block.nHeight)) return false;
    const CBlockIndex* fork_point{chain.FindFork(block)};
    return fork_point != nullptr && static_cast<size_t>(block.nHeight - fork_point->nHeight) > m_max_headers;
}

void StaleTipCache::AddLongBranchTip(const CBlockIndex& tip)
{
    AssertLockHeld(::cs_main);
    // Forget remembered tips that turned out to be invalid: the valid part of
    // their branch may still be too long, as `tip` shows.
    std::erase_if(m_long_branch_tips, [](const CBlockIndex* long_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return (long_tip->nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)) != 0;
    });
    if (std::ranges::any_of(m_long_branch_tips, [&](const CBlockIndex* long_tip) { return HasAncestor(*long_tip, tip); })) return;
    std::erase_if(m_long_branch_tips, [&](const CBlockIndex* long_tip) { return HasAncestor(tip, *long_tip); });
    m_long_branch_tips.push_back(&tip);
    if (m_long_branch_tips.size() > MAX_RETAINED_STALETIPS) m_long_branch_tips.pop_front();

    for (auto& entry : m_tips) {
        if (entry.tip != nullptr && HasAncestor(tip, *entry.tip)) entry = {};
    }
}

bool StaleTipCache::Add(const CChain& chain, const CBlockIndex& stale_tip)
{
    AssertLockHeld(::cs_main);

    // Blocks on a long branch are not tracked, unless the branch is no longer
    // long, for example after a reorg, or its tip turned out to be invalid.
    const bool on_long_branch{std::ranges::any_of(m_long_branch_tips, [&](const CBlockIndex* long_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return HasAncestor(*long_tip, stale_tip) && IsLongBranchTip(chain, *long_tip);
    })};
    if (on_long_branch) return false;

    Entry* available{nullptr};
    Entry* evict{nullptr};
    Entry* evict_ineligible{nullptr};
    std::vector<Entry*> replace;

    auto better_evict_candidate = [](const Entry* current, const Entry& candidate) {
        return current == nullptr || candidate.tip->nChainWork < current->tip->nChainWork ||
               (candidate.tip->nChainWork == current->tip->nChainWork && candidate.header_seqno < current->header_seqno);
    };

    for (auto& entry : m_tips) {
        if (entry.tip == nullptr) {
            if (available == nullptr) available = &entry;
            continue;
        }

        if (entry.tip == &stale_tip) return false;

        // A tracked tip known to be invalid doesn't make its valid ancestors
        // redundant: they replace it.
        const bool invalid{(entry.tip->nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)) != 0};
        if (HasAncestor(stale_tip, *entry.tip)) {
            replace.push_back(&entry);
            continue;
        }
        if (HasAncestor(*entry.tip, stale_tip)) {
            if (!invalid) return false;
            replace.push_back(&entry);
            continue;
        }

        // Prefer evicting tracked tips that are no longer eligible, such as
        // tips now on the active chain. `stale_tip` is the most recently
        // added, so it is preferred over tracked tips with equal chainwork.
        if (GetEligibleForkPoint(chain, *entry.tip) == nullptr) {
            if (better_evict_candidate(evict_ineligible, entry)) evict_ineligible = &entry;
        } else if (entry.tip->nChainWork <= stale_tip.nChainWork && better_evict_candidate(evict, entry)) {
            evict = &entry;
        }
    }

    Entry* target{!replace.empty() ? replace.front() :
                  available != nullptr ? available :
                  evict_ineligible != nullptr ? evict_ineligible : evict};
    if (target == nullptr) return false;

    for (Entry* entry : replace) {
        *entry = {};
    }
    target->tip = &stale_tip;
    target->header_seqno = m_next_seqno++;
    return true;
}

bool StaleTipCache::AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip)
{
    AssertLockHeld(::cs_main);
    if (stale_tip == nullptr) return false;
    if (IsLongBranchTip(chain, *stale_tip)) {
        AddLongBranchTip(*stale_tip);
        return false;
    }
    if (GetEligibleForkPoint(chain, *stale_tip) == nullptr) return false;

    return Add(chain, *stale_tip);
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

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
#include <utility>
#include <vector>

const uint256 StaleTipCache::TESTNET_MAX_TARGET{uint256::FromHex("0000000000000fffffffffffffffffffffffffffffffffffffffffffffffffff").value()};

namespace {

/** Whether `ancestor` is an ancestor of `block`, or `block` itself. */
bool HasAncestor(const CBlockIndex& block, const CBlockIndex& ancestor)
{
    return block.nHeight >= ancestor.nHeight && block.GetAncestor(ancestor.nHeight) == &ancestor;
}

/** Whether `a` and `b` are header variants of each other, or the same block:
 *  they have the same previous block and merkle root. */
bool IsSameVariant(const CBlockIndex* a, const CBlockIndex* b)
{
    return a != nullptr && b != nullptr && a->pprev == b->pprev && a->hashMerkleRoot == b->hashMerkleRoot;
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
    if (candidate.nHeight > existing.nHeight) {
        return IsSameVariant(&existing, candidate.GetAncestor(existing.nHeight)) ? VariantHeaderResult::PREFER_NEW : VariantHeaderResult::PREFER_BOTH;
    }

    return IsSameVariant(existing.GetAncestor(candidate.nHeight), &candidate) ? VariantHeaderResult::PREFER_OLD : VariantHeaderResult::PREFER_BOTH;
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

bool StaleTipCache::MeetsMinimumDifficulty(uint32_t bits) const
{
    if (m_chain_type != ChainType::TESTNET && m_chain_type != ChainType::TESTNET4) return true;
    bool negative;
    bool overflow;
    arith_uint256 target;
    target.SetCompact(bits, &negative, &overflow);
    return !negative && !overflow && target != 0 && target <= UintToArith256(TESTNET_MAX_TARGET);
}

const CBlockIndex* StaleTipCache::GetEligibleForkPoint(const CChain& chain, const CBlockIndex& stale_tip, bool require_signet_block_data, bool allow_more_work) const
{
    const CBlockIndex* active_tip{chain.Tip()};
    if (active_tip == nullptr) return nullptr;
    if (chain.Contains(stale_tip)) return nullptr;
    if (stale_tip.nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)) return nullptr;
    if (!IsRecentHeight(chain, stale_tip.nHeight)) return nullptr;
    if (!allow_more_work && stale_tip.nChainWork > active_tip->nChainWork) return nullptr;

    if (require_signet_block_data && m_chain_type == ChainType::SIGNET && !(stale_tip.nStatus & BLOCK_HAVE_DATA)) return nullptr;

    if (!MeetsMinimumDifficulty(stale_tip.nBits)) return nullptr;

    if (m_chain_type == ChainType::SIGNET && IsSameVariant(chain[stale_tip.nHeight], &stale_tip)) return nullptr;

    const CBlockIndex* fork_point{chain.FindFork(stale_tip)};
    if (fork_point == nullptr) return nullptr;

    const int fork_length{stale_tip.nHeight - fork_point->nHeight};
    if (fork_length <= 0 || static_cast<size_t>(fork_length) > m_max_headers) return nullptr;

    return fork_point;
}

bool StaleTipCache::IsStaleTipEligible(const CChain& chain, const CBlockIndex* stale_tip, bool require_signet_block_data, bool allow_more_work) const
{
    AssertLockHeld(::cs_main);
    return stale_tip != nullptr && GetEligibleForkPoint(chain, *stale_tip, require_signet_block_data, allow_more_work) != nullptr;
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
        if (entry.tip != nullptr && HasAncestor(tip, *entry.tip)) {
            entry = {};
            ++m_removal_count;
        }
    }
}

StaleTipCache::Placement StaleTipCache::GetPlacement(const CChain& chain, const CBlockIndex& stale_tip) const
{
    AssertLockHeld(::cs_main);

    // Blocks on a long branch are not tracked, unless the branch is no longer
    // long, for example after a reorg, or its tip turned out to be invalid.
    const bool on_long_branch{std::ranges::any_of(m_long_branch_tips, [&](const CBlockIndex* long_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return HasAncestor(*long_tip, stale_tip) && IsLongBranchTip(chain, *long_tip);
    })};
    if (on_long_branch) return {};

    Placement placement;
    std::optional<size_t> available;
    std::optional<size_t> evict;
    std::optional<size_t> evict_ineligible;

    auto better_evict_candidate = [&](const std::optional<size_t>& current, const Entry& candidate) {
        if (!current) return true;
        const Entry& entry{m_tips[*current]};
        return candidate.tip->nChainWork < entry.tip->nChainWork ||
               (candidate.tip->nChainWork == entry.tip->nChainWork && candidate.header_seqno < entry.header_seqno);
    };

    for (size_t i{0}; i < m_tips.size(); ++i) {
        const Entry& entry{m_tips[i]};
        if (entry.tip == nullptr) {
            if (!available) available = i;
            continue;
        }

        if (entry.tip == &stale_tip) return {.index = i, .tracked = true, .replace = {}};

        // A tracked tip known to be invalid doesn't make its valid ancestors
        // redundant: they replace it.
        const bool invalid{(entry.tip->nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)) != 0};
        if (HasAncestor(stale_tip, *entry.tip)) {
            placement.replace.push_back(i);
            continue;
        }
        if (HasAncestor(*entry.tip, stale_tip)) {
            if (!invalid) return {};
            placement.replace.push_back(i);
            continue;
        }

        if (m_chain_type == ChainType::SIGNET) {
            const auto variant_result{CompareVariantHeaders(stale_tip, *entry.tip)};
            if (variant_result == VariantHeaderResult::PREFER_OLD) return {};
            if (variant_result == VariantHeaderResult::PREFER_NEW) {
                placement.replace.push_back(i);
                continue;
            }
        }

        // Prefer evicting tracked tips that are no longer eligible, such as
        // tips now on the active chain. `stale_tip` is the most recently
        // added, so it is preferred over tracked tips with equal chainwork.
        if (GetEligibleForkPoint(chain, *entry.tip) == nullptr) {
            if (better_evict_candidate(evict_ineligible, entry)) evict_ineligible = i;
        } else if (entry.tip->nChainWork <= stale_tip.nChainWork && better_evict_candidate(evict, entry)) {
            evict = i;
        }
    }

    if (!placement.replace.empty()) {
        placement.index = placement.replace.front();
    } else {
        placement.index = available ? available : evict_ineligible ? evict_ineligible : evict;
    }
    return placement;
}

bool StaleTipCache::Add(const CChain& chain, const CBlockIndex& stale_tip)
{
    AssertLockHeld(::cs_main);

    const Placement placement{GetPlacement(chain, stale_tip)};
    if (!placement.index) return false;
    Entry& target{m_tips[*placement.index]};
    const bool have_block{(stale_tip.nStatus & BLOCK_HAVE_DATA) != 0};

    if (placement.tracked) {
        if (!have_block || target.block_seqno != 0) return false;
        // After STALETIP_BLOCK_WAIT, the tip may already have been announced
        // without block data to peers that prefer block data. Reuse its
        // sequence number so it is not announced to them again.
        const bool waited{NodeClock::now() >= target.header_time + STALETIP_BLOCK_WAIT};
        target.block_seqno = waited ? target.header_seqno : m_next_seqno++;
        return true;
    }

    if (target.tip != nullptr) ++m_removal_count;
    for (const size_t i : placement.replace) {
        if (i != *placement.index) ++m_removal_count;
        m_tips[i] = {};
    }
    target.tip = &stale_tip;
    target.header_seqno = m_next_seqno++;
    target.block_seqno = have_block ? target.header_seqno : 0;
    target.header_time = NodeClock::now();
    return true;
}

void StaleTipCache::Initialize(node::BlockManager& blockman, const CChain& chain)
{
    AssertLockHeld(::cs_main);

    const CBlockIndex* active_tip{chain.Tip()};
    if (active_tip == nullptr) return;

    const int min_height{std::max<int>(active_tip->nHeight - m_recent_window, 0)};
    std::vector<const CBlockIndex*> tips;
    std::set<const CBlockIndex*> parents;

    for (const auto& [_, block_index] : blockman.m_block_index) {
        if (!block_index.IsValid(BLOCK_VALID_TREE)) continue;
        if (block_index.nHeight < min_height) continue;
        if (block_index.pprev != nullptr) parents.insert(block_index.pprev);
        if (chain.Contains(block_index)) continue;
        tips.push_back(&block_index);
    }
    // A block with known children is not the tip of a stale branch.
    std::erase_if(tips, [&](const CBlockIndex* tip) { return parents.contains(tip); });

    std::ranges::sort(tips, [](const CBlockIndex* a, const CBlockIndex* b) {
        if (a->nHeight != b->nHeight) return a->nHeight > b->nHeight;
        return a->GetBlockHash() < b->GetBlockHash();
    });

    for (const CBlockIndex* tip : tips) {
        if (IsLongBranchTip(chain, *tip)) AddLongBranchTip(*tip);
    }
    for (const CBlockIndex* tip : tips) {
        if (IsStaleTipEligible(chain, tip)) (void)Add(chain, *tip);
    }
}

bool StaleTipCache::Empty() const
{
    AssertLockHeld(::cs_main);
    return std::ranges::all_of(m_tips, [](const Entry& entry) { return entry.tip == nullptr; });
}

bool StaleTipCache::AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip, bool allow_more_work)
{
    AssertLockHeld(::cs_main);
    if (stale_tip == nullptr) return false;
    if (IsLongBranchTip(chain, *stale_tip)) {
        AddLongBranchTip(*stale_tip);
        return false;
    }
    if (!IsStaleTipEligible(chain, stale_tip, /*require_signet_block_data=*/true, allow_more_work)) return false;

    return Add(chain, *stale_tip);
}

bool StaleTipCache::CanRequestStaleTipBlock(const CChain& chain, const CBlockIndex* stale_tip, bool allow_more_work) const
{
    AssertLockHeld(::cs_main);
    if (!IsStaleTipEligible(chain, stale_tip, /*require_signet_block_data=*/false, allow_more_work)) return false;
    for (const CBlockIndex* block{stale_tip}; block != nullptr && !chain.Contains(*block); block = block->pprev) {
        if (IsKnownVariant(chain, *block)) return false;
    }
    // Only request block data that could be served: that of a tip that is or
    // would be tracked, or that is on a tracked, eligible branch.
    return GetPlacement(chain, *stale_tip).index.has_value() ||
           std::ranges::any_of(m_tips, [&](const Entry& entry) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
               return entry.tip != nullptr && HasAncestor(*entry.tip, *stale_tip) &&
                      GetEligibleForkPoint(chain, *entry.tip, /*require_signet_block_data=*/true, allow_more_work) != nullptr;
           });
}

bool StaleTipCache::IsKnownVariant(const CChain& chain, const CBlockIndex& block) const
{
    AssertLockHeld(::cs_main);
    if (m_chain_type != ChainType::SIGNET || chain.Contains(block)) return false;

    if (IsSameVariant(chain[block.nHeight], &block)) return true;

    return std::ranges::any_of(m_tips, [&](const Entry& entry) {
        return entry.tip != nullptr && !HasAncestor(*entry.tip, block) &&
               CompareVariantHeaders(block, *entry.tip) == VariantHeaderResult::PREFER_OLD;
    });
}

bool StaleTipCache::CanServeStaleBranchBlock(const CChain& chain, const CBlockIndex* block) const
{
    AssertLockHeld(::cs_main);
    if (block == nullptr) return false;
    if (!(block->nStatus & BLOCK_HAVE_DATA)) return false;

    for (const auto& entry : m_tips) {
        if (entry.tip == nullptr) continue;

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

std::vector<StaleTipAnnouncement> StaleTipCache::GetTipsToAnnounce(const CChain& chain, bool want_blocks, const std::set<uint32_t>& skip_seqnos) const
{
    AssertLockHeld(::cs_main);

    std::vector<StaleTipAnnouncement> announcements;
    const auto now{NodeClock::now()};

    for (const auto& entry : m_tips) {
        if (entry.tip == nullptr) continue;
        if (skip_seqnos.contains(entry.header_seqno) || skip_seqnos.contains(entry.block_seqno)) continue;

        uint32_t seqno{entry.header_seqno};
        if (want_blocks) {
            // Wait for the block data, unless that would substantially delay
            // propagation.
            if (entry.block_seqno != 0) {
                seqno = entry.block_seqno;
            } else if (now < entry.header_time + STALETIP_BLOCK_WAIT) {
                continue;
            }
        }

        const CBlockIndex* fork_point{GetEligibleForkPoint(chain, *entry.tip)};
        if (fork_point == nullptr) continue;

        announcements.push_back({.fork = {.fork_point = fork_point, .tip = entry.tip}, .seqno = seqno, .header_seqno = entry.header_seqno, .header_time = entry.header_time});
    }

    std::ranges::sort(announcements, {}, &StaleTipAnnouncement::seqno);
    return announcements;
}

std::set<uint32_t> StaleTipCache::GetTrackedSeqnos() const
{
    AssertLockHeld(::cs_main);

    std::set<uint32_t> seqnos;
    for (const auto& entry : m_tips) {
        if (entry.tip == nullptr) continue;
        seqnos.insert(entry.header_seqno);
        if (entry.block_seqno != 0) seqnos.insert(entry.block_seqno);
    }
    return seqnos;
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

std::vector<StaleTipAnnouncement> GetUnadvertisedStaleTips(std::vector<StaleTipAnnouncement> known_tips, size_t max_tips)
{
    AssertLockHeld(::cs_main);
    if (known_tips.size() <= max_tips) return {};

    std::ranges::sort(known_tips, [](const StaleTipAnnouncement& a, const StaleTipAnnouncement& b) {
        if (a.fork.tip->nChainWork != b.fork.tip->nChainWork) return a.fork.tip->nChainWork > b.fork.tip->nChainWork;
        return a.seqno > b.seqno;
    });
    known_tips.erase(known_tips.begin(), known_tips.begin() + max_tips);
    return known_tips;
}

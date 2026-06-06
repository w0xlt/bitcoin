// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STALETIPS_H
#define BITCOIN_STALETIPS_H

#include <chain.h>
#include <kernel/cs_main.h>
#include <serialize.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <vector>

namespace node {
class BlockManager;
} // namespace node

/** Maximum number of compressed headers permitted in a `staletip` message. */
static constexpr size_t MAX_STALETIP_HEADERS{20};
/** Default number of blocks below the active tip within which a stale tip is
 *  still considered recent enough to be tracked and relayed. */
static constexpr int STALETIP_RECENT_WINDOW{1000};
/** Maximum number of stale tips retained in the StaleTips cache. */
static constexpr size_t MAX_RETAINED_STALETIPS{10};

/** A stale branch of the block tree, described by its tip and the point where
 *  it forks off the active chain. */
struct StaleFork {
    //! Last common ancestor of the stale tip and the active chain.
    const CBlockIndex* fork_point{nullptr};
    //! Tip of the stale branch.
    const CBlockIndex* tip{nullptr};
};

/** Summary of a tracked stale tip. */
struct StaleTipInfo {
    //! Block hash of the stale tip.
    uint256 hash{};
    //! Height of the stale tip.
    int height{-1};
    //! Whether the stale tip's block data is available locally.
    bool have_block{false};
    //! Block hash of the fork point on the active chain.
    uint256 fork_point{};
    //! Number of stale blocks between the fork point and the stale tip.
    int fork_length{0};
};

/** A block header without its previous block hash, as serialized in `staletip`
 *  messages. The omitted previous block hash is reconstructed from the
 *  preceding header in the message (or from the fork point for the first
 *  header), saving 32 bytes per header. */
struct StaleTipCompressedHeader {
    int32_t version{0};
    uint256 merkle_root{};
    uint32_t time{0};
    uint32_t bits{0};
    uint32_t nonce{0};

    friend bool operator==(const StaleTipCompressedHeader& a, const StaleTipCompressedHeader& b)
    {
        return a.version == b.version &&
               a.merkle_root == b.merkle_root &&
               a.time == b.time &&
               a.bits == b.bits &&
               a.nonce == b.nonce;
    }

    SERIALIZE_METHODS(StaleTipCompressedHeader, obj)
    {
        READWRITE(obj.version, obj.merkle_root, obj.time, obj.bits, obj.nonce);
    }
};

/** Contents of a `staletip` P2P message: an announcement of a stale branch,
 *  consisting of the fork point hash, the compressed headers of the branch and
 *  whether the announcer has the stale tip's block data. */
class StaleTipData
{
public:
    //! Block hash of the last common ancestor of the stale tip and the
    //! announcer's active chain.
    uint256 m_fork_point{};
    //! Compressed headers from the first block after the fork point up to the
    //! stale tip, in height order.
    std::vector<StaleTipCompressedHeader> m_headers;
    //! Whether the announcer can provide the stale tip's block data on request.
    bool m_have_block{false};

    StaleTipData() = default;
    /** Construct an announcement for `fork`, compressing the headers between
     *  `fork.fork_point` (exclusive) and `fork.tip` (inclusive). */
    explicit StaleTipData(const StaleFork& fork) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Rebuild the full block headers from `m_headers` by computing each
     *  header's previous block hash, starting from `m_fork_point`.
     *
     * @return The hash of the reconstructed stale tip, and the full headers in
     *         height order.
     */
    std::pair<uint256, std::vector<CBlockHeader>> ReconstructHeaders() const;

    friend bool operator==(const StaleTipData& a, const StaleTipData& b)
    {
        return a.m_fork_point == b.m_fork_point &&
               a.m_headers == b.m_headers &&
               a.m_have_block == b.m_have_block;
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << m_fork_point;
        WriteCompactSize(s, m_headers.size());
        for (const auto& header : m_headers) {
            s << header;
        }
        const uint8_t have_block{m_have_block};
        s << have_block;
    }

    /**
     * @throws std::ios_base::failure if the payload is malformed or declares
     *         more than MAX_STALETIP_HEADERS headers.
     */
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> m_fork_point;

        const uint64_t size{ReadCompactSize(s)};
        if (size == 0) {
            throw std::ios_base::failure("staletip headers empty");
        }
        if (size > MAX_STALETIP_HEADERS) {
            throw std::ios_base::failure("staletip headers limit exceeded");
        }

        m_headers.clear();
        m_headers.reserve(size);
        for (uint64_t i{0}; i < size; ++i) {
            m_headers.emplace_back();
            s >> m_headers.back();
        }

        uint8_t have_block{0};
        s >> have_block;
        if (have_block > 1) {
            throw std::ios_base::failure("staletip invalid bool");
        }
        m_have_block = have_block;
    }
};

/** Cache of recently seen stale tips: tips of valid (or potentially valid)
 *  branches of the block tree that are not part of the active chain.
 *
 * At most MAX_RETAINED_STALETIPS tips are retained, for relay to peers. A tip
 * is only tracked (and only relayed) while it remains eligible: its branch
 * forks off the active chain by no more than `m_max_headers` blocks, its
 * height is within `m_recent_window` blocks of the active tip, it has no more
 * work than the active tip, and it is not known to be invalid. Stricter
 * policies apply on test networks: on signet the tip's block data must be
 * available (the block signature cannot be verified from headers alone) and
 * header variants are deduplicated, while on testnet the tip must meet a
 * minimum difficulty so that min-difficulty blocks are not relayed.
 */
class StaleTips
{
private:
    struct Entry {
        //! Tracked stale tip, or nullptr for an unused slot.
        const CBlockIndex* tip{nullptr};
        //! Sequence number assigned when the tip was added.
        uint32_t header_seqno{0};
        //! Sequence number assigned when the tip's block data became
        //! available, or 0 while it is unavailable.
        uint32_t block_seqno{0};
    };

    std::array<Entry, MAX_RETAINED_STALETIPS> m_tips{};
    //! Sequence number to assign to the next addition.
    uint32_t m_next_seqno{1};
    ChainType m_chain_type{ChainType::MAIN};
    //! Tips more than this many blocks below the active tip are not tracked.
    int m_recent_window{STALETIP_RECENT_WINDOW};
    //! Maximum stale branch length to track.
    size_t m_max_headers{MAX_STALETIP_HEADERS};

    /** Find the fork point of `stale_tip` with the active chain, checking that
     *  the tip is eligible for tracking and relay.
     *
     * @return The fork point, or nullptr if the tip is not eligible.
     */
    const CBlockIndex* GetEligibleForkPoint(const CChain& chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Insert `stale_tip` into the cache, dropping any tracked tips that it
     *  descends from. If the tip is already tracked, only its block data
     *  availability is updated. Does nothing if one of its descendants is
     *  already tracked, or if the cache is full of tips of greater or equal
     *  height. On signet, tracked header variants of `stale_tip` are either
     *  kept in its place or replaced by it, whichever has the longer branch. */
    void Add(const CBlockIndex& stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

public:
    /** Maximum target allowed for testnet stale-tip relay policy. */
    static const uint256 TESTNET_MAX_TARGET;

    StaleTips() = default;
    /** Construct a cache with non-default policy parameters (used by tests). */
    explicit StaleTips(ChainType chain_type, int recent_window = STALETIP_RECENT_WINDOW, size_t max_headers = MAX_STALETIP_HEADERS)
        : m_chain_type{chain_type}, m_recent_window{recent_window}, m_max_headers{max_headers}
    {
    }

    explicit StaleTips(int recent_window, size_t max_headers)
        : StaleTips{ChainType::MAIN, recent_window, max_headers}
    {
    }

    /** Set the chain type and seed the cache with any eligible stale tips
     *  already present in the block index. Called at startup. */
    void Initialize(ChainType chain_type, node::BlockManager& blockman, const CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Track `stale_tip` if it is eligible (see GetEligibleForkPoint()).
     *
     * @return Whether the tip was eligible.
     */
    bool AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the tracked tips that are still eligible, with their fork points. */
    std::vector<StaleFork> GetStaleTips(const CChain& chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Get a summary of the tracked tips that are still eligible. */
    std::vector<StaleTipInfo> GetStaleTipInfo(const CChain& chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

#endif // BITCOIN_STALETIPS_H

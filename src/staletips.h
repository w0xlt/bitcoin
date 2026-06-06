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

static constexpr size_t MAX_STALETIP_HEADERS{20};
static constexpr int STALETIP_RECENT_WINDOW{1000};
static constexpr size_t MAX_RETAINED_STALETIPS{10};

struct StaleFork {
    const CBlockIndex* fork_point{nullptr};
    const CBlockIndex* tip{nullptr};
};

struct StaleTipInfo {
    uint256 hash{};
    int height{-1};
    bool have_block{false};
    uint256 fork_point{};
    int fork_length{0};
};

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

class StaleTipData
{
public:
    uint256 m_fork_point{};
    std::vector<StaleTipCompressedHeader> m_headers;
    bool m_have_block{false};

    StaleTipData() = default;
    explicit StaleTipData(const StaleFork& fork) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

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

class StaleTips
{
private:
    struct Entry {
        const CBlockIndex* tip{nullptr};
        uint32_t header_seqno{0};
        uint32_t block_seqno{0};
    };

    std::array<Entry, MAX_RETAINED_STALETIPS> m_tips{};
    uint32_t m_next_seqno{1};
    ChainType m_chain_type{ChainType::MAIN};
    int m_recent_window{STALETIP_RECENT_WINDOW};
    size_t m_max_headers{MAX_STALETIP_HEADERS};

    const CBlockIndex* GetEligibleForkPoint(const CChain& chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void Add(const CBlockIndex& stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

public:
    /** Maximum target allowed for testnet stale-tip relay policy. */
    static const uint256 TESTNET_MAX_TARGET;

    StaleTips() = default;
    explicit StaleTips(ChainType chain_type, int recent_window = STALETIP_RECENT_WINDOW, size_t max_headers = MAX_STALETIP_HEADERS)
        : m_chain_type{chain_type}, m_recent_window{recent_window}, m_max_headers{max_headers}
    {
    }

    explicit StaleTips(int recent_window, size_t max_headers)
        : StaleTips{ChainType::MAIN, recent_window, max_headers}
    {
    }

    void Initialize(ChainType chain_type, node::BlockManager& blockman, const CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    bool AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    std::vector<StaleFork> GetStaleTips(const CChain& chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    std::vector<StaleTipInfo> GetStaleTipInfo(const CChain& chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

#endif // BITCOIN_STALETIPS_H

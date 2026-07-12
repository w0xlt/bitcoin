// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STALETIPS_H
#define BITCOIN_STALETIPS_H

#include <chain.h>
#include <kernel/cs_main.h>
#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <string>
#include <vector>

/** Maximum number of compressed headers permitted in a `staletip` message. */
static constexpr size_t MAX_STALETIP_HEADERS{20};

/** A stale branch of the block tree, described by its tip and the point where
 *  it forks off the active chain. */
struct StaleFork {
    //! Last common ancestor of the stale tip and the active chain.
    const CBlockIndex* fork_point{nullptr};
    //! Tip of the stale branch.
    const CBlockIndex* tip{nullptr};
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

/** Thrown when deserializing a `staletip` payload that declares more than
 *  MAX_STALETIP_HEADERS headers. Distinguished from other deserialization
 *  failures so that such messages can be ignored without disconnecting the
 *  peer, as longer branches are valid but relayed via normal headers sync. */
class StaleTipHeadersLimitExceeded : public std::ios_base::failure
{
public:
    explicit StaleTipHeadersLimitExceeded(const std::string& message) : std::ios_base::failure{message} {}
};

/** Contents of a `staletip` P2P message: an announcement of a stale branch,
 *  consisting of the fork point hash, the compressed headers of the branch and
 *  whether the announcer has the stale tip's block data. */
struct StaleTipMessage
{
    //! Block hash of the last common ancestor of the stale tip and the
    //! announcer's active chain.
    uint256 m_fork_point{};
    //! Compressed headers from the first block after the fork point up to the
    //! stale tip, in height order.
    std::vector<StaleTipCompressedHeader> m_headers;
    //! Whether the announcer can provide the stale tip's block data on request.
    bool m_have_block{false};

    StaleTipMessage() = default;
    /** Construct an announcement for `fork`, compressing the headers between
     *  `fork.fork_point` (exclusive) and `fork.tip` (inclusive). */
    StaleTipMessage(const StaleFork& fork, bool have_block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Rebuild the full block headers from `m_headers` by computing each
     *  header's previous block hash, starting from `m_fork_point`.
     *
     * @return The hash of the reconstructed stale tip, and the full headers in
     *         height order.
     */
    std::pair<uint256, std::vector<CBlockHeader>> ReconstructHeaders() const;

    friend bool operator==(const StaleTipMessage& a, const StaleTipMessage& b)
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
     * @throws StaleTipHeadersLimitExceeded if more than MAX_STALETIP_HEADERS
     *         headers are declared, std::ios_base::failure for any other
     *         malformed payload.
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
            throw StaleTipHeadersLimitExceeded{"staletip headers limit exceeded"};
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

#endif // BITCOIN_STALETIPS_H

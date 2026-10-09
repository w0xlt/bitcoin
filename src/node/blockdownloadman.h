// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_H

#include <kernel/cs_main.h>
#include <net.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

class CBlockIndex;
class CTxMemPool;
class PartiallyDownloadedBlock;

/** Maximum number of outstanding CMPCTBLOCK requests for the same block. */
inline constexpr unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;

namespace node {

/** Blocks that are in flight, and that are in the queue to be downloaded. */
struct QueuedBlock {
    /** BlockIndex. We must have this since we only request blocks when we've already validated the header. */
    const CBlockIndex* pindex;
    /** Optional, used for CMPCTBLOCK downloads */
    std::unique_ptr<PartiallyDownloadedBlock> partialBlock;
};

/**
 * A peer's block download state. Its owner keeps it, but it has no interface of
 * its own: only BlockDownloadManager can read or change it, so every access is
 * synchronized like access to the manager. It must stay alive until after it
 * is passed to DisconnectedPeer.
 */
class BlockDownloadPeer
{
public:
    BlockDownloadPeer(NodeId id, bool is_inbound) : m_id{id}, m_is_inbound{is_inbound} {}
    ~BlockDownloadPeer();
    BlockDownloadPeer(const BlockDownloadPeer&) = delete;
    BlockDownloadPeer& operator=(const BlockDownloadPeer&) = delete;

private:
    friend class BlockDownloadManager;

    const NodeId m_id;
    const bool m_is_inbound;
    //! Since when we're stalling block download progress, or 0.
    std::chrono::microseconds m_stalling_since{0us};
    std::list<QueuedBlock> m_blocks_in_flight;
    //! Start time of the first outstanding download; unused when the list is empty.
    std::chrono::microseconds m_downloading_since{0us};
    //! Time before which block requests should not be sent to this peer.
    std::chrono::microseconds m_block_download_paused_until{0us};
    //! Set once the peer is disconnected, after which no block may be requested from it.
    bool m_disconnected{false};
};

/**
 * The number of peers we download blocks from. Only BlockDownloadManager changes
 * it, with access to the manager synchronized, and it can be read without
 * synchronization. It is zero exactly when no block is in flight.
 */
class BlockDownloadCounter
{
public:
    int Get() const { return m_value.load(); }

private:
    friend class BlockDownloadManager;

    std::atomic<int> m_value{0};
};

/** The requests for one block, as seen from one peer. */
struct BlockInFlightInfo {
    /** Number of peers the block is in flight from. */
    size_t already_in_flight{0};
    /** Whether the block is in flight from no peer, or first from this one. */
    bool first_in_flight{false};
    /** Whether the block is in flight from this peer. */
    bool requested_from_peer{false};
    /** This peer's request for the block, if it has a partial block. Only compact
     *  block requests have one. */
    QueuedBlock* compact_request{nullptr};
};

/**
 * Tracks block requests, meaning which blocks are in flight from which peers and
 * since when, and the sources of received blocks.
 *
 * This class is not thread-safe. Access to it, and through it to the
 * BlockDownloadPeer objects it is given, must be synchronized using an external
 * mutex. Pointers and iterators into its requests stay valid only while that
 * mutex is held.
 */
class BlockDownloadManager
{
public:
    /** The class maintains, in peers_downloading_from, the number of peers we
     *  download blocks from, so that its owner can read it without synchronization. */
    explicit BlockDownloadManager(BlockDownloadCounter& peers_downloading_from) : m_peers_downloading_from{peers_downloading_from} {}

    /** Drop a disconnected peer's requests. No block may be requested from it afterwards. */
    void DisconnectedPeer(BlockDownloadPeer& peer);
    /** Check that no block is in flight. */
    void CheckIsEmpty() const;

    /** Have we requested this block from a peer */
    bool IsBlockRequested(const uint256& hash) const { return mapBlocksInFlight.contains(hash); }
    /** Have we requested this block from an outbound peer */
    bool IsBlockRequestedFromOutbound(const uint256& hash) const;
    /** The peer this block was first requested from, if it is in flight. */
    BlockDownloadPeer* FirstRequestedFrom(const uint256& hash) const;

    /** Remove this block from our tracked requested blocks. Called if:
     *  - the block has been received from a peer
     *  - the request for the block has timed out
     * If "from_peer" is not null, then only remove the block if it is in
     * flight from that peer (to avoid one peer's network traffic from
     * affecting another's state).
     */
    void RemoveBlockRequest(const uint256& hash, const BlockDownloadPeer* from_peer);

    /** Mark a block as in flight from a peer that is not disconnected.
     *  Returns false, still setting pit, if the block was already in flight from the same peer.
     *  Setting pit creates a partial block, which needs the mempool.
     *  Requires cs_main, so that a cs_main holder sees no new requests, although
     *  existing ones may complete. */
    bool BlockRequested(BlockDownloadPeer& peer, const CBlockIndex& block,
                        std::list<QueuedBlock>::iterator** pit = nullptr,
                        CTxMemPool* mempool = nullptr) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Look up the requests for a block, as seen from one peer. */
    BlockInFlightInfo FindBlockInFlight(const uint256& hash, const BlockDownloadPeer& peer);
    /** Number of peers a block is in flight from. */
    size_t CountBlocksInFlight(const uint256& hash) const { return mapBlocksInFlight.count(hash); }
    /** Number of requests in flight, across all blocks and peers. */
    size_t GetTotalBlocksInFlight() const { return mapBlocksInFlight.size(); }

    NodeId PeerId(const BlockDownloadPeer& peer) const { return peer.m_id; }
    /** Number of blocks in flight from a peer. */
    size_t NumBlocksInFlight(const BlockDownloadPeer& peer) const { return peer.m_blocks_in_flight.size(); }
    /** The oldest block in flight from a peer, or nullptr. */
    const CBlockIndex* FirstBlockInFlight(const BlockDownloadPeer& peer) const
    {
        return peer.m_blocks_in_flight.empty() ? nullptr : peer.m_blocks_in_flight.front().pindex;
    }
    /** Heights of the blocks in flight from a peer, oldest request first. */
    std::vector<int> BlocksInFlightHeights(const BlockDownloadPeer& peer) const;
    /** Start time of a peer's first outstanding download; unused when nothing is in flight. */
    std::chrono::microseconds DownloadingSince(const BlockDownloadPeer& peer) const { return peer.m_downloading_since; }
    /** Since when a peer is stalling block download progress, or 0. */
    std::chrono::microseconds StallingSince(const BlockDownloadPeer& peer) const { return peer.m_stalling_since; }
    void SetStallingSince(BlockDownloadPeer& peer, std::chrono::microseconds time) { peer.m_stalling_since = time; }
    /** Time before which no block should be requested from a peer. */
    std::chrono::microseconds PausedUntil(const BlockDownloadPeer& peer) const { return peer.m_block_download_paused_until; }
    /** Release a peer's requests and request no block from it before "until". */
    void PauseBlockDownload(BlockDownloadPeer& peer, std::chrono::microseconds until);

    /** Record the peer a block was received from, unless one is already recorded.
     *  If punish_on_invalid is false, the peer should not be punished if the block
     *  turns out to be invalid. */
    void AddBlockSource(const uint256& hash, NodeId peer, bool punish_on_invalid)
    {
        mapBlockSource.emplace(hash, std::make_pair(peer, punish_on_invalid));
    }
    /** Remove and return the recorded source of a block. */
    std::optional<std::pair<NodeId, bool>> TakeBlockSource(const uint256& hash);
    void EraseBlockSource(const uint256& hash) { mapBlockSource.erase(hash); }

private:
    /* Multimap used to preserve insertion order */
    using BlockDownloadMap = std::multimap<uint256, std::pair<BlockDownloadPeer*, std::list<QueuedBlock>::iterator>>;
    /** Every block in flight has a block index entry, since BlockRequested()
     *  takes a CBlockIndex, and block index entries are never removed. INV
     *  handling relies on this to skip this map for blocks without an entry.
     *  Each entry points to its peer's state and request, which stay valid
     *  until DisconnectedPeer removes the peer's entries. */
    BlockDownloadMap mapBlocksInFlight;

    /**
     * Sources of received blocks, saved to be able punish them when processing
     * happens afterwards.
     * Set mapBlockSource[hash].second to false if the node should not be
     * punished if the block is invalid.
     */
    std::map<uint256, std::pair<NodeId, bool>> mapBlockSource;

    /** Number of peers from which we're downloading blocks, kept by the owner. */
    BlockDownloadCounter& m_peers_downloading_from;
};
} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_H

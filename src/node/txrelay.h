// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXRELAY_H
#define BITCOIN_NODE_TXRELAY_H

#include <common/bloom.h>
#include <consensus/amount.h>
#include <merkleblock.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <sync.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <vector>

namespace node {
using namespace std::chrono_literals;

/**
 * Per-peer state for transaction relay. Manages bloom filter and
 * transaction inventory data, each protected by its own mutex.
 *
 * Methods are grouped by locking convention: self-locking methods take the
 * relevant mutex themselves and require callers NOT to hold it
 * (EXCLUSIVE_LOCKS_REQUIRED(!mutex)), while caller-locked methods require it
 * to be held (EXCLUSIVE_LOCKS_REQUIRED(mutex)) and exist for the
 * SendMessages() sections that hold a lock across batched work.
 */
class TxRelay
{
private:
    mutable Mutex m_bloom_filter_mutex ACQUIRED_AFTER(m_tx_inventory_mutex);
    mutable Mutex m_tx_inventory_mutex ACQUIRED_BEFORE(m_bloom_filter_mutex);

    /** Whether we relay transactions to this peer. */
    bool m_relay_txs GUARDED_BY(m_bloom_filter_mutex){false};
    /** A bloom filter for which transactions to announce to the peer. See BIP37. */
    std::unique_ptr<CBloomFilter> m_bloom_filter PT_GUARDED_BY(m_bloom_filter_mutex) GUARDED_BY(m_bloom_filter_mutex){nullptr};
    /** A filter of all the (w)txids that the peer has announced to
     *  us or we have announced to the peer. We use this to avoid announcing
     *  the same (w)txid to a peer that already has the transaction. */
    CRollingBloomFilter m_tx_inventory_known_filter GUARDED_BY(m_tx_inventory_mutex){50000, 0.000001};
    /** Set of wtxids we still have to announce. For non-wtxid-relay peers,
     *  we retrieve the txid from the corresponding mempool transaction when
     *  constructing the `inv` message. We use the mempool to sort transactions
     *  in dependency order before relay, so this does not have to be sorted. */
    std::set<Wtxid> m_tx_inventory_to_send GUARDED_BY(m_tx_inventory_mutex);
    /** Whether the peer has requested us to send our complete mempool. Only
     *  permitted if the peer has NetPermissionFlags::Mempool or we advertise
     *  NODE_BLOOM. See BIP35. */
    bool m_send_mempool GUARDED_BY(m_tx_inventory_mutex){false};
    /** The next time after which we will send an `inv` message containing
     *  transaction announcements to this peer. */
    std::chrono::microseconds m_next_inv_send_time GUARDED_BY(m_tx_inventory_mutex){0};
    /** The mempool sequence num at which we sent the last `inv` message to this peer.
     *  Can relay txs with lower sequence numbers than this (see CTxMempool::info_for_relay). */
    uint64_t m_last_inv_sequence GUARDED_BY(m_tx_inventory_mutex){1};

    /** Minimum fee rate with which to filter transaction announcements to this node. See BIP133. */
    std::atomic<CAmount> m_fee_filter_received{0};

public:
    // Mutex accessors, exposing the mutexes for thread-safety annotations at
    // call sites and for the SendMessages() sections that hold a lock across
    // batched work.

    Mutex& GetBloomFilterMutex() const LOCK_RETURNED(m_bloom_filter_mutex) { return m_bloom_filter_mutex; }

    Mutex& GetTxInventoryMutex() const LOCK_RETURNED(m_tx_inventory_mutex) { return m_tx_inventory_mutex; }

    // Self-locking methods: the method takes the relevant mutex itself, so
    // callers must not hold it.

    bool GetRelayTxs() const EXCLUSIVE_LOCKS_REQUIRED(!m_bloom_filter_mutex)
    {
        return WITH_LOCK(m_bloom_filter_mutex, return m_relay_txs);
    }

    void SetRelayTxs(bool relay_txs) EXCLUSIVE_LOCKS_REQUIRED(!m_bloom_filter_mutex)
    {
        LOCK(m_bloom_filter_mutex);
        m_relay_txs = relay_txs;
    }

    void SetBloomFilter(CBloomFilter filter) EXCLUSIVE_LOCKS_REQUIRED(!m_bloom_filter_mutex)
    {
        LOCK(m_bloom_filter_mutex);
        m_bloom_filter = std::make_unique<CBloomFilter>(std::move(filter));
        m_relay_txs = true;
    }

    /** Returns false if no bloom filter is set. */
    bool AddToBloomFilter(std::span<const unsigned char> data) EXCLUSIVE_LOCKS_REQUIRED(!m_bloom_filter_mutex)
    {
        LOCK(m_bloom_filter_mutex);
        if (!m_bloom_filter) return false;
        m_bloom_filter->insert(data);
        return true;
    }

    void ClearBloomFilter() EXCLUSIVE_LOCKS_REQUIRED(!m_bloom_filter_mutex)
    {
        LOCK(m_bloom_filter_mutex);
        m_bloom_filter = nullptr;
        m_relay_txs = true;
    }

    /** Compute a BIP37 merkle block from `block`, filtered through this
     *  peer's bloom filter, or std::nullopt if no filter is set. Matched
     *  transactions are added to the filter (see CMerkleBlock). */
    std::optional<CMerkleBlock> MakeMerkleBlock(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_bloom_filter_mutex)
    {
        LOCK(m_bloom_filter_mutex);
        if (!m_bloom_filter) return std::nullopt;
        return CMerkleBlock{block, *m_bloom_filter};
    }

    void AddKnownTx(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(!m_tx_inventory_mutex)
    {
        LOCK(m_tx_inventory_mutex);
        TxInventoryKnownInsert(hash);
    }

    uint64_t GetLastInvSequence() const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_inventory_mutex)
    {
        return WITH_LOCK(m_tx_inventory_mutex, return m_last_inv_sequence);
    }

    void SetSendMempool() EXCLUSIVE_LOCKS_REQUIRED(!m_tx_inventory_mutex)
    {
        LOCK(m_tx_inventory_mutex);
        m_send_mempool = true;
    }

    struct InventoryStats {
        uint64_t m_last_inv_seq;
        size_t m_inv_to_send;
    };

    InventoryStats GetInventoryStats() const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_inventory_mutex)
    {
        LOCK(m_tx_inventory_mutex);
        return {m_last_inv_sequence, m_tx_inventory_to_send.size()};
    }

    /** Queue a transaction for relay if the peer doesn't already know about
     *  it. Only queue transactions for announcement once the version handshake
     *  is completed. The time of arrival for these transactions is otherwise
     *  at risk of leaking to a spy, if the spy is able to distinguish
     *  transactions received during the handshake from the rest in the
     *  announcement. */
    void PushInventory(const uint256& hash, const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_tx_inventory_mutex)
    {
        LOCK(m_tx_inventory_mutex);
        if (m_next_inv_send_time == 0s) return;
        if (!m_tx_inventory_known_filter.contains(hash)) {
            m_tx_inventory_to_send.insert(wtxid);
        }
    }

    /** Returns true if the inventory is empty and no send has been scheduled. */
    bool IsInventoryPristine() const EXCLUSIVE_LOCKS_REQUIRED(!m_tx_inventory_mutex)
    {
        LOCK(m_tx_inventory_mutex);
        return m_tx_inventory_to_send.empty() && m_next_inv_send_time == 0s;
    }

    // Lock-free methods.

    CAmount GetFeeFilterReceived() const
    {
        return m_fee_filter_received.load();
    }

    void SetFeeFilterReceived(CAmount fee_filter_received)
    {
        m_fee_filter_received = fee_filter_received;
    }

    // Caller-locked methods: callers must hold the relevant mutex.

    bool IsTxRelevantAndUpdate(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(m_bloom_filter_mutex)
    {
        return !m_bloom_filter || m_bloom_filter->IsRelevantAndUpdate(tx);
    }

    void SetLastInvSequence(uint64_t sequence) EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        m_last_inv_sequence = sequence;
    }

    bool IsInvSendTimeReached(std::chrono::microseconds current_time) const EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        return m_next_inv_send_time < current_time;
    }

    void SetNextInvSendTime(std::chrono::microseconds next_time) EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        m_next_inv_send_time = next_time;
    }

    bool ConsumeSendMempool() EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        if (!m_send_mempool) return false;
        m_send_mempool = false;
        return true;
    }

    /** Clears the announcement queue if the peer has requested we not relay
     *  transactions. Takes the bloom filter mutex itself, in the documented
     *  m_tx_inventory_mutex -> m_bloom_filter_mutex order. */
    void ClearTxInventoryToSendIfNoRelayTxs() EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex, !m_bloom_filter_mutex)
    {
        LOCK(m_bloom_filter_mutex);
        if (!m_relay_txs) m_tx_inventory_to_send.clear();
    }

    using TxInventoryIterator = std::set<Wtxid>::iterator;

    std::vector<TxInventoryIterator> GetTxInventoryToSendIterators() EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        std::vector<TxInventoryIterator> iters;
        iters.reserve(m_tx_inventory_to_send.size());
        for (TxInventoryIterator it = m_tx_inventory_to_send.begin(); it != m_tx_inventory_to_send.end(); ++it) {
            iters.push_back(it);
        }
        return iters;
    }

    size_t TxInventoryToSendSize() const EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        return m_tx_inventory_to_send.size();
    }

    void TxInventoryToSendErase(const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        m_tx_inventory_to_send.erase(wtxid);
    }

    void TxInventoryToSendErase(TxInventoryIterator it) EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        m_tx_inventory_to_send.erase(it);
    }

    bool TxInventoryKnownContains(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        return m_tx_inventory_known_filter.contains(hash);
    }

    void TxInventoryKnownInsert(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(m_tx_inventory_mutex)
    {
        m_tx_inventory_known_filter.insert(hash);
    }
};
} // namespace node

#endif // BITCOIN_NODE_TXRELAY_H

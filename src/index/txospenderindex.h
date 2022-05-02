// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TXOSPENDERINDEX_H
#define BITCOIN_INDEX_TXOSPENDERINDEX_H

#include <index/base.h>

/**
 * TxoSpenderIndex is used to look up which transaction spent a given output.
 * The index is written to a LevelDB database and, for each input of each transaction in a block,
 * records the outpoint that is spent and the hash of the spending transaction.
 */
class TxoSpenderIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

    bool AllowPrune() const override { return false; }

protected:
    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    BaseIndex::DB& GetDB() const override;

    const char* GetName() const override { return "txospenderindex"; }

public:
    /// Constructs the index, which becomes available to be queried.
    explicit TxoSpenderIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~TxoSpenderIndex() override;

    bool FindSpender(const COutPoint& txo, std::pair<uint256, int>& tx_hash) const;
};

/// The global txo spender index. May be null.
extern std::unique_ptr<TxoSpenderIndex> g_txospenderindex;


#endif // BITCOIN_INDEX_TXOSPENDERINDEX_H

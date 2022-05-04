#ifndef BITCOIN_INDEX_SILENTPAYMENTINDEX_H
#define BITCOIN_INDEX_SILENTPAYMENTINDEX_H

#include <coins.h>
#include <index/base.h>
#include <pubkey.h>

static constexpr bool DEFAULT_SILENTPAYMENTINDEX{false};

/**
 * SilentPaymentIndex is used to look up the public key of the first input of a given transaction hash.
 * The index is written to a LevelDB database, and for each transaction in a block,
 * checks if all outputs are Taproot, and if so, records the public key of the first input of the transaction.
 */
class SilentPaymentIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

    bool AllowPrune() const override { return false; }

    bool GetSilentPaymentKey(const CTransactionRef& tx, const CBlockIndex* pindex, XOnlyPubKey& result);

    bool ExtractPubkeyFromInput(const Coin& prevCoin, const CTxIn& txin,  XOnlyPubKey& senderPubKey) const;

protected:
    bool CustomAppend(const interfaces::BlockInfo& block) override;

    BaseIndex::DB& GetDB() const override;
public:

    explicit SilentPaymentIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~SilentPaymentIndex() override;

    bool FindSilentPayment(const uint256& tx_hash, XOnlyPubKey& firstInputPubKey) const;
};

/// The global txo silent payment index. May be null.
extern std::unique_ptr<SilentPaymentIndex> g_silentpaymentindex;

#endif // BITCOIN_INDEX_SILENTPAYMENTINDEX_H
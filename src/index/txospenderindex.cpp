#include <index/txospenderindex.h>

#include <index/disktxpos.h>
#include <node/blockstorage.h>
#include <util/system.h>
#include <validation.h>

constexpr uint8_t DB_TXOSPENDERINDEX{'s'};

std::unique_ptr<TxoSpenderIndex> g_txospenderindex;

/** Access to the txo spender index database (indexes/txospenderindex/) */
class TxoSpenderIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    bool WriteSpenderInfos(const std::vector<std::pair<COutPoint, uint256>>& items);
};

TxoSpenderIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "txospenderindex", n_cache_size, f_memory, f_wipe)
{}

TxoSpenderIndex::TxoSpenderIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_db(std::make_unique<TxoSpenderIndex::DB>(n_cache_size, f_memory, f_wipe))
{}

TxoSpenderIndex::~TxoSpenderIndex() {}

bool TxoSpenderIndex::DB::WriteSpenderInfos(const std::vector<std::pair<COutPoint, uint256>>& items)
{
    CDBBatch batch(*this);
    for (const auto& tuple : items) {
        batch.Write(std::make_pair(DB_TXOSPENDERINDEX, tuple.first), tuple.second);
    }
    return WriteBatch(batch);
}

bool TxoSpenderIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    std::vector<std::pair<COutPoint, uint256>> items;
    items.reserve(block.vtx.size());

    for (const auto& tx : block.vtx) {
        for (const auto& input: tx->vin) {
            items.emplace_back(input.prevout, tx->GetHash());
        }
    }
    return m_db->WriteSpenderInfos(items);
}

bool TxoSpenderIndex::FindSpender(const COutPoint& txo, uint256& tx_hash) const
{
    return m_db->Read(std::make_pair(DB_TXOSPENDERINDEX, txo), tx_hash);
}


BaseIndex::DB& TxoSpenderIndex::GetDB() const { return *m_db; }


#include <index/silentpaymentindex.h>

#include <chainparams.h>
#include <coins.h>
#include <index/disktxpos.h>
#include <node/blockstorage.h>
#include <pubkey.h>
#include <undo.h>
#include <util/system.h>
#include <validation.h>
#include <silentpayment.h>

#include <dbwrapper.h>
#include <hash.h>

using node::UndoReadFromDisk;

constexpr uint8_t DB_SILENTPAYMENTINDEX_TX{'t'};
constexpr uint8_t DB_SILENTPAYMENTINDEX_BLK{'b'};

std::unique_ptr<SilentPaymentIndex> g_silentpaymentindex;

/** Access to the silent payment index database (indexes/silentpaymentindex/) */
class SilentPaymentIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    bool WriteSilentPayments(const uint256& blockhash, const std::vector<std::tuple<uint256, CPubKey, uint256>>& items);
};

SilentPaymentIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "silentpaymentindex", n_cache_size, f_memory, f_wipe)
{}

bool SilentPaymentIndex::DB::WriteSilentPayments(const uint256& blockhash, const std::vector<std::tuple<uint256, CPubKey, uint256>>& items)
{
    CDBBatch batch(*this);
    std::vector<std::pair<CPubKey, uint256>> items_blk;

    for (const auto& [tx_hash, pubkey, outpoint_hash] : items) {

        batch.Write(std::make_pair(DB_SILENTPAYMENTINDEX_TX, tx_hash), std::make_pair(pubkey, outpoint_hash));
        items_blk.emplace_back(pubkey, outpoint_hash);
    }
    batch.Write(std::make_pair(DB_SILENTPAYMENTINDEX_BLK, blockhash), items_blk);
    return WriteBatch(batch);
}

SilentPaymentIndex::SilentPaymentIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "silentpaymentindex"), m_db(std::make_unique<SilentPaymentIndex::DB>(n_cache_size, f_memory, f_wipe))
{}

SilentPaymentIndex::~SilentPaymentIndex() {}

std::vector<std::tuple<uint256, CPubKey, uint256>> SilentPaymentIndex::GetSilentPaymentKeysPerBlock(const interfaces::BlockInfo& block) const
{
    std::vector<std::tuple<uint256, CPubKey, uint256>> items; // <tx_hash, sum of public keys of transaction inputs, hash of the outpoints >

    CBlockUndo blockUndo;
    const CBlockIndex* pindex = WITH_LOCK(cs_main, return m_chainstate->m_blockman.LookupBlockIndex(block.hash));

    if (!(UndoReadFromDisk(blockUndo, pindex))) {
        return {};
    }

    for (const auto& tx : block.data->vtx) {

        if (tx->IsCoinBase()) {
            continue;
        }

        std::unordered_set<TxoutType> tx_vout_types;
        for (auto& vout : tx->vout) {
            std::vector<std::vector<unsigned char>> solutions;
            TxoutType whichType = Solver(vout.scriptPubKey, solutions);
            tx_vout_types.insert(whichType);
        }

        // Silent Payments require that the recipients use Taproot address
        // so one output at least must be Taproot
        if (tx_vout_types.find(TxoutType::WITNESS_V1_TAPROOT) == tx_vout_types.end()) {
            continue;
        }

        auto it = std::find_if(block.data->vtx.cbegin(), block.data->vtx.cend(), [tx](CTransactionRef t){ return *t == *tx; });
        // TODO: redundant verification ?
        if (it == block.data->vtx.end()) {
            continue;
        }

        // -1 as blockundo does not have coinbase tx
        const auto& undoTX = blockUndo.vtxundo.at(it - block.data->vtx.begin() - 1);

        assert(tx->vin.size() == undoTX.vprevout.size());

        std::vector<COutPoint> tx_outpoints;

        std::vector<Coin> coins;
        for (size_t i = 0; i < tx->vin.size(); i++)
        {
            coins.push_back(undoTX.vprevout[i]);
            tx_outpoints.push_back(tx->vin[i].prevout);
        }

        CPubKey sum_tx_pubkeys = silentpayment::Recipient::CombinePublicKeys(*tx, coins);

        const auto& outpoint_hash = silentpayment::HashOutpoints(tx_outpoints);

        if (sum_tx_pubkeys.IsFullyValid()) {
            items.emplace_back(tx->GetHash(), sum_tx_pubkeys, outpoint_hash);
        }
    }

    return items;
}

bool SilentPaymentIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    // Exclude genesis block transaction because outputs are not spendable.
    if (block.height == 0) return true;

    assert(block.data);

    Consensus::Params consensus = Params().GetConsensus();

    if (block.height < consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height) {
        return true;
    }

    auto items = GetSilentPaymentKeysPerBlock(block);

    if (items.empty()) return true;

    return m_db->WriteSilentPayments(block.hash, items);
}

std::pair<CPubKey, uint256> SilentPaymentIndex::FindSilentPaymentByTransactionId(const uint256& tx_hash) const
{
    std::pair<CPubKey, uint256> item;
    bool ret = m_db->Read(std::make_pair(DB_SILENTPAYMENTINDEX_TX, tx_hash), item);
    if (ret) {
        assert(item.first.IsFullyValid());
    }
    return item;
}

std::vector<std::pair<CPubKey, uint256>> SilentPaymentIndex::FindSilentPaymentByBlockHash(const uint256& blockhash) const
{
    // std::vector<std::pair<uint256, CPubKey>> items;
    std::vector<std::pair<CPubKey, uint256>> items;
    bool ret = m_db->Read(std::make_pair(DB_SILENTPAYMENTINDEX_BLK, blockhash), items);
    if (ret) {
        assert(!items.empty());
    }
    return items;
}


BaseIndex::DB& SilentPaymentIndex::GetDB() const { return *m_db; }
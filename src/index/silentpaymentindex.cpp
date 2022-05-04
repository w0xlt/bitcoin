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

using node::ReadBlockFromDisk;
using node::UndoReadFromDisk;

constexpr uint8_t DB_SILENTPAYMENTINDEX{'s'};

std::unique_ptr<SilentPaymentIndex> g_silentpaymentindex;

/** Access to the silent payment index database (indexes/silentpaymentindex/) */
class SilentPaymentIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    bool WriteSilentPayments(const std::vector<std::pair<uint256, CPubKey>>& items);
};

SilentPaymentIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "silentpaymentindex", n_cache_size, f_memory, f_wipe)
{}

bool SilentPaymentIndex::DB::WriteSilentPayments(const std::vector<std::pair<uint256, CPubKey>>& items)
{
    CDBBatch batch(*this);
    for (const auto& [tx_hash, pubkey] : items) {
        batch.Write(std::make_pair(DB_SILENTPAYMENTINDEX, tx_hash), pubkey);
    }
    return WriteBatch(batch);
}

SilentPaymentIndex::SilentPaymentIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "silentpaymentindex"), m_db(std::make_unique<SilentPaymentIndex::DB>(n_cache_size, f_memory, f_wipe))
{}

SilentPaymentIndex::~SilentPaymentIndex() {}

bool SilentPaymentIndex::GetSilentPaymentKey(const CTransactionRef& tx, const CBlockIndex* blockindex, CPubKey& sum_tx_pubkeys) const
{
    if (tx->IsCoinBase()) {
        return false;
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
        return false;
    }

    CBlockUndo blockUndo;
    CBlock block;

    if (!(UndoReadFromDisk(blockUndo, blockindex) && ReadBlockFromDisk(block, blockindex, Params().GetConsensus()))) {
        return false;
    }

    CTxUndo* undoTX {nullptr};
    auto it = std::find_if(block.vtx.begin(), block.vtx.end(), [tx](CTransactionRef t){ return *t == *tx; });
    if (it != block.vtx.end()) {
        // -1 as blockundo does not have coinbase tx
        undoTX = &blockUndo.vtxundo.at(it - block.vtx.begin() - 1);
    }

    if (undoTX == nullptr) {
        return false;
    }

    assert(tx->vin.size() == undoTX->vprevout.size());

    std::vector<XOnlyPubKey> input_xonly_pubkeys;
    std::vector<CPubKey> input_pubkeys;

    for (size_t i = 0; i < tx->vin.size(); i++)
    {
        const Coin& prev_coin{undoTX->vprevout[i]};

        const CTxIn& txin{tx->vin.at(i)};

        const auto& pubkey_variant{silentpayment::ExtractPubkeyFromInput(prev_coin, txin)};

        if (std::holds_alternative<CPubKey>(pubkey_variant)) {
            const auto& pubkey{std::get<CPubKey>(pubkey_variant)};
            if (pubkey.IsFullyValid()) {
                input_pubkeys.push_back(pubkey);
            }
        } else if (std::holds_alternative<XOnlyPubKey>(pubkey_variant)) {
            const auto& pubkey{std::get<XOnlyPubKey>(pubkey_variant)};
            if (pubkey.IsFullyValid()) {
                input_xonly_pubkeys.push_back(pubkey);
            }
        }
    }

    // Currently Silent Payment scheme uses all keys. If not possible to
    // retrieve all keys, it is not a SP transaction.
    if ((input_pubkeys.size() + input_xonly_pubkeys.size()) != tx->vin.size()) {
        return false;
    }

    sum_tx_pubkeys = silentpayment::Recipient::SumPublicKeys(input_pubkeys, input_xonly_pubkeys);
    assert(sum_tx_pubkeys.IsFullyValid());

    return true;
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

    std::vector<std::pair<uint256, CPubKey>> items; // <tx_hash, sum of public keys of transaction inputs >

    const CBlockIndex* pindex = WITH_LOCK(cs_main, return m_chainstate->m_blockman.LookupBlockIndex(block.hash));

    for (const auto& tx : block.data->vtx) {
        CPubKey tweakedKey;
        if (GetSilentPaymentKey(tx, pindex, tweakedKey)) {
            items.emplace_back(tx->GetHash(), tweakedKey);
        }

    }

    if (items.empty()) return true;

    return m_db->WriteSilentPayments(items);
}

bool SilentPaymentIndex::FindSilentPayment(const uint256& tx_hash, CPubKey& pubkey) const
{
    bool ret = m_db->Read(std::make_pair(DB_SILENTPAYMENTINDEX, tx_hash), pubkey);
    if (ret) {
        assert(pubkey.IsFullyValid());
    }
    return ret;
}

BaseIndex::DB& SilentPaymentIndex::GetDB() const { return *m_db; }
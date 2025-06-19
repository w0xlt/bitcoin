// Copyright (c) 2018 Blockstream

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <outoforder.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>
#include <common/system.h>

#include <deque>
#include <map>
#include <memory>
#include <utility>
#include <vector>

static int ExtractHeightFromBlock(const Consensus::Params& consensusParams, const std::shared_ptr<const CBlock> pblock)
{
    if (pblock->nBits > consensusParams.BIP34AssumedBits) {
        // We can't be sure BIP34 is active, and without that we can't figure out the height yet
        return -1;
    }

    if (pblock->vtx.size() < 1) return -1;
    if (pblock->vtx[0]->vin.size() < 1) return -1;

    const auto& scriptSig = pblock->vtx[0]->vin[0].scriptSig;
    auto pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!scriptSig.GetOp(pc, opcode, data)) return -1;
    try {
        CScriptNum bn(data, /*require minimal encoding=*/true);
        return bn.getint();
    } catch (const scriptnum_error&) {
        return -1;
    }
}

static const unsigned char DB_SUBSEQUENT_BLOCK = 'S';

static RecursiveMutex cs_ooob;
static std::unique_ptr<CDBWrapper> ooob_db;

static void AssertInitOoOBlockDB() EXCLUSIVE_LOCKS_REQUIRED(cs_ooob)
{
    if (!ooob_db) {
        ooob_db = std::make_unique<CDBWrapper>(DBParams{
            .path = gArgs.GetDataDirNet() / "future_blocks",
            .cache_bytes = 1024});
    }
}

void ResetOoOBlockDb()
{
    LOCK(cs_ooob);
    ooob_db.reset();
}

bool StoreOoOBlock(ChainstateManager& chainman, const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, const bool force, const int in_height)
{
    LOCK(cs_ooob);
    LOCK(cs_main);
    AssertInitOoOBlockDB();
    auto key = std::make_pair(DB_SUBSEQUENT_BLOCK, pblock->hashPrevBlock);
    std::map<uint256, FlatFilePos> successors;

    ooob_db->Read(key, successors);
    if (successors.count(pblock->GetHash())) {
        // Already have it stored, so nothing to do
        return true;
    }

    // Figure out the block's height from BIP34
    const Consensus::Params& consensusParams = chainparams.GetConsensus();
    const int height = (in_height == -1) ? ExtractHeightFromBlock(consensusParams, pblock) : in_height;
    if (height == -1 || (!force && height < consensusParams.BIP34Height)) return false; // nonsensical

    // Don't save blocks too far in the future, to prevent a DoS on pruning
    if (!force && (height > int(chainman.ActiveHeight() + MIN_BLOCKS_TO_KEEP))) return false;

    LogPrintf("Adding block %s (height %u) to out-of-order disk cache\n", pblock->GetHash().GetHex(), height);
    const FlatFilePos diskpos = chainman.m_blockman.WriteBlock(*pblock, height);
    successors.emplace(pblock->GetHash(), diskpos);
    if (!ooob_db->Write(key, successors)) {
        LogPrintf("ERROR adding block %s to out-of-order disk cache\n", pblock->GetHash().GetHex());
        return false;
    }
    return true;
}

void ProcessSuccessorOoOBlocks(ChainstateManager& chainman, const Consensus::Params& consensusParams, const uint256& prev_block_hash, const bool force)
{
    std::deque<uint256> queue;
    queue.push_back(prev_block_hash);

    const node::BlockManager& blockman = chainman.ActiveChainstate().m_blockman;

    for (; !queue.empty(); queue.pop_front()) {
        uint256 head = queue.front();
        auto key = std::make_pair(DB_SUBSEQUENT_BLOCK, head);

        LOCK(cs_ooob);
        AssertInitOoOBlockDB();
        std::map<uint256, FlatFilePos> successors;
        ooob_db->Read(key, successors);

        if (successors.empty()) continue;

        for (const auto& successor : successors) {
            std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
            CBlock& block = *pblock;
            LogPrintf("Accepting deferred block %s from out-of-order disk cache\n", block.GetHash().GetHex());

            if(!blockman.ReadBlock(block, successor.second)) {
                LogPrintf("Failed while reading block %s from disk\n", block.GetHash().GetHex());
                continue;
            }
            chainman.ProcessNewBlock(pblock, force, /*min_pow_checked=*/true, /*is new block?=*/nullptr, &successor.second, /*do_ooob=*/false);
            queue.push_back(pblock->GetHash());
        }

        ooob_db->Erase(key);
    }
}

void CheckForOoOBlocks(ChainstateManager& chainman, const CChainParams& chainparams)
{
    std::vector<uint256> to_process;
    {
        LOCK(cs_ooob);
        AssertInitOoOBlockDB();
        std::unique_ptr<CDBIterator> pcursor(ooob_db->NewIterator());

        LOCK(cs_main);
        for (pcursor->Seek(std::make_pair(DB_SUBSEQUENT_BLOCK, uint256())); pcursor->Valid(); pcursor->Next()) {
            std::pair<unsigned char, uint256> key;
            if (!(pcursor->GetKey(key) && key.first == DB_SUBSEQUENT_BLOCK)) break;

            const uint256& prev_block_hash = key.second;
            if (chainman.BlockIndex().count(prev_block_hash)) {
                to_process.push_back(prev_block_hash);
            }
        }
    }

    for (const auto& prev_block_hash : to_process) {
        ProcessSuccessorOoOBlocks(chainman, chainparams.GetConsensus(), prev_block_hash);
    }
}

size_t CountOoOBlocks()
{
    size_t n_blocks = 0;
    {
        LOCK(cs_ooob);
        AssertInitOoOBlockDB();
        std::unique_ptr<CDBIterator> pcursor(ooob_db->NewIterator());
        for (pcursor->SeekToFirst(); pcursor->Valid(); pcursor->Next()) {
            n_blocks++;
        }
    }
    return n_blocks;
}

std::map<uint256, std::vector<uint256>> GetOoOBlockMap()
{
    std::map<uint256, std::vector<uint256>> ooob_map;
    {
        LOCK(cs_ooob);
        AssertInitOoOBlockDB();
        std::unique_ptr<CDBIterator> pcursor(ooob_db->NewIterator());

        for (pcursor->SeekToFirst(); pcursor->Valid(); pcursor->Next()) {
            std::pair<unsigned char, uint256> key;
            std::map<uint256, FlatFilePos> successors;
            if (!pcursor->GetKey(key)) {
                LogPrintf("Warning: failed to read key from out-of-order block database\n");
                continue;
            }
            if (!pcursor->GetValue(successors)) {
                LogPrintf("Warning: failed to read value from out-of-order block database\n");
                continue;
            }

            ooob_map[key.second] = std::vector<uint256>();
            for (const auto& successor : successors) {
                ooob_map[key.second].push_back(successor.first);
            }
        }
    }
    return ooob_map;
}

// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <interfaces/mining.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/util/common.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/fs.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <latch>
#include <map>
#include <memory>
#include <span>
#include <thread>
#include <utility>
#include <vector>

using kernel::ChainstateRole;

namespace validation_block_tests {
struct MinerTestingSetup : public RegTestingSetup {
    std::shared_ptr<CBlock> Block(const uint256& prev_hash);
    std::shared_ptr<const CBlock> GoodBlock(const uint256& prev_hash);
    std::shared_ptr<const CBlock> BadBlock(const uint256& prev_hash);
    std::shared_ptr<CBlock> FinalizeBlock(std::shared_ptr<CBlock> pblock);
    void BuildChain(const uint256& root, int height, unsigned int invalid_rate, unsigned int branch_rate, unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks);
};
} // namespace validation_block_tests

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, MinerTestingSetup)

struct AcceptResult {
    bool ok;
    bool new_block;
    CBlockIndex* pindex;
};

static AcceptResult AcceptInThread(
    ChainstateManager& chainman,
    const std::shared_ptr<const CBlock>& block,
    std::latch* entered_cs,
    std::atomic<unsigned>& completed)
{
    BlockValidationState state;
    AcceptResult r{false, false, nullptr};
    r.ok = static_cast<TestChainstateManager&>(chainman).AcceptBlock(block, state, &r.pindex, /*pos=*/nullptr, &r.new_block, entered_cs);
    completed.fetch_add(1, std::memory_order_relaxed);
    return r;
}

struct TestSubscriber final : public CValidationInterface {
    uint256 m_expected_tip;

    explicit TestSubscriber(uint256 tip) : m_expected_tip(tip) {}

    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, pindexNew->GetBlockHash());
    }

    void BlockConnected(const ChainstateRole& role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->hashPrevBlock);
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->pprev->GetBlockHash());

        m_expected_tip = block->GetHash();
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->GetHash());
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->GetBlockHash());

        m_expected_tip = block->hashPrevBlock;
    }
};

std::shared_ptr<CBlock> MinerTestingSetup::Block(const uint256& prev_hash)
{
    static int i = 0;
    static uint64_t time = Params().GenesisBlock().nTime;

    auto mining{interfaces::MakeMining(m_node)};
    auto block_template{mining->createNewBlock({
        .coinbase_output_script = CScript{} << i++ << OP_TRUE,
    }, /*cooldown=*/false)};
    BOOST_REQUIRE(block_template);
    auto pblock = std::make_shared<CBlock>(block_template->getBlock());
    pblock->hashPrevBlock = prev_hash;
    pblock->nTime = ++time;

    // Make the coinbase transaction with two outputs:
    // One zero-value one that has a unique pubkey to make sure that blocks at the same height can have a different hash
    // Another one that has the coinbase reward in a P2WSH with OP_TRUE as witness program to make it easy to spend
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vout.resize(2);
    txCoinbase.vout[1].scriptPubKey = P2WSH_OP_TRUE;
    txCoinbase.vout[1].nValue = txCoinbase.vout[0].nValue;
    txCoinbase.vout[0].nValue = 0;
    txCoinbase.vin[0].scriptWitness.SetNull();
    // Always pad with OP_0 as dummy extraNonce (also avoids bad-cb-length error for block <=16)
    const int prev_height{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(prev_hash)->nHeight)};
    txCoinbase.vin[0].scriptSig = CScript{} << prev_height + 1 << OP_0;
    txCoinbase.nLockTime = static_cast<uint32_t>(prev_height);
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    return pblock;
}

std::shared_ptr<CBlock> MinerTestingSetup::FinalizeBlock(std::shared_ptr<CBlock> pblock)
{
    const CBlockIndex* prev_block{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(pblock->hashPrevBlock))};
    m_node.chainman->GenerateCoinbaseCommitment(*pblock, prev_block);

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) {
        ++(pblock->nNonce);
    }

    // submit block header, so that miner can get the block height from the
    // global state and the node has the topology of the chain
    BlockValidationState ignored;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{*pblock}}, true, ignored));

    return pblock;
}

// construct a valid block
std::shared_ptr<const CBlock> MinerTestingSetup::GoodBlock(const uint256& prev_hash)
{
    return FinalizeBlock(Block(prev_hash));
}

// construct an invalid block (but with a valid header)
std::shared_ptr<const CBlock> MinerTestingSetup::BadBlock(const uint256& prev_hash)
{
    auto pblock = Block(prev_hash);

    CMutableTransaction coinbase_spend;
    coinbase_spend.vin.emplace_back(COutPoint(pblock->vtx[0]->GetHash(), 0), CScript(), 0);
    coinbase_spend.vout.push_back(pblock->vtx[0]->vout[0]);

    CTransactionRef tx = MakeTransactionRef(coinbase_spend);
    pblock->vtx.push_back(tx);

    auto ret = FinalizeBlock(pblock);
    return ret;
}

// NOLINTNEXTLINE(misc-no-recursion)
void MinerTestingSetup::BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks)
{
    if (height <= 0 || blocks.size() >= max_size) return;

    bool gen_invalid = m_rng.randrange(100U) < invalid_rate;
    bool gen_fork = m_rng.randrange(100U) < branch_rate;

    const std::shared_ptr<const CBlock> pblock = gen_invalid ? BadBlock(root) : GoodBlock(root);
    blocks.push_back(pblock);
    if (!gen_invalid) {
        BuildChain(pblock->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }

    if (gen_fork) {
        blocks.push_back(GoodBlock(root));
        BuildChain(blocks.back()->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }
}

BOOST_AUTO_TEST_CASE(processnewblock_signals_ordering)
{
    // build a large-ish chain that's likely to have some forks
    std::vector<std::shared_ptr<const CBlock>> blocks;
    while (blocks.size() < 50) {
        blocks.clear();
        BuildChain(Params().GenesisBlock().GetHash(), 100, 15, 10, 500, blocks);
    }

    bool ignored;
    // Connect the genesis block and drain any outstanding events
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // subscribe to events (this subscriber will validate event ordering)
    const CBlockIndex* initial_tip = nullptr;
    {
        LOCK(cs_main);
        initial_tip = m_node.chainman->ActiveChain().Tip();
    }
    auto sub = std::make_shared<TestSubscriber>(initial_tip->GetBlockHash());
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    // create a bunch of threads that repeatedly process a block generated above at random
    // this will create parallelism and randomness inside validation - the ValidationInterface
    // will subscribe to events generated during block validation and assert on ordering invariance
    std::vector<std::thread> threads;
    threads.reserve(10);
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&]() {
            bool ignored;
            FastRandomContext insecure;
            for (int i = 0; i < 1000; i++) {
                const auto& block = blocks[insecure.randrange(blocks.size() - 1)];
                Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
            }

            // to make sure that eventually we process the full chain - do it here
            for (const auto& block : blocks) {
                if (block->vtx.size() == 1) {
                    bool processed = Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
                    assert(processed);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    m_node.validation_signals->UnregisterSharedValidationInterface(sub);

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(sub->m_expected_tip, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(acceptblock_concurrent_distinct_blocks)
{
    auto& chainman{*Assert(m_node.chainman)};

    bool ignored;
    BOOST_CHECK(chainman.ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    auto& test_blockman{static_cast<TestBlockManager&>(chainman.m_blockman)};
    const int initial_file{WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()->GetBlockPos().nFile)};
    const auto file_info_before{test_blockman.GetBlockFileInfo(initial_file)};
    const auto first_block{GoodBlock(Params().GenesisBlock().GetHash())};
    const auto second_block{GoodBlock(Params().GenesisBlock().GetHash())};

    std::latch blockfile_locked{1};
    std::latch release_blockfile{1};
    std::latch entered_cs{1};
    std::latch second_started{1};
    std::atomic<unsigned> completed{0};
    std::thread blockfile_gate{[&] {
        test_blockman.BlockFileWrites(blockfile_locked, release_blockfile);
    }};
    blockfile_locked.wait();

    AcceptResult first_result{};
    AcceptResult second_result{};
    std::thread first_worker{[&] {
        first_result = AcceptInThread(chainman, first_block, &entered_cs, completed);
    }};
    entered_cs.wait();
    std::thread second_worker{[&] {
        second_started.count_down();
        second_result = AcceptInThread(chainman, second_block, nullptr, completed);
    }};

    second_started.wait();
    bool accept_completed_before_release;
    {
        // The writer owned cs_main when it decremented entered_cs. Acquiring
        // it here proves the write releases cs_main despite retaining the
        // acceptance mutex. The other caller waits before acquiring cs_main.
        WAIT_LOCK(cs_main, rendezvous);
        accept_completed_before_release = completed.load(std::memory_order_relaxed) != 0;
    }

    release_blockfile.count_down();
    blockfile_gate.join();
    first_worker.join();
    second_worker.join();

    BOOST_CHECK(!accept_completed_before_release);
    BOOST_CHECK(first_result.ok);
    BOOST_CHECK(second_result.ok);
    BOOST_CHECK(first_result.new_block);
    BOOST_CHECK(second_result.new_block);

    FlatFilePos first_pos;
    FlatFilePos second_pos;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(first_result.pindex);
        BOOST_REQUIRE(second_result.pindex);
        BOOST_CHECK(first_result.pindex->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(second_result.pindex->nStatus & BLOCK_HAVE_DATA);
        first_pos = first_result.pindex->GetBlockPos();
        second_pos = second_result.pindex->GetBlockPos();
    }
    BOOST_CHECK(first_pos != second_pos);
    BOOST_REQUIRE_GE(first_pos.nFile, initial_file);
    BOOST_REQUIRE_GE(second_pos.nFile, initial_file);

    CBlock first_read;
    BOOST_REQUIRE(chainman.m_blockman.ReadBlock(first_read, first_pos, first_block->GetHash()));
    BOOST_CHECK_EQUAL(first_read.GetHash(), first_block->GetHash());
    CBlock second_read;
    BOOST_REQUIRE(chainman.m_blockman.ReadBlock(second_read, second_pos, second_block->GetHash()));
    BOOST_CHECK_EQUAL(second_read.GetHash(), second_block->GetHash());

    const auto first_file_info_after{test_blockman.GetBlockFileInfo(first_pos.nFile)};
    const auto second_file_info_after{test_blockman.GetBlockFileInfo(second_pos.nFile)};
    // A higher-numbered file was created after file_info_before and initially had no blocks.
    const auto blocks_before{(first_pos.nFile == initial_file ? file_info_before.nBlocks : 0U) +
                             (second_pos.nFile != first_pos.nFile && second_pos.nFile == initial_file ? file_info_before.nBlocks : 0U)};
    const auto blocks_after{first_file_info_after.nBlocks + (first_pos.nFile == second_pos.nFile ? 0U : second_file_info_after.nBlocks)};
    BOOST_CHECK_EQUAL(blocks_after, blocks_before + 2);

    LOCK(cs_main);
    chainman.CheckBlockIndex();
}

BOOST_AUTO_TEST_CASE(acceptblock_concurrent_same_block)
{
    auto& chainman{*Assert(m_node.chainman)};

    bool ignored;
    BOOST_CHECK(chainman.ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    auto& test_blockman{static_cast<TestBlockManager&>(chainman.m_blockman)};
    const int initial_file{WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()->GetBlockPos().nFile)};
    const auto file_info_before{test_blockman.GetBlockFileInfo(initial_file)};
    const auto block{GoodBlock(Params().GenesisBlock().GetHash())};

    std::latch blockfile_locked{1};
    std::latch release_blockfile{1};
    std::latch entered_cs{1};
    std::latch second_started{1};
    std::atomic<unsigned> completed{0};
    std::thread blockfile_gate{[&] {
        test_blockman.BlockFileWrites(blockfile_locked, release_blockfile);
    }};
    blockfile_locked.wait();

    AcceptResult first_result{};
    AcceptResult second_result{};
    std::thread first_worker{[&] {
        first_result = AcceptInThread(chainman, block, &entered_cs, completed);
    }};
    entered_cs.wait();
    std::thread second_worker{[&] {
        second_started.count_down();
        second_result = AcceptInThread(chainman, block, nullptr, completed);
    }};

    second_started.wait();
    bool accept_completed_before_release;
    {
        // The writer owned cs_main when it decremented entered_cs. Acquiring
        // it here proves the write releases cs_main despite retaining the
        // acceptance mutex. The duplicate waits before acquiring cs_main.
        WAIT_LOCK(cs_main, rendezvous);
        accept_completed_before_release = completed.load(std::memory_order_relaxed) != 0;
    }

    release_blockfile.count_down();
    blockfile_gate.join();
    first_worker.join();
    second_worker.join();

    BOOST_CHECK(!accept_completed_before_release);
    BOOST_CHECK(first_result.ok);
    BOOST_CHECK(second_result.ok);
    BOOST_CHECK_EQUAL(first_result.new_block + second_result.new_block, 1);

    FlatFilePos block_pos;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(first_result.pindex);
        BOOST_REQUIRE(second_result.pindex);
        BOOST_CHECK_EQUAL(first_result.pindex, second_result.pindex);
        BOOST_CHECK(first_result.pindex->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(second_result.pindex->nStatus & BLOCK_HAVE_DATA);
        block_pos = first_result.pindex->GetBlockPos();
    }
    BOOST_REQUIRE_GE(block_pos.nFile, initial_file);

    CBlock block_read;
    BOOST_REQUIRE(chainman.m_blockman.ReadBlock(block_read, block_pos, block->GetHash()));
    BOOST_CHECK_EQUAL(block_read.GetHash(), block->GetHash());

    const auto file_info_after{test_blockman.GetBlockFileInfo(block_pos.nFile)};
    // A higher-numbered file was created after file_info_before and initially had no blocks.
    const auto blocks_before{block_pos.nFile == initial_file ? file_info_before.nBlocks : 0U};
    BOOST_CHECK_EQUAL(file_info_after.nBlocks, blocks_before + 1);

    LOCK(cs_main);
    chainman.CheckBlockIndex();
}

BOOST_AUTO_TEST_CASE(acceptblock_invalidation_during_write)
{
    auto& chainman{*m_node.chainman};
    const auto block{GoodBlock(Params().GenesisBlock().GetHash())};
    auto* index{WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block->GetHash()))};
    BOOST_REQUIRE(index);

    PausedAcceptance pending{chainman, block};
    BlockValidationState invalidation_state;
    const bool invalidated{chainman.ActiveChainstate().InvalidateBlock(invalidation_state, index)};
    pending.Finish();

    BOOST_CHECK(invalidated);
    BOOST_CHECK(!pending.m_accepted);
    BOOST_CHECK(pending.m_state.GetResult() == BlockValidationResult::BLOCK_CACHED_INVALID);
    {
        LOCK(cs_main);
        BOOST_CHECK(index->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(!(index->nStatus & BLOCK_HAVE_DATA));
        BOOST_CHECK_EQUAL(index->nTx, 0U);
        chainman.CheckBlockIndex();
    }
    BlockValidationState duplicate_state;
    BOOST_CHECK(!static_cast<TestChainstateManager&>(chainman).AcceptBlock(block, duplicate_state, nullptr));
    BOOST_CHECK(duplicate_state.GetResult() == BlockValidationResult::BLOCK_CACHED_INVALID);
}

/** Enable pruning before loading chainstate; no network users hold the manager. */
struct PruningAcceptanceSetup : ChainTestingSetup {
    PruningAcceptanceSetup() : ChainTestingSetup{ChainType::REGTEST, {.setup_validation_interface = false}}
    {
        auto chainman_opts{m_node.chainman->m_options};
        const node::BlockManager::Options blockman_opts{
            .chainparams = Params(),
            .prune_target = 1,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .block_tree_db_params = DBParams{
                .path = m_args.GetDataDirNet() / "blocks" / "index",
                .cache_bytes = 0,
                .memory_only = true,
            },
        };
        m_node.chainman.reset();
        m_node.chainman = std::make_unique<ChainstateManager>(*m_node.shutdown_signal, chainman_opts, blockman_opts);
        LoadVerifyActivateChainstate();
    }
};

BOOST_FIXTURE_TEST_CASE(acceptblock_pruning_during_write, PruningAcceptanceSetup)
{
    auto& chainman{*m_node.chainman};
    auto& blockman{static_cast<TestBlockManager&>(chainman.m_blockman)};
    const auto blocks{CreateBlockChain(1002, Params())};
    BOOST_REQUIRE(chainman.ProcessNewBlock(blocks[0], true, true, nullptr));
    blockman.SetBlockFileSize(0, node::MAX_BLOCKFILE_SIZE);
    for (size_t i{1}; i < blocks.size() - 1; ++i) {
        BOOST_REQUIRE(chainman.ProcessNewBlock(blocks[i], true, true, nullptr));
    }
    // Make file zero eligible for automatic pruning without writing hundreds
    // of megabytes. Its last block is below the retention window.
    blockman.SetBlockFileSize(0, MIN_DISK_SPACE_FOR_BLOCK_FILES);
    const auto path{blockman.GetBlockPosFilename(FlatFilePos{0, 0})};
    BOOST_REQUIRE(fs::exists(path));
    // Allocate another chunk through storage alone, leaving its automatic
    // pruning request for acceptance to handle. The pending write below fits
    // in this chunk, so it cannot replace an incorrectly cleared request.
    blockman.SetBlockFileSize(1, node::BLOCKFILE_CHUNK_SIZE);
    const auto allocation{blockman.WriteBlock(*blocks[1000], 1001)};
    BOOST_REQUIRE(!allocation.value.IsNull());
    BOOST_REQUIRE(allocation.notifications.empty());

    PausedAcceptance pending{chainman, blocks.back()};
    BlockValidationState automatic_state, manual_state;
    const bool automatic{chainman.ActiveChainstate().FlushStateToDisk(automatic_state, FlushStateMode::NONE)};
    const bool manual{chainman.ActiveChainstate().FlushStateToDisk(manual_state, FlushStateMode::NONE, 1000)};
    const bool retained{fs::exists(path)};
    pending.Finish();

    BOOST_CHECK(automatic);
    BOOST_CHECK(manual);
    BOOST_CHECK(retained);
    BOOST_REQUIRE(pending.m_accepted);
    // Publication clears the barrier before the acceptance tail retries pruning.
    BOOST_CHECK(!fs::exists(path));
    CBlock readback;
    const auto pos{WITH_LOCK(cs_main, return pending.m_index->GetBlockPos())};
    BOOST_CHECK(blockman.ReadBlock(readback, pos, blocks.back()->GetHash()));
    LOCK(cs_main);
    BOOST_CHECK(pending.m_index->nStatus & BLOCK_HAVE_DATA);
    BOOST_CHECK(!(chainman.ActiveChain().Genesis()->nStatus & BLOCK_HAVE_DATA));
    chainman.CheckBlockIndex();
}

BOOST_FIXTURE_TEST_CASE(acceptblock_write_failure_cleanup, PruningAcceptanceSetup)
{
    auto& chainman{*m_node.chainman};
    auto& blockman{chainman.m_blockman};
    const auto block{CreateBlockChain(1, Params()).front()};
    const auto path{blockman.GetBlockPosFilename(FlatFilePos{0, 0})};
    const auto saved_path{path.parent_path() / "blk00000.saved"};
    // Only replace a file in this fixture's temporary directory. The real
    // WriteBlock open failure must release both locks and the pruning barrier.
    fs::rename(path, saved_path);
    BOOST_REQUIRE(fs::create_directory(path));
    m_node.notifications->m_shutdown_on_fatal_error = false;

    PausedAcceptance pending{chainman, block};
    pending.Finish();
    BOOST_CHECK(!pending.m_accepted);
    BOOST_CHECK(pending.m_state.IsError());
    BOOST_REQUIRE(pending.m_index);
    {
        LOCK(cs_main);
        BOOST_CHECK(!(pending.m_index->nStatus & BLOCK_HAVE_DATA));
        BOOST_CHECK_EQUAL(pending.m_index->nTx, 0U);
        chainman.CheckBlockIndex();
    }
    BOOST_REQUIRE(fs::remove(path));
    fs::rename(saved_path, path);

    BlockValidationState retry_state;
    bool new_block{false};
    BOOST_REQUIRE(static_cast<TestChainstateManager&>(chainman).AcceptBlock(block, retry_state, nullptr, nullptr, &new_block));
    BOOST_CHECK(new_block);
    CBlock readback;
    const auto pos{WITH_LOCK(cs_main, return pending.m_index->GetBlockPos())};
    BOOST_CHECK(blockman.ReadBlock(readback, pos, block->GetHash()));
    LOCK(cs_main);
    chainman.CheckBlockIndex();
}

BOOST_AUTO_TEST_CASE(acceptblock_import_during_write)
{
    auto& chainman{*m_node.chainman};
    auto& blockman{static_cast<TestBlockManager&>(chainman.m_blockman)};
    const auto blocks{CreateBlockChain(3, Params())};
    // Import includes a duplicate of the pending write and an out-of-order
    // child. Use the real reindex path, including recursive child acceptance.
    AutoFile output{blockman.OpenBlockFile(FlatFilePos{1, 0}, false)};
    BOOST_REQUIRE(!output.IsNull());
    for (const auto i : {2, 0, 1}) {
        output << Params().MessageStart() << static_cast<uint32_t>(GetSerializeSize(TX_WITH_WITNESS(*blocks[i])))
               << TX_WITH_WITNESS(*blocks[i]);
    }
    BOOST_REQUIRE_EQUAL(output.fclose(), 0);
    AutoFile input{blockman.OpenBlockFile(FlatFilePos{1, 0}, true)};
    BOOST_REQUIRE(!input.IsNull());
    FlatFilePos import_pos{1, 0};
    std::multimap<uint256, FlatFilePos> unknown_parents;
    std::latch importer_started{1};
    PausedAcceptance pending{chainman, blocks[0]};
    std::thread importer{[&] {
        importer_started.count_down();
        chainman.LoadExternalBlockFile(input, &import_pos, &unknown_parents);
    }};
    importer_started.wait();
    pending.Finish();
    importer.join();

    BOOST_REQUIRE(pending.m_accepted);
    BOOST_CHECK(unknown_parents.empty());
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(0).nBlocks, 2U);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(1).nBlocks, 2U);
    for (size_t i{0}; i < blocks.size(); ++i) {
        FlatFilePos pos;
        {
            LOCK(cs_main);
            const auto* index{blockman.LookupBlockIndex(blocks[i]->GetHash())};
            BOOST_REQUIRE(index);
            BOOST_CHECK(index->nStatus & BLOCK_HAVE_DATA);
            BOOST_CHECK_EQUAL(index->nTx, blocks[i]->vtx.size());
            pos = index->GetBlockPos();
        }
        BOOST_CHECK_EQUAL(pos.nFile, i == 0 ? 0 : 1);
        CBlock readback;
        BOOST_CHECK(blockman.ReadBlock(readback, pos, blocks[i]->GetHash()));
    }
    LOCK(cs_main);
    chainman.CheckBlockIndex();
}

/**
 * Test that mempool updates happen atomically with reorgs.
 *
 * This prevents RPC clients, among others, from retrieving immediately-out-of-date mempool data
 * during large reorgs.
 *
 * The test verifies this by creating a chain of `num_txs` blocks, matures their coinbases, and then
 * submits txns spending from their coinbase to the mempool. A fork chain is then processed,
 * invalidating the txns and evicting them from the mempool.
 *
 * We verify that the mempool updates atomically by polling it continuously
 * from another thread during the reorg and checking that its size only changes
 * once. The size changing exactly once indicates that the polling thread's
 * view of the mempool is either consistent with the chain state before reorg,
 * or consistent with the chain state after the reorg, and not just consistent
 * with some intermediate state during the reorg.
 */
BOOST_AUTO_TEST_CASE(mempool_locks_reorg)
{
    bool ignored;
    auto ProcessBlock = [&](std::shared_ptr<const CBlock> block) -> bool {
        return Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&ignored);
    };

    // Process all mined blocks
    BOOST_REQUIRE(ProcessBlock(std::make_shared<CBlock>(Params().GenesisBlock())));
    auto last_mined = GoodBlock(Params().GenesisBlock().GetHash());
    BOOST_REQUIRE(ProcessBlock(last_mined));

    // Run the test multiple times
    for (int test_runs = 3; test_runs > 0; --test_runs) {
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // Later on split from here
        const uint256 split_hash{last_mined->hashPrevBlock};

        // Create a bunch of transactions to spend the miner rewards of the
        // most recent blocks
        std::vector<CTransactionRef> txs;
        for (int num_txs = 22; num_txs > 0; --num_txs) {
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint{last_mined->vtx[0]->GetHash(), 1}, CScript{});
            mtx.vin[0].scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
            mtx.vout.push_back(last_mined->vtx[0]->vout[1]);
            mtx.vout[0].nValue -= 1000;
            txs.push_back(MakeTransactionRef(mtx));

            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mature the inputs of the txs
        for (int j = COINBASE_MATURITY; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mine a reorg (and hold it back) before adding the txs to the mempool
        const uint256 tip_init{last_mined->GetHash()};

        std::vector<std::shared_ptr<const CBlock>> reorg;
        last_mined = GoodBlock(split_hash);
        reorg.push_back(last_mined);
        for (size_t j = COINBASE_MATURITY + txs.size() + 1; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            reorg.push_back(last_mined);
        }

        // Add the txs to the tx pool
        {
            LOCK(cs_main);
            for (const auto& tx : txs) {
                const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx);
                BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
            }
        }

        // Check that all txs are in the pool
        {
            BOOST_CHECK_EQUAL(m_node.mempool->size(), txs.size());
        }

        // Run a thread that simulates an RPC caller that is polling while
        // validation is doing a reorg
        std::thread rpc_thread{[&]() {
            // This thread is checking that the mempool either contains all of
            // the transactions invalidated by the reorg, or none of them, and
            // not some intermediate amount.
            while (true) {
                LOCK(m_node.mempool->cs);
                if (m_node.mempool->size() == 0) {
                    // We are done with the reorg
                    break;
                }
                // Internally, we might be in the middle of the reorg, but
                // externally the reorg to the most-proof-of-work chain should
                // be atomic. So the caller assumes that the returned mempool
                // is consistent. That is, it has all txs that were there
                // before the reorg.
                assert(m_node.mempool->size() == txs.size());
                continue;
            }
            LOCK(cs_main);
            // We are done with the reorg, so the tip must have changed
            assert(tip_init != m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }};

        // Submit the reorg in this thread to invalidate and remove the txs from the tx pool
        for (const auto& b : reorg) {
            ProcessBlock(b);
        }
        // Check that the reorg was eventually successful
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // We can join the other thread, which returns when the reorg was successful
        rpc_thread.join();
    }
}

BOOST_AUTO_TEST_CASE(witness_commitment_index)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    CScript pubKey;
    pubKey << 1 << OP_TRUE;
    auto mining{interfaces::MakeMining(m_node)};
    auto block_template{mining->createNewBlock({
        .coinbase_output_script = pubKey,
    }, /*cooldown=*/false)};
    BOOST_REQUIRE(block_template);
    CBlock pblock{block_template->getBlock()};

    CTxOut witness;
    witness.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
    witness.scriptPubKey[0] = OP_RETURN;
    witness.scriptPubKey[1] = 0x24;
    witness.scriptPubKey[2] = 0xaa;
    witness.scriptPubKey[3] = 0x21;
    witness.scriptPubKey[4] = 0xa9;
    witness.scriptPubKey[5] = 0xed;

    // A witness larger than the minimum size is still valid
    CTxOut min_plus_one = witness;
    min_plus_one.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT + 1);

    CTxOut invalid = witness;
    invalid.scriptPubKey[0] = OP_VERIFY;

    CMutableTransaction txCoinbase(*pblock.vtx[0]);
    txCoinbase.vout.resize(4);
    txCoinbase.vout[0] = witness;
    txCoinbase.vout[1] = witness;
    txCoinbase.vout[2] = min_plus_one;
    txCoinbase.vout[3] = invalid;
    pblock.vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    BOOST_CHECK_EQUAL(GetWitnessCommitmentIndex(pblock), 2);
}
BOOST_AUTO_TEST_SUITE_END()

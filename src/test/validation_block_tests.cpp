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
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/util/common.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <latch>
#include <memory>
#include <span>
#include <string_view>
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

// Mine a private block without checking it or publishing its header.
static void MineUncheckedBlock(CBlock& block, const Consensus::Params& consensus)
{
    block.m_validation_cache.m_checked.store(false);
    block.m_validation_cache.m_checked_merkle_root.store(false);
    block.m_validation_cache.m_checked_witness_commitment.store(false);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
        ++block.nNonce;
    }
}

static std::vector<std::byte> BlockBytes(const CBlock& block)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(block);
    return {stream.begin(), stream.end()};
}

static void CheckStoredBlock(ChainstateManager& chainman, const CBlock& block)
{
    LOCK(cs_main);
    const auto* index{chainman.m_blockman.LookupBlockIndex(block.GetHash())};
    BOOST_REQUIRE(index);
    BOOST_CHECK(index->nStatus & BLOCK_HAVE_DATA);
    BOOST_CHECK(index->IsValid(BLOCK_VALID_TRANSACTIONS));
    CBlock readback;
    BOOST_REQUIRE(chainman.m_blockman.ReadBlock(readback, *index));
    BOOST_CHECK(BlockBytes(readback) == BlockBytes(block));
}

struct BlockCheckedCatcher final : CValidationInterface {
    const uint256 m_hash;
    std::atomic<bool> m_returned{false};
    size_t m_count GUARDED_BY(cs_main){0};
    size_t m_pow_count GUARDED_BY(cs_main){0};
    bool m_before_return GUARDED_BY(cs_main){true};
    std::thread::id m_thread GUARDED_BY(cs_main);
    BlockValidationState m_state GUARDED_BY(cs_main);

    explicit BlockCheckedCatcher(const uint256& hash) : m_hash{hash} {}

    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& state) override EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        AssertLockHeld(cs_main);
        if (block->GetHash() != m_hash) return;
        ++m_count;
        m_before_return &= !m_returned.load();
        m_thread = std::this_thread::get_id();
        m_state = state;
    }

    void NewPoWValidBlock(const CBlockIndex*, const std::shared_ptr<const CBlock>& block) override EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        AssertLockHeld(cs_main);
        if (block->GetHash() == m_hash) ++m_pow_count;
    }
};

BOOST_AUTO_TEST_CASE(processnewblock_check_outside_main)
{
    auto& chainman{*Assert(m_node.chainman)};
    for (bool valid : {true, false}) {
        const auto prev{WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash())};
        auto block{Block(prev)};
        if (!valid) {
            CMutableTransaction coinbase{*block->vtx[0]};
            coinbase.vin[0].scriptSig.clear();
            block->vtx[0] = MakeTransactionRef(std::move(coinbase));
        }
        MineUncheckedBlock(*block, chainman.GetConsensus());
        CBlock reference{*block};
        BlockValidationState expected;
        BOOST_REQUIRE_EQUAL(CheckBlock(reference, expected, chainman.GetConsensus()), valid);
        BOOST_CHECK(!block->m_validation_cache.m_checked.load());
        BOOST_CHECK(!block->m_validation_cache.m_checked_merkle_root.load());
        BOOST_CHECK(!block->m_validation_cache.m_checked_witness_commitment.load());

        auto catcher{std::make_shared<BlockCheckedCatcher>(block->GetHash())};
        m_node.validation_signals->RegisterSharedValidationInterface(catcher);
        bool processed{false}, new_block{true}, progressed{false}, unpublished{false};
        size_t callbacks_while_locked{0};
        std::exception_ptr exception;
        // On every unwind, release main before this owner joins its worker.
        std::jthread worker;
        {
            LOCK(cs_main);
            BOOST_REQUIRE(!chainman.m_blockman.LookupBlockIndex(block->GetHash()));
            worker = std::jthread{[&] {
                try {
                    processed = chainman.ProcessNewBlock(block, true, true, &new_block);
                } catch (...) {
                    exception = std::current_exception();
                }
                catcher->m_returned.store(true);
            }};
            const auto& progress{valid ? block->m_validation_cache.m_checked : block->m_validation_cache.m_checked_merkle_root};
            const auto deadline{std::chrono::steady_clock::now() + std::chrono::seconds{10}};
            while (!progress.load() && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::yield();
            }
            progressed = progress.load();
            unpublished = !chainman.m_blockman.LookupBlockIndex(block->GetHash());
            callbacks_while_locked = catcher->m_count + catcher->m_pow_count;
        }
        const auto caller{worker.get_id()};
        // Release main and join before reporting a missed progress deadline.
        worker.join();
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.validation_signals->UnregisterSharedValidationInterface(catcher);
        BOOST_CHECK(!exception);
        BOOST_CHECK(progressed);
        BOOST_CHECK(unpublished);
        BOOST_CHECK_EQUAL(callbacks_while_locked, 0);
        BOOST_CHECK_EQUAL(processed, valid);
        BOOST_CHECK_EQUAL(new_block, valid);
        {
            LOCK(cs_main);
            BOOST_CHECK_EQUAL(catcher->m_count, 1);
            BOOST_CHECK(catcher->m_before_return);
            BOOST_CHECK(catcher->m_thread == caller);
            BOOST_CHECK(catcher->m_state.GetResult() == expected.GetResult());
            BOOST_CHECK_EQUAL(catcher->m_state.ToString(), expected.ToString());
            if (!valid) {
                BOOST_CHECK(!chainman.m_blockman.LookupBlockIndex(block->GetHash()));
                BOOST_CHECK(!block->m_validation_cache.m_checked.load());
            }
        }
        if (valid) CheckStoredBlock(chainman, *block);
        BOOST_CHECK_EQUAL(chainman.ProcessNewBlock(block, true, true, nullptr), valid);
    }
}

BOOST_AUTO_TEST_CASE(processnewblock_check_gate_released_before_main)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto prev{WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash())};
    const std::array blocks{Block(prev), Block(prev)};
    std::array<std::shared_ptr<BlockCheckedCatcher>, 2> catchers;
    for (size_t i = 0; i < blocks.size(); ++i) {
        MineUncheckedBlock(*blocks[i], chainman.GetConsensus());
        BOOST_CHECK(!blocks[i]->m_validation_cache.m_checked.load());
        BOOST_CHECK(!blocks[i]->m_validation_cache.m_checked_merkle_root.load());
        BOOST_CHECK(!blocks[i]->m_validation_cache.m_checked_witness_commitment.load());
        catchers[i] = std::make_shared<BlockCheckedCatcher>(blocks[i]->GetHash());
        m_node.validation_signals->RegisterSharedValidationInterface(catchers[i]);
    }
    BOOST_REQUIRE(blocks[0]->GetHash() != blocks[1]->GetHash());
    struct Result {
        bool processed{false};
        bool new_block{false};
        std::exception_ptr exception;
    };
    std::array<Result, 2> results;
    std::array<bool, 2> progressed{}, unpublished{};
    std::array<size_t, 2> callbacks_while_locked{};
    // In particular, failure to launch B releases main before joining A.
    std::array<std::jthread, 2> workers;
    {
        LOCK(cs_main);
        for (const auto& block : blocks) {
            BOOST_REQUIRE(!chainman.m_blockman.LookupBlockIndex(block->GetHash()));
        }
        for (size_t i = 0; i < blocks.size(); ++i) {
            workers[i] = std::jthread{[&, i] {
                try {
                    results[i].processed = chainman.ProcessNewBlock(blocks[i], true, true, &results[i].new_block);
                } catch (...) {
                    results[i].exception = std::current_exception();
                }
                catchers[i]->m_returned.store(true);
            }};
            const auto deadline{std::chrono::steady_clock::now() + std::chrono::seconds{10}};
            while (!blocks[i]->m_validation_cache.m_checked.load() && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::yield();
            }
            progressed[i] = blocks[i]->m_validation_cache.m_checked.load();
        }
        for (size_t i = 0; i < blocks.size(); ++i) {
            unpublished[i] = !chainman.m_blockman.LookupBlockIndex(blocks[i]->GetHash());
            callbacks_while_locked[i] = catchers[i]->m_count + catchers[i]->m_pow_count;
        }
    }
    for (auto& worker : workers) {
        worker.join();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    for (const auto& catcher : catchers) {
        m_node.validation_signals->UnregisterSharedValidationInterface(catcher);
    }
    for (size_t i = 0; i < blocks.size(); ++i) {
        BOOST_CHECK_MESSAGE(progressed[i], "caller " << i << " did not finish initial checking before main release");
        BOOST_CHECK(unpublished[i]);
        BOOST_CHECK_EQUAL(callbacks_while_locked[i], 0);
        BOOST_CHECK(!results[i].exception);
        BOOST_CHECK(results[i].processed);
        BOOST_CHECK(results[i].new_block);
        CheckStoredBlock(chainman, *blocks[i]);
    }
}

BOOST_FIXTURE_TEST_CASE(processnewblock_invalid_and_mutated, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto check_failure = [&](const std::shared_ptr<const CBlock>& block, BlockValidationResult result, std::string_view reason, bool initial = true) {
        CBlock reference{*block};
        BlockValidationState expected;
        BOOST_CHECK_EQUAL(CheckBlock(reference, expected, chainman.GetConsensus()), !initial);
        const CBlockIndex* before;
        uint32_t status{0};
        {
            LOCK(cs_main);
            before = chainman.m_blockman.LookupBlockIndex(block->GetHash());
            if (before) status = before->nStatus;
        }
        auto catcher{std::make_shared<BlockCheckedCatcher>(block->GetHash())};
        m_node.validation_signals->RegisterSharedValidationInterface(catcher);
        bool new_block{true};
        const bool processed{chainman.ProcessNewBlock(block, true, true, &new_block)};
        catcher->m_returned.store(true);
        m_node.validation_signals->UnregisterSharedValidationInterface(catcher);
        BOOST_CHECK(!processed);
        BOOST_CHECK(!new_block);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(catcher->m_count, 1);
        BOOST_CHECK_EQUAL(catcher->m_pow_count, 0);
        BOOST_CHECK(catcher->m_before_return);
        BOOST_CHECK(catcher->m_thread == std::this_thread::get_id());
        BOOST_CHECK(catcher->m_state.GetResult() == result);
        BOOST_CHECK_EQUAL(catcher->m_state.GetRejectReason(), reason);
        const auto* after{chainman.m_blockman.LookupBlockIndex(block->GetHash())};
        if (initial) {
            BOOST_CHECK_EQUAL(catcher->m_state.ToString(), expected.ToString());
            BOOST_CHECK(after == before);
            if (after) BOOST_CHECK_EQUAL(after->nStatus, status);
        } else {
            BOOST_REQUIRE(after);
            BOOST_CHECK(!(after->nStatus & (BLOCK_HAVE_DATA | BLOCK_FAILED_VALID)));
        }
    };
    const auto make_block = [&] {
        auto block{std::make_shared<CBlock>(CreateBlock({}, CScript{} << OP_TRUE))};
        MineUncheckedBlock(*block, chainman.GetConsensus());
        return block;
    };

    auto bad_pow{make_block()};
    while (CheckProofOfWork(bad_pow->GetHash(), bad_pow->nBits, chainman.GetConsensus())) {
        ++bad_pow->nNonce;
    }
    check_failure(bad_pow, BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash");

    auto negative_output{make_block()};
    CMutableTransaction negative_coinbase{*negative_output->vtx[0]};
    negative_coinbase.vout[0].nValue = -1;
    negative_output->vtx[0] = MakeTransactionRef(std::move(negative_coinbase));
    MineUncheckedBlock(*negative_output, chainman.GetConsensus());
    check_failure(negative_output, BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-vout-negative");

    // Three valid transactions allow duplication of the last leaf without changing the header.
    auto spend{CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey, CScript{} << OP_TRUE, 49 * COIN, /*submit=*/false)};
    CMutableTransaction child;
    child.vin.emplace_back(COutPoint{spend.GetHash(), 0});
    child.vout.emplace_back(48 * COIN, CScript{} << OP_TRUE);
    auto correct{std::make_shared<CBlock>(CreateBlock({spend, child}, CScript{} << OP_TRUE))};
    MineUncheckedBlock(*correct, chainman.GetConsensus());
    auto wrong_merkle{std::make_shared<CBlock>(*correct)};
    wrong_merkle->vtx.pop_back();
    check_failure(wrong_merkle, BlockValidationResult::BLOCK_MUTATED, "bad-txnmrklroot");
    auto duplicate{std::make_shared<CBlock>(*correct)};
    duplicate->vtx.push_back(duplicate->vtx.back());
    BOOST_REQUIRE(duplicate->GetHash() == correct->GetHash());
    BOOST_REQUIRE(BlockMerkleRoot(*duplicate) == correct->hashMerkleRoot);
    check_failure(duplicate, BlockValidationResult::BLOCK_MUTATED, "bad-txns-duplicate");

    // The same malformed body must also leave an already-known header unchanged.
    BlockValidationState header_state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({{*correct}}, true, header_state));
    check_failure(duplicate, BlockValidationResult::BLOCK_MUTATED, "bad-txns-duplicate");
    bool new_block{false};
    BOOST_REQUIRE(chainman.ProcessNewBlock(correct, true, true, &new_block));
    BOOST_CHECK(new_block);
    CheckStoredBlock(chainman, *correct);

    // Witness data is checked contextually, not by the initial CheckBlock call.
    auto witness{make_block()};
    BOOST_REQUIRE(witness->vtx[0]->HasWitness());
    auto bad_witness{std::make_shared<CBlock>(*witness)};
    CMutableTransaction witness_coinbase{*bad_witness->vtx[0]};
    witness_coinbase.vin[0].scriptWitness.stack[0][0] ^= 1;
    bad_witness->vtx[0] = MakeTransactionRef(std::move(witness_coinbase));
    BOOST_REQUIRE(bad_witness->GetHash() == witness->GetHash());
    check_failure(bad_witness, BlockValidationResult::BLOCK_MUTATED, "bad-witness-merkle-match", /*initial=*/false);
    BOOST_CHECK(bad_witness->m_validation_cache.m_checked.load());
    BOOST_CHECK(!bad_witness->m_validation_cache.m_checked_witness_commitment.load());
    BOOST_REQUIRE(chainman.ProcessNewBlock(witness, true, true, nullptr));
    BOOST_CHECK(witness->m_validation_cache.m_checked_witness_commitment.load());
    CheckStoredBlock(chainman, *witness);
}

BOOST_AUTO_TEST_CASE(processnewblock_concurrent)
{
    auto& chainman{*Assert(m_node.chainman)};
    // Initial checks use their own gate; master cs_main still serializes admission.
    for (size_t worker_count : {8U, 20U}) {
        // Shared pointer, separately decoded copies, and independent sibling blocks.
        for (int mode : {0, 1, 2}) {
            for (int round = 0; round < 4; ++round) {
                const auto prev{WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash())};
                auto original{Block(prev)};
                MineUncheckedBlock(*original, chainman.GetConsensus());
                std::vector<std::shared_ptr<const CBlock>> blocks;
                blocks.reserve(worker_count);
                for (size_t i = 0; i < worker_count; ++i) {
                    if (mode == 0) {
                        blocks.push_back(original);
                    } else if (mode == 1) {
                        DataStream stream{BlockBytes(*original)};
                        auto decoded{std::make_shared<CBlock>()};
                        stream >> TX_WITH_WITNESS(*decoded);
                        blocks.push_back(std::move(decoded));
                    } else {
                        auto sibling{Block(prev)};
                        MineUncheckedBlock(*sibling, chainman.GetConsensus());
                        blocks.push_back(std::move(sibling));
                    }
                    BOOST_CHECK(!blocks.back()->m_validation_cache.m_checked.load());
                }
                struct Result {
                    bool processed{false};
                    bool new_block{false};
                    bool duplicate{false};
                    bool duplicate_new{true};
                    bool null_output{false};
                    std::exception_ptr exception;
                };
                std::vector<Result> results(worker_count);
                std::latch start{1};
                bool cancelled{false};
                std::vector<std::thread> workers;
                workers.reserve(worker_count);
                try {
                    for (size_t i = 0; i < worker_count; ++i) {
                        workers.emplace_back([&, i] {
                            start.wait();
                            if (cancelled) return;
                            try {
                                auto& result{results[i]};
                                result.processed = chainman.ProcessNewBlock(blocks[i], true, true, &result.new_block);
                                result.duplicate = chainman.ProcessNewBlock(blocks[i], true, true, &result.duplicate_new);
                                result.null_output = chainman.ProcessNewBlock(blocks[i], true, true, nullptr);
                            } catch (...) {
                                results[i].exception = std::current_exception();
                            }
                        });
                    }
                } catch (...) {
                    // Cancel before releasing a partially launched group.
                    cancelled = true;
                    start.count_down();
                    for (auto& worker : workers) {
                        worker.join();
                    }
                    throw;
                }
                start.count_down();
                for (auto& worker : workers) {
                    worker.join();
                }
                size_t admissions{0};
                for (size_t i = 0; i < worker_count; ++i) {
                    const auto& result{results[i]};
                    BOOST_CHECK(!result.exception);
                    BOOST_CHECK(result.processed);
                    BOOST_CHECK(result.duplicate);
                    BOOST_CHECK(!result.duplicate_new);
                    BOOST_CHECK(result.null_output);
                    admissions += result.new_block;
                    CheckStoredBlock(chainman, *blocks[i]);
                }
                BOOST_CHECK_EQUAL(admissions, mode == 2 ? worker_count : 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(processnewblock_concurrent_invalidation)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{WITH_LOCK(cs_main, return chainman.ActiveChainstate())};
    for (int round = 0; round < 4; ++round) {
        const auto root{WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash())};
        const auto parent{GoodBlock(root)};
        BOOST_REQUIRE(chainman.ProcessNewBlock(parent, true, true, nullptr));
        auto child{Block(parent->GetHash())};
        MineUncheckedBlock(*child, chainman.GetConsensus());

        // InvalidateBlock snapshots known headers. Keep the sole racing child's
        // index in that snapshot; concurrent creation of new headers is not covered.
        BlockValidationState header_state;
        BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({{*child}}, true, header_state));
        CBlockIndex* parent_index;
        {
            LOCK(cs_main);
            parent_index = chainman.m_blockman.LookupBlockIndex(parent->GetHash());
            BOOST_REQUIRE(parent_index);
            const auto* child_index{chainman.m_blockman.LookupBlockIndex(child->GetHash())};
            BOOST_REQUIRE(child_index);
            BOOST_CHECK(child_index->IsValid(BLOCK_VALID_TREE));
            BOOST_CHECK(!(child_index->nStatus & (BLOCK_HAVE_DATA | BLOCK_FAILED_VALID)));
        }
        BOOST_CHECK(!child->m_validation_cache.m_checked.load());
        BOOST_CHECK(!child->m_validation_cache.m_checked_merkle_root.load());
        BOOST_CHECK(!child->m_validation_cache.m_checked_witness_commitment.load());

        std::array<std::exception_ptr, 2> exceptions;
        BlockValidationState state;
        bool invalidated{false};
        std::latch start{1};
        std::jthread worker{[&] {
            start.wait();
            try {
                chainman.ProcessNewBlock(child, true, true, nullptr);
            } catch (...) {
                exceptions[0] = std::current_exception();
            }
        }};
        start.count_down();
        try {
            // This API acquires its own locks; never invoke it while holding main.
            invalidated = chainstate.InvalidateBlock(state, parent_index);
        } catch (...) {
            exceptions[1] = std::current_exception();
        }
        worker.join();
        for (const auto& exception : exceptions) {
            BOOST_CHECK(!exception);
        }
        BOOST_REQUIRE(invalidated);
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(child->m_validation_cache.m_checked.load());
        {
            LOCK(cs_main);
            BOOST_CHECK(parent_index->nStatus & BLOCK_FAILED_VALID);
            BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == root);
        }
        // Either concurrent ordering is allowed. Only after joining, construct
        // a fresh child to check invalid-parent rejection and then reconsider.
        auto later{Block(parent->GetHash())};
        MineUncheckedBlock(*later, chainman.GetConsensus());
        bool new_block{true};
        BOOST_CHECK(!chainman.ProcessNewBlock(later, true, true, &new_block));
        BOOST_CHECK(!new_block);
        BOOST_CHECK(later->m_validation_cache.m_checked.load());
        {
            LOCK(cs_main);
            BOOST_CHECK(!chainman.m_blockman.LookupBlockIndex(later->GetHash()));
            chainstate.ResetBlockFailureFlags(parent_index);
            chainman.RecalculateBestHeader();
        }
        BOOST_REQUIRE(chainman.ProcessNewBlock(child, true, true, nullptr));
        BOOST_CHECK(WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()) == child->GetHash());
        CheckStoredBlock(chainman, *child);
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

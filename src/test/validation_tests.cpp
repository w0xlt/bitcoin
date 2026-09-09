// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <pow.h>
#include <primitives/block.h>
#include <signet.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <barrier>
#include <cstddef>
#include <exception>
#include <latch>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(validation_tests, BasicTestingSetup)

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    int maxHalvings = 64;
    CAmount nInitialSubsidy = 50 * COIN;

    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == 0
    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nSubsidy;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    TestBlockSubsidyHalvings(chainParams->GetConsensus()); // As in main
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 14000000; nHeight += 1000) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy <= 50 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, CAmount{2099999997690000});
}

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of kernel/chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    const auto out110 = *params->AssumeutxoForHeight(110);
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "86e9a1205b418b16dde3a18a78c730e30137e28466bda5dbf6b33ab8fc05447c");
    BOOST_CHECK_EQUAL(out110.m_chain_tx_count, 111U);

    const auto out110_2 = *params->AssumeutxoForBlockhash(uint256{"135eec25a6fb277884e5824e7aa7d052c4868161c99a5122170b5266f86c273d"});
    BOOST_CHECK_EQUAL(out110_2.hash_serialized.ToString(), "86e9a1205b418b16dde3a18a78c730e30137e28466bda5dbf6b33ab8fc05447c");
    BOOST_CHECK_EQUAL(out110_2.m_chain_tx_count, 111U);
}

static void CheckBlockCache(const CBlock& block, bool checked, bool merkle, bool witness)
{
    BOOST_CHECK_EQUAL(block.m_validation_cache.m_checked.load(), checked);
    BOOST_CHECK_EQUAL(block.m_validation_cache.m_checked_merkle_root.load(), merkle);
    BOOST_CHECK_EQUAL(block.m_validation_cache.m_checked_witness_commitment.load(), witness);
}

static std::vector<std::byte> BlockBytes(const CBlock& block)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(block);
    return {stream.begin(), stream.end()};
}

BOOST_AUTO_TEST_CASE(block_validation_cache)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::REGTEST)};
    const auto& consensus{params->GetConsensus()};
    CheckBlockCache(CBlock{}, false, false, false);
    CheckBlockCache(CBlock{static_cast<const CBlockHeader&>(params->GenesisBlock())}, false, false, false);

    for (bool check_pow : {false, true}) {
        for (bool check_merkle : {false, true}) {
            CBlock block{params->GenesisBlock()};
            CheckBlockCache(block, false, false, false);
            const auto bytes{BlockBytes(block)};
            const auto hash{block.GetHash()};

            // Only enabling both optional checks can cache full success.
            for (int repeat = 0; repeat < 2; ++repeat) {
                BlockValidationState state;
                BOOST_CHECK(CheckBlock(block, state, consensus, check_pow, check_merkle));
                BOOST_CHECK(state.IsValid());
                CheckBlockCache(block, check_pow && check_merkle, check_merkle, false);
            }
            BlockValidationState state;
            BOOST_CHECK(CheckBlock(block, state, consensus));
            BOOST_CHECK(state.IsValid());
            CheckBlockCache(block, true, true, false);
            BOOST_CHECK(BlockBytes(block) == bytes);
            BOOST_CHECK(block.GetHash() == hash);

            // Serialized blocks do not carry any of the memory-only success flags.
            CBlock decoded;
            SpanReader{bytes} >> TX_WITH_WITNESS(decoded);
            CheckBlockCache(decoded, false, false, false);
            BOOST_CHECK(BlockBytes(decoded) == bytes);
            BOOST_CHECK(decoded.GetHash() == hash);
        }
    }

    // A successful merkle check remains cached when a later body check fails.
    CBlock invalid{params->GenesisBlock()};
    CMutableTransaction coinbase{*invalid.vtx[0]};
    coinbase.vin[0].scriptSig.clear();
    invalid.vtx[0] = MakeTransactionRef(std::move(coinbase));
    invalid.hashMerkleRoot = BlockMerkleRoot(invalid);
    while (!CheckProofOfWork(invalid.GetHash(), invalid.nBits, consensus)) {
        ++invalid.nNonce;
    }

    BlockValidationState state;
    BOOST_CHECK(!CheckBlock(invalid, state, consensus));
    BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_CONSENSUS);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-length");
    CheckBlockCache(invalid, false, true, false);
    BlockValidationState repeated_state;
    BOOST_CHECK(!CheckBlock(invalid, repeated_state, consensus));
    BOOST_CHECK(repeated_state.GetResult() == state.GetResult());
    BOOST_CHECK_EQUAL(repeated_state.GetRejectReason(), state.GetRejectReason());
    BOOST_CHECK_EQUAL(repeated_state.GetDebugMessage(), state.GetDebugMessage());
    CheckBlockCache(invalid, false, true, false);
}

static CBlock WitnessBlock(const CChainParams& params)
{
    const auto& consensus{params.GetConsensus()};
    CBlock block{params.GenesisBlock()};
    CMutableTransaction coinbase{*block.vtx[0]};
    coinbase.vin[0].scriptWitness.stack = {std::vector<unsigned char>(32, 0)};
    uint256 commitment;
    CHash256().Write(BlockWitnessMerkleRoot(block)).Write(coinbase.vin[0].scriptWitness.stack[0]).Finalize(commitment);
    std::vector<unsigned char> commitment_bytes{0xaa, 0x21, 0xa9, 0xed};
    commitment_bytes.insert(commitment_bytes.end(), commitment.begin(), commitment.end());
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << commitment_bytes);
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
        ++block.nNonce;
    }
    return block;
}

BOOST_AUTO_TEST_CASE(block_validation_cache_copy)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::REGTEST)};
    const auto& consensus{params->GetConsensus()};
    CBlock block{WitnessBlock(*params)};
    const auto bytes{BlockBytes(block)};
    const auto hash{block.GetHash()};

    CheckBlockCache(block, false, false, false);
    BOOST_CHECK(!IsBlockMutated(block, /*check_witness_root=*/true));
    CheckBlockCache(block, false, true, true);
    // A cached commitment must not allow witness data when none is expected.
    BOOST_CHECK(IsBlockMutated(block, /*check_witness_root=*/false));
    CheckBlockCache(block, false, true, true);

    for (bool check_all : {false, true}) {
        if (check_all) {
            BlockValidationState state;
            BOOST_CHECK(CheckBlock(block, state, consensus));
            BOOST_CHECK(state.IsValid());
        }
        CheckBlockCache(block, check_all, true, true);
        BOOST_CHECK(BlockBytes(block) == bytes);
        BOOST_CHECK(block.GetHash() == hash);

        CBlock copied{block};
        CBlock assigned;
        assigned = block;
        CheckBlockCache(copied, check_all, true, true);
        CheckBlockCache(assigned, check_all, true, true);
        BOOST_CHECK(BlockBytes(copied) == bytes);
        BOOST_CHECK(BlockBytes(assigned) == bytes);

        const CBlock& assigned_alias{assigned};
        assigned = assigned_alias;
        CheckBlockCache(assigned, check_all, true, true);
        BOOST_CHECK(BlockBytes(assigned) == bytes);
        BOOST_CHECK(assigned.GetHash() == hash);

        // Deserialization preserves memory-only flags until an exclusive reset.
        CBlock reused{block};
        SpanReader{bytes} >> TX_WITH_WITNESS(reused);
        CheckBlockCache(reused, check_all, true, true);
        BOOST_CHECK(BlockBytes(reused) == bytes);
        BOOST_CHECK(reused.GetHash() == hash);
        reused.SetNull();
        SpanReader{bytes} >> TX_WITH_WITNESS(reused);
        CheckBlockCache(reused, false, false, false);
        BOOST_CHECK(BlockBytes(reused) == bytes);
        BOOST_CHECK(reused.GetHash() == hash);

        CBlock moved{std::move(copied)};
        copied = std::move(assigned);
        CheckBlockCache(moved, check_all, true, true);
        CheckBlockCache(copied, check_all, true, true);
        BOOST_CHECK(BlockBytes(moved) == bytes);
        BOOST_CHECK(BlockBytes(copied) == bytes);

        // Assignment must copy false bits too, not retain the destination cache.
        copied = params->GenesisBlock();
        CheckBlockCache(copied, false, false, false);
        BOOST_CHECK(copied.GetHash() == params->GenesisBlock().GetHash());
        moved.SetNull();
        CheckBlockCache(moved, false, false, false);
        BOOST_CHECK(moved.IsNull());
        BOOST_CHECK(moved.vtx.empty());
    }
}

BOOST_AUTO_TEST_CASE(block_validation_cache_concurrent)
{
    static_assert(std::is_nothrow_move_constructible_v<CBlock>);
    static_assert(std::is_nothrow_move_assignable_v<CBlock>);
    const auto params{CreateChainParams(*m_node.args, ChainType::REGTEST)};
    const CBlock original{WitnessBlock(*params)};
    CheckBlockCache(original, false, false, false);
    const auto bytes{BlockBytes(original)};
    const auto check = [&](const CBlock& block) {
        BlockValidationState state;
        return CheckBlock(block, state, params->GetConsensus()) && state.IsValid();
    };
    constexpr size_t ROUNDS{16};

    for (size_t worker_count : {8U, 20U}) {
        for (bool shared : {true, false}) {
            // Build every cold fixture before workers start; never reset a shared cache.
            const std::vector<CBlock> blocks(shared ? ROUNDS : ROUNDS * worker_count, original);
            struct Result {
                bool valid{true};
                std::exception_ptr exception;
            };
            std::vector<Result> results(worker_count);
            std::barrier start{static_cast<std::ptrdiff_t>(worker_count)};
            std::latch launched{1};
            bool cancelled{false};
            std::vector<std::thread> workers;
            workers.reserve(worker_count);
            try {
                for (size_t i = 0; i < worker_count; ++i) {
                    workers.emplace_back([&, i] {
                        launched.wait();
                        if (cancelled) return;
                        for (size_t round = 0; round < ROUNDS; ++round) {
                            start.arrive_and_wait();
                            try {
                                const CBlock& block{blocks[shared ? round : round * worker_count + i]};
                                auto& valid{results[i].valid};
                                if (i % 3 == 0) {
                                    valid &= check(block);
                                } else if (i % 3 == 1) {
                                    valid &= !IsBlockMutated(block, /*check_witness_root=*/true);
                                } else {
                                    // Copy while other callers may be caching successful checks.
                                    CBlock copied{block};
                                    CBlock assigned;
                                    assigned = block;
                                    valid &= BlockBytes(copied) == bytes && BlockBytes(assigned) == bytes;
                                    valid &= check(copied) && check(assigned);
                                    valid &= !IsBlockMutated(copied, /*check_witness_root=*/true);
                                    valid &= !IsBlockMutated(assigned, /*check_witness_root=*/true);
                                }
                                valid &= check(block);
                                valid &= !IsBlockMutated(block, /*check_witness_root=*/true);
                            } catch (...) {
                                results[i].exception = std::current_exception();
                            }
                        }
                    });
                }
            } catch (...) {
                // Publish cancellation before releasing partially launched workers.
                cancelled = true;
                launched.count_down();
                for (auto& worker : workers) {
                    worker.join();
                }
                throw;
            }
            launched.count_down();
            for (auto& worker : workers) {
                worker.join();
            }
            for (const auto& result : results) {
                BOOST_CHECK(!result.exception);
                BOOST_CHECK(result.valid);
            }
            for (const auto& block : blocks) {
                CheckBlockCache(block, true, true, true);
                BOOST_CHECK(BlockBytes(block) == bytes);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.m_validation_cache.m_checked.store(false);
        block.m_validation_cache.m_checked_witness_commitment.store(false);
        block.m_validation_cache.m_checked_merkle_root.store(false);
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        if (include_witness) {
            coinbase.vin[0].scriptWitness.stack.resize(1);
            coinbase.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash().ToUint256() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash().ToUint256();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash().ToUint256();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash().ToUint256());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].scriptWitness.stack.resize(1);
            mtx.vin[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.vin[0].scriptWitness.stack[0].empty());
            ++mtx.vin[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.vin[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

BOOST_AUTO_TEST_SUITE_END()

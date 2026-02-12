// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <addresstype.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <script/txhash.h>
#include <test/data/txhash_tests.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cstdint>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txhash_tests)

namespace {
bool VerifySingleInputTaprootScriptPathSpend(
    const CScript& tapscript,
    const std::vector<std::vector<unsigned char>>& initial_stack,
    script_verify_flags flags,
    ScriptError& out_error)
{
    const std::vector<unsigned char> script_bytes{tapscript.begin(), tapscript.end()};

    TaprootBuilder builder;
    builder.Add(/*depth=*/0, script_bytes, TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    if (!builder.IsComplete()) {
        return false;
    }
    builder.Finalize(XOnlyPubKey::NUMS_H);

    const CScript script_pubkey = GetScriptForDestination(builder.GetOutput());
    const TaprootSpendData spend_data = builder.GetSpendData();
    const auto it = spend_data.scripts.find({script_bytes, TAPROOT_LEAF_TAPSCRIPT});
    if (it == spend_data.scripts.end() || it->second.empty()) {
        return false;
    }
    const std::vector<unsigned char> control_block = *it->second.begin();

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{}, 0xFFFFFFFF);
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);

    auto& witness_stack = mtx.vin[0].scriptWitness.stack;
    witness_stack = initial_stack;
    witness_stack.push_back(script_bytes);
    witness_stack.push_back(control_block);

    const CTransaction tx(mtx);
    const std::vector<CTxOut> prevouts{CTxOut{2000, script_pubkey}};

    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>(prevouts));

    TransactionSignatureChecker checker(
        &tx,
        /*nInIn=*/0,
        prevouts[0].nValue,
        txdata,
        MissingDataBehavior::ASSERT_FAIL
    );

    out_error = SCRIPT_ERR_UNKNOWN_ERROR;
    return VerifyScript(
        tx.vin[0].scriptSig,
        prevouts[0].scriptPubKey,
        &tx.vin[0].scriptWitness,
        flags,
        checker,
        &out_error
    );
}
} // namespace

BOOST_FIXTURE_TEST_CASE(txhash_vectors, BasicTestingSetup)
{
    UniValue groups = read_json(json_tests::txhash_tests);

    for (unsigned int g = 0; g < groups.size(); g++) {
        const UniValue& group = groups[g];
        if (!group.isObject()) continue;

        // Deserialize the transaction
        CMutableTransaction mtx;
        BOOST_CHECK_MESSAGE(DecodeHexTx(mtx, group.find_value("tx").get_str()),
                            strprintf("Failed to decode transaction in group %u", g));
        const CTransaction tx(mtx);

        // Deserialize the spent outputs (prevouts)
        const UniValue& prevs_arr = group.find_value("prevs").get_array();
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(prevs_arr.size());
        for (unsigned int p = 0; p < prevs_arr.size(); p++) {
            CTxOut txout;
            BOOST_CHECK_MESSAGE(DecodeHexTxOut(txout, prevs_arr[p].get_str()),
                                strprintf("Failed to decode prevout %u in group %u", p, g));
            spent_outputs.push_back(txout);
        }
        BOOST_CHECK_EQUAL(spent_outputs.size(), tx.vin.size());

        // Run each test vector
        const UniValue& vectors = group.find_value("vectors").get_array();
        TxHashCache cache;
        for (unsigned int v = 0; v < vectors.size(); v++) {
            const UniValue& vec = vectors[v];
            const std::string id = vec.find_value("id").get_str();
            const unsigned int input_idx = vec.find_value("input").getInt<unsigned int>();
            const std::string txfs_hex = vec.find_value("txfs").get_str();
            const std::string expected_hex = vec.find_value("txhash").get_str();

            // Parse codeseparator position (null means 0xFFFFFFFF)
            uint32_t codeseparator_pos = 0xFFFFFFFF;
            const UniValue& cs = vec.find_value("codeseparator");
            if (!cs.isNull()) {
                codeseparator_pos = cs.getInt<uint32_t>();
            }

            // Parse TxFieldSelector
            std::vector<unsigned char> txfs_bytes = ParseHex(txfs_hex);

            // Parse expected hash (big-endian hex)
            auto expected_hash = uint256::FromHexBE(expected_hex);
            BOOST_CHECK_MESSAGE(expected_hash.has_value(),
                                "Failed to parse expected hash for vector " + id);

            // Calculate TxHash
            uint256 result;
            std::span<const unsigned char> field_selector{txfs_bytes};
            bool ok = calculate_txhash(result, field_selector, cache, tx, spent_outputs, codeseparator_pos, input_idx);
            BOOST_CHECK_MESSAGE(ok, "calculate_txhash failed for vector " + id);
            BOOST_CHECK_MESSAGE(result == *expected_hash,
                                "Hash mismatch for vector " + id +
                                ": expected " + expected_hex);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(txhash_invalid_selectors, BasicTestingSetup)
{
    // Build a minimal 3-input, 2-output transaction
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    for (int i = 0; i < 3; i++) {
        mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), static_cast<uint32_t>(i)}, CScript{});
    }
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    mtx.vout.emplace_back(2000, CScript{} << OP_TRUE);
    const CTransaction tx(mtx);

    // Matching prevouts (one per input)
    std::vector<CTxOut> prevouts(3, CTxOut{5000, CScript{} << OP_TRUE});

    struct InvalidCase {
        const char* description;
        std::vector<unsigned char> selector;
        uint32_t in_pos;
    };

    std::vector<InvalidCase> cases = {
        // 1. Invalid short form: input bits = 0b10
        {"short form invalid input bits", {0x02}, 0},
        // 2. Invalid short form: output bits = 0b10
        {"short form invalid output bits", {0x08}, 0},
        // 3. Current output OOB (in_pos=2, only 2 outputs)
        {"current output out of bounds", {0xff, 0xff, 0x3f, 0x40}, 2},
        // 4. Leading count > nb_items (leading 5, only 3 inputs)
        {"leading count exceeds inputs", {0xff, 0xff, 0x05, 0x00}, 0},
        // 5. Individual index >= nb_items (absolute index 5, only 3 inputs)
        {"individual index out of bounds", {0xff, 0xff, 0x41, 0x05, 0x00}, 0},
        // 6. Individual indices not strictly increasing (2 then 1)
        {"individual indices not increasing", {0xff, 0xff, 0x42, 0x02, 0x01, 0x00}, 0},
        // 7. Truncated: leading size bit set but no next byte
        {"truncated leading size", {0xff, 0xff, 0x20}, 0},
        // 8. Trailing extra bytes after valid selectors
        {"trailing extra bytes", {0xff, 0xff, 0x3f, 0x3f, 0x00}, 0},
        // 9. Relative index underflow (in_pos=0, rel=-1 encoded as i7 0x7f)
        {"relative index underflow", {0xff, 0xff, 0x61, 0x7f, 0x00}, 0},
        // 10. Two-byte absolute index with idx == nb_inputs (boundary)
        {"two-byte absolute index equals inputs length", {0xff, 0xff, 0x41, 0x80, 0x03, 0x00}, 0},
        // 11. Two-byte relative index with idx == nb_inputs (boundary)
        {"two-byte relative index equals inputs length", {0xff, 0xff, 0x61, 0x80, 0x02, 0x00}, 1},
        // 12. Two-byte absolute output index with idx == nb_outputs (boundary)
        {"two-byte absolute output index equals outputs length", {0xff, 0xff, 0x00, 0x41, 0x80, 0x02}, 0},
    };

    for (const auto& tc : cases) {
        uint256 hash;
        TxHashCache cache;
        std::span<const unsigned char> selector{tc.selector};
        bool ok = calculate_txhash(hash, selector, cache, tx, prevouts, 0xFFFFFFFF, tc.in_pos);
        BOOST_CHECK_MESSAGE(!ok, strprintf("Expected failure for: %s", tc.description));
    }
}

BOOST_FIXTURE_TEST_CASE(txhash_two_byte_individual_indices, BasicTestingSetup)
{
    // Build a 3-input, 2-output transaction for cross-checking 2-byte
    // individual index selection against SELECTION_ALL.
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    for (int i = 0; i < 3; i++) {
        mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), static_cast<uint32_t>(i)}, CScript{} << std::vector<unsigned char>(i + 1, 0x42));
    }
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    mtx.vout.emplace_back(2000, CScript{} << OP_2);
    const CTransaction tx(mtx);
    std::vector<CTxOut> prevouts{
        CTxOut{5000, CScript{} << OP_TRUE},
        CTxOut{6000, CScript{} << OP_2},
        CTxOut{7000, CScript{} << OP_3},
    };

    // Reference hash: select all inputs and outputs via SELECTION_ALL.
    // Selector: [global=0x00, fields=all_inputs|all_outputs, inputs=ALL, outputs=ALL]
    const std::vector<unsigned char> sel_all{0x00, TXFS_INPUTS_ALL | TXFS_OUTPUTS_ALL, TXFS_INOUT_SELECTION_ALL, TXFS_INOUT_SELECTION_ALL};
    TxHashCache cache_ref;
    uint256 hash_all;
    BOOST_REQUIRE(calculate_txhash(hash_all, sel_all, cache_ref, tx, prevouts, 0xFFFFFFFF, 0));

    // 2-byte absolute individual: select inputs 0, 1, 2 each as 2-byte index.
    // Individual mode (bit 6) | absolute (bit 5 clear) | count=3 → 0x43
    // Each index: high bit set → 2-byte. Index N → [0x80|(N>>8), N&0xFF]
    const std::vector<unsigned char> sel_abs_2b{
        0x00, TXFS_INPUTS_ALL | TXFS_OUTPUTS_ALL,
        0x43, 0x80, 0x00, 0x80, 0x01, 0x80, 0x02, // inputs: abs 2-byte [0,1,2]
        TXFS_INOUT_SELECTION_ALL,                    // outputs: all
    };
    TxHashCache cache_abs;
    uint256 hash_abs_2b;
    BOOST_CHECK(calculate_txhash(hash_abs_2b, sel_abs_2b, cache_abs, tx, prevouts, 0xFFFFFFFF, 0));
    BOOST_CHECK_MESSAGE(hash_abs_2b == hash_all,
        "2-byte absolute individual selection of all inputs must match SELECTION_ALL");

    // 2-byte absolute individual for outputs: select outputs 0, 1.
    // Individual mode | absolute | count=2 → 0x42
    const std::vector<unsigned char> sel_abs_2b_out{
        0x00, TXFS_INPUTS_ALL | TXFS_OUTPUTS_ALL,
        TXFS_INOUT_SELECTION_ALL,                        // inputs: all
        0x42, 0x80, 0x00, 0x80, 0x01,                   // outputs: abs 2-byte [0,1]
    };
    TxHashCache cache_abs_out;
    uint256 hash_abs_2b_out;
    BOOST_CHECK(calculate_txhash(hash_abs_2b_out, sel_abs_2b_out, cache_abs_out, tx, prevouts, 0xFFFFFFFF, 0));
    BOOST_CHECK_MESSAGE(hash_abs_2b_out == hash_all,
        "2-byte absolute individual selection of all outputs must match SELECTION_ALL");

    // 2-byte relative individual: from in_pos=1, select relative -1, 0, +1 → abs [0,1,2].
    // Individual mode (bit 6) | relative (bit 5) | count=3 → 0x63
    // Relative -1 as i15: 0x7FFF → [0xFF, 0xFF]
    // Relative  0 as i15: 0x0000 → [0x80, 0x00]
    // Relative +1 as i15: 0x0001 → [0x80, 0x01]
    const std::vector<unsigned char> sel_rel_2b{
        0x00, TXFS_INPUTS_ALL | TXFS_OUTPUTS_ALL,
        0x63, 0xFF, 0xFF, 0x80, 0x00, 0x80, 0x01, // inputs: rel 2-byte [-1,0,+1] from in_pos=1
        TXFS_INOUT_SELECTION_ALL,                    // outputs: all
    };
    TxHashCache cache_rel;
    uint256 hash_rel_2b;
    BOOST_CHECK(calculate_txhash(hash_rel_2b, sel_rel_2b, cache_rel, tx, prevouts, 0xFFFFFFFF, /*in_pos=*/1));

    // Cross-check: same hash as SELECTION_ALL from in_pos=1
    TxHashCache cache_ref2;
    uint256 hash_all_pos1;
    BOOST_REQUIRE(calculate_txhash(hash_all_pos1, sel_all, cache_ref2, tx, prevouts, 0xFFFFFFFF, /*in_pos=*/1));
    BOOST_CHECK_MESSAGE(hash_rel_2b == hash_all_pos1,
        "2-byte relative individual selection resolving to all inputs must match SELECTION_ALL");
}

BOOST_FIXTURE_TEST_CASE(txhash_pre_activation_opsuccess_behavior, BasicTestingSetup)
{
    const script_verify_flags base_flags =
        SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT;
    const CScript tapscript = CScript() << OP_TXHASH;

    ScriptError err;
    BOOST_CHECK(VerifySingleInputTaprootScriptPathSpend(tapscript, /*initial_stack=*/{}, base_flags, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    BOOST_CHECK(!VerifySingleInputTaprootScriptPathSpend(
        tapscript,
        /*initial_stack=*/{},
        base_flags | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
        err
    ));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
}

BOOST_FIXTURE_TEST_CASE(txhash_validation_weight_budget, BasicTestingSetup)
{
    const script_verify_flags flags =
        SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_TXHASH;

    // With one OP_TXHASH the script should stay within tapscript validation weight.
    const CScript one_txhash = CScript() << OP_0 << OP_TXHASH << OP_DROP << OP_TRUE;
    ScriptError err;
    BOOST_CHECK(VerifySingleInputTaprootScriptPathSpend(one_txhash, /*initial_stack=*/{}, flags, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Four OP_TXHASH executions exceed the budget for this witness.
    const CScript four_txhash = CScript()
        << OP_0 << OP_TXHASH << OP_DROP
        << OP_0 << OP_TXHASH << OP_DROP
        << OP_0 << OP_TXHASH << OP_DROP
        << OP_0 << OP_TXHASH << OP_DROP
        << OP_TRUE;
    BOOST_CHECK(!VerifySingleInputTaprootScriptPathSpend(four_txhash, /*initial_stack=*/{}, flags, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
}

BOOST_FIXTURE_TEST_CASE(txhash_checker_without_explicit_cache, BasicTestingSetup)
{
    UniValue groups = read_json(json_tests::txhash_tests);
    BOOST_REQUIRE(groups.isArray());
    BOOST_REQUIRE(!groups.empty());

    const UniValue& group = groups[0];
    BOOST_REQUIRE(group.isObject());

    CMutableTransaction mtx;
    BOOST_REQUIRE(DecodeHexTx(mtx, group.find_value("tx").get_str()));
    const CTransaction tx(mtx);

    const UniValue& prevs_arr = group.find_value("prevs").get_array();
    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(prevs_arr.size());
    for (unsigned int p = 0; p < prevs_arr.size(); ++p) {
        CTxOut txout;
        BOOST_REQUIRE(DecodeHexTxOut(txout, prevs_arr[p].get_str()));
        spent_outputs.push_back(txout);
    }
    BOOST_REQUIRE_EQUAL(spent_outputs.size(), tx.vin.size());

    const UniValue& vec = group.find_value("vectors").get_array()[0];
    const unsigned int input_idx = vec.find_value("input").getInt<unsigned int>();
    const std::vector<unsigned char> txfs_bytes = ParseHex(vec.find_value("txfs").get_str());

    uint32_t codeseparator_pos = 0xFFFFFFFF;
    const UniValue& cs = vec.find_value("codeseparator");
    if (!cs.isNull()) {
        codeseparator_pos = cs.getInt<uint32_t>();
    }

    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>(spent_outputs));

    // Exercise checker path without explicitly threading a TxHashCache.
    TransactionSignatureChecker checker(
        &tx,
        input_idx,
        spent_outputs[input_idx].nValue,
        txdata,
        MissingDataBehavior::ASSERT_FAIL
    );

    uint256 checker_hash;
    BOOST_CHECK(checker.CalculateTxHash(checker_hash, txfs_bytes, codeseparator_pos));

    // Cross-check against direct helper invocation.
    TxHashCache cache;
    uint256 direct_hash;
    BOOST_CHECK(calculate_txhash(direct_hash, txfs_bytes, cache, tx, spent_outputs, codeseparator_pos, input_idx));
    BOOST_CHECK(checker_hash == direct_hash);
}

BOOST_FIXTURE_TEST_CASE(txhash_cache_reuse_across_different_shapes, BasicTestingSetup)
{
    CMutableTransaction mtx_small;
    mtx_small.version = 2;
    mtx_small.nLockTime = 0;
    mtx_small.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{} << OP_TRUE);
    mtx_small.vout.emplace_back(1000, CScript{} << OP_TRUE);
    const CTransaction tx_small(mtx_small);
    const std::vector<CTxOut> prevouts_small{CTxOut{4000, CScript{} << OP_TRUE}};

    CMutableTransaction mtx_large;
    mtx_large.version = 2;
    mtx_large.nLockTime = 0;
    mtx_large.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{} << OP_TRUE);
    mtx_large.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1}, CScript{} << OP_TRUE);
    mtx_large.vout.emplace_back(1000, CScript{} << OP_TRUE);
    mtx_large.vout.emplace_back(2000, CScript{} << OP_TRUE);
    const CTransaction tx_large(mtx_large);
    const std::vector<CTxOut> prevouts_large{
        CTxOut{4000, CScript{} << OP_TRUE},
        CTxOut{5000, CScript{} << OP_TRUE},
    };

    std::vector<unsigned char> selector_bytes;
    std::span<const unsigned char> selector{selector_bytes};

    TxHashCache reused_cache;
    uint256 small_hash;
    BOOST_CHECK(calculate_txhash(small_hash, selector, reused_cache, tx_small, prevouts_small, 0xFFFFFFFF, 0));

    uint256 large_hash_with_reused_cache;
    BOOST_CHECK(calculate_txhash(large_hash_with_reused_cache, selector, reused_cache, tx_large, prevouts_large, 0xFFFFFFFF, 0));

    TxHashCache fresh_cache;
    uint256 large_hash_with_fresh_cache;
    BOOST_CHECK(calculate_txhash(large_hash_with_fresh_cache, selector, fresh_cache, tx_large, prevouts_large, 0xFFFFFFFF, 0));

    BOOST_CHECK(large_hash_with_reused_cache == large_hash_with_fresh_cache);
}

BOOST_FIXTURE_TEST_CASE(txhash_cache_reuse_across_same_shape, BasicTestingSetup)
{
    CMutableTransaction mtx_a;
    mtx_a.version = 2;
    mtx_a.nLockTime = 0;
    mtx_a.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{} << OP_TRUE, 1);
    mtx_a.vout.emplace_back(1000, CScript{} << OP_TRUE);
    const CTransaction tx_a(mtx_a);
    const std::vector<CTxOut> prevouts_a{CTxOut{4000, CScript{} << OP_TRUE}};

    CMutableTransaction mtx_b;
    mtx_b.version = 2;
    mtx_b.nLockTime = 0;
    mtx_b.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1}, CScript{} << OP_2, 2);
    mtx_b.vout.emplace_back(2000, CScript{} << OP_2);
    const CTransaction tx_b(mtx_b);
    const std::vector<CTxOut> prevouts_b{CTxOut{5000, CScript{} << OP_3}};

    std::vector<unsigned char> selector_bytes;
    std::span<const unsigned char> selector{selector_bytes};

    TxHashCache reused_cache;

    uint256 hash_a;
    BOOST_CHECK(calculate_txhash(hash_a, selector, reused_cache, tx_a, prevouts_a, 0xFFFFFFFF, 0));

    uint256 hash_b_with_reused_cache;
    BOOST_CHECK(calculate_txhash(hash_b_with_reused_cache, selector, reused_cache, tx_b, prevouts_b, 0xFFFFFFFF, 0));

    TxHashCache fresh_cache;
    uint256 hash_b_with_fresh_cache;
    BOOST_CHECK(calculate_txhash(hash_b_with_fresh_cache, selector, fresh_cache, tx_b, prevouts_b, 0xFFFFFFFF, 0));

    BOOST_CHECK(hash_a != hash_b_with_fresh_cache);
    BOOST_CHECK(hash_b_with_reused_cache == hash_b_with_fresh_cache);
}

BOOST_FIXTURE_TEST_CASE(txhash_cache_reuse_with_inplace_mutation, BasicTestingSetup)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{} << OP_TRUE, 1);
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);

    std::vector<CTxOut> prevouts{CTxOut{4000, CScript{} << OP_TRUE}};

    // Empty selector resolves to TXFS_SPECIAL_TEMPLATE and commits to scriptSig.
    const std::vector<unsigned char> selector_default_bytes;
    std::span<const unsigned char> selector_default{selector_default_bytes};

    TxHashCache reused_cache;
    uint256 before_tx_mutation;
    BOOST_CHECK(calculate_txhash(before_tx_mutation, selector_default, reused_cache, mtx, prevouts, 0xFFFFFFFF, 0));

    // In-place mutation at the same object address must invalidate cache entries.
    mtx.vin[0].scriptSig = CScript{} << OP_2;

    uint256 after_tx_mutation_reused_cache;
    BOOST_CHECK(calculate_txhash(after_tx_mutation_reused_cache, selector_default, reused_cache, mtx, prevouts, 0xFFFFFFFF, 0));

    TxHashCache fresh_cache_for_tx_mutation;
    uint256 after_tx_mutation_fresh_cache;
    BOOST_CHECK(calculate_txhash(after_tx_mutation_fresh_cache, selector_default, fresh_cache_for_tx_mutation, mtx, prevouts, 0xFFFFFFFF, 0));

    BOOST_CHECK(before_tx_mutation != after_tx_mutation_fresh_cache);
    BOOST_CHECK(after_tx_mutation_reused_cache == after_tx_mutation_fresh_cache);

    // Explicit selector that commits to prevout scriptPubKeys only.
    const std::vector<unsigned char> selector_prev_spk_bytes{
        0x00,
        TXFS_INPUTS_PREV_SCRIPTPUBKEYS,
        TXFS_INOUT_SELECTION_ALL,
    };
    std::span<const unsigned char> selector_prev_spk{selector_prev_spk_bytes};

    TxHashCache reused_cache_for_prevouts;
    uint256 before_prevouts_mutation;
    BOOST_CHECK(calculate_txhash(before_prevouts_mutation, selector_prev_spk, reused_cache_for_prevouts, mtx, prevouts, 0xFFFFFFFF, 0));

    // Mutate prevouts in place and verify reused cache tracks updated content.
    prevouts[0].scriptPubKey = CScript{} << OP_3;

    uint256 after_prevouts_mutation_reused_cache;
    BOOST_CHECK(calculate_txhash(after_prevouts_mutation_reused_cache, selector_prev_spk, reused_cache_for_prevouts, mtx, prevouts, 0xFFFFFFFF, 0));

    TxHashCache fresh_cache_for_prevouts_mutation;
    uint256 after_prevouts_mutation_fresh_cache;
    BOOST_CHECK(calculate_txhash(after_prevouts_mutation_fresh_cache, selector_prev_spk, fresh_cache_for_prevouts_mutation, mtx, prevouts, 0xFFFFFFFF, 0));

    BOOST_CHECK(before_prevouts_mutation != after_prevouts_mutation_fresh_cache);
    BOOST_CHECK(after_prevouts_mutation_reused_cache == after_prevouts_mutation_fresh_cache);
}

BOOST_FIXTURE_TEST_CASE(txhash_cache_reuse_const_tx_context_identity_based, BasicTestingSetup)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{} << OP_TRUE, 1);
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    const CTransaction tx(mtx);

    std::vector<CTxOut> prevouts{CTxOut{4000, CScript{} << OP_TRUE}};

    // Selector committing to prevout scriptPubKeys only.
    const std::vector<unsigned char> selector_prev_spk_bytes{
        0x00,
        TXFS_INPUTS_PREV_SCRIPTPUBKEYS,
        TXFS_INOUT_SELECTION_ALL,
    };
    std::span<const unsigned char> selector_prev_spk{selector_prev_spk_bytes};

    TxHashCache cache;
    uint256 hash_before;
    BOOST_CHECK(calculate_txhash(hash_before, selector_prev_spk, cache, tx, prevouts, 0xFFFFFFFF, 0));

    // Immutable tx contexts should avoid content fingerprinting and rely on
    // identity/shape to decide cache compatibility.
    {
        LOCK(cache.mtx);
        BOOST_CHECK(cache.context_initialized);
        BOOST_CHECK(cache.cached_tx_ref == &tx);
        BOOST_CHECK(cache.cached_prevouts_ref == &prevouts);
        BOOST_CHECK(cache.cached_tx_content_fingerprint.IsNull());
#ifdef DEBUG
        BOOST_CHECK(!cache.cached_prevouts_content_fingerprint.IsNull());
#else
        BOOST_CHECK(cache.cached_prevouts_content_fingerprint.IsNull());
#endif
    }

    uint256 hash_before_repeat;
    BOOST_CHECK(calculate_txhash(hash_before_repeat, selector_prev_spk, cache, tx, prevouts, 0xFFFFFFFF, 0));
    BOOST_CHECK(hash_before_repeat == hash_before);

    // Rebinding prevouts to a new vector should invalidate cache entries and
    // produce the same result as a fresh cache.
    std::vector<CTxOut> mutated_prevouts{CTxOut{4000, CScript{} << OP_2}};
    uint256 hash_after_reused_cache;
    BOOST_CHECK(calculate_txhash(hash_after_reused_cache, selector_prev_spk, cache, tx, mutated_prevouts, 0xFFFFFFFF, 0));

    TxHashCache fresh_cache;
    uint256 hash_after_fresh_cache;
    BOOST_CHECK(calculate_txhash(hash_after_fresh_cache, selector_prev_spk, fresh_cache, tx, mutated_prevouts, 0xFFFFFFFF, 0));

    BOOST_CHECK(hash_before != hash_after_fresh_cache);
    BOOST_CHECK(hash_after_reused_cache == hash_after_fresh_cache);
}

BOOST_AUTO_TEST_SUITE_END()

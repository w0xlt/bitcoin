// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <primitives/transaction.h>
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
    };

    for (const auto& tc : cases) {
        uint256 hash;
        TxHashCache cache;
        std::span<const unsigned char> selector{tc.selector};
        bool ok = calculate_txhash(hash, selector, cache, tx, prevouts, 0xFFFFFFFF, tc.in_pos);
        BOOST_CHECK_MESSAGE(!ok, strprintf("Expected failure for: %s", tc.description));
    }
}

BOOST_AUTO_TEST_SUITE_END()

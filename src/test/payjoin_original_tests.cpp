// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/messages.h>
#include <payjoin/original.h>

#include <key.h>
#include <psbt.h>
#include <pubkey.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> SerializePSBTForTest(const PartiallySignedTransaction& psbt)
{
    DataStream ds;
    ds << psbt;
    std::vector<uint8_t> result(ds.size());
    std::memcpy(result.data(), ds.data(), ds.size());
    return result;
}

PartiallySignedTransaction CreateTestPsbt()
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vout.emplace_back(12345, CScript() << OP_1);
    return PartiallySignedTransaction(mtx);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(payjoin_original_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(original_payload_roundtrip)
{
    const PartiallySignedTransaction original = CreateTestPsbt();
    const std::string query = "v=2&disableoutputsubstitution=true&minfeerate=2";

    auto payload = payjoin::SerializeOriginalPayload(original, query);
    auto parsed = payjoin::DeserializeOriginalPayload(payload);
    BOOST_REQUIRE(parsed.has_value());

    BOOST_CHECK_EQUAL(parsed->query_params, query);
    BOOST_CHECK(SerializePSBTForTest(parsed->psbt) == SerializePSBTForTest(original));
}

BOOST_AUTO_TEST_CASE(original_payload_trims_padding_after_message_a_decryption)
{
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    const PartiallySignedTransaction original = CreateTestPsbt();
    const std::string query = payjoin::BuildOriginalPayloadQuery(/*disable_output_substitution=*/true);
    auto payload = payjoin::SerializeOriginalPayload(original, query);

    auto encrypted = payjoin::EncryptMessageA(payload, reply_pk, receiver_pk);
    BOOST_REQUIRE(encrypted.has_value());

    auto decrypted = payjoin::DecryptMessageA(*encrypted, receiver_sk);
    BOOST_REQUIRE(decrypted.has_value());

    auto parsed = payjoin::DeserializeOriginalPayload(std::span<const uint8_t>(decrypted->first.data(), decrypted->first.size()));
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->query_params == query);
    BOOST_CHECK(SerializePSBTForTest(parsed->psbt) == SerializePSBTForTest(original));
}

BOOST_AUTO_TEST_CASE(original_payload_without_newline_fails)
{
    const std::vector<uint8_t> invalid{'n', 'o', '-', 'n', 'e', 'w', 'l', 'i', 'n', 'e'};
    BOOST_CHECK(!payjoin::DeserializeOriginalPayload(invalid).has_value());
}

BOOST_AUTO_TEST_CASE(build_original_payload_query_defaults_to_v2)
{
    BOOST_CHECK_EQUAL(payjoin::BuildOriginalPayloadQuery(/*disable_output_substitution=*/false), "v=2");
    BOOST_CHECK_EQUAL(payjoin::BuildOriginalPayloadQuery(/*disable_output_substitution=*/true),
                      "v=2&disableoutputsubstitution=true");
}

BOOST_AUTO_TEST_CASE(parse_original_payload_query_supports_fee_parameters)
{
    const auto parsed = payjoin::ParseOriginalPayloadQuery(
        "v=2&disableoutputsubstitution=true&additionalfeeoutputindex=1&maxadditionalfeecontribution=250&minfeerate=1.5");
    BOOST_REQUIRE(parsed.has_value());

    BOOST_CHECK(parsed->disable_output_substitution);
    BOOST_REQUIRE(parsed->additional_fee_contribution.has_value());
    BOOST_CHECK_EQUAL(parsed->additional_fee_contribution->additional_fee_output_index, 1U);
    BOOST_CHECK_EQUAL(parsed->additional_fee_contribution->max_additional_fee_contribution, 250);
    BOOST_CHECK_EQUAL(parsed->min_fee_rate.GetFeePerK(), 1500);
}

BOOST_AUTO_TEST_CASE(parse_original_payload_query_ignores_partial_fee_parameters)
{
    const auto parsed = payjoin::ParseOriginalPayloadQuery("v=2&maxadditionalfeecontribution=250");
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(!parsed->additional_fee_contribution.has_value());
}

BOOST_AUTO_TEST_CASE(parse_original_payload_query_rejects_invalid_version_and_fee_rate)
{
    BOOST_CHECK(!payjoin::ParseOriginalPayloadQuery("v=1").has_value());
    BOOST_CHECK(!payjoin::ParseOriginalPayloadQuery("v=2&minfeerate=abc").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

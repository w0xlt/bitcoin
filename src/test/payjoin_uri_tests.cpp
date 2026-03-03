// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/uri.h>

#include <key.h>
#include <key_io.h>
#include <ohttp/ohttp.h>
#include <pubkey.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(payjoin_uri_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(parse_basic_payjoin_uri)
{
    // Generate a test receiver key
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    // Build a URI, then parse it back
    payjoin::PayjoinUri uri;
    uri.address = DecodeDestination("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");
    uri.amount = 100000;
    uri.output_substitution = true;

    uri.pj.directory_url = "https://payjo.in";
    uri.pj.receiver_key = receiver_pk;
    uri.pj.expiration = 1700000000;

    // Set up a minimal OHTTP KeyConfig
    ohttp::KeyConfig ohttp_cfg;
    ohttp_cfg.key_id = 1;
    ohttp_cfg.kem_id = ohttp::KEM_SECP256K1;
    // Use the receiver pubkey as a stand-in for the OHTTP key
    std::copy(receiver_pk.begin(), receiver_pk.end(), ohttp_cfg.pkR.begin());
    ohttp_cfg.syms.push_back({ohttp::KDF_HKDF_SHA256, ohttp::AEAD_CHACHA20POLY1305});
    uri.pj.ohttp_keys = ohttp_cfg;

    std::string built = payjoin::BuildPayjoinUri(uri);
    BOOST_CHECK(!built.empty());
    BOOST_CHECK(built.find("bitcoin:") == 0);
    BOOST_CHECK(built.find("pj=") != std::string::npos);

    // Parse it back
    auto parsed = payjoin::ParsePayjoinUri(built);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->amount.has_value());
    BOOST_CHECK_EQUAL(*parsed->amount, 100000);
    BOOST_CHECK(parsed->pj.receiver_key == receiver_pk);
    BOOST_CHECK_EQUAL(parsed->pj.expiration, 1700000000);
}

BOOST_AUTO_TEST_CASE(parse_missing_pj_param_fails)
{
    // A normal BIP 21 URI without pj parameter
    auto parsed = payjoin::ParsePayjoinUri("bitcoin:bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080?amount=0.001");
    BOOST_CHECK(!parsed.has_value());
}

BOOST_AUTO_TEST_CASE(parse_invalid_uri_fails)
{
    auto parsed = payjoin::ParsePayjoinUri("not a uri");
    BOOST_CHECK(!parsed.has_value());

    auto parsed2 = payjoin::ParsePayjoinUri("");
    BOOST_CHECK(!parsed2.has_value());
}

BOOST_AUTO_TEST_CASE(roundtrip_build_parse)
{
    CKey sk;
    sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey pk = sk.GetPubKey();

    payjoin::PayjoinUri uri;
    uri.address = DecodeDestination("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");
    uri.amount = 50000;
    uri.output_substitution = false;

    uri.pj.directory_url = "https://example.onion";
    uri.pj.receiver_key = pk;
    uri.pj.expiration = 1800000000;

    ohttp::KeyConfig cfg;
    cfg.key_id = 0;
    cfg.kem_id = ohttp::KEM_SECP256K1;
    std::copy(pk.begin(), pk.end(), cfg.pkR.begin());
    cfg.syms.push_back({ohttp::KDF_HKDF_SHA256, ohttp::AEAD_CHACHA20POLY1305});
    uri.pj.ohttp_keys = cfg;

    std::string built = payjoin::BuildPayjoinUri(uri);
    auto parsed = payjoin::ParsePayjoinUri(built);
    BOOST_REQUIRE(parsed.has_value());

    // Verify roundtrip
    BOOST_CHECK_EQUAL(*parsed->amount, 50000);
    BOOST_CHECK(parsed->pj.receiver_key == pk);
    BOOST_CHECK_EQUAL(parsed->pj.expiration, 1800000000);
}

BOOST_AUTO_TEST_SUITE_END()

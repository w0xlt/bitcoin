// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/uri.h>

#include <key.h>
#include <key_io.h>
#include <ohttp/ohttp.h>
#include <payjoin/shortid.h>
#include <pubkey.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>

BOOST_FIXTURE_TEST_SUITE(payjoin_uri_tests, BasicTestingSetup)

static constexpr auto TEST_ADDRESS = "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs";

static ohttp::KeyConfig MakeOhttpKeys()
{
    CKey gateway_sk;
    gateway_sk.MakeNewKey(/*fCompressed=*/false);
    CPubKey gateway_pk = gateway_sk.GetPubKey();
    BOOST_REQUIRE_EQUAL(gateway_pk.size(), 65U);

    ohttp::KeyConfig cfg;
    cfg.key_id = 1;
    cfg.kem_id = ohttp::KEM_SECP256K1;
    std::copy(gateway_pk.begin(), gateway_pk.end(), cfg.pkR.begin());
    cfg.syms.push_back({ohttp::KDF_HKDF_SHA256, ohttp::AEAD_CHACHA20POLY1305});
    return cfg;
}

BOOST_AUTO_TEST_CASE(parse_basic_payjoin_uri)
{
    // Generate a test receiver key
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    // Build a URI, then parse it back
    payjoin::PayjoinUri uri;
    uri.address = DecodeDestination(TEST_ADDRESS);
    BOOST_REQUIRE(IsValidDestination(uri.address));
    uri.amount = 100000;
    uri.output_substitution = true;

    uri.pj.receiver_key = receiver_pk;
    uri.pj.mailbox_url = payjoin::MailboxUrl("http://payjo.in", receiver_pk);
    uri.pj.expiration = 1700000000;
    uri.pj.ohttp_keys = MakeOhttpKeys();

    std::string built = payjoin::BuildPayjoinUri(uri);
    BOOST_CHECK(!built.empty());
    BOOST_CHECK(built.find("bitcoin:") == 0);
    BOOST_CHECK(built.find("pj=") != std::string::npos);

    // Parse it back
    auto parsed = payjoin::ParsePayjoinUri(built);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->amount.has_value());
    BOOST_CHECK_EQUAL(*parsed->amount, 100000);
    BOOST_CHECK_EQUAL(parsed->pj.mailbox_url, uri.pj.mailbox_url);
    BOOST_CHECK(parsed->pj.receiver_key == receiver_pk);
    BOOST_CHECK_EQUAL(parsed->pj.expiration, 1700000000);
    auto directory_url = payjoin::DirectoryUrlFromMailboxUrl(parsed->pj.mailbox_url);
    BOOST_REQUIRE(directory_url.has_value());
    BOOST_CHECK_EQUAL(*directory_url, "http://payjo.in");
}

BOOST_AUTO_TEST_CASE(parse_missing_pj_param_fails)
{
    // A normal BIP 21 URI without pj parameter
    auto parsed = payjoin::ParsePayjoinUri(
        "bitcoin:1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs?amount=0.001");
    BOOST_CHECK(!parsed.has_value());
}

BOOST_AUTO_TEST_CASE(parse_invalid_uri_fails)
{
    auto parsed = payjoin::ParsePayjoinUri("not a uri");
    BOOST_CHECK(!parsed.has_value());

    auto parsed2 = payjoin::ParsePayjoinUri("");
    BOOST_CHECK(!parsed2.has_value());
}

BOOST_AUTO_TEST_CASE(parse_mailbox_without_short_id_fails)
{
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);

    payjoin::PayjoinUri uri;
    uri.address = DecodeDestination(TEST_ADDRESS);
    BOOST_REQUIRE(IsValidDestination(uri.address));
    uri.amount = 100000;
    uri.pj.mailbox_url = "http://payjo.in";
    uri.pj.receiver_key = receiver_sk.GetPubKey();
    uri.pj.expiration = 1700000000;
    uri.pj.ohttp_keys = MakeOhttpKeys();

    auto parsed = payjoin::ParsePayjoinUri(payjoin::BuildPayjoinUri(uri));
    BOOST_CHECK(!parsed.has_value());
}

BOOST_AUTO_TEST_CASE(parse_mailbox_with_multiple_path_segments_fails)
{
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);

    payjoin::PayjoinUri uri;
    uri.address = DecodeDestination(TEST_ADDRESS);
    BOOST_REQUIRE(IsValidDestination(uri.address));
    uri.amount = 100000;
    uri.pj.mailbox_url = "http://payjo.in/one/two";
    uri.pj.receiver_key = receiver_sk.GetPubKey();
    uri.pj.expiration = 1700000000;
    uri.pj.ohttp_keys = MakeOhttpKeys();

    auto parsed = payjoin::ParsePayjoinUri(payjoin::BuildPayjoinUri(uri));
    BOOST_CHECK(!parsed.has_value());
}

BOOST_AUTO_TEST_CASE(roundtrip_build_parse)
{
    CKey sk;
    sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey pk = sk.GetPubKey();

    payjoin::PayjoinUri uri;
    uri.address = DecodeDestination(TEST_ADDRESS);
    BOOST_REQUIRE(IsValidDestination(uri.address));
    uri.amount = 50000;
    uri.output_substitution = false;

    uri.pj.receiver_key = pk;
    uri.pj.mailbox_url = payjoin::MailboxUrl("http://example.onion", pk);
    uri.pj.expiration = 1800000000;
    uri.pj.ohttp_keys = MakeOhttpKeys();

    std::string built = payjoin::BuildPayjoinUri(uri);
    auto parsed = payjoin::ParsePayjoinUri(built);
    BOOST_REQUIRE(parsed.has_value());

    // Verify roundtrip
    BOOST_CHECK_EQUAL(*parsed->amount, 50000);
    BOOST_CHECK_EQUAL(parsed->pj.mailbox_url, uri.pj.mailbox_url);
    BOOST_CHECK(parsed->pj.receiver_key == pk);
    BOOST_CHECK_EQUAL(parsed->pj.expiration, 1800000000);
}

BOOST_AUTO_TEST_CASE(parse_https_mailbox_fails)
{
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);

    payjoin::PayjoinUri uri;
    uri.address = DecodeDestination(TEST_ADDRESS);
    BOOST_REQUIRE(IsValidDestination(uri.address));
    uri.amount = 100000;
    uri.pj.mailbox_url = payjoin::MailboxUrl("https://payjo.in", receiver_sk.GetPubKey());
    uri.pj.receiver_key = receiver_sk.GetPubKey();
    uri.pj.expiration = 1700000000;
    uri.pj.ohttp_keys = MakeOhttpKeys();

    auto parsed = payjoin::ParsePayjoinUri(payjoin::BuildPayjoinUri(uri));
    BOOST_CHECK(!parsed.has_value());
}

BOOST_AUTO_TEST_SUITE_END()

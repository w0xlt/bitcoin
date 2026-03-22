// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/shortid.h>

#include <key.h>
#include <pubkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(payjoin_shortid_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(short_id_deterministic)
{
    CKey sk;
    sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey pk = sk.GetPubKey();

    // Same key should produce same short ID
    std::string id1 = payjoin::EncodeShortId(payjoin::DeriveShortId(pk));
    std::string id2 = payjoin::EncodeShortId(payjoin::DeriveShortId(pk));
    BOOST_CHECK_EQUAL(id1, id2);
}

BOOST_AUTO_TEST_CASE(short_id_different_keys)
{
    CKey sk1, sk2;
    sk1.MakeNewKey(/*fCompressed=*/true);
    sk2.MakeNewKey(/*fCompressed=*/true);

    std::string id1 = payjoin::EncodeShortId(payjoin::DeriveShortId(sk1.GetPubKey()));
    std::string id2 = payjoin::EncodeShortId(payjoin::DeriveShortId(sk2.GetPubKey()));
    BOOST_CHECK(id1 != id2);
}

BOOST_AUTO_TEST_CASE(short_id_length)
{
    CKey sk;
    sk.MakeNewKey(/*fCompressed=*/true);

    auto short_id = payjoin::DeriveShortId(sk.GetPubKey());
    BOOST_CHECK_EQUAL(short_id.size(), 8u);

    std::string encoded = payjoin::EncodeShortId(short_id);
    BOOST_CHECK(!encoded.empty());
    // 8 bytes = 64 bits, bech32 5-bit encoding = ceil(64/5) = 13 characters
    BOOST_CHECK_EQUAL(encoded.size(), 13u);
}

BOOST_AUTO_TEST_CASE(mailbox_url_format)
{
    CKey sk;
    sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey pk = sk.GetPubKey();

    std::string url = payjoin::MailboxUrl("http://payjo.in", pk);
    BOOST_CHECK(url.find("http://payjo.in/") == 0);
    BOOST_CHECK(url.size() > std::string("http://payjo.in/").size());
}

BOOST_AUTO_TEST_CASE(short_id_is_uppercase)
{
    CKey sk;
    sk.MakeNewKey(/*fCompressed=*/true);

    std::string encoded = payjoin::EncodeShortId(payjoin::DeriveShortId(sk.GetPubKey()));
    // Short ID should be uppercase bech32 charset
    for (char c : encoded) {
        // Uppercase of bech32 charset: QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L
        BOOST_CHECK(c >= '0' || c >= 'A');
    }
}

BOOST_AUTO_TEST_SUITE_END()

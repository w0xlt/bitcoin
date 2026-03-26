// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/messages.h>

#include <dhkem_secp256k1.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(payjoin_messages_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(message_a_roundtrip)
{
    dhkem_secp256k1::InitContext();

    // Generate receiver keypair (compressed)
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    // Generate sender's ephemeral reply keypair (compressed)
    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    // Test body (simulated PSBT)
    std::vector<uint8_t> body(500);
    std::iota(body.begin(), body.end(), 0);

    // Encrypt
    auto encrypted = payjoin::EncryptMessageA(body, reply_pk, receiver_pk);
    BOOST_REQUIRE(encrypted.has_value());
    BOOST_CHECK_EQUAL(encrypted->size(), payjoin::PADDED_MESSAGE_BYTES);

    // Decrypt
    auto decrypted = payjoin::DecryptMessageA(*encrypted, receiver_sk);
    BOOST_REQUIRE(decrypted.has_value());

    auto& [dec_body, dec_reply_pk] = *decrypted;

    // Reply pubkey should match
    BOOST_CHECK(dec_reply_pk == reply_pk);

    // Body should match (first `body.size()` bytes; rest is zero padding)
    BOOST_CHECK_EQUAL(dec_body.size(), payjoin::PADDED_PLAINTEXT_A);
    BOOST_CHECK(std::memcmp(dec_body.data(), body.data(), body.size()) == 0);

    // Padding bytes should be zero
    for (size_t i = body.size(); i < dec_body.size(); ++i) {
        BOOST_CHECK_EQUAL(dec_body[i], 0);
    }
}

BOOST_AUTO_TEST_CASE(message_b_roundtrip)
{
    dhkem_secp256k1::InitContext();

    // Generate receiver keypair
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    // Generate sender's reply keypair
    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    // Test body (simulated proposal PSBT)
    std::vector<uint8_t> body(1000);
    std::iota(body.begin(), body.end(), 42);

    // Encrypt (receiver -> sender)
    auto encrypted = payjoin::EncryptMessageB(body, receiver_sk, receiver_pk, reply_pk);
    BOOST_REQUIRE(encrypted.has_value());
    BOOST_CHECK_EQUAL(encrypted->size(), payjoin::PADDED_MESSAGE_BYTES);

    // Decrypt (sender side)
    auto decrypted = payjoin::DecryptMessageB(*encrypted, receiver_pk, reply_sk);
    BOOST_REQUIRE(decrypted.has_value());

    // Body should match (first `body.size()` bytes; rest is zero padding)
    BOOST_CHECK_EQUAL(decrypted->size(), payjoin::PADDED_PLAINTEXT_B);
    BOOST_CHECK(std::memcmp(decrypted->data(), body.data(), body.size()) == 0);

    for (size_t i = body.size(); i < decrypted->size(); ++i) {
        BOOST_CHECK_EQUAL((*decrypted)[i], 0);
    }
}

BOOST_AUTO_TEST_CASE(message_a_wrong_key_fails)
{
    dhkem_secp256k1::InitContext();

    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    std::vector<uint8_t> body{0x01, 0x02, 0x03};
    auto encrypted = payjoin::EncryptMessageA(body, reply_pk, receiver_pk);
    BOOST_REQUIRE(encrypted.has_value());

    // Try decrypting with a different key
    CKey wrong_sk;
    wrong_sk.MakeNewKey(/*fCompressed=*/true);
    auto decrypted = payjoin::DecryptMessageA(*encrypted, wrong_sk);
    BOOST_CHECK(!decrypted.has_value());
}

BOOST_AUTO_TEST_CASE(message_b_wrong_key_fails)
{
    dhkem_secp256k1::InitContext();

    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    std::vector<uint8_t> body{0xAA, 0xBB, 0xCC};
    auto encrypted = payjoin::EncryptMessageB(body, receiver_sk, receiver_pk, reply_pk);
    BOOST_REQUIRE(encrypted.has_value());

    // Wrong sender reply key
    CKey wrong_reply_sk;
    wrong_reply_sk.MakeNewKey(/*fCompressed=*/true);
    auto decrypted = payjoin::DecryptMessageB(*encrypted, receiver_pk, wrong_reply_sk);
    BOOST_CHECK(!decrypted.has_value());

    // Wrong receiver pubkey (auth mismatch)
    CKey other_receiver_sk;
    other_receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey other_receiver_pk = other_receiver_sk.GetPubKey();
    auto decrypted2 = payjoin::DecryptMessageB(*encrypted, other_receiver_pk, reply_sk);
    BOOST_CHECK(!decrypted2.has_value());
}

BOOST_AUTO_TEST_CASE(corrupted_ciphertext_fails)
{
    dhkem_secp256k1::InitContext();

    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    std::vector<uint8_t> body{0x01, 0x02, 0x03};

    // Corrupt Message A
    auto encrypted_a = payjoin::EncryptMessageA(body, reply_pk, receiver_pk);
    BOOST_REQUIRE(encrypted_a.has_value());
    (*encrypted_a)[payjoin::PADDED_MESSAGE_BYTES - 1] ^= 0xFF; // flip last byte
    auto decrypted_a = payjoin::DecryptMessageA(*encrypted_a, receiver_sk);
    BOOST_CHECK(!decrypted_a.has_value());

    // Corrupt Message B
    auto encrypted_b = payjoin::EncryptMessageB(body, receiver_sk, receiver_pk, reply_pk);
    BOOST_REQUIRE(encrypted_b.has_value());
    (*encrypted_b)[100] ^= 0xFF; // flip a byte in the ciphertext
    auto decrypted_b = payjoin::DecryptMessageB(*encrypted_b, receiver_pk, reply_sk);
    BOOST_CHECK(!decrypted_b.has_value());
}

BOOST_AUTO_TEST_CASE(output_size_exactly_7168)
{
    dhkem_secp256k1::InitContext();

    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    // Empty body
    std::vector<uint8_t> empty_body;
    auto enc_a = payjoin::EncryptMessageA(empty_body, reply_pk, receiver_pk);
    BOOST_REQUIRE(enc_a.has_value());
    BOOST_CHECK_EQUAL(enc_a->size(), 7168u);

    // Max-size body for Message A
    std::vector<uint8_t> max_body_a(payjoin::PADDED_PLAINTEXT_A, 0xAA);
    auto enc_a_max = payjoin::EncryptMessageA(max_body_a, reply_pk, receiver_pk);
    BOOST_REQUIRE(enc_a_max.has_value());
    BOOST_CHECK_EQUAL(enc_a_max->size(), 7168u);

    // Max-size body for Message B
    std::vector<uint8_t> max_body_b(payjoin::PADDED_PLAINTEXT_B, 0xBB);
    auto enc_b = payjoin::EncryptMessageB(max_body_b, receiver_sk, receiver_pk, reply_pk);
    BOOST_REQUIRE(enc_b.has_value());
    BOOST_CHECK_EQUAL(enc_b->size(), 7168u);
}

BOOST_AUTO_TEST_CASE(body_too_large_fails)
{
    dhkem_secp256k1::InitContext();

    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    // One byte over limit for Message A
    std::vector<uint8_t> too_large_a(payjoin::PADDED_PLAINTEXT_A + 1, 0xCC);
    auto enc_a = payjoin::EncryptMessageA(too_large_a, reply_pk, receiver_pk);
    BOOST_CHECK(!enc_a.has_value());

    // One byte over limit for Message B
    std::vector<uint8_t> too_large_b(payjoin::PADDED_PLAINTEXT_B + 1, 0xDD);
    auto enc_b = payjoin::EncryptMessageB(too_large_b, receiver_sk, receiver_pk, reply_pk);
    BOOST_CHECK(!enc_b.has_value());
}

BOOST_AUTO_TEST_CASE(message_a_with_various_body_sizes)
{
    dhkem_secp256k1::InitContext();

    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey receiver_pk = receiver_sk.GetPubKey();

    CKey reply_sk;
    reply_sk.MakeNewKey(/*fCompressed=*/true);
    CPubKey reply_pk = reply_sk.GetPubKey();

    // Test a range of body sizes
    for (size_t sz : {size_t{0}, size_t{1}, size_t{100}, size_t{1000}, size_t{5000}, payjoin::PADDED_PLAINTEXT_A}) {
        std::vector<uint8_t> body(sz, static_cast<uint8_t>(sz & 0xFF));
        auto encrypted = payjoin::EncryptMessageA(body, reply_pk, receiver_pk);
        BOOST_REQUIRE(encrypted.has_value());
        BOOST_CHECK_EQUAL(encrypted->size(), payjoin::PADDED_MESSAGE_BYTES);

        auto decrypted = payjoin::DecryptMessageA(*encrypted, receiver_sk);
        BOOST_REQUIRE(decrypted.has_value());
        BOOST_CHECK(decrypted->second == reply_pk);
        BOOST_CHECK(std::memcmp(decrypted->first.data(), body.data(), sz) == 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/session.h>

#include <key.h>
#include <ohttp/ohttp.h>
#include <pubkey.h>
#include <random.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstring>

BOOST_FIXTURE_TEST_SUITE(payjoin_session_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(session_serialize_roundtrip_sender)
{
    payjoin::PayjoinSession session;
    GetRandBytes(session.session_id);
    session.role = payjoin::SessionRole::Sender;
    session.sender_state = payjoin::SenderState::PostedOriginal;
    session.created_at = 1700000000;
    session.expires_at = 1700086400;
    session.directory_url = "https://payjo.in";
    session.sender_disable_output_substitution = true;

    // Generate keys
    session.reply_key.MakeNewKey(/*fCompressed=*/true);
    CKey receiver_sk;
    receiver_sk.MakeNewKey(/*fCompressed=*/true);
    session.receiver_pubkey = receiver_sk.GetPubKey();

    // OHTTP KeyConfig
    session.ohttp_keys.key_id = 1;
    session.ohttp_keys.kem_id = ohttp::KEM_SECP256K1;
    std::copy(session.receiver_pubkey.begin(), session.receiver_pubkey.end(),
              session.ohttp_keys.pkR.begin());
    session.ohttp_keys.syms.push_back({ohttp::KDF_HKDF_SHA256, ohttp::AEAD_CHACHA20POLY1305});

    // Serialize
    DataStream ds;
    session.Serialize(ds);

    // Deserialize
    payjoin::PayjoinSession loaded;
    loaded.Unserialize(ds);

    BOOST_CHECK(loaded.session_id == session.session_id);
    BOOST_CHECK(loaded.role == payjoin::SessionRole::Sender);
    BOOST_CHECK(loaded.sender_state == payjoin::SenderState::PostedOriginal);
    BOOST_CHECK_EQUAL(loaded.created_at, 1700000000);
    BOOST_CHECK_EQUAL(loaded.expires_at, 1700086400);
    BOOST_CHECK_EQUAL(loaded.directory_url, "https://payjo.in");
    BOOST_CHECK_EQUAL(loaded.sender_disable_output_substitution, true);
    BOOST_CHECK(loaded.reply_key.IsValid());
    BOOST_CHECK(loaded.reply_key.GetPubKey() == session.reply_key.GetPubKey());
    BOOST_CHECK(loaded.receiver_pubkey == session.receiver_pubkey);
}

BOOST_AUTO_TEST_CASE(session_serialize_roundtrip_receiver)
{
    payjoin::PayjoinSession session;
    GetRandBytes(session.session_id);
    session.role = payjoin::SessionRole::Receiver;
    session.receiver_state = payjoin::ReceiverState::Initialized;
    session.created_at = 1700000000;
    session.expires_at = 1700086400;
    session.original_query_params = "v=2&disableoutputsubstitution=true";

    session.receiver_key.MakeNewKey(/*fCompressed=*/true);
    session.payjoin_uri = "bitcoin:bcrt1q...?pj=HTTPS://PAYJO.IN/...";

    // OHTTP KeyConfig
    CPubKey pk = session.receiver_key.GetPubKey();
    session.ohttp_keys.key_id = 0;
    session.ohttp_keys.kem_id = ohttp::KEM_SECP256K1;
    std::copy(pk.begin(), pk.end(), session.ohttp_keys.pkR.begin());
    session.ohttp_keys.syms.push_back({ohttp::KDF_HKDF_SHA256, ohttp::AEAD_CHACHA20POLY1305});

    // Serialize
    DataStream ds;
    session.Serialize(ds);

    // Deserialize
    payjoin::PayjoinSession loaded;
    loaded.Unserialize(ds);

    BOOST_CHECK(loaded.role == payjoin::SessionRole::Receiver);
    BOOST_CHECK(loaded.receiver_state == payjoin::ReceiverState::Initialized);
    BOOST_CHECK(loaded.receiver_key.IsValid());
    BOOST_CHECK(loaded.receiver_key.GetPubKey() == session.receiver_key.GetPubKey());
    BOOST_CHECK_EQUAL(loaded.payjoin_uri, session.payjoin_uri);
    BOOST_CHECK_EQUAL(loaded.original_query_params, session.original_query_params);
}

BOOST_AUTO_TEST_CASE(session_terminal_states)
{
    payjoin::PayjoinSession session;
    session.role = payjoin::SessionRole::Sender;

    session.sender_state = payjoin::SenderState::Created;
    BOOST_CHECK(!session.IsTerminal());
    BOOST_CHECK(!session.IsPolling());

    session.sender_state = payjoin::SenderState::PostedOriginal;
    BOOST_CHECK(!session.IsTerminal());
    BOOST_CHECK(session.IsPolling());

    session.sender_state = payjoin::SenderState::Completed;
    BOOST_CHECK(session.IsTerminal());
    BOOST_CHECK(!session.IsPolling());

    session.sender_state = payjoin::SenderState::Failed;
    BOOST_CHECK(session.IsTerminal());

    session.sender_state = payjoin::SenderState::Expired;
    BOOST_CHECK(session.IsTerminal());
}

BOOST_AUTO_TEST_CASE(session_with_final_txid)
{
    payjoin::PayjoinSession session;
    GetRandBytes(session.session_id);
    session.role = payjoin::SessionRole::Sender;
    session.sender_state = payjoin::SenderState::Completed;

    uint256 txid;
    GetRandBytes(txid);
    session.final_txid = txid;

    session.ohttp_keys.key_id = 0;
    session.ohttp_keys.kem_id = ohttp::KEM_SECP256K1;
    session.ohttp_keys.syms.push_back({ohttp::KDF_HKDF_SHA256, ohttp::AEAD_CHACHA20POLY1305});

    DataStream ds;
    session.Serialize(ds);

    payjoin::PayjoinSession loaded;
    loaded.Unserialize(ds);

    BOOST_REQUIRE(loaded.final_txid.has_value());
    BOOST_CHECK(loaded.final_txid == txid);
}

BOOST_AUTO_TEST_SUITE_END()

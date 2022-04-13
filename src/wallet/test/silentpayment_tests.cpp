#include <test/util/setup_common.h>
#include <silentpayment.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(silentpayment_tests, BasicTestingSetup)

/* BOOST_AUTO_TEST_CASE(silent_addresses_new_approach_2)
{
    std::vector<std::tuple<CKey, bool>> sender_secret_keys;
    std::vector<CPubKey> sender_pub_keys;
    std::vector<XOnlyPubKey> sender_x_only_pub_keys;

    // non-taproot inputs
    for(size_t i =0; i < 38; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);
        CPubKey senderPubkey = senderkey.GetPubKey();

        sender_secret_keys.push_back({senderkey, false});
        sender_pub_keys.push_back(senderPubkey);
    }

    // taproot inputs
    for(size_t i =0; i < 49; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);

        sender_secret_keys.push_back({senderkey, true});
        sender_x_only_pub_keys.push_back(XOnlyPubKey{senderkey.GetPubKey()});
    }

    CKey recipient_key;
    recipient_key.MakeNewKey(true);
    CPubKey recipient_pubkey{recipient_key.GetPubKey()};

    CPubKey sum_tx_pubkeys{silentpayment::Recipient::SumPublicKeys(sender_pub_keys, sender_x_only_pub_keys)};
    auto silent_recipient = silentpayment::Recipient(recipient_key);
    silent_recipient.SetSenderPublicKey(sum_tx_pubkeys);

    silentpayment::Sender silent_sender{sender_secret_keys, recipient_pubkey};

    for (int32_t identifier = 0; identifier < 10; identifier++) {
        XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak2(identifier);
        const auto [recipient_priv_key, recipient_pub_key] = silent_recipient.Tweak2(identifier);

        BOOST_CHECK(XOnlyPubKey{recipient_priv_key.GetPubKey()} == recipient_pub_key);

        BOOST_CHECK(sender_tweaked_pubkey == recipient_pub_key);
    }
}

BOOST_AUTO_TEST_CASE(silent_addresses_2)
{
    std::vector<std::tuple<CKey, bool>> sender_secret_keys;
    std::vector<CPubKey> sender_pub_keys;
    std::vector<XOnlyPubKey> sender_x_only_pub_keys;

    // non-taproot inputs
    for(size_t i =0; i < 38; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);
        CPubKey senderPubkey = senderkey.GetPubKey();

        sender_secret_keys.push_back({senderkey, false});
        sender_pub_keys.push_back(senderPubkey);
    }

    // taproot inputs
    for(size_t i =0; i < 49; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);

        sender_secret_keys.push_back({senderkey, true});
        sender_x_only_pub_keys.push_back(XOnlyPubKey{senderkey.GetPubKey()});
    }

    CKey recipient_spend_seckey;
    recipient_spend_seckey.MakeNewKey(true);
    CPubKey recipient_spend_pubkey = recipient_spend_seckey.GetPubKey();

    unsigned char hash[32] = {};
    CSHA256().Write(recipient_spend_seckey.begin(), 32).Finalize(hash);

    CKey recipient_scan_key;
    recipient_scan_key.Set(std::begin(hash), std::end(hash), true);

    int32_t identifier = 0;

    auto silent_recipient = silentpayment::RecipientNS(recipient_spend_seckey);
    CPubKey sum_tx_pubkeys{silentpayment::Recipient::SumPublicKeys(sender_pub_keys, sender_x_only_pub_keys)};
    silent_recipient.SetSenderPublicKey(sum_tx_pubkeys);

    silentpayment::SenderNS silent_sender{
        sender_secret_keys,
        XOnlyPubKey(recipient_spend_pubkey),
        XOnlyPubKey(recipient_scan_key.GetPubKey())
    };

    for (int32_t identifier = 0; identifier < 100; identifier++) {
        XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak(identifier);
        const auto [recipient_priv_key, recipient_pub_key] = silent_recipient.Tweak(identifier);

        BOOST_CHECK(XOnlyPubKey{recipient_priv_key.GetPubKey()} == recipient_pub_key);
        BOOST_CHECK(sender_tweaked_pubkey == recipient_pub_key);
    }
}

BOOST_AUTO_TEST_CASE(silent_addresses_3)
{
    std::vector<std::tuple<CKey, bool>> sender_secret_keys;
    std::vector<CPubKey> sender_pub_keys;
    std::vector<XOnlyPubKey> sender_x_only_pub_keys;

    // non-taproot inputs
    for(size_t i =0; i < 38; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);
        CPubKey senderPubkey = senderkey.GetPubKey();

        sender_secret_keys.push_back({senderkey, false});
        sender_pub_keys.push_back(senderPubkey);
    }

    // taproot inputs
    for(size_t i =0; i < 49; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);

        sender_secret_keys.push_back({senderkey, true});
        sender_x_only_pub_keys.push_back(XOnlyPubKey{senderkey.GetPubKey()});
    }

    CKey recipient_spend_seckey;
    recipient_spend_seckey.MakeNewKey(true);
    XOnlyPubKey recipient_spend_pubkey = XOnlyPubKey{recipient_spend_seckey.GetPubKey()};

    XOnlyPubKey recipient_scan_pubkey = silentpayment::RecipientNS::GenerateScanPubkey(recipient_spend_seckey);

    silentpayment::SenderNS silent_sender{
        sender_secret_keys,
        recipient_spend_pubkey,
        recipient_scan_pubkey
    };

    auto silent_recipient = silentpayment::RecipientNS(recipient_spend_seckey);
    CPubKey sum_tx_pubkeys{silentpayment::Recipient::SumPublicKeys(sender_pub_keys, sender_x_only_pub_keys)};
    silent_recipient.SetSenderPublicKey(sum_tx_pubkeys);

    for (int32_t identifier = 0; identifier < 450; identifier++) {

        XOnlyPubKey tweaked_recipient_spend_pubkey = silentpayment::RecipientNS::TweakSpendPubkey(recipient_spend_pubkey, identifier);
        XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak(tweaked_recipient_spend_pubkey);

        const auto [recipient_priv_key, recipient_pub_key] = silent_recipient.Tweak2(identifier);

        BOOST_CHECK(XOnlyPubKey{recipient_priv_key.GetPubKey()} == recipient_pub_key);
        BOOST_CHECK(sender_tweaked_pubkey == recipient_pub_key);
    }
} */

BOOST_AUTO_TEST_CASE(silent_addresses_4)
{
    std::vector<std::tuple<CKey, bool>> sender_secret_keys;
    std::vector<CPubKey> sender_pub_keys;
    std::vector<XOnlyPubKey> sender_x_only_pub_keys;

    // non-taproot inputs
    for(size_t i =0; i < 2; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);
        CPubKey senderPubkey = senderkey.GetPubKey();

        sender_secret_keys.push_back({senderkey, false});
        sender_pub_keys.push_back(senderPubkey);
    }

    // taproot inputs
    for(size_t i =0; i < 2; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);

        sender_secret_keys.push_back({senderkey, true});
        sender_x_only_pub_keys.push_back(XOnlyPubKey{senderkey.GetPubKey()});
    }

    CKey recipient_spend_seckey;
    recipient_spend_seckey.MakeNewKey(true);
    // XOnlyPubKey recipient_spend_pubkey = XOnlyPubKey{recipient_spend_seckey.GetPubKey()};

    // TODO: REMOVE
    // XOnlyPubKey recipient_scan_pubkey = silentpayment::Recipient::GenerateScanPubkey(recipient_spend_seckey);


    auto silent_recipient = silentpayment::Recipient(recipient_spend_seckey, 440);

    CPubKey combined_tx_pubkeys{silentpayment::Recipient::CombinePublicKeys(sender_pub_keys, sender_x_only_pub_keys)};

    silent_recipient.SetSenderPublicKey(combined_tx_pubkeys);

    for (int32_t identifier = 0; identifier < 434; identifier++) {
        // TODO: REMOVE
        // XOnlyPubKey tweaked_recipient_spend_pubkey = silentpayment::Recipient::TweakSpendPubkey(recipient_spend_pubkey, identifier);

        const auto&[recipient_scan_pubkey, recipient_spend_pubkey]{silent_recipient.GetAddress(identifier)};

        silentpayment::Sender silent_sender{
            sender_secret_keys,
            recipient_scan_pubkey
        };

        XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak(recipient_spend_pubkey);
        const auto [recipient_priv_key, recipient_pub_key] = silent_recipient.Tweak(identifier);

        BOOST_CHECK(XOnlyPubKey{recipient_priv_key.GetPubKey()} == recipient_pub_key);
        BOOST_CHECK(sender_tweaked_pubkey == recipient_pub_key);
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

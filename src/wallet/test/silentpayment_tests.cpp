#include <test/util/setup_common.h>
#include <silentpayment.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(silentpayment_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(silent_addresses)
{
    std::vector<std::tuple<CKey, bool>> sender_secret_keys;
    std::vector<CPubKey> sender_pub_keys;
    std::vector<XOnlyPubKey> sender_x_only_pub_keys;

    // non-taproot inputs
    for(size_t i =0; i < 2; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);
        CPubKey senderPubkey = senderkey.GetPubKey();

        sender_secret_keys.emplace_back(senderkey, false);
        sender_pub_keys.emplace_back(senderPubkey);
    }

    // taproot inputs
    for(size_t i =0; i < 2; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);

        sender_secret_keys.emplace_back(senderkey, true);
        sender_x_only_pub_keys.emplace_back(senderkey.GetPubKey());
    }

    CKey recipient_spend_seckey;
    recipient_spend_seckey.MakeNewKey(true);

    auto silent_recipient = silentpayment::Recipient(recipient_spend_seckey, 440);

    CPubKey combined_tx_pubkeys{silentpayment::Recipient::CombinePublicKeys(sender_pub_keys, sender_x_only_pub_keys)};

    silent_recipient.SetSenderPublicKey(combined_tx_pubkeys);

    for (int32_t identifier = 0; identifier < 434; identifier++) {
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

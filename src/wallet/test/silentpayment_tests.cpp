#include <test/util/setup_common.h>
#include <silentpayment.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(silentpayment_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(silent_addresses_new_approach_2)
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

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

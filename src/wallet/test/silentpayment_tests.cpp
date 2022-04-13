#include <test/util/setup_common.h>
#include <silentpayment.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(silentpayment_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(silent_addresses_multiple)
{
    std::srand(std::time(nullptr));

    for (size_t num_inputs_keys : {1, 3, 25, 150, 300})
    {
        std::vector<CKey> sender_secret_keys;
        std::vector<XOnlyPubKey> sender_x_only_pub_keys;

        for(size_t i =0; i < num_inputs_keys; i++) {
            CKey senderkey;
            senderkey.MakeNewKey(true);
            CPubKey senderPubkey = senderkey.GetPubKey();
            XOnlyPubKey senderXonlyPubkey = XOnlyPubKey(senderPubkey);
            BOOST_CHECK(senderXonlyPubkey.IsFullyValid());

            sender_secret_keys.push_back(senderkey);
            sender_x_only_pub_keys.push_back(senderXonlyPubkey);
        }

        CKey recipient_key;
        recipient_key.MakeNewKey(true);
        XOnlyPubKey recipient_pubkey = XOnlyPubKey(recipient_key.GetPubKey());

        CPubKey sum_tx_pubkeys{silentpayment::Recipient::SumXOnlyPublicKeys(sender_x_only_pub_keys)};
        auto silent_recipient = silentpayment::Recipient(recipient_key);
        silent_recipient.SetSenderPublicKey(sum_tx_pubkeys);

        silentpayment::Sender silent_sender{sender_secret_keys, recipient_pubkey};

        for (int32_t identifier = 0; identifier < 10; identifier++) {

            XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak(identifier);
            const auto [recipient_priv_key, recipient_pub_key] = silent_recipient.Tweak(identifier);

            (void) recipient_priv_key;

            BOOST_CHECK(sender_tweaked_pubkey == recipient_pub_key);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

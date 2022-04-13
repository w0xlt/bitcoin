#include <test/util/setup_common.h>
#include <silentpayment.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(silentpayment_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(silent_addresses)
{
    CKey senderkey;
    senderkey.MakeNewKey(true);
    XOnlyPubKey senderPubkey = XOnlyPubKey(senderkey.GetPubKey());
    BOOST_CHECK(senderPubkey.IsFullyValid());

    CKey recipientkey;
    recipientkey.MakeNewKey(true);
    XOnlyPubKey recipientPubkey = XOnlyPubKey(recipientkey.GetPubKey());

    silentpayment::Sender silent_sender{senderkey, recipientPubkey};
    silentpayment::Recipient silent_recipient{recipientkey, senderPubkey};

    for (int32_t identifier = 0; identifier < 10; identifier++) {

        XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak(identifier);
        const CKey recipient_private_key = silent_recipient.Tweak(identifier);

        BOOST_CHECK(sender_tweaked_pubkey == XOnlyPubKey(recipient_private_key.GetPubKey()));
    }
}

BOOST_AUTO_TEST_CASE(silent_addresses_multiple)
{
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

        CKey sender_secret_key = silentpayment::Sender::SumPrivateKeys(sender_secret_keys);
        XOnlyPubKey sender_x_only_pub_key = silentpayment::Recipient::SumXOnlyPublicKeys(sender_x_only_pub_keys);

        silentpayment::Sender silent_sender{sender_secret_key, recipient_pubkey};
        silentpayment::Recipient silent_recipient{recipient_key, sender_x_only_pub_key};

        for (int32_t identifier = 0; identifier < 10; identifier++) {

            XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak(identifier);
            const CKey recipient_private_key = silent_recipient.Tweak(identifier);

            BOOST_CHECK(sender_tweaked_pubkey == XOnlyPubKey(recipient_private_key.GetPubKey()));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

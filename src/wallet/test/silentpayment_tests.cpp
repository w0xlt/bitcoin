#include <test/util/setup_common.h>
#include <wallet/silentpayment.h>

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

    silentpayment::Sender silent_sender{silentpayment::Sender(senderkey, recipientPubkey)};
    silentpayment::Recipient silent_recipient{silentpayment::Recipient(recipientkey, senderPubkey)};

    for (int32_t identifier = 0; identifier < 10; identifier++) {

        XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak(identifier);
        const CKey recipient_private_key = silent_recipient.Tweak(identifier);

        BOOST_CHECK(sender_tweaked_pubkey == XOnlyPubKey(recipient_private_key.GetPubKey()));
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

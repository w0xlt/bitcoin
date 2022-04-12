#include <test/util/setup_common.h>
#include <wallet/silentpayment.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(silentpayment_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(silent_addresses)
{
    // test CreateSilentAddress

    CKey senderkey;
    senderkey.MakeNewKey(true);
    XOnlyPubKey senderPubkey = XOnlyPubKey(senderkey.GetPubKey());
    BOOST_CHECK(senderPubkey.IsFullyValid());

    CKey recipientkey;
    recipientkey.MakeNewKey(true);
    XOnlyPubKey recipientPubkey = XOnlyPubKey(recipientkey.GetPubKey());
    BOOST_CHECK(recipientPubkey.IsFullyValid());

    XOnlyPubKey senderTweakedPubKey = silentpayment::Sender::CreateSilentAddress(senderkey,recipientPubkey);

    CKey ckey = silentpayment::Recipient::CreateSilentAddress(recipientkey, senderPubkey);

    BOOST_CHECK(senderTweakedPubKey == XOnlyPubKey(ckey.GetPubKey()));

}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
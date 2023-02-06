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

BOOST_AUTO_TEST_CASE(silent_addresses2)
{
    auto txid1 = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
    uint32_t vout1 = 4;

    auto txid2 = uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    uint32_t vout2 = 7;

    std::vector<COutPoint> tx_outpoints;
    tx_outpoints.emplace_back(txid1, vout1);
    tx_outpoints.emplace_back(txid2, vout2);

    // ---

    std::vector<std::tuple<CKey, bool>> sender_secret_keys;
    std::vector<CPubKey> sender_pub_keys;
    std::vector<XOnlyPubKey> sender_x_only_pub_keys;

    // non-taproot inputs
    for(size_t i =0; i < 34; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);
        CPubKey senderPubkey = senderkey.GetPubKey();

        sender_secret_keys.emplace_back(senderkey, false);
        sender_pub_keys.emplace_back(senderPubkey);
    }

    // taproot inputs
    for(size_t i =0; i < 45; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);

        sender_secret_keys.emplace_back(senderkey, true);
        sender_x_only_pub_keys.emplace_back(senderkey.GetPubKey());
    }

    CKey recipient_spend_seckey;
    recipient_spend_seckey.MakeNewKey(true);

    auto silent_recipient = silentpayment::Recipient2(recipient_spend_seckey, 440);

    CPubKey combined_tx_pubkeys{silentpayment::Recipient::CombinePublicKeys(sender_pub_keys, sender_x_only_pub_keys)};

    silent_recipient.SetSenderPublicKey(combined_tx_pubkeys, tx_outpoints);

    for (int32_t identifier = 0; identifier < 234; identifier++) {
        const auto&[recipient_scan_pubkey, recipient_spend_pubkey]{silent_recipient.GetAddress(identifier)};

        silentpayment::Sender2 silent_sender{
            sender_secret_keys,
            tx_outpoints,
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

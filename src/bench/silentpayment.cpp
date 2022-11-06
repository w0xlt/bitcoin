// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <random.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <silentpayment.h>
#include <test/util/setup_common.h>

static void SumXOnlyPublicKeys(benchmark::Bench& bench, size_t key_count)
{
    ECC_Start();

    std::vector<CPubKey> sender_pub_keys;
    std::vector<XOnlyPubKey> sender_x_only_pub_keys;

    // non-taproot inputs
    for(size_t i =0; i < key_count; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);
        CPubKey senderPubkey = senderkey.GetPubKey();
        sender_pub_keys.push_back(senderPubkey);
    }

    // taproot inputs
    for(size_t i =0; i < key_count; i++) {
        CKey senderkey;
        senderkey.MakeNewKey(true);
        sender_x_only_pub_keys.push_back(XOnlyPubKey{senderkey.GetPubKey()});
    }

    bench.run([&] {
        CPubKey sum_tx_pubkeys{silentpayment::Recipient::SumPublicKeys(sender_pub_keys, sender_x_only_pub_keys)};
    });

    ECC_Stop();
}

static void ECDHPerformance(benchmark::Bench& bench, int32_t pool_size)
{
    ECC_Start();

    std::vector<std::tuple<CKey, bool>> sender_secret_keys;

    CKey senderkey1;
    senderkey1.MakeNewKey(true);
    CPubKey senderPubkey1 = senderkey1.GetPubKey();
    sender_secret_keys.push_back({senderkey1, false});

    CKey senderkey2;
    senderkey2.MakeNewKey(true);
    XOnlyPubKey senderPubkey2 = XOnlyPubKey(senderkey2.GetPubKey());
    sender_secret_keys.push_back({senderkey2, true});

    CKey recipient_spend_seckey;
    recipient_spend_seckey.MakeNewKey(true);
    XOnlyPubKey recipient_spend_pubkey = XOnlyPubKey{recipient_spend_seckey.GetPubKey()};

    XOnlyPubKey recipient_scan_pubkey = silentpayment::RecipientNS2::GenerateScanPubkey(recipient_spend_seckey);

    silentpayment::SenderNS2 silent_sender{
        sender_secret_keys,
        recipient_spend_pubkey,
        recipient_scan_pubkey
    };

    auto silent_recipient = silentpayment::RecipientNS2(recipient_spend_seckey, pool_size);
    CPubKey sum_tx_pubkeys{silentpayment::Recipient::SumPublicKeys({senderPubkey1}, {senderPubkey2})};

    bench.run([&] {
        silent_recipient.SetSenderPublicKey(sum_tx_pubkeys);

        for (int32_t identifier = 0; identifier < pool_size; identifier++) {
            XOnlyPubKey tweaked_recipient_spend_pubkey = silentpayment::RecipientNS2::TweakSpendPubkey(recipient_spend_pubkey, identifier);

            XOnlyPubKey sender_tweaked_pubkey = silent_sender.Tweak(tweaked_recipient_spend_pubkey);
            const auto [recipient_priv_key, recipient_pub_key] = silent_recipient.Tweak(identifier);

            assert(sender_tweaked_pubkey == recipient_pub_key);
        }
    });

    ECC_Stop();
}

static void SumXOnlyPublicKeys_1(benchmark::Bench& bench)
{
    SumXOnlyPublicKeys(bench, 1);
}
static void SumXOnlyPublicKeys_10(benchmark::Bench& bench)
{
    SumXOnlyPublicKeys(bench, 10);
}
static void SumXOnlyPublicKeys_100(benchmark::Bench& bench)
{
    SumXOnlyPublicKeys(bench, 100);
}
static void SumXOnlyPublicKeys_1000(benchmark::Bench& bench)
{
    SumXOnlyPublicKeys(bench, 1000);
}

static void ECDHPerformance_100(benchmark::Bench& bench)
{
    ECDHPerformance(bench, 100);
}

BENCHMARK(SumXOnlyPublicKeys_1, benchmark::PriorityLevel::HIGH);
BENCHMARK(SumXOnlyPublicKeys_10, benchmark::PriorityLevel::HIGH);
BENCHMARK(SumXOnlyPublicKeys_100, benchmark::PriorityLevel::HIGH);
BENCHMARK(SumXOnlyPublicKeys_1000, benchmark::PriorityLevel::HIGH);
BENCHMARK(ECDHPerformance_100, benchmark::PriorityLevel::HIGH);
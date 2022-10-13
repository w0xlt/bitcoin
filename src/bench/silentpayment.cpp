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

static XOnlyPubKey gen_key(secp256k1_context* ctx) {
    unsigned char seckey[32];
    GetRandBytes(seckey);

    secp256k1_pubkey pubkey;
    int return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    assert(return_val);

    secp256k1_xonly_pubkey xonly_pubkey;
    return_val = secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey, nullptr, &pubkey);
    assert(return_val);

    unsigned char xonly_pubkey_bytes[32];
    return_val = secp256k1_xonly_pubkey_serialize(ctx, xonly_pubkey_bytes, &xonly_pubkey);
    assert(return_val);

    return XOnlyPubKey(xonly_pubkey_bytes);
}

static void SumXOnlyPublicKeys(benchmark::Bench& bench, int key_count)
{
    auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    std::vector<XOnlyPubKey> sender_x_only_public_keys;
    for (int i = 0; i < key_count; i++) {
        sender_x_only_public_keys.push_back(gen_key(ctx));
    }

    bench.run([&] {
        silentpayment::Recipient::SumXOnlyPublicKeys(sender_x_only_public_keys);
    });

    secp256k1_context_destroy(ctx);
}

/** Test ECDH performance **/
static void ECDHPerformance(benchmark::Bench& bench, size_t sender_key_count, size_t op_count)
{
    auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    std::vector<XOnlyPubKey> sender_x_only_public_keys;
    for (size_t i = 0; i < sender_key_count; i++) {
        sender_x_only_public_keys.push_back(gen_key(ctx));
    }

    unsigned char seckey1[32];
    GetRandBytes(seckey1);

    secp256k1_pubkey pubkey1;
    int return_val = secp256k1_ec_pubkey_create(ctx, &pubkey1, seckey1);
    assert(return_val);

    unsigned char seckey2[32];
    GetRandBytes(seckey2);

    secp256k1_pubkey pubkey2;
    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey2, seckey2);
    assert(return_val);

    bench.run([&] {
        for(size_t i = 0; i < op_count; i++) {
            // Silent payment recipients perform an ECDH for each transaction received
            unsigned char shared_secret[32];
            return_val = secp256k1_ecdh(ctx, shared_secret, &pubkey2, seckey1, nullptr, nullptr);
            assert(return_val);
        }
    });

    secp256k1_context_destroy(ctx);
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

static void ECDHPerformance_10_100(benchmark::Bench& bench)
{
    ECDHPerformance(bench, 10, 100);
}

BENCHMARK(SumXOnlyPublicKeys_1);
BENCHMARK(SumXOnlyPublicKeys_10);
BENCHMARK(SumXOnlyPublicKeys_100);
BENCHMARK(SumXOnlyPublicKeys_1000);
BENCHMARK(ECDHPerformance_10_100);
#include <wallet/silentpayment.h>

#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>

namespace silentpayment {

secp256k1_pubkey Sender::CreateTweakedPubkey(
    const secp256k1_context* ctx,
    const secp256k1_xonly_pubkey recipient_public_key,
    const unsigned char sender_secret_key[32])
{
    unsigned char shared_secret[32];

    secp256k1_pubkey output_pubkey;

    int return_val;

    return_val = secp256k1_ecdh_xonly(ctx, shared_secret, &recipient_public_key, sender_secret_key, nullptr, nullptr);
    assert(return_val);

    return_val = secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, shared_secret);
    assert(return_val);

    return_val = secp256k1_xonly_pubkey_tweak_add(ctx, &output_pubkey, &recipient_public_key, shared_secret);
    assert(return_val);

    return output_pubkey;
}

XOnlyPubKey Sender::CreateSilentPaymentAddress(
    const CKey& sender_secret_key,
    const XOnlyPubKey& _recipient_public_key)
{
    int return_val;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_xonly_pubkey recipient_public_key;
    return_val = secp256k1_xonly_pubkey_parse(ctx, &recipient_public_key, _recipient_public_key.data());
    assert(return_val);

    secp256k1_pubkey sender_output_pubkey;
    sender_output_pubkey = CreateTweakedPubkey(ctx, recipient_public_key, sender_secret_key.begin());

    // Test the key
    size_t len;
    unsigned char sender_serialized_output_pubkey[33];
    len = sizeof(sender_serialized_output_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, sender_serialized_output_pubkey, &len, &sender_output_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    CPubKey pubKey = CPubKey(sender_serialized_output_pubkey);

    assert(pubKey.IsFullyValid());

    XOnlyPubKey xOnlyPubKey = XOnlyPubKey(pubKey);

    secp256k1_context_destroy(ctx);

    return xOnlyPubKey;
}

void Recipient::CreateTweakedKeyPair(
    const secp256k1_context* ctx,
    const secp256k1_xonly_pubkey sender_public_key,
    secp256k1_keypair& recipient_keypair)
{
    unsigned char recipient_secret_key[32];
    unsigned char shared_secret[32];

    int return_val;

    return_val = secp256k1_keypair_sec(ctx, recipient_secret_key, &recipient_keypair);
    assert(return_val);

    return_val = secp256k1_ecdh_xonly(ctx, shared_secret, &sender_public_key, recipient_secret_key, nullptr, nullptr);
    assert(return_val);

    return_val = secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, shared_secret);
    assert(return_val);

    return_val = secp256k1_keypair_xonly_tweak_add(ctx, &recipient_keypair, shared_secret);
    assert(return_val);
}

CKey Recipient::CreateSilentPaymentAddress(const CKey& recipient_secret_key, const XOnlyPubKey& _sender_public_key)
{
    int return_val;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair recipient_keypair;
    return_val = secp256k1_keypair_create(ctx, &recipient_keypair, recipient_secret_key.begin());
    assert(return_val);

    secp256k1_xonly_pubkey sender_public_key;
    return_val = secp256k1_xonly_pubkey_parse(ctx, &sender_public_key, _sender_public_key.data());
    assert(return_val);

    // secp256k1_pubkey tweaked_pubkey;
    CreateTweakedKeyPair(ctx, sender_public_key, recipient_keypair);

    unsigned char result_secret_key[32];
    return_val = secp256k1_keypair_sec(ctx, result_secret_key, &recipient_keypair);

    CKey ckey;
    ckey.Set(std::begin(result_secret_key), std::end(result_secret_key), true);

    secp256k1_context_destroy(ctx);

    return ckey;
}

} // namespace silentpayment

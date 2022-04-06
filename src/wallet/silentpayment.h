#ifndef BITCOIN_SILENT_PAYMENT_H
#define BITCOIN_SILENT_PAYMENT_H

#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <base58.h>

namespace silentpaymet {

secp256k1_pubkey sender_tweak_payment_address(
    const secp256k1_context* ctx,
    const secp256k1_xonly_pubkey recipient_public_key,
    const unsigned char sender_secret_key[32]) {

    unsigned char shared_secret[32];

    secp256k1_pubkey output_pubkey;

    int return_val;

    return_val = secp256k1_ecdh_xonly(ctx, shared_secret, &recipient_public_key, sender_secret_key, NULL, NULL);
    assert(return_val);

    return_val = secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, shared_secret);
    assert(return_val);

    return_val =secp256k1_xonly_pubkey_tweak_add(ctx, &output_pubkey, &recipient_public_key, shared_secret);
    assert(return_val);

    return output_pubkey;
}

XOnlyPubKey GenerateSilentAddress(const CKey& sender_secret_key, const XOnlyPubKey& _recipient_public_key) {

    int return_val;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_xonly_pubkey recipient_public_key;
    return_val = secp256k1_xonly_pubkey_parse(ctx, &recipient_public_key, _recipient_public_key.data());
    assert(return_val);

    secp256k1_pubkey sender_output_pubkey;
    sender_output_pubkey =  sender_tweak_payment_address(ctx, recipient_public_key, sender_secret_key.data());

    // Test the key
    size_t len;
    unsigned char sender_serialized_output_pubkey[33];
    len = sizeof(sender_serialized_output_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, sender_serialized_output_pubkey, &len, &sender_output_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    CPubKey pubKey = CPubKey(sender_serialized_output_pubkey);

    assert(pubKey.IsFullyValid());

    XOnlyPubKey xOnlyPubKey = XOnlyPubKey(pubKey);

    return xOnlyPubKey;

}


} // namespace silentpaymet

#endif // BITCOIN_SILENT_PAYMENT_H

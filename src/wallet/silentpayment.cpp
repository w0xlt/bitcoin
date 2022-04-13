#include <wallet/silentpayment.h>

#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <arith_uint256.h>

namespace silentpayment {

Sender::Sender(const CKey sender_secret_key, const XOnlyPubKey recipient_x_only_public_key)
{
    m_context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // Parse the recipient's XOnlyPubKey to secp256k1_xonly_pubkey
    int return_val = secp256k1_xonly_pubkey_parse(m_context, &m_recipient_x_only_public_key, recipient_x_only_public_key.data());
    assert(return_val);

    // Create the shared secret using the recipient's x-only pubkey and the sender' secret key
    return_val = secp256k1_ecdh_xonly(m_context, m_shared_secret, &m_recipient_x_only_public_key, sender_secret_key.begin(), nullptr, nullptr);
    assert(return_val);
}

Sender::~Sender()
{
    secp256k1_context_destroy(m_context);
    memset(m_shared_secret, 0, sizeof(m_shared_secret));
    memset(m_recipient_x_only_public_key.data, 0, sizeof(m_recipient_x_only_public_key.data));
}

XOnlyPubKey Sender::Tweak(const int32_t& identifier)
{
    // Add the identifier to the shared_secret
    arith_uint256 tweak{*m_shared_secret};
    tweak = tweak + identifier;

    // Tweak the recipient's x-only pubkey with identifier + shared_secret
    secp256k1_pubkey output_pubkey;

    int return_val = secp256k1_xonly_pubkey_tweak_add(m_context, &output_pubkey, &m_recipient_x_only_public_key, ArithToUint256(tweak).data());
    assert(return_val);

    // Serialize and test the tweaked public key
    size_t len;
    unsigned char sender_serialized_output_pubkey[33];
    len = sizeof(sender_serialized_output_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(m_context, sender_serialized_output_pubkey, &len, &output_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    CPubKey pubKey = CPubKey(sender_serialized_output_pubkey);

    assert(pubKey.IsFullyValid());

    return XOnlyPubKey(pubKey);
}

Recipient::Recipient(const CKey& recipient_secret_key, const XOnlyPubKey& sender_x_only_public_key)
{
    m_context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    int return_val = secp256k1_keypair_create(m_context, &m_recipient_keypair, recipient_secret_key.begin());
    assert(return_val);

    secp256k1_xonly_pubkey parsed_sender_x_only_public_key;
    return_val = secp256k1_xonly_pubkey_parse(m_context, &parsed_sender_x_only_public_key, sender_x_only_public_key.data());
    assert(return_val);

    return_val = secp256k1_ecdh_xonly(m_context, m_shared_secret, &parsed_sender_x_only_public_key, recipient_secret_key.begin(), nullptr, nullptr);
    assert(return_val);

    return_val = secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, m_shared_secret);
    assert(return_val);
}

Recipient::~Recipient()
{
    secp256k1_context_destroy(m_context);
    memset(m_shared_secret, 0, sizeof(m_shared_secret));
    memset(m_recipient_keypair.data, 0, sizeof(m_recipient_keypair.data));
}

CKey Recipient::Tweak(const int32_t& identifier)
{
    secp256k1_keypair recipient_keypair;
    memcpy(recipient_keypair.data, m_recipient_keypair.data, 96);
    assert(memcmp(recipient_keypair.data, m_recipient_keypair.data, 96) == 0);

    arith_uint256 tweak{*m_shared_secret};
    tweak = tweak + identifier;

    int return_val = secp256k1_keypair_xonly_tweak_add(m_context, &recipient_keypair, ArithToUint256(tweak).data());
    assert(return_val);

    unsigned char result_secret_key[32];
    return_val = secp256k1_keypair_sec(m_context, result_secret_key, &recipient_keypair);

    CKey ckey;
    ckey.Set(std::begin(result_secret_key), std::end(result_secret_key), true);

    return ckey;
}

} // namespace silentpayment

#include <silentpayment.h>

#include <coins.h>
#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <arith_uint256.h>

namespace silentpayment {

Sender::Sender(const CKey& sender_secret_key, const XOnlyPubKey& recipient_x_only_public_key)
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

XOnlyPubKey Sender::Tweak(const int32_t& identifier) const
{
    unsigned char shared_secret[32];
    memcpy(shared_secret, m_shared_secret, 32);
    assert(memcmp(shared_secret, m_shared_secret, 32) == 0);

    // Add the identifier to the shared_secret
    arith_uint256 tweak;
    tweak = tweak + identifier;

    int return_val = secp256k1_ec_seckey_tweak_add(m_context, shared_secret, ArithToUint256(tweak).data());
    assert(return_val);

    // Tweak the recipient's x-only pubkey with identifier + shared_secret
    secp256k1_pubkey output_pubkey;

    return_val = secp256k1_xonly_pubkey_tweak_add(m_context, &output_pubkey, &m_recipient_x_only_public_key, shared_secret);
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

CKey Sender::SumPrivateKeys(const std::vector<CKey>& sender_secret_keys)
{
    auto context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    assert(!sender_secret_keys.empty());

    const auto& first_seckey{sender_secret_keys.at(0)};

    unsigned char seckey[32];
    memcpy(seckey, first_seckey.data(), 32);
    assert(memcmp(seckey, first_seckey.data(), 32) == 0);

    if (first_seckey.GetPubKey()[0] == 3) {
        int return_val = secp256k1_ec_seckey_negate(context, seckey);
        assert(return_val);
    }

    if (sender_secret_keys.size() > 1) {
        for (size_t i = 1; i < sender_secret_keys.size(); i++) {

            const auto& sender_seckey{sender_secret_keys.at(i)};

            unsigned char seckey_i[32];
            memcpy(seckey_i, sender_seckey.begin(), 32);
            assert(memcmp(seckey_i, sender_seckey.begin(), 32) == 0);

            if (sender_seckey.GetPubKey()[0] == 3) {
                int return_val = secp256k1_ec_seckey_negate(context, seckey_i);
                assert(return_val);
            }

            int return_val = secp256k1_ec_seckey_tweak_add(context, seckey, seckey_i);
            assert(return_val);
        }
    }



    CKey ckey;
    ckey.Set(std::begin(seckey), std::end(seckey), true);

    secp256k1_context_destroy(context);
    memset(seckey, 0, sizeof(seckey));

    return ckey;
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

CKey Recipient::Tweak(const int32_t& identifier) const
{
    secp256k1_keypair recipient_keypair;
    memcpy(recipient_keypair.data, m_recipient_keypair.data, 96);
    assert(memcmp(recipient_keypair.data, m_recipient_keypair.data, 96) == 0);

    // arith_uint256 tweak{*m_shared_secret};
    // tweak = tweak + identifier;

    unsigned char shared_secret[32];
    memcpy(shared_secret, m_shared_secret, 32);
    assert(memcmp(shared_secret, m_shared_secret, 32) == 0);

    arith_uint256 tweak;
    tweak = tweak + identifier;

    int return_val = secp256k1_ec_seckey_tweak_add(m_context, shared_secret, ArithToUint256(tweak).data());
    assert(return_val);

    return_val = secp256k1_keypair_xonly_tweak_add(m_context, &recipient_keypair, shared_secret);
    assert(return_val);

    unsigned char result_secret_key[32];
    return_val = secp256k1_keypair_sec(m_context, result_secret_key, &recipient_keypair);

    CKey ckey;
    ckey.Set(std::begin(result_secret_key), std::end(result_secret_key), true);

    return ckey;
}

XOnlyPubKey Recipient::SumXOnlyPublicKeys(const std::vector<XOnlyPubKey>& sender_x_only_public_keys)
{
    auto context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    std::vector<secp256k1_pubkey> v_pubkeys;

    for (auto& x_only_pubkey : sender_x_only_public_keys) {
        secp256k1_xonly_pubkey parsed_sender_x_only_public_key;
        int return_val = secp256k1_xonly_pubkey_parse(context, &parsed_sender_x_only_public_key, x_only_pubkey.data());
        assert(return_val);

        secp256k1_pubkey pubkey;
        return_val = secp256k1_xonly_pubkey_to_pubkey(context, &pubkey,  &parsed_sender_x_only_public_key);
        assert(return_val);
        return_val = secp256k1_ec_pubkey_negate(context, &pubkey);
        assert(return_val);
        v_pubkeys.push_back(pubkey);
    }

    std::vector<secp256k1_pubkey *> p_pubkeys;
    for (size_t i = 0; i < v_pubkeys.size(); i++) {
        p_pubkeys.push_back(&v_pubkeys.at(i));
    }

    // Sum all pubkeys
    secp256k1_pubkey sum_pubkey;
    int return_val = secp256k1_ec_pubkey_combine(context, &sum_pubkey, p_pubkeys.data(), sender_x_only_public_keys.size());
    assert(return_val);

    size_t len;
    unsigned char sum_serialized_pubkey[33];
    len = sizeof(sum_serialized_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(context, sum_serialized_pubkey, &len, &sum_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    CPubKey pubKey = CPubKey(sum_serialized_pubkey);

    assert(pubKey.IsFullyValid());

    secp256k1_context_destroy(context);

    return XOnlyPubKey(pubKey);
}

bool ExtractPubkeyFromInput(const Coin& prevCoin, const CTxIn& txin,  XOnlyPubKey& senderPubKey)
{
    // scriptPubKey being spent by this input
    CScript scriptPubKey = prevCoin.out.scriptPubKey;

    if (scriptPubKey.IsPayToWitnessScriptHash()) {
        return false;
    }

    // Vector of parsed pubkeys and hashes
    std::vector<std::vector<unsigned char>> solutions;

    TxoutType whichType = Solver(scriptPubKey, solutions);

    if (whichType == TxoutType::NONSTANDARD ||
    whichType == TxoutType::MULTISIG ||
    whichType == TxoutType::WITNESS_UNKNOWN ) {
        return false;
    }

    const CScript scriptSig = txin.scriptSig;
    const CScriptWitness scriptWitness = txin.scriptWitness;

    assert(senderPubKey.IsNull());

    // TODO: Condition not tested
    if (whichType == TxoutType::PUBKEY) {

        CPubKey pubkey = CPubKey(solutions[0]);
        assert(pubkey.IsFullyValid());
        senderPubKey = XOnlyPubKey(pubkey);
    }

    else if (whichType == TxoutType::PUBKEYHASH) {

        int sigSize = static_cast<int>(scriptSig[0]);
        int pubKeySize = static_cast<int>(scriptSig[sigSize + 1]);
        auto serializedPubKey = std::vector<unsigned char>(scriptSig.begin() + sigSize + 2, scriptSig.end());
        assert(serializedPubKey.size() == (size_t) pubKeySize);

        CPubKey pubkey = CPubKey(serializedPubKey);
        assert(pubkey.IsFullyValid());

        senderPubKey = XOnlyPubKey(pubkey);

    }

    else if (whichType == TxoutType::WITNESS_V0_KEYHASH || scriptPubKey.IsPayToScriptHash()) {
        if (scriptWitness.stack.size() != 2) return false;
        assert(scriptWitness.stack.at(1).size() == 33);

        CPubKey pubkey = CPubKey(scriptWitness.stack.at(1));
        assert(pubkey.IsFullyValid());

        senderPubKey = XOnlyPubKey(pubkey);
    }

    else if (whichType == TxoutType::WITNESS_V1_TAPROOT) {

        senderPubKey = XOnlyPubKey(solutions[0]);
        assert(senderPubKey.IsFullyValid());
    }

    CTxDestination address;
    ExtractDestination(scriptPubKey, address);

    return true;
}

} // namespace silentpayment

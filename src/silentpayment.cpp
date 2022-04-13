#include <silentpayment.h>

#include <coins.h>
#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <arith_uint256.h>

namespace silentpayment {

Sender::Sender(const std::vector<std::tuple<CKey, bool>>& sender_secret_keys, const CPubKey& recipient_public_key)
{
    m_context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    const auto& [seckey, is_taproot] = sender_secret_keys.at(0);

    unsigned char sum_seckey[32];
    memcpy(sum_seckey, seckey.data(), 32);
    assert(memcmp(sum_seckey, seckey.data(), 32) == 0);

    if (is_taproot && seckey.GetPubKey()[0] == 3) {
        int return_val = secp256k1_ec_seckey_negate(m_context, sum_seckey);
        assert(return_val);
    }

    if (sender_secret_keys.size() > 1) {
        for (size_t i = 1; i < sender_secret_keys.size(); i++) {

            const auto& [sender_seckey, sender_is_taproot] = sender_secret_keys.at(i);

            unsigned char seckey_i[32];
            memcpy(seckey_i, sender_seckey.begin(), 32);
            assert(memcmp(seckey_i, sender_seckey.begin(), 32) == 0);

            if (sender_is_taproot && sender_seckey.GetPubKey()[0] == 3) {
                int return_val = secp256k1_ec_seckey_negate(m_context, seckey_i);
                assert(return_val);
            }

            int return_val = secp256k1_ec_seckey_tweak_add(m_context, sum_seckey, seckey_i);
            assert(return_val);
        }
    }

    secp256k1_pubkey parsed_recipient_public_key;
    int return_val = secp256k1_ec_pubkey_parse(m_context, &parsed_recipient_public_key, recipient_public_key.data(), recipient_public_key.size());
    assert(return_val);


    return_val = secp256k1_ecdh(m_context, m_shared_secret, &parsed_recipient_public_key, sum_seckey, nullptr, nullptr);
    assert(return_val);

    // store recipient's pubkey
    return_val = secp256k1_ec_pubkey_parse(m_context, &m_recipient_public_key, recipient_public_key.data(), recipient_public_key.size());
    assert(return_val);

    CKey ckey;
    ckey.Set(std::begin(m_shared_secret), std::end(m_shared_secret), true);
}

Sender::~Sender()
{
    secp256k1_context_destroy(m_context);
    memset(m_shared_secret, 0, sizeof(m_shared_secret));
    memset(m_recipient_x_only_public_key.data, 0, sizeof(m_recipient_x_only_public_key.data));
}

XOnlyPubKey Sender::Tweak2(const int32_t& identifier) const
{
    unsigned char shared_secret[32];
    memcpy(shared_secret, m_shared_secret, 32);
    int return_val = memcmp(shared_secret, m_shared_secret, 32);
    assert(return_val == 0);

    // Add the identifier to the shared_secret
    arith_uint256 tweak;
    tweak = tweak + identifier;

    return_val = secp256k1_ec_seckey_tweak_add(m_context, shared_secret, ArithToUint256(tweak).data());
    assert(return_val);

    secp256k1_pubkey recipient_public_key;
    memcpy(recipient_public_key.data, m_recipient_public_key.data, 64);
    assert(memcmp(recipient_public_key.data, m_recipient_public_key.data, 64) == 0);

    // Tweak the recipient's pubkey with identifier + shared_secret
    return_val = secp256k1_ec_pubkey_tweak_add(m_context, &recipient_public_key, shared_secret);
    assert(return_val);

    // Serialize and test the tweaked public key
    size_t len;
    unsigned char serialized_output_pubkey[33];
    len = sizeof(serialized_output_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(m_context, serialized_output_pubkey, &len, &recipient_public_key, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    CPubKey pubKey = CPubKey(serialized_output_pubkey);

    assert(pubKey.IsFullyValid());

    return XOnlyPubKey(pubKey);
}

Recipient::Recipient(const CKey& recipient_secret_key)
{
    m_context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    int return_val = secp256k1_keypair_create(m_context, &m_recipient_keypair, recipient_secret_key.begin());
    assert(return_val);

    memcpy(m_recipient_seckey, recipient_secret_key.data(), 32);
    assert(memcmp(m_recipient_seckey, recipient_secret_key.data(), 32) == 0);
}

void Recipient::SetSenderPublicKey(const CPubKey& sender_public_key)
{
    secp256k1_pubkey sender_pubkey;
    int return_val = secp256k1_ec_pubkey_parse(m_context, &sender_pubkey, sender_public_key.data(), sender_public_key.size());
    assert(return_val);

    return_val = secp256k1_ecdh(m_context, m_shared_secret, &sender_pubkey, m_recipient_seckey, nullptr, nullptr);
    assert(return_val);

    CKey ckey;
    ckey.Set(std::begin(m_shared_secret), std::end(m_shared_secret), true);
}

Recipient::~Recipient()
{
    secp256k1_context_destroy(m_context);
    memset(m_recipient_seckey, 0, sizeof(m_recipient_seckey));
    memset(m_shared_secret, 0, sizeof(m_shared_secret));
    memset(m_recipient_keypair.data, 0, sizeof(m_recipient_keypair.data));
}

std::tuple<CKey,XOnlyPubKey> Recipient::Tweak2(const int32_t& identifier) const
{
    secp256k1_keypair recipient_keypair;
    memcpy(recipient_keypair.data, m_recipient_keypair.data, 96);
    assert(memcmp(recipient_keypair.data, m_recipient_keypair.data, 96) == 0);

    unsigned char shared_secret[32];
    memcpy(shared_secret, m_shared_secret, 32);
    int return_val = memcmp(shared_secret, m_shared_secret, 32);
    assert(return_val == 0);

    arith_uint256 tweak;
    tweak = tweak + identifier;

    return_val = secp256k1_ec_seckey_tweak_add(m_context, shared_secret, ArithToUint256(tweak).data());
    assert(return_val);

    unsigned char result_secret_key[32];
    return_val = secp256k1_keypair_sec(m_context, result_secret_key, &recipient_keypair);
    assert(return_val);

    secp256k1_pubkey result_pubkey;
    return_val = secp256k1_keypair_pub(m_context, &result_pubkey, &recipient_keypair);
    assert(return_val);

    return_val = secp256k1_ec_seckey_tweak_add(m_context, result_secret_key, shared_secret);
    assert(return_val);

    return_val = secp256k1_ec_pubkey_tweak_add(m_context, &result_pubkey, shared_secret);
    assert(return_val);

    // Serialize and test the tweaked public key
    size_t len;
    unsigned char pubkey_bytes[33];
    len = sizeof(pubkey_bytes);
    return_val = secp256k1_ec_pubkey_serialize(m_context, pubkey_bytes, &len, &result_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    CKey ckey;
    ckey.Set(std::begin(result_secret_key), std::end(result_secret_key), true);

    return {ckey, XOnlyPubKey{CPubKey{pubkey_bytes}}};
}

CPubKey Recipient::SumPublicKeys(const std::vector<CPubKey>& sender_public_keys, const std::vector<XOnlyPubKey>& sender_x_only_public_key)
{
    auto context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    std::vector<secp256k1_pubkey> v_pubkeys;

    for (auto& pubkey : sender_public_keys) {
        secp256k1_pubkey parsed_pubkey;
        int return_val = secp256k1_ec_pubkey_parse(context, &parsed_pubkey, pubkey.data(), pubkey.size());
        assert(return_val);

        v_pubkeys.push_back(parsed_pubkey);
    }

    for (auto& xpubkey : sender_x_only_public_key) {
        auto pubkey = xpubkey.ConvertToCompressedPubKey();
        secp256k1_pubkey parsed_pubkey;
        int return_val = secp256k1_ec_pubkey_parse(context, &parsed_pubkey, pubkey.data(), pubkey.size());
        assert(return_val);

        v_pubkeys.push_back(parsed_pubkey);
    }

    std::vector<secp256k1_pubkey *> p_pubkeys;
    for (auto& pubkey : v_pubkeys) {
        p_pubkeys.push_back(&pubkey);
    }

    // Sum all pubkeys
    secp256k1_pubkey sum_pubkey;
    int return_val = secp256k1_ec_pubkey_combine(context, &sum_pubkey, p_pubkeys.data(), v_pubkeys.size());
    assert(return_val);

    // Serialize and test the tweaked public key
    size_t len;
    unsigned char output_pubkey[33];
    len = sizeof(output_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(context, output_pubkey, &len, &sum_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    CPubKey pubKey = CPubKey(output_pubkey);

    assert(pubKey.IsFullyValid());

    secp256k1_context_destroy(context);

    return pubKey;
}

std::variant<CPubKey, XOnlyPubKey> ExtractPubkeyFromInput(const Coin& prevCoin, const CTxIn& txin)
{
    // scriptPubKey being spent by this input
    CScript scriptPubKey = prevCoin.out.scriptPubKey;

    if (scriptPubKey.IsPayToWitnessScriptHash()) {
        return CPubKey(); // returns an invalid pubkey
    }

    // Vector of parsed pubkeys and hashes
    std::vector<std::vector<unsigned char>> solutions;

    TxoutType whichType = Solver(scriptPubKey, solutions);

    if (whichType == TxoutType::NONSTANDARD ||
    whichType == TxoutType::MULTISIG ||
    whichType == TxoutType::WITNESS_UNKNOWN ) {
        return CPubKey(); // returns an invalid pubkey
    }

    const CScript scriptSig = txin.scriptSig;
    const CScriptWitness scriptWitness = txin.scriptWitness;

    // TODO: Condition not tested
    if (whichType == TxoutType::PUBKEY) {

        CPubKey pubkey = CPubKey(solutions[0]);
        assert(pubkey.IsFullyValid());
        return pubkey;
    }

    else if (whichType == TxoutType::PUBKEYHASH) {

        int sigSize = static_cast<int>(scriptSig[0]);
        int pubKeySize = static_cast<int>(scriptSig[sigSize + 1]);
        auto serializedPubKey = std::vector<unsigned char>(scriptSig.begin() + sigSize + 2, scriptSig.end());
        assert(serializedPubKey.size() == (size_t) pubKeySize);

        CPubKey pubkey = CPubKey(serializedPubKey);
        assert(pubkey.IsFullyValid());

        return pubkey;

    }

    else if (whichType == TxoutType::WITNESS_V0_KEYHASH || scriptPubKey.IsPayToScriptHash()) {
        if (scriptWitness.stack.size() != 2) return CPubKey(); // returns an invalid pubkey

        if (scriptWitness.stack.at(1).size() != 33) {
            return CPubKey();
        }

        CPubKey pubkey = CPubKey(scriptWitness.stack.at(1));
        assert(pubkey.IsFullyValid());

        return pubkey;
    }

    else if (whichType == TxoutType::WITNESS_V1_TAPROOT) {

        XOnlyPubKey pubkey = XOnlyPubKey(solutions[0]);
        assert(pubkey.IsFullyValid());
        return pubkey;
    }

    return CPubKey(); // returns an invalid pubkey

}
} // namespace silentpayment

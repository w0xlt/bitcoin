#include <silentpayment.h>

#include <coins.h>
#include <crypto/hmac_sha512.h>
#include <key_io.h>
#include <arith_uint256.h>

namespace silentpayment {

Recipient::Recipient(const CKey& spend_seckey, size_t pool_size)
{
    std::vector<std::pair<CKey, XOnlyPubKey>> spend_keys;

    unsigned char scan_seckey_bytes[32];
    CSHA256().Write(spend_seckey.begin(), 32).Finalize(scan_seckey_bytes);

    CKey scan_key;
    scan_key.Set(std::begin(scan_seckey_bytes), std::end(scan_seckey_bytes), true);

    m_scan_pubkey = XOnlyPubKey(scan_key.GetPubKey());

    m_negated_scan_seckey = scan_key;
    if (scan_key.GetPubKey().data()[0] == 3) {
        m_negated_scan_seckey.Negate();
    }

    for(size_t identifier = 0; identifier < pool_size; identifier++) {

        CKey spend_seckey1{spend_seckey};
        if (spend_seckey.GetPubKey().data()[0] == 3) {
            spend_seckey1.Negate();
        }

        arith_uint256 tweak;
        tweak = tweak + identifier;

        CKey spend_seckey2 = spend_seckey1.AddTweak(ArithToUint256(tweak).data());

        CKey tweaked_spend_seckey{spend_seckey2};
        if (spend_seckey2.GetPubKey().data()[0] == 3) {
            tweaked_spend_seckey.Negate();
        }

        spend_keys.push_back(std::make_pair(tweaked_spend_seckey, XOnlyPubKey{tweaked_spend_seckey.GetPubKey()}));
    }

    m_spend_keys = spend_keys;
}

void Recipient::SetSenderPublicKey(const CPubKey& sender_public_key)
{
    std::array<unsigned char, 32> result = m_negated_scan_seckey.ECDH(sender_public_key);

    std::copy(std::begin(result), std::end(result), std::begin(m_shared_secret));
}

std::tuple<CKey,XOnlyPubKey> Recipient::Tweak(const int32_t& identifier) const
{
    const auto& [seckey, xonly_pubkey]{m_spend_keys.at(identifier)};

    const auto& result_xonly_pubkey{xonly_pubkey.AddTweak(m_shared_secret)};

    const auto& result_seckey{seckey.AddTweak(m_shared_secret)};

    return {result_seckey, result_xonly_pubkey};
}

std::pair<XOnlyPubKey,XOnlyPubKey> Recipient::GetAddress(const int32_t& identifier) const
{
    const auto& [_, spend_pubkey]{m_spend_keys.at(identifier)};
    return {m_scan_pubkey, spend_pubkey};
}

int32_t Recipient::GetIdentifier(XOnlyPubKey spend_pubkey) const
{
    for(std::size_t i; i < spend_pubkey.size(); i++) {
        const auto& [_, pubkey] = m_spend_keys.at(i);
        if (pubkey == spend_pubkey) {
            return i;
        }
    }
    return -1;
}

CPubKey Recipient::CombinePublicKeys(const std::vector<CPubKey>& sender_public_keys, const std::vector<XOnlyPubKey>& sender_x_only_public_key)
{
    std::vector<CPubKey> v_pubkeys;

    v_pubkeys.insert(v_pubkeys.end(), sender_public_keys.begin(), sender_public_keys.end());

    for (auto& xpubkey : sender_x_only_public_key) {
        v_pubkeys.push_back(xpubkey.ConvertToCompressedPubKey());
    }

    return CPubKey::Combine(v_pubkeys);
}

Sender::Sender(const std::vector<std::tuple<CKey, bool>>& sender_secret_keys, const XOnlyPubKey& recipient_scan_xonly_pubkey)
{
    const auto& [seckey, is_taproot] = sender_secret_keys.at(0);

    CKey sum_seckey{seckey};

    if (is_taproot && sum_seckey.GetPubKey()[0] == 3) {
        sum_seckey.Negate();
    }

    if (sender_secret_keys.size() > 1) {
        for (size_t i = 1; i < sender_secret_keys.size(); i++) {
            const auto& [sender_seckey, sender_is_taproot] = sender_secret_keys.at(i);

            auto temp_key{sender_seckey};
            if (sender_is_taproot && sender_seckey.GetPubKey()[0] == 3) {
                temp_key.Negate();
            }

            sum_seckey = sum_seckey.AddTweak(temp_key.begin());
        }
    }

    CPubKey recipient_scan_pubkey = recipient_scan_xonly_pubkey.ConvertToCompressedPubKey();

    std::array<unsigned char, 32> result = sum_seckey.ECDH(recipient_scan_pubkey);

    std::copy(std::begin(result), std::end(result), std::begin(m_shared_secret));
}

XOnlyPubKey Sender::Tweak(const XOnlyPubKey spend_xonly_pubkey) const
{
    return spend_xonly_pubkey.AddTweak(m_shared_secret);
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

#ifndef BITCOIN_SILENTPAYMENT_H
#define BITCOIN_SILENTPAYMENT_H

#include <coins.h>
#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>

namespace silentpayment {

using SilentKey = std::variant<CPubKey, XOnlyPubKey>;

class Sender {
    private:
        secp256k1_context* m_context{nullptr};
        secp256k1_xonly_pubkey m_recipient_x_only_public_key;
        unsigned char m_shared_secret[32];

        secp256k1_pubkey m_recipient_public_key;

    public:
        Sender(const std::vector<CKey>& sender_secret_keys, const XOnlyPubKey& recipient_x_only_public_key);
        Sender(const std::vector<CKey>& sender_secret_keys, const CPubKey& recipient_public_key);

        Sender(const std::vector<std::tuple<CKey, bool>>& sender_secret_keys, const CPubKey& recipient_public_key);

        XOnlyPubKey Tweak(const int32_t& identifier) const;
        CPubKey Tweak2(const int32_t& identifier) const;
        ~Sender();
};// class Sender

class Recipient {
    private:
        secp256k1_context* m_context{nullptr};
        unsigned char m_recipient_seckey[32];
        secp256k1_keypair m_recipient_keypair;
        unsigned char m_shared_secret[32];

    public:
        Recipient(const CKey& recipient_secret_key);
        Recipient(const CKey& recipient_secret_key, const CKey& possibly_negated_key);
        /** This method expects the sender_public_key parameter to be
         * the sender's public keys already summed. See SumXOnlyPublicKeys().**/
        void SetSenderPublicKey(const CPubKey& sender_public_key);
        std::tuple<CKey,XOnlyPubKey> Tweak(const int32_t& identifier) const;
        std::tuple<CKey,CPubKey> Tweak2(const int32_t& identifier) const;
        ~Recipient();

        static CKey NegatePrivateKeyIfOdd(const CKey& seckey);
        static CPubKey SumXOnlyPublicKeys(const std::vector<XOnlyPubKey>& sender_x_only_public_key);
        static CPubKey SumPublicKeys(const std::vector<CPubKey>& sender_public_keys);
        static CPubKey SumPublicKeys(const std::vector<CPubKey>& sender_public_keys, const std::vector<XOnlyPubKey>& sender_x_only_public_key);
}; // class Recipient

/** Extract Pubkey from an input according to the transaction type **/
bool ExtractPubkeyFromInput(const Coin& prevCoin, const CTxIn& txin,  XOnlyPubKey& senderPubKey);
} // namespace silentpayment

#endif // BITCOIN_SILENTPAYMENT_H

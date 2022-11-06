#ifndef BITCOIN_SILENTPAYMENT_H
#define BITCOIN_SILENTPAYMENT_H

#include <coins.h>
#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>

namespace silentpayment {

using SilentKey = std::variant<CPubKey, XOnlyPubKey>;

class SenderOLD {
    private:
        secp256k1_context* m_context{nullptr};
        secp256k1_xonly_pubkey m_recipient_x_only_public_key;
        unsigned char m_shared_secret[32];

        secp256k1_pubkey m_recipient_public_key;

    public:
        SenderOLD(const std::vector<std::tuple<CKey, bool>>& sender_secret_keys, const CPubKey& recipient_public_key);
        XOnlyPubKey Tweak2(const int32_t& identifier) const;
        ~SenderOLD();
};// class Sender

class RecipientOLD {
    private:
        secp256k1_context* m_context{nullptr};
        unsigned char m_recipient_seckey[32];
        secp256k1_keypair m_recipient_keypair;
        unsigned char m_shared_secret[32];

    public:
        RecipientOLD(const CKey& recipient_secret_key);
        /** This method expects the sender_public_key parameter to be
         * the sender's public keys already summed. See SumXOnlyPublicKeys().**/
        void SetSenderPublicKey(const CPubKey& sender_public_key);
        std::tuple<CKey,XOnlyPubKey> Tweak2(const int32_t& identifier) const;
        ~RecipientOLD();

        static CPubKey SumPublicKeys(const std::vector<CPubKey>& sender_public_keys, const std::vector<XOnlyPubKey>& sender_x_only_public_key);
}; // class Recipient

/* class SenderNS {
    private:
        secp256k1_context* m_context{nullptr};

        secp256k1_xonly_pubkey m_recipient_spend_xonly_pubkey;

        unsigned char m_shared_secret[32];

    public:
        SenderNS(
            const std::vector<std::tuple<CKey, bool>>& sender_secret_keys,
            const XOnlyPubKey& recipient_spend_xonly_pubkey,
            const XOnlyPubKey& recipient_scan_xonly_pubkey);

        XOnlyPubKey Tweak(const int32_t& identifier) const;
        XOnlyPubKey Tweak(const XOnlyPubKey spend_xonly_pubkey) const;
        ~SenderNS();
}; // class SenderNS

class RecipientNS {
    private:
        secp256k1_context* m_context{nullptr};

        unsigned char m_negated_scan_seckey[32];

        secp256k1_keypair m_spend_keypair;

        unsigned char m_shared_secret[32];

    public:
        XOnlyPubKey scan_xonly_pubkey;
        XOnlyPubKey original_spend_xonly_pubkey;

        RecipientNS(const CKey& spend_seckey);
        void SetSenderPublicKey(const CPubKey& sender_public_key);
        XOnlyPubKey TweakSpendPubkey(const int32_t& identifier);
        std::tuple<CKey,XOnlyPubKey> Tweak(const int32_t& identifier) const;
        std::tuple<CKey,XOnlyPubKey> Tweak2(const int32_t& identifier) const;
        ~RecipientNS();

        static XOnlyPubKey TweakSpendPubkey(const XOnlyPubKey spend_xonly_pubkey, const int32_t& identifier);
        static XOnlyPubKey GenerateScanPubkey(const CKey& spend_seckey);
}; // class RecipientNS */

class RecipientNS2 {
    private:
        CKey m_negated_scan_seckey;
        unsigned char m_shared_secret[32];
        std::vector<std::pair<CKey, XOnlyPubKey>> m_spend_keys;

    public:
        RecipientNS2(const CKey& spend_seckey, size_t pool_size);
        void SetSenderPublicKey(const CPubKey& sender_public_key);
        std::tuple<CKey,XOnlyPubKey> Tweak(const int32_t& identifier) const;

        static XOnlyPubKey GenerateScanPubkey(const CKey& spend_seckey);
        static XOnlyPubKey TweakSpendPubkey(const XOnlyPubKey spend_xonly_pubkey, const int32_t& identifier);
        static CPubKey CombinePublicKeys(const std::vector<CPubKey>& sender_public_keys, const std::vector<XOnlyPubKey>& sender_x_only_public_key);
}; // class RecipientNS2

class SenderNS2 {
    private:
        XOnlyPubKey m_recipient_spend_xonly_pubkey;
        unsigned char m_shared_secret[32];

    public:
        SenderNS2(const std::vector<std::tuple<CKey, bool>>& sender_secret_keys,
            const XOnlyPubKey& recipient_spend_xonly_pubkey,
            const XOnlyPubKey& recipient_scan_xonly_pubkey);
        XOnlyPubKey Tweak(const XOnlyPubKey spend_xonly_pubkey) const;
};  // class SenderNS2


/** Extract Pubkey from an input according to the transaction type **/
std::variant<CPubKey, XOnlyPubKey> ExtractPubkeyFromInput(const Coin& prevCoin, const CTxIn& txin);


} // namespace silentpayment

#endif // BITCOIN_SILENTPAYMENT_H

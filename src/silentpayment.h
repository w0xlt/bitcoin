#ifndef BITCOIN_SILENTPAYMENT_H
#define BITCOIN_SILENTPAYMENT_H

#include <coins.h>
#include <key_io.h>

namespace silentpayment {

class Recipient {
    private:
        CKey m_negated_scan_seckey;
        unsigned char m_shared_secret[32];
        std::vector<std::pair<CKey, XOnlyPubKey>> m_spend_keys;
        XOnlyPubKey m_scan_pubkey;

    public:
        Recipient(const CKey& spend_seckey, size_t pool_size);
        void SetSenderPublicKey(const CPubKey& sender_public_key);
        std::tuple<CKey,XOnlyPubKey> Tweak(const int32_t& identifier) const;
        std::pair<XOnlyPubKey,XOnlyPubKey> GetAddress(const int32_t& identifier) const;
        int32_t GetIdentifier(XOnlyPubKey spend_pubkey) const;

        static CPubKey CombinePublicKeys(const std::vector<CPubKey>& sender_public_keys, const std::vector<XOnlyPubKey>& sender_x_only_public_key);
}; // class Recipient

class Sender {
    private:
        XOnlyPubKey m_recipient_spend_xonly_pubkey;
        unsigned char m_shared_secret[32];

    public:
        Sender(const std::vector<std::tuple<CKey, bool>>& sender_secret_keys, const XOnlyPubKey& recipient_scan_xonly_pubkey);
        XOnlyPubKey Tweak(const XOnlyPubKey spend_xonly_pubkey) const;
};  // class Sender

/** Extract Pubkey from an input according to the transaction type **/
std::variant<CPubKey, XOnlyPubKey> ExtractPubkeyFromInput(const Coin& prevCoin, const CTxIn& txin);
} // namespace silentpayment

#endif // BITCOIN_SILENTPAYMENT_H

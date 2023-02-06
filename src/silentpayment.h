#ifndef BITCOIN_SILENTPAYMENT_H
#define BITCOIN_SILENTPAYMENT_H

#include <coins.h>
#include <key_io.h>

namespace silentpayment {

class Recipient {
    protected:
        CKey m_negated_scan_seckey;
        unsigned char m_shared_secret[32];
        std::vector<std::pair<CKey, XOnlyPubKey>> m_spend_keys;
        XOnlyPubKey m_scan_pubkey;

    public:
        Recipient(const CKey& spend_seckey, size_t pool_size);
        void SetSenderPublicKey(const CPubKey& sender_public_key);
        std::tuple<CKey,XOnlyPubKey> Tweak(const int32_t& identifier) const;
        std::pair<XOnlyPubKey,XOnlyPubKey> GetAddress(const int32_t& identifier) const;
        int32_t GetIdentifier(const XOnlyPubKey& spend_pubkey) const;

        static CPubKey CombinePublicKeys(const std::vector<CPubKey>& sender_public_keys, const std::vector<XOnlyPubKey>& sender_x_only_public_key);
        static CPubKey CombinePublicKeys(const CTransaction& tx, const std::vector<Coin>& coins);
}; // class Recipient

class Recipient2: public Recipient  {
    public:
        Recipient2(const CKey& spend_seckey, size_t pool_size) : Recipient(spend_seckey, pool_size) { };
        void SetSenderPublicKey(const CPubKey& sender_public_key, const std::vector<COutPoint>& tx_outpoints);
};

class Sender {
    protected:
        XOnlyPubKey m_recipient_spend_xonly_pubkey;
        unsigned char m_shared_secret[32];

    public:
        Sender() {}
        Sender(const std::vector<std::tuple<CKey, bool>>& sender_secret_keys, const XOnlyPubKey& recipient_scan_xonly_pubkey);
        XOnlyPubKey Tweak(const XOnlyPubKey spend_xonly_pubkey) const;
};  // class Sender

class Sender2 : public Sender {
    public:
        Sender2(const std::vector<std::tuple<CKey, bool>>& sender_secret_keys, const std::vector<COutPoint>& tx_outpoints, const XOnlyPubKey& recipient_scan_xonly_pubkey);
}; // class Sender2

/** Extract Pubkey from an input according to the transaction type **/
std::variant<CPubKey, XOnlyPubKey> ExtractPubkeyFromInput(const Coin& prevCoin, const CTxIn& txin);
} // namespace silentpayment

#endif // BITCOIN_SILENTPAYMENT_H

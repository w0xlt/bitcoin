#ifndef BITCOIN_WALLET_SILENTPAYMENT_H
#define BITCOIN_WALLET_SILENTPAYMENT_H

#include <coins.h>
#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>

namespace silentpayment {

class Sender {
    private:
        secp256k1_context* m_context;
        secp256k1_xonly_pubkey m_recipient_x_only_public_key;
        unsigned char m_shared_secret[32];

    public:
        Sender(const CKey& sender_secret_key, const XOnlyPubKey& recipient_x_only_public_key);
        XOnlyPubKey Tweak(const int32_t& identifier) const;
        ~Sender();

        static CKey SumPrivateKeys(const std::vector<CKey>& sender_secret_keys);
};// class Sender

class Recipient {
    private:
        secp256k1_context* m_context;
        secp256k1_keypair m_recipient_keypair;
        unsigned char m_shared_secret[32];

    public:
        Recipient(const CKey& recipient_secret_key, const XOnlyPubKey& sender_x_only_public_key);
        CKey Tweak(const int32_t& identifier) const;
        ~Recipient();

        static XOnlyPubKey SumXOnlyPublicKeys(const std::vector<XOnlyPubKey>& sender_x_only_public_keys);
}; // class Recipient

/** Extract Pubkey from an input according to the transaction type **/
bool ExtractPubkeyFromInput(const Coin& prevCoin, const CTxIn& txin,  XOnlyPubKey& senderPubKey);

} // namespace silentpayment

#endif // BITCOIN_WALLET_SILENTPAYMENT_H

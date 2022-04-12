#ifndef BITCOIN_SILENT_PAYMENT_H
#define BITCOIN_SILENT_PAYMENT_H

#include <base58.h>
#include <key_io.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>

namespace silentpayment {

class Sender {

    private:
        static secp256k1_pubkey CreateTweakedPubkey(
            const secp256k1_context* ctx,
            const secp256k1_xonly_pubkey recipient_public_key,
            const unsigned char sender_secret_key[32]);

    public:
        static XOnlyPubKey CreateSilentAddress(const CKey& sender_secret_key, const XOnlyPubKey& _recipient_public_key);
};// class Sender

class Recipient {

    private:
        static void CreateTweakedPubkey(
            const secp256k1_context* ctx,
            const secp256k1_xonly_pubkey sender_public_key,
            secp256k1_keypair& recipient_keypair);

    public:
        static CKey CreateSilentAddress(const CKey& recipient_secret_key, const XOnlyPubKey& _sender_public_key);

}; // class Recipient

class SilentTransactionData {
    public:
        CScript originalScripitPubKey;
        CKey originalPrivKey;
        CScript tweakedScripitPubKey;
        CKey tweakedPrivKey;

    SilentTransactionData(CScript originalScripitPubKey, CKey originalPrivKey, CScript tweakedScripitPubKey, CKey tweakedPrivKey) :
        originalScripitPubKey(originalScripitPubKey),
        originalPrivKey(originalPrivKey),
        tweakedScripitPubKey(tweakedScripitPubKey),
        tweakedPrivKey(tweakedPrivKey) {}
};

} // namespace silentpayment

#endif // BITCOIN_SILENT_PAYMENT_H

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_SENDER_H
#define BITCOIN_PAYJOIN_SENDER_H

#include <payjoin/net.h>
#include <payjoin/session.h>
#include <uint256.h>

#include <memory>
#include <optional>
#include <string>

namespace wallet {
class CWallet;
}

namespace payjoin {

/**
 * BIP 77 Sender state machine.
 *
 * Manages the sender side of the payjoin protocol:
 * 1. Create: Parse URI, create funded PSBT, generate ephemeral reply key
 * 2. PostOriginal: Encrypt and send Original PSBT to receiver's mailbox
 * 3. PollForProposal: Check sender's mailbox for the Proposal PSBT
 * 4. FinalizeAndBroadcast: Validate, sign, and broadcast the proposal
 */
class Sender {
    std::shared_ptr<PayjoinSession> m_session;
    wallet::CWallet& m_wallet;
    HttpClient& m_http;

public:
    Sender(std::shared_ptr<PayjoinSession> session, wallet::CWallet& wallet, HttpClient& http)
        : m_session(std::move(session)), m_wallet(wallet), m_http(http) {}

    /**
     * Create a new sender session from a BIP 77 payjoin URI.
     *
     * Parses the URI, creates a funded PSBT paying the requested amount,
     * and generates an ephemeral reply keypair.
     *
     * @param[in] wallet   The wallet to fund the transaction from
     * @param[in] http     HTTP client for directory communication
     * @param[in] bip21_uri BIP 21 URI string with pj parameter
     * @param[in] fee_rate Fee rate for the transaction
     * @return Sender instance, or nullopt on failure
     */
    static std::optional<Sender> Create(wallet::CWallet& wallet, HttpClient& http,
                                        const std::string& bip21_uri,
                                        const CFeeRate& fee_rate);

    /**
     * Post the Original PSBT to the receiver's directory mailbox.
     *
     * Encrypts as BIP 77 Message A, wraps in OHTTP, and POSTs to directory.
     * Updates session state to PostedOriginal on success.
     *
     * @return true on success
     */
    bool PostOriginal();

    /**
     * Poll for the Proposal PSBT (single non-blocking attempt).
     *
     * GETs from the sender's mailbox, decrypts Message B if available.
     *
     * @return true if proposal received, false if not yet available,
     *         nullopt on error or expiration
     */
    std::optional<bool> PollForProposal();

    /**
     * Validate the proposal, sign sender's inputs, and broadcast.
     *
     * Performs BIP 78 sender validation checklist:
     * - All original inputs still present
     * - Sender outputs preserved (within fee tolerance)
     * - Fee didn't decrease
     * - New inputs are finalized
     *
     * @return Transaction ID on success, nullopt on failure
     */
    std::optional<uint256> FinalizeAndBroadcast();

    /** Get the current session state. */
    const PayjoinSession& GetSession() const { return *m_session; }
    std::shared_ptr<PayjoinSession> GetSessionPtr() { return m_session; }
};

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_SENDER_H

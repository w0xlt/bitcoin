// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_RECEIVER_H
#define BITCOIN_PAYJOIN_RECEIVER_H

#include <consensus/amount.h>
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
 * BIP 77 Receiver state machine.
 *
 * Manages the receiver side of the payjoin protocol:
 * 1. Create: Generate ephemeral receiver key, build BIP 77 URI
 * 2. PollForOriginal: Check receiver's mailbox for the Original PSBT
 * 3. ProcessAndRespond: Validate original, add receiver input, send proposal
 * 4. CheckPayment: Monitor mempool for the final transaction
 */
class Receiver {
    std::shared_ptr<PayjoinSession> m_session;
    wallet::CWallet& m_wallet;
    HttpClient& m_http;

public:
    Receiver(std::shared_ptr<PayjoinSession> session, wallet::CWallet& wallet, HttpClient& http)
        : m_session(std::move(session)), m_wallet(wallet), m_http(http) {}

    /**
     * Create a new receiver session.
     *
     * Generates an ephemeral receiver keypair, builds a BIP 77 URI
     * containing the receiver's pubkey and directory info.
     *
     * @param[in] wallet        The wallet to receive into
     * @param[in] http          HTTP client for directory communication
     * @param[in] amount        Requested payment amount in satoshis
     * @param[in] directory_url Directory base URL
     * @param[in] ohttp_keys   Directory OHTTP key configuration
     * @param[in] expiry_secs  Session expiration in seconds (default 24h)
     * @return Receiver instance, or nullopt on failure
     */
    static std::optional<Receiver> Create(wallet::CWallet& wallet, HttpClient& http,
                                          CAmount amount,
                                          const std::string& directory_url,
                                          const ohttp::KeyConfig& ohttp_keys,
                                          int64_t expiry_secs = 86400);

    /** Get the payjoin URI to share with the sender. */
    std::string GetUri() const;

    /**
     * Poll for the Original PSBT (single non-blocking attempt).
     *
     * GETs from the receiver's mailbox, decrypts Message A if available.
     *
     * @return true if original received, false if not yet available,
     *         nullopt on error or expiration
     */
    std::optional<bool> PollForOriginal();

    /**
     * Validate the original, build a proposal, and send it back.
     *
     * Performs BIP 78 receiver validation:
     * - Verify all inputs are NOT owned by receiver
     * - Identify receiver's output
     * - Select a receiver UTXO to contribute (matching script type)
     * - Add receiver input at random position
     * - Adjust outputs as needed
     * - Sign receiver's inputs
     * - Encrypt as Message B and POST to sender's mailbox
     *
     * @return true on success
     */
    bool ProcessAndRespond();

    /**
     * Check if the payjoin or fallback transaction has been broadcast.
     *
     * @return true if payment detected, false if not yet,
     *         nullopt on error
     */
    std::optional<bool> CheckPayment();

    /** Get the current session state. */
    const PayjoinSession& GetSession() const { return *m_session; }
    std::shared_ptr<PayjoinSession> GetSessionPtr() { return m_session; }
};

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_RECEIVER_H

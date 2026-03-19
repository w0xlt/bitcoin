// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/payjoin.h>

#include <logging.h>
#include <netbase.h>
#include <payjoin/net.h>
#include <payjoin/receiver.h>
#include <payjoin/sender.h>
#include <payjoin/session.h>
#include <sync.h>
#include <util/time.h>
#include <util/strencodings.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <map>

namespace wallet {

namespace {
constexpr std::string_view PAYJOIN_ROLE_KEY{"payjoin_role"};
constexpr std::string_view PAYJOIN_AMOUNT_KEY{"payjoin_amount_sats"};
} // namespace

std::optional<PayjoinTxMetadata> GetPayjoinTxMetadata(const mapValue_t& map_value)
{
    auto role_it = map_value.find(std::string{PAYJOIN_ROLE_KEY});
    auto amount_it = map_value.find(std::string{PAYJOIN_AMOUNT_KEY});
    if (role_it == map_value.end() || amount_it == map_value.end()) return std::nullopt;

    std::optional<PayjoinTxRole> role;
    if (role_it->second == "sender") {
        role = PayjoinTxRole::Sender;
    } else if (role_it->second == "receiver") {
        role = PayjoinTxRole::Receiver;
    } else {
        return std::nullopt;
    }

    return PayjoinTxMetadata{*role, LocaleIndependentAtoi<CAmount>(amount_it->second)};
}

std::optional<PayjoinTxMetadata> GetPayjoinTxMetadata(const CWalletTx& wtx)
{
    return GetPayjoinTxMetadata(wtx.mapValue);
}

void SetPayjoinTxMetadata(mapValue_t& map_value, PayjoinTxRole role, CAmount amount)
{
    map_value[std::string{PAYJOIN_ROLE_KEY}] = role == PayjoinTxRole::Sender ? "sender" : "receiver";
    map_value[std::string{PAYJOIN_AMOUNT_KEY}] = std::to_string(amount);
}

bool IsPayjoinTxMetadataKey(std::string_view key)
{
    return key == PAYJOIN_ROLE_KEY || key == PAYJOIN_AMOUNT_KEY;
}

/** Minimum seconds between background polls of the same session. */
static constexpr int64_t POLL_INTERVAL_SECS = 15;

/** Maximum sessions to advance per scheduler tick.
 *  Each session requires a Tor round-trip (~3-5s), so this caps the
 *  scheduler callback duration at roughly MAX_SESSIONS_PER_TICK * 5s. */
static constexpr int MAX_SESSIONS_PER_TICK = 4;

/** Mark session as failed after this many consecutive advance errors. */
static constexpr int MAX_CONSECUTIVE_ERRORS = 5;

/** In-memory error count per session (not persisted — resets on restart). */
static Mutex g_error_counts_mutex;
static std::map<uint256, int> g_session_error_counts GUARDED_BY(g_error_counts_mutex);

static bool SessionHasTooManyErrors(const uint256& session_id) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(g_error_counts_mutex);
    auto it = g_session_error_counts.find(session_id);
    return it != g_session_error_counts.end() && it->second >= MAX_CONSECUTIVE_ERRORS;
}

static void ResetSessionErrors(const uint256& session_id) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(g_error_counts_mutex);
    g_session_error_counts.erase(session_id);
}

/** Increment error count and return the new count. */
static int IncrementSessionErrors(const uint256& session_id) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(g_error_counts_mutex);
    return ++g_session_error_counts[session_id];
}

static payjoin::HttpClient MakePayjoinHttpClient()
{
    Proxy tor_proxy;
    if (!GetProxy(NET_ONION, tor_proxy)) {
        if (!GetProxy(NET_IPV4, tor_proxy)) {
            throw std::runtime_error("No Tor/SOCKS5 proxy configured");
        }
    }
    return payjoin::HttpClient(tor_proxy);
}

bool AdvancePayjoinSession(CWallet& wallet,
                           std::shared_ptr<payjoin::PayjoinSession> session)
{
    // Pre-flight: verify session data integrity before doing network/wallet I/O
    if (session->role == payjoin::SessionRole::Receiver &&
        session->receiver_state == payjoin::ReceiverState::ReceivedOriginal) {
        if (!session->original_psbt.tx.has_value()) {
            throw std::runtime_error("Session in ReceivedOriginal state but original PSBT has no tx");
        }
        if (!session->sender_reply_pubkey.has_value()) {
            throw std::runtime_error("Session in ReceivedOriginal state but no sender reply pubkey");
        }
    }

    auto http_client = MakePayjoinHttpClient();
    std::string old_state = session->GetStateString();

    if (session->role == payjoin::SessionRole::Sender) {
        payjoin::Sender sender(session, wallet, http_client);

        switch (session->sender_state) {
        case payjoin::SenderState::PostedOriginal:
        case payjoin::SenderState::PollingForProposal:
        {
            auto poll_result = sender.PollForProposal();
            if (!poll_result.has_value()) {
                // Error or expiration - session state already updated
            } else if (*poll_result) {
                // Got proposal - try to finalize
                sender.FinalizeAndBroadcast();
            }
            // else: not ready yet, state stays as polling
            break;
        }
        default:
            break;
        }
    } else {
        payjoin::Receiver receiver(session, wallet, http_client);

        switch (session->receiver_state) {
        case payjoin::ReceiverState::Initialized:
        {
            receiver.PollForOriginal();
            break;
        }
        case payjoin::ReceiverState::ReceivedOriginal:
        {
            receiver.ProcessAndRespond();
            break;
        }
        case payjoin::ReceiverState::ProposalSent:
        case payjoin::ReceiverState::Monitoring:
        {
            receiver.CheckPayment();
            break;
        }
        default:
            break;
        }
    }

    return session->GetStateString() != old_state;
}

void MaybeAdvancePayjoinSessions(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        // Read sessions under lock, then release for HTTP I/O
        std::vector<std::pair<uint256, payjoin::PayjoinSession>> sessions;
        {
            LOCK(pwallet->cs_wallet);
            WalletBatch batch(pwallet->GetDatabase());
            batch.ListPayjoinSessions(sessions);
        }

        int advanced_count = 0;
        for (auto& [session_id, session] : sessions) {
            if (session.IsTerminal()) continue;

            // Skip sessions that have failed too many times
            if (SessionHasTooManyErrors(session_id)) continue;

            // Throttle: skip if polled too recently
            int64_t now = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
            if (now - session.last_poll_time < POLL_INTERVAL_SECS) continue;

            // Cap sessions per tick to bound scheduler callback duration
            if (advanced_count >= MAX_SESSIONS_PER_TICK) break;
            ++advanced_count;

            session.last_poll_time = now;

            auto session_ptr = std::make_shared<payjoin::PayjoinSession>(std::move(session));

            try {
                std::string old_state = session_ptr->GetStateString();
                bool changed = AdvancePayjoinSession(*pwallet, session_ptr);
                if (changed) {
                    LogPrintf("payjoin: session %s advanced: %s -> %s\n",
                              session_id.ToString(), old_state, session_ptr->GetStateString());
                    ResetSessionErrors(session_id);
                }
            } catch (const std::exception& e) {
                LogPrintf("payjoin: background advance failed for %s: %s\n",
                          session_id.ToString(), e.what());
                int count = IncrementSessionErrors(session_id);
                if (count >= MAX_CONSECUTIVE_ERRORS) {
                    LogPrintf("payjoin: session %s marked failed after %d consecutive errors\n",
                              session_id.ToString(), count);
                    session_ptr->error_message = "Background polling failed repeatedly: " + std::string(e.what());
                    if (session_ptr->role == payjoin::SessionRole::Sender) {
                        session_ptr->sender_state = payjoin::SenderState::Failed;
                    } else {
                        session_ptr->receiver_state = payjoin::ReceiverState::Failed;
                    }
                }
            }

            // Clean up error tracking for terminal sessions
            if (session_ptr->IsTerminal()) {
                ResetSessionErrors(session_id);
            }

            // Persist updated session, but respect concurrent cancellation.
            // Re-read from DB under lock to avoid overwriting a cancel.
            {
                LOCK(pwallet->cs_wallet);
                WalletBatch batch(pwallet->GetDatabase());
                payjoin::PayjoinSession current;
                if (batch.ReadPayjoinSession(session_id, current) && current.IsTerminal()) {
                    // Session was cancelled/failed by RPC while we did I/O — don't overwrite
                    LogPrintf("payjoin: session %s was cancelled concurrently, skipping write-back\n",
                              session_id.ToString());
                } else {
                    batch.WritePayjoinSession(session_id, *session_ptr);
                }
            }
        }
    }
}

} // namespace wallet

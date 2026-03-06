// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <key_io.h>
#include <netbase.h>
#include <ohttp/ohttp.h>
#include <payjoin/net.h>
#include <payjoin/receiver.h>
#include <payjoin/sender.h>
#include <payjoin/session.h>
#include <payjoin/uri.h>
#include <policy/fees.h>
#include <rpc/util.h>
#include <uint256.h>
#include <util/time.h>
#include <wallet/payjoin.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <univalue.h>

namespace wallet {

static payjoin::HttpClient GetPayjoinHttpClient()
{
    Proxy tor_proxy;
    if (!GetProxy(NET_ONION, tor_proxy)) {
        // Fall back to IPv4 proxy
        if (!GetProxy(NET_IPV4, tor_proxy)) {
            throw JSONRPCError(RPC_MISC_ERROR, "No Tor/SOCKS5 proxy configured. Set -proxy= or -onion=");
        }
    }
    return payjoin::HttpClient(tor_proxy);
}

static UniValue SessionToJSON(const payjoin::PayjoinSession& session)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("session_id", session.session_id.ToString());
    result.pushKV("role", session.role == payjoin::SessionRole::Sender ? "sender" : "receiver");
    result.pushKV("created_at", session.created_at);
    result.pushKV("expires_at", session.expires_at);

    if (session.role == payjoin::SessionRole::Sender) {
        std::string state_str;
        switch (session.sender_state) {
        case payjoin::SenderState::Created: state_str = "created"; break;
        case payjoin::SenderState::PostedOriginal: state_str = "posted_original"; break;
        case payjoin::SenderState::PollingForProposal: state_str = "polling"; break;
        case payjoin::SenderState::Completed: state_str = "completed"; break;
        case payjoin::SenderState::Failed: state_str = "failed"; break;
        case payjoin::SenderState::Expired: state_str = "expired"; break;
        case payjoin::SenderState::Cancelled: state_str = "cancelled"; break;
        }
        result.pushKV("state", state_str);
    } else {
        std::string state_str;
        switch (session.receiver_state) {
        case payjoin::ReceiverState::Initialized: state_str = "initialized"; break;
        case payjoin::ReceiverState::ReceivedOriginal: state_str = "received_original"; break;
        case payjoin::ReceiverState::ProposalSent: state_str = "proposal_sent"; break;
        case payjoin::ReceiverState::Monitoring: state_str = "monitoring"; break;
        case payjoin::ReceiverState::Completed: state_str = "completed"; break;
        case payjoin::ReceiverState::Failed: state_str = "failed"; break;
        case payjoin::ReceiverState::Expired: state_str = "expired"; break;
        case payjoin::ReceiverState::Cancelled: state_str = "cancelled"; break;
        }
        result.pushKV("state", state_str);
    }

    if (session.final_txid) {
        result.pushKV("txid", session.final_txid->ToString());
    }
    if (!session.error_message.empty()) {
        result.pushKV("error", session.error_message);
    }
    if (!session.payjoin_uri.empty()) {
        result.pushKV("payjoin_uri", session.payjoin_uri);
    }

    result.pushKV("is_terminal", session.IsTerminal());
    result.pushKV("is_polling", session.IsPolling());

    return result;
}

// ---------------------------------------------------------------------------
// sendpayjoin
// ---------------------------------------------------------------------------

RPCHelpMan sendpayjoin()
{
    return RPCHelpMan{
        "sendpayjoin",
        "Initiate a BIP 77 payjoin send using a payjoin URI.\n"
        "Creates a funded PSBT, encrypts it, and posts to the payjoin directory.\n"
        "Starts background polling for the receiver's proposal.\n",
        {
            {"bip21", RPCArg::Type::STR, RPCArg::Optional::NO, "The BIP 21 URI with payjoin parameters (pj=...)"},
            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Default{"wallet default"}, "Fee rate in sat/vB"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "The payjoin session identifier"},
                {RPCResult::Type::STR, "state", "Current session state"},
            },
        },
        RPCExamples{
            HelpExampleCli("sendpayjoin", "\"bitcoin:bc1q...?pj=HTTPS://PAYJO.IN/...\" 10")
            + HelpExampleRpc("sendpayjoin", "\"bitcoin:bc1q...?pj=HTTPS://PAYJO.IN/...\", 10")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    std::string bip21_uri = request.params[0].get_str();

    // Validate URI before attempting network operations
    auto parsed_uri = payjoin::ParsePayjoinUri(bip21_uri);
    if (!parsed_uri) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to parse payjoin URI. Expected BIP 21 URI with pj= parameter.");
    }

    CFeeRate fee_rate{CFeeRate(DEFAULT_TRANSACTION_MINFEE)};
    if (!request.params[1].isNull()) {
        fee_rate = CFeeRate(AmountFromValue(request.params[1]));
    }

    auto http_client = GetPayjoinHttpClient();

    auto sender = payjoin::Sender::Create(*pwallet, http_client, bip21_uri, fee_rate);
    if (!sender) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create payjoin sender session");
    }

    // Post the original PSBT
    if (!sender->PostOriginal()) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            "Failed to post original PSBT: " + sender->GetSession().error_message);
    }

    // Persist session to wallet DB
    auto session_ptr = sender->GetSessionPtr();
    {
        LOCK(pwallet->cs_wallet);
        WalletBatch batch(pwallet->GetDatabase());
        if (!batch.WritePayjoinSession(session_ptr->session_id, *session_ptr)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist payjoin session to wallet DB");
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("session_id", session_ptr->session_id.ToString());
    result.pushKV("state", "posted_original");
    return result;
},
    };
}

// ---------------------------------------------------------------------------
// receivepayjoin
// ---------------------------------------------------------------------------

RPCHelpMan receivepayjoin()
{
    return RPCHelpMan{
        "receivepayjoin",
        "Create a BIP 77 payjoin receive session.\n"
        "Generates a payjoin URI that can be shared with the sender.\n"
        "Starts background polling for the sender's original PSBT.\n",
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount to request in BTC"},
            {"directory", RPCArg::Type::STR, RPCArg::Default{"https://payjo.in"}, "The payjoin directory URL"},
            {"expiry_secs", RPCArg::Type::NUM, RPCArg::Default{86400}, "Session expiration in seconds"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "The payjoin session identifier"},
                {RPCResult::Type::STR, "payjoin_uri", "The BIP 21 URI to share with the sender"},
                {RPCResult::Type::STR, "state", "Current session state"},
            },
        },
        RPCExamples{
            HelpExampleCli("receivepayjoin", "0.001")
            + HelpExampleCli("receivepayjoin", "0.001 \"https://payjo.in\" 3600")
            + HelpExampleRpc("receivepayjoin", "0.001")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CAmount amount = AmountFromValue(request.params[0]);

    std::string directory_url = "https://payjo.in";
    if (!request.params[1].isNull()) {
        directory_url = request.params[1].get_str();
    }

    int64_t expiry_secs = 86400;
    if (!request.params[2].isNull()) {
        expiry_secs = request.params[2].getInt<int64_t>();
    }

    // Fetch OHTTP keys from directory
    auto http_client = GetPayjoinHttpClient();
    auto ohttp_keys = payjoin::FetchOhttpKeys(http_client, directory_url);
    if (!ohttp_keys) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to fetch OHTTP keys from directory");
    }

    auto receiver = payjoin::Receiver::Create(*pwallet, http_client, amount,
                                                directory_url, *ohttp_keys, expiry_secs);
    if (!receiver) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create payjoin receiver session");
    }

    // Persist session to wallet DB
    auto session_ptr = receiver->GetSessionPtr();
    {
        LOCK(pwallet->cs_wallet);
        WalletBatch batch(pwallet->GetDatabase());
        batch.WritePayjoinSession(session_ptr->session_id, *session_ptr);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("session_id", session_ptr->session_id.ToString());
    result.pushKV("payjoin_uri", receiver->GetUri());
    result.pushKV("state", "initialized");
    return result;
},
    };
}

// ---------------------------------------------------------------------------
// payjoininfo
// ---------------------------------------------------------------------------

RPCHelpMan payjoininfo()
{
    return RPCHelpMan{
        "payjoininfo",
        "Get information about a payjoin session.\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The session identifier"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "The session identifier"},
                {RPCResult::Type::STR, "role", "sender or receiver"},
                {RPCResult::Type::NUM_TIME, "created_at", "Creation timestamp"},
                {RPCResult::Type::NUM_TIME, "expires_at", "Expiration timestamp"},
                {RPCResult::Type::STR, "state", "Current state"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Final transaction ID if completed"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if failed"},
                {RPCResult::Type::STR, "payjoin_uri", /*optional=*/true, "Payjoin URI for receiver sessions"},
                {RPCResult::Type::BOOL, "is_terminal", "Whether session is in a terminal state"},
                {RPCResult::Type::BOOL, "is_polling", "Whether session is actively polling"},
            },
        },
        RPCExamples{
            HelpExampleCli("payjoininfo", "\"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    uint256 session_id = ParseHashV(request.params[0], "session_id");

    LOCK(pwallet->cs_wallet);

    WalletBatch batch(pwallet->GetDatabase());
    payjoin::PayjoinSession session;

    if (!batch.ReadPayjoinSession(session_id, session)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Session not found");
    }

    return SessionToJSON(session);
},
    };
}

// ---------------------------------------------------------------------------
// listpayjoin
// ---------------------------------------------------------------------------

RPCHelpMan listpayjoin()
{
    return RPCHelpMan{
        "listpayjoin",
        "List all payjoin sessions.\n",
        {
            {"active_only", RPCArg::Type::BOOL, RPCArg::Default{false}, "Only show active (non-terminal) sessions"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "session_id", "The session identifier"},
                        {RPCResult::Type::STR, "role", "sender or receiver"},
                        {RPCResult::Type::NUM_TIME, "created_at", "Creation timestamp"},
                        {RPCResult::Type::NUM_TIME, "expires_at", "Expiration timestamp"},
                        {RPCResult::Type::STR, "state", "Current state"},
                        {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Final transaction ID if completed"},
                        {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if failed"},
                        {RPCResult::Type::STR, "payjoin_uri", /*optional=*/true, "Payjoin URI for receiver sessions"},
                        {RPCResult::Type::BOOL, "is_terminal", "Whether session is in a terminal state"},
                        {RPCResult::Type::BOOL, "is_polling", "Whether session is actively polling"},
                    },
                },
            },
        },
        RPCExamples{
            HelpExampleCli("listpayjoin", "")
            + HelpExampleCli("listpayjoin", "true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    bool active_only = false;
    if (!request.params[0].isNull()) {
        active_only = request.params[0].get_bool();
    }

    LOCK(pwallet->cs_wallet);

    UniValue result(UniValue::VARR);

    WalletBatch batch(pwallet->GetDatabase());
    std::vector<std::pair<uint256, payjoin::PayjoinSession>> sessions;
    batch.ListPayjoinSessions(sessions);

    for (const auto& [id, session] : sessions) {
        if (active_only && session.IsTerminal()) continue;
        result.push_back(SessionToJSON(session));
    }

    return result;
},
    };
}

// ---------------------------------------------------------------------------
// cancelpayjoin
// ---------------------------------------------------------------------------

RPCHelpMan cancelpayjoin()
{
    return RPCHelpMan{
        "cancelpayjoin",
        "Cancel an active payjoin session.\n"
        "For sender sessions, optionally broadcasts the fallback (original) transaction.\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The session identifier to cancel"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "The cancelled session identifier"},
                {RPCResult::Type::STR, "state", "New state (cancelled)"},
            },
        },
        RPCExamples{
            HelpExampleCli("cancelpayjoin", "\"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    uint256 session_id = ParseHashV(request.params[0], "session_id");

    LOCK(pwallet->cs_wallet);

    WalletBatch batch(pwallet->GetDatabase());
    payjoin::PayjoinSession session;

    if (!batch.ReadPayjoinSession(session_id, session)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Session not found");
    }

    if (session.IsTerminal()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Session is already in a terminal state");
    }

    // Mark as cancelled
    if (session.role == payjoin::SessionRole::Sender) {
        session.sender_state = payjoin::SenderState::Cancelled;
    } else {
        session.receiver_state = payjoin::ReceiverState::Cancelled;
    }
    session.error_message = "Cancelled by user";

    batch.WritePayjoinSession(session_id, session);

    UniValue result(UniValue::VOBJ);
    result.pushKV("session_id", session_id.ToString());
    result.pushKV("state", "cancelled");
    return result;
},
    };
}

// ---------------------------------------------------------------------------
// advancepayjoin
// ---------------------------------------------------------------------------

RPCHelpMan advancepayjoin()
{
    return RPCHelpMan{
        "advancepayjoin",
        "Advance a payjoin session by one protocol step.\n"
        "For sender sessions: polls for proposal or finalizes and broadcasts.\n"
        "For receiver sessions: polls for original, processes and responds, or checks payment.\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The session identifier to advance"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "The session identifier"},
                {RPCResult::Type::STR, "role", "sender or receiver"},
                {RPCResult::Type::NUM_TIME, "created_at", "Creation timestamp"},
                {RPCResult::Type::NUM_TIME, "expires_at", "Expiration timestamp"},
                {RPCResult::Type::STR, "state", "Current state after advancing"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Final transaction ID if completed"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if failed"},
                {RPCResult::Type::STR, "payjoin_uri", /*optional=*/true, "Payjoin URI for receiver sessions"},
                {RPCResult::Type::BOOL, "is_terminal", "Whether session is in a terminal state"},
                {RPCResult::Type::BOOL, "is_polling", "Whether session is actively polling"},
            },
        },
        RPCExamples{
            HelpExampleCli("advancepayjoin", "\"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    uint256 session_id = ParseHashV(request.params[0], "session_id");

    // Read session from wallet DB
    auto session = std::make_shared<payjoin::PayjoinSession>();
    {
        LOCK(pwallet->cs_wallet);
        WalletBatch batch(pwallet->GetDatabase());
        if (!batch.ReadPayjoinSession(session_id, *session)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Session not found");
        }
    }

    if (session->IsTerminal()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Session is already in a terminal state");
    }

    AdvancePayjoinSession(*pwallet, session);

    // Persist updated session
    {
        LOCK(pwallet->cs_wallet);
        WalletBatch batch(pwallet->GetDatabase());
        batch.WritePayjoinSession(session_id, *session);
    }

    return SessionToJSON(*session);
},
    };
}

} // namespace wallet

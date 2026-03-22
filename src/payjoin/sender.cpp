// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/sender.h>

#include <core_io.h>
#include <key.h>
#include <logging.h>
#include <node/transaction.h>
#include <ohttp/bhttp.h>
#include <ohttp/ohttp.h>
#include <payjoin/messages.h>
#include <payjoin/net.h>
#include <payjoin/original.h>
#include <payjoin/session.h>
#include <payjoin/shortid.h>
#include <payjoin/uri.h>
#include <payjoin/sender_validation.h>
#include <policy/fees.h>
#include <psbt.h>
#include <random.h>
#include <streams.h>
#include <uint256.h>
#include <util/time.h>
#include <wallet/coincontrol.h>
#include <wallet/payjoin.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace payjoin {

static std::optional<PartiallySignedTransaction> DeserializePSBT(std::span<const uint8_t> data)
{
    try {
        DataStream ds(data);
        PartiallySignedTransaction psbt;
        ds >> psbt;
        return psbt;
    } catch (...) {
        return std::nullopt;
    }
}

static std::optional<CAmount> GetRequestedPayjoinAmount(wallet::CWallet& wallet,
                                                        const PartiallySignedTransaction& psbt)
{
    if (!psbt.tx) return std::nullopt;

    LOCK(wallet.cs_wallet);
    for (const auto& txout : psbt.tx->vout) {
        if (!wallet.IsMine(txout.scriptPubKey)) {
            return txout.nValue;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Sender::Create
// ---------------------------------------------------------------------------

std::optional<Sender> Sender::Create(wallet::CWallet& wallet, HttpClient& http,
                                      const std::string& bip21_uri,
                                      const CFeeRate& fee_rate)
{
    // 1. Parse the BIP 77 URI
    auto uri = ParsePayjoinUri(bip21_uri);
    if (!uri) {
        LogPrintf("payjoin sender: Failed to parse URI\n");
        return std::nullopt;
    }

    if (!uri->amount) {
        LogPrintf("payjoin sender: URI missing amount\n");
        return std::nullopt;
    }

    // 2. Create session
    auto session = std::make_shared<PayjoinSession>();
    GetRandBytes(session->session_id);
    session->role = SessionRole::Sender;
    session->sender_state = SenderState::Created;
    session->created_at = GetTime();
    session->expires_at = uri->pj.expiration;
    session->receiver_pubkey = uri->pj.receiver_key;
    session->sender_disable_output_substitution = !uri->output_substitution;
    auto directory_url = DirectoryUrlFromMailboxUrl(uri->pj.mailbox_url);
    if (!directory_url) {
        LogPrintf("payjoin sender: URI mailbox endpoint missing valid short-id path\n");
        return std::nullopt;
    }
    session->directory_url = *directory_url;
    session->ohttp_keys = uri->pj.ohttp_keys;

    // 3. Generate ephemeral reply keypair
    session->reply_key.MakeNewKey(/*fCompressed=*/true);

    // 4. Create funded transaction paying the receiver
    wallet::CCoinControl coin_control;
    coin_control.m_feerate = fee_rate;

    std::vector<wallet::CRecipient> recipients;
    recipients.push_back(wallet::CRecipient{uri->address, *uri->amount, false});

    auto tx_result = wallet::CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt, coin_control);
    if (!tx_result) {
        LogPrintf("payjoin sender: Failed to create transaction: %s\n",
                  util::ErrorString(tx_result).original);
        return std::nullopt;
    }

    // 5. Convert to PSBT (strip scriptSigs/witnesses — PSBT requires unsigned tx)
    CMutableTransaction mtx(*tx_result->tx);
    for (auto& txin : mtx.vin) {
        txin.scriptSig = CScript();
        txin.scriptWitness.SetNull();
    }

    PartiallySignedTransaction psbtx(mtx);
    bool complete = false;
    wallet.FillPSBT(psbtx, complete, /*sighash_type=*/std::nullopt, /*sign=*/true, /*bip32derivs=*/true);

    session->original_psbt = psbtx;

    return Sender(std::move(session), wallet, http);
}

// ---------------------------------------------------------------------------
// Sender::PostOriginal
// ---------------------------------------------------------------------------

bool Sender::PostOriginal()
{
    if (m_session->sender_state != SenderState::Created) {
        LogPrintf("payjoin sender: Cannot post original from state %d\n",
                  static_cast<int>(m_session->sender_state));
        return false;
    }

    // 1. Serialize Original PSBT in the BIP 77 Message A plaintext format
    const std::string sender_query = BuildOriginalPayloadQuery(m_session->sender_disable_output_substitution);
    auto plaintext = SerializeOriginalPayload(m_session->original_psbt, sender_query);

    // 2. Encrypt as Message A
    CPubKey reply_pk = m_session->reply_key.GetPubKey();
    auto message_a = EncryptMessageA(plaintext, reply_pk, m_session->receiver_pubkey);
    if (!message_a) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to encrypt Message A";
        return false;
    }

    // 3. Build BHTTP POST request to receiver's mailbox
    std::string mailbox = MailboxUrl(m_session->directory_url, m_session->receiver_pubkey);

    bhttp::Request bhttp_req;
    bhttp_req.method = "POST";
    if (!ParseUrlIntoBhttpRequest(mailbox, bhttp_req)) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Unsupported mailbox URL transport";
        return false;
    }
    bhttp_req.headers.push_back({"Content-Type", "message/payjoin+psbt"});
    bhttp_req.body.assign(message_a->begin(), message_a->end());

    // 4. Encode bHTTP with padding
    auto bhttp_encoded = bhttp::EncodeKnownLengthRequestPadded(bhttp_req, ohttp::PADDED_BHTTP_REQ_BYTES);
    if (!bhttp_encoded) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to encode padded bHTTP request";
        return false;
    }

    // 5. OHTTP encapsulate
    ohttp::ClientContext ohttp_ctx;
    auto ohttp_req = ohttp_ctx.EncapsulateRequest(m_session->ohttp_keys, *bhttp_encoded);
    if (!ohttp_req) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to OHTTP encapsulate";
        return false;
    }

    // 6. POST to directory gateway
    std::string gateway_url = OhttpGatewayUrl(m_session->directory_url);
    auto resp = m_http.Post(gateway_url, *ohttp_req, "message/ohttp-req");
    if (!resp || resp->status_code != 200) {
        m_session->sender_state = SenderState::Failed;
        if (!resp) {
            m_session->error_message = "Directory POST failed: no HTTP response";
        } else {
            m_session->error_message = "Directory POST failed: HTTP " + std::to_string(resp->status_code);
        }
        return false;
    }

    m_session->sender_state = SenderState::PostedOriginal;
    LogPrintf("payjoin sender: Original PSBT posted to directory\n");
    return true;
}

// ---------------------------------------------------------------------------
// Sender::PollForProposal
// ---------------------------------------------------------------------------

std::optional<bool> Sender::PollForProposal()
{
    if (m_session->sender_state != SenderState::PostedOriginal &&
        m_session->sender_state != SenderState::PollingForProposal) {
        return std::nullopt;
    }

    // Check expiration
    if (GetTime() > m_session->expires_at) {
        m_session->sender_state = SenderState::Expired;
        m_session->error_message = "Session expired";
        return std::nullopt;
    }

    m_session->sender_state = SenderState::PollingForProposal;

    // 1. Build BHTTP GET to sender's mailbox
    CPubKey reply_pk = m_session->reply_key.GetPubKey();
    std::string mailbox = MailboxUrl(m_session->directory_url, reply_pk);

    bhttp::Request bhttp_req;
    bhttp_req.method = "GET";
    if (!ParseUrlIntoBhttpRequest(mailbox, bhttp_req)) return std::nullopt;

    // 2. Encode and encapsulate
    auto bhttp_encoded = bhttp::EncodeKnownLengthRequestPadded(bhttp_req, ohttp::PADDED_BHTTP_REQ_BYTES);
    if (!bhttp_encoded) return std::nullopt;

    ohttp::ClientContext ohttp_ctx;
    auto ohttp_req = ohttp_ctx.EncapsulateRequest(m_session->ohttp_keys, *bhttp_encoded);
    if (!ohttp_req) return std::nullopt;

    // 3. POST to directory gateway
    auto resp = m_http.Post(OhttpGatewayUrl(m_session->directory_url), *ohttp_req, "message/ohttp-req");
    if (!resp) return std::nullopt;

    // 4. OHTTP decapsulate
    auto ohttp_resp_bytes = ohttp_ctx.OpenResponse(resp->body);
    if (!ohttp_resp_bytes) return std::nullopt;

    // 5. Decode bHTTP response
    auto bhttp_resp = bhttp::DecodeKnownLengthResponse(*ohttp_resp_bytes);
    if (!bhttp_resp) return std::nullopt;

    // 6. Check status
    if (bhttp_resp->status == 202) {
        return false; // Not ready yet
    }

    if (bhttp_resp->status != 200) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Unexpected directory response: " + std::to_string(bhttp_resp->status);
        return std::nullopt;
    }

    // 7. Decrypt Message B
    auto decrypted = DecryptMessageB(bhttp_resp->body, m_session->receiver_pubkey, m_session->reply_key);
    if (!decrypted) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to decrypt Message B";
        return std::nullopt;
    }

    // 8. Deserialize Proposal PSBT (strip trailing zero padding)
    // Find the end of the PSBT (look for the terminating 0x00 after proper structure)
    auto proposal = DeserializePSBT(*decrypted);
    if (!proposal) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to parse Proposal PSBT";
        return std::nullopt;
    }

    const auto validation_context = detail::BuildSenderProposalValidationContext(
        m_wallet, m_session->original_psbt, m_session->sender_disable_output_substitution);
    if (!validation_context) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to build sender proposal validation context";
        return std::nullopt;
    }
    if (const auto validation_error =
            detail::ValidateSenderProposal(m_session->original_psbt, *proposal, *validation_context)) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = *validation_error;
        return std::nullopt;
    }

    m_session->proposal_psbt = *proposal;
    LogPrintf("payjoin sender: Received proposal PSBT\n");
    return true;
}

// ---------------------------------------------------------------------------
// Sender::FinalizeAndBroadcast
// ---------------------------------------------------------------------------

std::optional<uint256> Sender::FinalizeAndBroadcast()
{
    if (!m_session->proposal_psbt) {
        m_session->error_message = "No proposal PSBT available";
        return std::nullopt;
    }

    auto proposal = *m_session->proposal_psbt;

    const auto validation_context = detail::BuildSenderProposalValidationContext(
        m_wallet, m_session->original_psbt, m_session->sender_disable_output_substitution);
    if (!validation_context) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to build sender proposal validation context";
        return std::nullopt;
    }
    if (const auto validation_error =
            detail::ValidateSenderProposal(m_session->original_psbt, proposal, *validation_context)) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = *validation_error;
        return std::nullopt;
    }

    detail::RestoreOriginalSenderData(m_session->original_psbt, proposal);

    // 1. Sign sender's inputs in the proposal
    bool complete = false;
    auto error = m_wallet.FillPSBT(proposal, complete, /*sighash_type=*/std::nullopt,
                                    /*sign=*/true, /*bip32derivs=*/true);
    if (error) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to sign proposal";
        return std::nullopt;
    }

    // 2. Finalize and extract raw transaction
    CMutableTransaction mtx;
    bool extracted = FinalizeAndExtractPSBT(proposal, mtx);
    if (!extracted) {
        m_session->sender_state = SenderState::Failed;
        m_session->error_message = "Failed to finalize proposal PSBT";
        return std::nullopt;
    }

    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    // 3. Broadcast
    wallet::mapValue_t map_value;
    if (auto amount = GetRequestedPayjoinAmount(m_wallet, m_session->original_psbt)) {
        wallet::SetPayjoinTxMetadata(map_value, wallet::PayjoinTxRole::Sender, *amount);
    }
    m_wallet.CommitTransaction(tx, std::move(map_value), /*orderForm=*/{});

    m_session->final_txid = tx->GetHash().ToUint256();
    m_session->sender_state = SenderState::Completed;
    LogPrintf("payjoin sender: Broadcast payjoin tx %s\n", tx->GetHash().ToString());

    return tx->GetHash().ToUint256();
}

} // namespace payjoin

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/receiver.h>

#include <core_io.h>
#include <key.h>
#include <logging.h>
#include <ohttp/bhttp.h>
#include <ohttp/ohttp.h>
#include <outputtype.h>
#include <primitives/transaction_identifier.h>
#include <payjoin/messages.h>
#include <payjoin/net.h>
#include <payjoin/original.h>
#include <payjoin/session.h>
#include <payjoin/shortid.h>
#include <payjoin/uri.h>
#include <psbt.h>
#include <random.h>
#include <script/script.h>
#include <script/solver.h>
#include <streams.h>
#include <uint256.h>
#include <util/time.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/payjoin.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace payjoin {

// ---------------------------------------------------------------------------
// Helper: serialize / deserialize PSBT
// ---------------------------------------------------------------------------
static std::vector<uint8_t> SerializePSBT(const PartiallySignedTransaction& psbt)
{
    DataStream ds;
    ds << psbt;
    std::vector<uint8_t> result(ds.size());
    std::memcpy(result.data(), ds.data(), ds.size());
    return result;
}

// ---------------------------------------------------------------------------
// Helper: determine OutputType from a scriptPubKey
// ---------------------------------------------------------------------------
static OutputType ClassifyScript(const CScript& script)
{
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType type = Solver(script, solutions);

    switch (type) {
    case TxoutType::WITNESS_V0_KEYHASH:
    case TxoutType::WITNESS_V0_SCRIPTHASH:
        return OutputType::BECH32;
    case TxoutType::WITNESS_V1_TAPROOT:
        return OutputType::BECH32M;
    case TxoutType::SCRIPTHASH:
        return OutputType::P2SH_SEGWIT;
    default:
        return OutputType::LEGACY;
    }
}

// ---------------------------------------------------------------------------
// Helper: extract bHTTP request fields from a URL
// ---------------------------------------------------------------------------
static void ParseUrlIntoBhttp(const std::string& url, bhttp::Request& req)
{
    req.scheme = "https";
    size_t scheme_end = url.find("://");
    if (scheme_end != std::string::npos) {
        std::string rest = url.substr(scheme_end + 3);
        size_t path_start = rest.find('/');
        if (path_start != std::string::npos) {
            req.authority = rest.substr(0, path_start);
            req.path = rest.substr(path_start);
        } else {
            req.authority = rest;
            req.path = "/";
        }
    }
}

// ---------------------------------------------------------------------------
// Receiver::Create
// ---------------------------------------------------------------------------

std::optional<Receiver> Receiver::Create(wallet::CWallet& wallet, HttpClient& http,
                                          CAmount amount,
                                          const std::string& directory_url,
                                          const ohttp::KeyConfig& ohttp_keys,
                                          int64_t expiry_secs)
{
    // 1. Create session
    auto session = std::make_shared<PayjoinSession>();
    GetRandBytes(session->session_id);
    session->role = SessionRole::Receiver;
    session->receiver_state = ReceiverState::Initialized;
    session->created_at = GetTime();
    session->expires_at = GetTime() + expiry_secs;
    session->directory_url = directory_url;
    session->ohttp_keys = ohttp_keys;

    // 2. Generate ephemeral receiver keypair
    session->receiver_key.MakeNewKey(/*fCompressed=*/true);

    // 3. Get a fresh receiving address from the wallet
    auto dest_result = wallet.GetNewDestination(OutputType::BECH32, "payjoin");
    if (!dest_result) {
        LogPrintf("payjoin receiver: Failed to get new address\n");
        return std::nullopt;
    }

    // 4. Build BIP 77 URI
    PayjoinUri uri;
    uri.address = *dest_result;
    uri.amount = amount;
    uri.output_substitution = true;

    uri.pj.receiver_key = session->receiver_key.GetPubKey();
    uri.pj.mailbox_url = MailboxUrl(directory_url, uri.pj.receiver_key);
    uri.pj.ohttp_keys = ohttp_keys;
    uri.pj.expiration = session->expires_at;

    session->payjoin_uri = BuildPayjoinUri(uri);

    LogPrintf("payjoin receiver: Session created, URI ready\n");
    return Receiver(std::move(session), wallet, http);
}

// ---------------------------------------------------------------------------
// Receiver::GetUri
// ---------------------------------------------------------------------------

std::string Receiver::GetUri() const
{
    return m_session->payjoin_uri;
}

// ---------------------------------------------------------------------------
// Receiver::PollForOriginal
// ---------------------------------------------------------------------------

std::optional<bool> Receiver::PollForOriginal()
{
    if (m_session->receiver_state != ReceiverState::Initialized) {
        return std::nullopt;
    }

    // Check expiration
    if (GetTime() > m_session->expires_at) {
        m_session->receiver_state = ReceiverState::Expired;
        m_session->error_message = "Session expired";
        return std::nullopt;
    }

    // 1. Build BHTTP GET to receiver's mailbox
    CPubKey receiver_pk = m_session->receiver_key.GetPubKey();
    std::string mailbox = MailboxUrl(m_session->directory_url, receiver_pk);

    bhttp::Request bhttp_req;
    bhttp_req.method = "GET";
    ParseUrlIntoBhttp(mailbox, bhttp_req);

    // 2. Encode and OHTTP encapsulate
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
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "Unexpected directory response: " + std::to_string(bhttp_resp->status);
        return std::nullopt;
    }

    // 7. Decrypt Message A
    auto decrypted = DecryptMessageA(bhttp_resp->body, m_session->receiver_key);
    if (!decrypted) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "Failed to decrypt Message A";
        return std::nullopt;
    }

    auto& [body, reply_pk] = *decrypted;

    // 8. Store sender's reply pubkey
    m_session->sender_reply_pubkey = reply_pk;

    // 9. Parse the BIP 77 Message A plaintext body
    auto original = DeserializeOriginalPayload(body);
    if (!original) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "Failed to parse Original PSBT";
        return std::nullopt;
    }

    m_session->original_psbt = std::move(original->psbt);
    m_session->original_query_params = std::move(original->query_params);
    m_session->receiver_state = ReceiverState::ReceivedOriginal;
    LogPrintf("payjoin receiver: Received Original PSBT from sender\n");
    return true;
}

// ---------------------------------------------------------------------------
// Receiver::ProcessAndRespond
// ---------------------------------------------------------------------------

bool Receiver::ProcessAndRespond()
{
    if (m_session->receiver_state != ReceiverState::ReceivedOriginal) {
        LogPrintf("payjoin receiver: Cannot process from state %d\n",
                  static_cast<int>(m_session->receiver_state));
        return false;
    }

    if (!m_session->sender_reply_pubkey) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "No sender reply pubkey";
        return false;
    }

    const auto& original = m_session->original_psbt;
    if (!original.tx) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "Original PSBT has no transaction";
        return false;
    }

    const CMutableTransaction& orig_tx = *original.tx;

    // -----------------------------------------------------------------------
    // BIP 78 Receiver Validation
    // -----------------------------------------------------------------------

    // 1. Verify sender's inputs are NOT owned by receiver
    {
        LOCK(m_wallet.cs_wallet);
        for (size_t i = 0; i < original.inputs.size(); ++i) {
            if (!original.inputs[i].witness_utxo.IsNull()) {
                if (m_wallet.IsMine(original.inputs[i].witness_utxo.scriptPubKey)) {
                    m_session->receiver_state = ReceiverState::Failed;
                    m_session->error_message = "Original contains receiver-owned input";
                    return false;
                }
            }
        }
    }

    // 2. Identify the receiver's output (matching our address)
    int receiver_output_idx = -1;
    CAmount receiver_amount = 0;
    OutputType sender_input_type = OutputType::BECH32; // default

    // Determine script type from sender's inputs for matching
    if (!original.inputs.empty() && !original.inputs[0].witness_utxo.IsNull()) {
        sender_input_type = ClassifyScript(original.inputs[0].witness_utxo.scriptPubKey);
    }

    {
        LOCK(m_wallet.cs_wallet);
        for (size_t i = 0; i < orig_tx.vout.size(); ++i) {
            if (m_wallet.IsMine(orig_tx.vout[i].scriptPubKey)) {
                receiver_output_idx = static_cast<int>(i);
                receiver_amount = orig_tx.vout[i].nValue;
                break;
            }
        }
    }

    if (receiver_output_idx < 0) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "No receiver output found in original";
        return false;
    }

    // 3. Select a receiver UTXO to contribute
    //    Manual iteration with null-safety instead of AvailableCoins to
    //    tolerate wallet entries with corrupt CTransactionRef fields.
    std::optional<wallet::COutput> selected_coin;

    {
        LOCK(m_wallet.cs_wallet);

        CAmount best_distance = std::numeric_limits<CAmount>::max();

        for (const auto& [outpoint, txo] : m_wallet.GetTXOs()) {
            const wallet::CWalletTx& wtx = txo.GetWalletTx();

            // Guard against corrupt wallet entries (null or invalid tx)
            if (!wtx.tx) {
                LogPrintf("payjoin receiver: skipping corrupt wallet tx %s (null tx)\n",
                          outpoint.hash.ToString());
                continue;
            }

            int depth = m_wallet.GetTxDepthInMainChain(wtx);
            if (depth < 1) continue;  // require at least 1 confirmation

            if (m_wallet.IsSpent(outpoint)) continue;
            if (m_wallet.IsLockedCoin(outpoint)) continue;

            const CTxOut& output = txo.GetTxOut();

            OutputType coin_type = ClassifyScript(output.scriptPubKey);

            int input_bytes = wallet::CalculateMaximumSignedInputSize(
                output, &m_wallet, /*coin_control=*/nullptr);

            wallet::COutput coin(outpoint, output, depth, input_bytes,
                                  /*solvable=*/input_bytes > -1,
                                  /*safe=*/true, wtx.GetTxTime(),
                                  /*from_me=*/false, /*fees=*/std::nullopt);

            // Prefer coins matching the sender's script type
            // Also prefer amount close to payment amount (UIH2 avoidance)
            if (coin_type == sender_input_type) {
                CAmount distance = std::abs(output.nValue - receiver_amount);
                if (distance < best_distance) {
                    best_distance = distance;
                    selected_coin = coin;
                }
            }

            // Fallback: any confirmed coin
            if (!selected_coin) {
                selected_coin = coin;
            }
        }
    }

    if (!selected_coin) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "No suitable UTXO available for payjoin";
        return false;
    }

    // -----------------------------------------------------------------------
    // Build Proposal PSBT
    // -----------------------------------------------------------------------

    // Start with a copy of the original transaction
    CMutableTransaction proposal_tx(*original.tx);

    // 4. Add receiver's input at a random position
    CTxIn receiver_input(
        selected_coin->outpoint,
        CScript(),
        original.tx->vin.empty() ? CTxIn::SEQUENCE_FINAL : original.tx->vin.front().nSequence);
    FastRandomContext rng;
    size_t insert_pos = rng.randrange(proposal_tx.vin.size() + 1);
    proposal_tx.vin.insert(proposal_tx.vin.begin() + insert_pos, receiver_input);

    // 5. Adjust receiver's output amount (add the contributed input value)
    // The receiver's output increases by the value of the added input
    proposal_tx.vout[receiver_output_idx].nValue += selected_coin->txout.nValue;

    // 6. Clear all signatures from the proposal (sender will re-sign)
    for (auto& txin : proposal_tx.vin) {
        txin.scriptSig.clear();
        txin.scriptWitness.SetNull();
    }

    // 7. Build proposal PSBT
    PartiallySignedTransaction proposal(proposal_tx);

    // Copy UTXO info for original inputs
    size_t orig_idx = 0;
    for (size_t i = 0; i < proposal.inputs.size(); ++i) {
        if (i == insert_pos) {
            // This is the receiver's added input - set witness_utxo
            proposal.inputs[i].witness_utxo = selected_coin->txout;
            continue;
        }
        if (orig_idx < original.inputs.size()) {
            // Copy witness_utxo from original for sender's inputs
            if (!original.inputs[orig_idx].witness_utxo.IsNull()) {
                proposal.inputs[i].witness_utxo = original.inputs[orig_idx].witness_utxo;
            }
            if (original.inputs[orig_idx].non_witness_utxo) {
                proposal.inputs[i].non_witness_utxo = original.inputs[orig_idx].non_witness_utxo;
            }
            orig_idx++;
        }
    }

    // 8. Sign the receiver's input
    bool complete = false;
    auto sign_error = m_wallet.FillPSBT(proposal, complete, /*sighash_type=*/std::nullopt,
                                          /*sign=*/true, /*bip32derivs=*/false);
    if (sign_error) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "Failed to sign receiver's input in proposal";
        return false;
    }

    // Store the proposal
    m_session->proposal_psbt = proposal;

    // -----------------------------------------------------------------------
    // Send Proposal as Message B
    // -----------------------------------------------------------------------

    // 9. Serialize Proposal PSBT
    auto psbt_bytes = SerializePSBT(proposal);

    // 10. Encrypt as Message B
    CPubKey receiver_pk = m_session->receiver_key.GetPubKey();
    auto message_b = EncryptMessageB(psbt_bytes, m_session->receiver_key,
                                      receiver_pk, *m_session->sender_reply_pubkey);
    if (!message_b) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "Failed to encrypt Message B";
        return false;
    }

    // 11. Build BHTTP POST to sender's reply mailbox
    std::string sender_mailbox = MailboxUrl(m_session->directory_url, *m_session->sender_reply_pubkey);

    bhttp::Request bhttp_req;
    bhttp_req.method = "POST";
    ParseUrlIntoBhttp(sender_mailbox, bhttp_req);
    bhttp_req.headers.push_back({"Content-Type", "message/payjoin+psbt"});
    bhttp_req.body.assign(message_b->begin(), message_b->end());

    // 12. Encode bHTTP with padding
    auto bhttp_encoded = bhttp::EncodeKnownLengthRequestPadded(bhttp_req, ohttp::PADDED_BHTTP_REQ_BYTES);
    if (!bhttp_encoded) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "Failed to encode padded bHTTP request";
        return false;
    }

    // 13. OHTTP encapsulate
    ohttp::ClientContext ohttp_ctx;
    auto ohttp_req = ohttp_ctx.EncapsulateRequest(m_session->ohttp_keys, *bhttp_encoded);
    if (!ohttp_req) {
        m_session->receiver_state = ReceiverState::Failed;
        m_session->error_message = "Failed to OHTTP encapsulate";
        return false;
    }

    // 14. POST to directory gateway
    auto resp = m_http.Post(OhttpGatewayUrl(m_session->directory_url), *ohttp_req, "message/ohttp-req");
    if (!resp || resp->status_code != 200) {
        m_session->receiver_state = ReceiverState::Failed;
        if (!resp) {
            m_session->error_message = "Directory POST failed for proposal: no HTTP response";
        } else {
            m_session->error_message = "Directory POST failed for proposal: HTTP " + std::to_string(resp->status_code);
        }
        return false;
    }

    m_session->receiver_state = ReceiverState::ProposalSent;
    LogPrintf("payjoin receiver: Proposal PSBT sent to sender's mailbox\n");
    return true;
}

// ---------------------------------------------------------------------------
// Receiver::CheckPayment
// ---------------------------------------------------------------------------

std::optional<bool> Receiver::CheckPayment()
{
    if (m_session->receiver_state != ReceiverState::ProposalSent &&
        m_session->receiver_state != ReceiverState::Monitoring) {
        return std::nullopt;
    }

    // Check expiration
    if (GetTime() > m_session->expires_at) {
        m_session->receiver_state = ReceiverState::Expired;
        m_session->error_message = "Session expired waiting for broadcast";
        return std::nullopt;
    }

    m_session->receiver_state = ReceiverState::Monitoring;

    // Check if the proposal or original transaction has been seen.
    // We cannot simply look up by the unsigned PSBT txid because the final
    // broadcast transaction may have non-empty scriptSigs that change the txid.
    // Instead, search wallet transactions for one that spends the same inputs.
    LOCK(m_wallet.cs_wallet);

    const auto parsed_uri = ParsePayjoinUri(m_session->payjoin_uri);
    const std::optional<CAmount> payjoin_amount =
        (parsed_uri && parsed_uri->amount) ? std::optional<CAmount>{*parsed_uri->amount} : std::nullopt;

    auto annotate_final_tx = [&](const CTransaction& final_tx) {
        if (!payjoin_amount) return;
        auto it = m_wallet.mapWallet.find(final_tx.GetHash());
        if (it == m_wallet.mapWallet.end()) return;

        wallet::SetPayjoinTxMetadata(it->second.mapValue, wallet::PayjoinTxRole::Receiver, *payjoin_amount);
        wallet::WalletBatch batch(m_wallet.GetDatabase());
        if (!batch.WriteTx(it->second)) {
            LogPrintf("payjoin receiver: Failed to persist payjoin tx metadata for %s\n",
                      final_tx.GetHash().ToString());
        }
    };

    // Collect proposal input outpoints for matching
    std::set<COutPoint> proposal_outpoints;
    if (m_session->proposal_psbt && m_session->proposal_psbt->tx) {
        for (const auto& vin : m_session->proposal_psbt->tx->vin) {
            proposal_outpoints.insert(vin.prevout);
        }
    }

    // Also collect original input outpoints as fallback
    std::set<COutPoint> original_outpoints;
    if (m_session->original_psbt.tx) {
        for (const auto& vin : m_session->original_psbt.tx->vin) {
            original_outpoints.insert(vin.prevout);
        }
    }

    // Search wallet transactions for a match
    for (const auto& [wtxid, wtx] : m_wallet.mapWallet) {
        const CTransaction& tx = *wtx.tx;

        // Check if this tx matches the proposal (all proposal inputs present)
        if (!proposal_outpoints.empty()) {
            bool all_found = true;
            for (const auto& op : proposal_outpoints) {
                bool found = false;
                for (const auto& vin : tx.vin) {
                    if (vin.prevout == op) { found = true; break; }
                }
                if (!found) { all_found = false; break; }
            }
            if (all_found) {
                annotate_final_tx(tx);
                m_session->final_txid = tx.GetHash().ToUint256();
                m_session->receiver_state = ReceiverState::Completed;
                LogPrintf("payjoin receiver: Payjoin transaction confirmed: %s\n",
                          tx.GetHash().ToString());
                return true;
            }
        }

        // Check if this tx matches the original (fallback)
        if (!original_outpoints.empty()) {
            bool all_found = true;
            for (const auto& op : original_outpoints) {
                bool found = false;
                for (const auto& vin : tx.vin) {
                    if (vin.prevout == op) { found = true; break; }
                }
                if (!found) { all_found = false; break; }
            }
            if (all_found) {
                annotate_final_tx(tx);
                m_session->final_txid = tx.GetHash().ToUint256();
                m_session->receiver_state = ReceiverState::Completed;
                LogPrintf("payjoin receiver: Fallback transaction seen: %s\n",
                          tx.GetHash().ToString());
                return true;
            }
        }
    }

    return false; // Not yet seen
}

} // namespace payjoin

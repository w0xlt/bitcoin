// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_SESSION_H
#define BITCOIN_PAYJOIN_SESSION_H

#include <key.h>
#include <ohttp/ohttp.h>
#include <psbt.h>
#include <pubkey.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace payjoin {

enum class SessionRole : uint8_t {
    Sender = 0,
    Receiver = 1,
};

enum class SenderState : uint8_t {
    Created = 0,             //!< PSBT built, not yet sent
    PostedOriginal = 1,      //!< Message A sent to directory
    PollingForProposal = 2,  //!< Waiting for Message B
    Completed = 3,           //!< Payjoin broadcast
    Failed = 4,
    Expired = 5,
    Cancelled = 6,
};

enum class ReceiverState : uint8_t {
    Initialized = 0,         //!< URI generated, polling for original
    ReceivedOriginal = 1,    //!< Got Message A, validating
    ProposalSent = 2,        //!< Message B sent
    Monitoring = 3,          //!< Watching mempool
    Completed = 4,
    Failed = 5,
    Expired = 6,
    Cancelled = 7,
};

/**
 * Persistent payjoin session state.
 *
 * Stored in the wallet database under DBKeys::PAYJOIN_SESSION.
 * Contains all state needed to resume protocol after restart.
 */
struct PayjoinSession {
    static constexpr uint8_t CURRENT_VERSION = 1;
    uint8_t version{CURRENT_VERSION};

    uint256 session_id;            //!< Random 256-bit session identifier
    SessionRole role{SessionRole::Sender};
    int64_t created_at{0};         //!< Unix timestamp
    int64_t expires_at{0};         //!< Unix timestamp

    // --- Sender fields ---
    SenderState sender_state{SenderState::Created};
    CKey reply_key;                //!< Ephemeral sender keypair for decrypting proposal
    CPubKey receiver_pubkey;       //!< Receiver's public key from URI
    std::string directory_url;
    PartiallySignedTransaction original_psbt;
    std::optional<PartiallySignedTransaction> proposal_psbt;

    // --- Receiver fields ---
    ReceiverState receiver_state{ReceiverState::Initialized};
    CKey receiver_key;             //!< Ephemeral receiver keypair
    std::optional<CPubKey> sender_reply_pubkey; //!< Learned from Message A
    std::string payjoin_uri;       //!< Generated BIP 21 URI

    // --- Shared fields ---
    ohttp::KeyConfig ohttp_keys;   //!< Directory OHTTP key config
    std::optional<uint256> final_txid;
    std::string error_message;
    int64_t last_poll_time{0};     //!< Unix timestamp of last background poll
    bool sender_disable_output_substitution{false};
    std::string original_query_params;

    /** Check if the session is in a terminal state. */
    bool IsTerminal() const
    {
        if (role == SessionRole::Sender) {
            return sender_state == SenderState::Completed ||
                   sender_state == SenderState::Failed ||
                   sender_state == SenderState::Expired ||
                   sender_state == SenderState::Cancelled;
        } else {
            return receiver_state == ReceiverState::Completed ||
                   receiver_state == ReceiverState::Failed ||
                   receiver_state == ReceiverState::Expired ||
                   receiver_state == ReceiverState::Cancelled;
        }
    }

    /** Check if the session is actively polling. */
    bool IsPolling() const
    {
        if (role == SessionRole::Sender) {
            return sender_state == SenderState::PostedOriginal ||
                   sender_state == SenderState::PollingForProposal;
        } else {
            return receiver_state == ReceiverState::Initialized ||
                   receiver_state == ReceiverState::ProposalSent ||
                   receiver_state == ReceiverState::Monitoring;
        }
    }

    /** Return a human-readable string for the current state. */
    std::string GetStateString() const
    {
        if (role == SessionRole::Sender) {
            switch (sender_state) {
            case SenderState::Created: return "created";
            case SenderState::PostedOriginal: return "posted_original";
            case SenderState::PollingForProposal: return "polling";
            case SenderState::Completed: return "completed";
            case SenderState::Failed: return "failed";
            case SenderState::Expired: return "expired";
            case SenderState::Cancelled: return "cancelled";
            }
        } else {
            switch (receiver_state) {
            case ReceiverState::Initialized: return "initialized";
            case ReceiverState::ReceivedOriginal: return "received_original";
            case ReceiverState::ProposalSent: return "proposal_sent";
            case ReceiverState::Monitoring: return "monitoring";
            case ReceiverState::Completed: return "completed";
            case ReceiverState::Failed: return "failed";
            case ReceiverState::Expired: return "expired";
            case ReceiverState::Cancelled: return "cancelled";
            }
        }
        return "unknown";
    }

    /** Custom serialization for wallet database persistence.
     *  CKey requires manual serialization since it lacks SERIALIZE_METHODS.
     *  PSBT fields are length-prefixed to avoid issues with PSBT's
     *  self-delimiting format and default-constructed (tx=nullopt) PSBTs. */
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << version;
        s << session_id;
        s << static_cast<uint8_t>(role);
        s << created_at;
        s << expires_at;

        // Sender state
        s << static_cast<uint8_t>(sender_state);

        // CKey: serialize as (valid_flag, compressed_flag, 32_bytes)
        SerializeCKey(s, reply_key);

        s << receiver_pubkey;
        s << directory_url;

        // PSBT: wrap in length-prefixed blob (safe for default-constructed PSBTs)
        SerializePSBTField(s, original_psbt);
        SerializeOptionalPSBTField(s, proposal_psbt);

        // Receiver state
        s << static_cast<uint8_t>(receiver_state);
        SerializeCKey(s, receiver_key);

        bool has_reply_pk = sender_reply_pubkey.has_value();
        s << has_reply_pk;
        if (has_reply_pk) s << *sender_reply_pubkey;

        s << payjoin_uri;

        // OHTTP keys as serialized KeyConfig list
        auto ohttp_bytes = ohttp::SerializeKeyConfigList({ohttp_keys});
        s << ohttp_bytes;

        bool has_txid = final_txid.has_value();
        s << has_txid;
        if (has_txid) s << *final_txid;

        s << error_message;

        s << last_poll_time;
        s << sender_disable_output_substitution;
        s << original_query_params;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> version;
        s >> session_id;
        uint8_t role_byte; s >> role_byte; role = static_cast<SessionRole>(role_byte);
        s >> created_at;
        s >> expires_at;

        uint8_t sender_state_byte; s >> sender_state_byte;
        sender_state = static_cast<SenderState>(sender_state_byte);

        UnserializeCKey(s, reply_key);

        s >> receiver_pubkey;
        s >> directory_url;

        UnserializePSBTField(s, original_psbt);
        UnserializeOptionalPSBTField(s, proposal_psbt);

        uint8_t receiver_state_byte; s >> receiver_state_byte;
        receiver_state = static_cast<ReceiverState>(receiver_state_byte);

        UnserializeCKey(s, receiver_key);

        bool has_reply_pk; s >> has_reply_pk;
        if (has_reply_pk) {
            sender_reply_pubkey.emplace();
            s >> *sender_reply_pubkey;
        }

        s >> payjoin_uri;

        std::vector<uint8_t> ohttp_bytes;
        s >> ohttp_bytes;
        if (!ohttp_bytes.empty()) {
            auto configs = ohttp::ParseKeyConfigList(ohttp_bytes);
            if (!configs.empty()) ohttp_keys = configs[0];
        }

        bool has_txid; s >> has_txid;
        if (has_txid) {
            final_txid.emplace();
            s >> *final_txid;
        }

        s >> error_message;

        // last_poll_time was added after initial format; gracefully handle
        // old sessions that don't have it.
        try {
            s >> last_poll_time;
        } catch (...) {
            last_poll_time = 0;
        }

        try {
            s >> sender_disable_output_substitution;
            s >> original_query_params;
        } catch (...) {
            sender_disable_output_substitution = false;
            original_query_params.clear();
        }
    }

private:
    template <typename Stream>
    static void SerializeCKey(Stream& s, const CKey& key)
    {
        bool valid = key.IsValid();
        s << valid;
        if (valid) {
            bool compressed = key.IsCompressed();
            s << compressed;
            std::vector<uint8_t> key_data(32);
            std::memcpy(key_data.data(), key.data(), 32);
            s << key_data;
        }
    }

    template <typename Stream>
    static void UnserializeCKey(Stream& s, CKey& key)
    {
        bool valid; s >> valid;
        if (valid) {
            bool compressed; s >> compressed;
            std::vector<uint8_t> key_data;
            s >> key_data;
            if (key_data.size() == 32) {
                key.Set(key_data.begin(), key_data.end(), compressed);
            }
        }
    }

    /** Serialize a PSBT as a length-prefixed blob.
     *  Writes empty vector if PSBT has no tx (default-constructed). */
    template <typename Stream>
    static void SerializePSBTField(Stream& s, const PartiallySignedTransaction& psbt)
    {
        bool has_tx = psbt.tx.has_value();
        s << has_tx;
        if (has_tx) {
            DataStream ds;
            ds << psbt;
            std::vector<uint8_t> psbt_data(ds.size());
            std::memcpy(psbt_data.data(), ds.data(), ds.size());
            s << psbt_data;
        }
    }

    template <typename Stream>
    static void UnserializePSBTField(Stream& s, PartiallySignedTransaction& psbt)
    {
        bool has_tx; s >> has_tx;
        if (has_tx) {
            std::vector<uint8_t> psbt_data;
            s >> psbt_data;
            DataStream ds(psbt_data);
            ds >> psbt;
        }
    }

    /** Serialize an optional PSBT field. */
    template <typename Stream>
    static void SerializeOptionalPSBTField(Stream& s, const std::optional<PartiallySignedTransaction>& psbt)
    {
        bool has_value = psbt.has_value();
        s << has_value;
        if (has_value) {
            SerializePSBTField(s, *psbt);
        }
    }

    template <typename Stream>
    static void UnserializeOptionalPSBTField(Stream& s, std::optional<PartiallySignedTransaction>& psbt)
    {
        bool has_value; s >> has_value;
        if (has_value) {
            psbt.emplace();
            UnserializePSBTField(s, *psbt);
        }
    }
};

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_SESSION_H

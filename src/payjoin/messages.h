// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_MESSAGES_H
#define BITCOIN_PAYJOIN_MESSAGES_H

#include <key.h>
#include <pubkey.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace payjoin {

// BIP 77 message constants
constexpr size_t PADDED_MESSAGE_BYTES = 7168;
constexpr size_t ELLSWIFT_SIZE = 64;
constexpr size_t COMPRESSED_PK_SIZE = 33;
constexpr size_t AEAD_TAG_SIZE = 16;
constexpr size_t PADDED_PLAINTEXT_A = PADDED_MESSAGE_BYTES - ELLSWIFT_SIZE - COMPRESSED_PK_SIZE - AEAD_TAG_SIZE; // 7055
constexpr size_t PADDED_PLAINTEXT_B = PADDED_MESSAGE_BYTES - ELLSWIFT_SIZE - AEAD_TAG_SIZE; // 7088

// Domain separation info strings per BIP 77
constexpr char INFO_A[] = "PjV2MsgA";
constexpr char INFO_B[] = "PjV2MsgB";

/**
 * Encrypt Message A (sender -> receiver, HPKE Base mode).
 *
 * The body (Original PSBT) is zero-padded to PADDED_PLAINTEXT_A bytes, then
 * prepended with the sender's compressed reply public key, encrypted with
 * HPKE Base mode to the receiver's public key, and wrapped with an
 * ElligatorSwift-encoded ephemeral key for the wire.
 *
 * @param[in] body      Plaintext body; must be <= PADDED_PLAINTEXT_A bytes
 * @param[in] reply_pk  Sender's ephemeral reply public key (compressed, 33 bytes)
 * @param[in] receiver_pk Receiver's public key (compressed, 33 bytes)
 * @return Exactly PADDED_MESSAGE_BYTES (7168) bytes, or nullopt on failure
 */
std::optional<std::array<uint8_t, PADDED_MESSAGE_BYTES>>
EncryptMessageA(std::span<const uint8_t> body,
                const CPubKey& reply_pk,
                const CPubKey& receiver_pk);

/**
 * Decrypt Message A.
 *
 * @param[in] message_a  Exactly PADDED_MESSAGE_BYTES bytes
 * @param[in] receiver_sk Receiver's private key
 * @return (padded_body, reply_pk) pair, or nullopt on failure.
 *         padded_body is PADDED_PLAINTEXT_A bytes (caller strips trailing zeros).
 */
std::optional<std::pair<std::vector<uint8_t>, CPubKey>>
DecryptMessageA(std::span<const uint8_t> message_a,
                const CKey& receiver_sk);

/**
 * Encrypt Message B (receiver -> sender, HPKE Auth mode).
 *
 * The body (Proposal PSBT) is zero-padded to PADDED_PLAINTEXT_B bytes,
 * encrypted with HPKE Auth mode (receiver authenticates), and wrapped with
 * an ElligatorSwift-encoded ephemeral key.
 *
 * @param[in] body            Plaintext body; must be <= PADDED_PLAINTEXT_B bytes
 * @param[in] receiver_sk     Receiver's private key (for authentication)
 * @param[in] receiver_pk     Receiver's public key (compressed)
 * @param[in] sender_reply_pk Sender's ephemeral reply public key (compressed)
 * @return Exactly PADDED_MESSAGE_BYTES (7168) bytes, or nullopt on failure
 */
std::optional<std::array<uint8_t, PADDED_MESSAGE_BYTES>>
EncryptMessageB(std::span<const uint8_t> body,
                const CKey& receiver_sk,
                const CPubKey& receiver_pk,
                const CPubKey& sender_reply_pk);

/**
 * Decrypt Message B.
 *
 * @param[in] message_b      Exactly PADDED_MESSAGE_BYTES bytes
 * @param[in] receiver_pk    Receiver's public key (for auth verification)
 * @param[in] sender_reply_sk Sender's ephemeral reply private key
 * @return Padded body (PADDED_PLAINTEXT_B bytes), or nullopt on failure
 */
std::optional<std::vector<uint8_t>>
DecryptMessageB(std::span<const uint8_t> message_b,
                const CPubKey& receiver_pk,
                const CKey& sender_reply_sk);

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_MESSAGES_H

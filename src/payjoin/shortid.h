// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_SHORTID_H
#define BITCOIN_PAYJOIN_SHORTID_H

#include <pubkey.h>

#include <array>
#include <string>

namespace payjoin {

/** Size of a BIP 77 Short ID in bytes (SHA256 truncated to 8 bytes). */
constexpr size_t SHORT_ID_SIZE = 8;

using ShortId = std::array<uint8_t, SHORT_ID_SIZE>;

/**
 * Derive a BIP 77 Short ID from a compressed public key.
 * Short ID = SHA256(compressed_pubkey)[0..8]
 */
ShortId DeriveShortId(const CPubKey& pubkey);

/**
 * Encode a Short ID as an uppercase bech32-charset string (no HRP, no checksum).
 */
std::string EncodeShortId(const ShortId& id);

/**
 * Build the full mailbox URL for a given directory base URL and public key.
 * Returns directory_base + "/" + EncodeShortId(DeriveShortId(pubkey))
 */
std::string MailboxUrl(const std::string& directory_base, const CPubKey& pubkey);

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_SHORTID_H

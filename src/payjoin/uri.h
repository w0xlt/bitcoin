// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_URI_H
#define BITCOIN_PAYJOIN_URI_H

#include <addresstype.h>
#include <consensus/amount.h>
#include <ohttp/ohttp.h>
#include <pubkey.h>

#include <cstdint>
#include <optional>
#include <string>

namespace payjoin {

/** Parameters extracted from the pj URI fragment (EX, OH, RK). */
struct PjParam {
    std::string mailbox_url;       //!< Full mailbox endpoint URL from the pj parameter
    CPubKey receiver_key;           //!< RK: receiver's ephemeral public key (compressed)
    ohttp::KeyConfig ohttp_keys;   //!< OH: directory OHTTP key config
    int64_t expiration{0};          //!< EX: unix timestamp
};

/** A fully parsed BIP 21 + BIP 77 payjoin URI. */
struct PayjoinUri {
    CTxDestination address;         //!< Bitcoin address
    std::optional<CAmount> amount;  //!< Optional BTC amount
    bool output_substitution{true}; //!< pjos parameter (default: allowed)
    PjParam pj;                     //!< Payjoin-specific params
};

/**
 * Parse a BIP 21 URI containing a BIP 77 payjoin `pj` parameter.
 *
 * Expected format:
 *   bitcoin:<address>?amount=<btc>&pjos=<0|1>&pj=HTTP://EXAMPLE.ONION/<shortid>%23EX1<data>-OH1<data>-RK1<data>
 *
 * The `pj` value is the mailbox endpoint URL itself. The fragment (after %23)
 * contains EX, OH, RK params separated by '-', each encoded as HRP + '1' +
 * bech32-charset data (no checksum). Only cleartext `http://` transport URLs
 * are supported by this wallet.
 *
 * @param[in] uri_str The full BIP 21 URI string
 * @return Parsed PayjoinUri or nullopt on failure
 */
std::optional<PayjoinUri> ParsePayjoinUri(const std::string& uri_str);

/**
 * Extract the directory base URL (scheme + authority) from a BIP 77 mailbox
 * endpoint URL. Returns nullopt if the URL does not contain exactly one path
 * segment for the mailbox Short ID.
 */
std::optional<std::string> DirectoryUrlFromMailboxUrl(const std::string& mailbox_url);

/**
 * Build a BIP 21 + BIP 77 payjoin URI string.
 *
 * @param[in] uri The PayjoinUri to serialize
 * @return The URI string
 */
std::string BuildPayjoinUri(const PayjoinUri& uri);

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_URI_H

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_ORIGINAL_H
#define BITCOIN_PAYJOIN_ORIGINAL_H

#include <psbt.h>

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace payjoin {

struct OriginalPayload {
    PartiallySignedTransaction psbt;
    std::string query_params;
};

/** Build the Message A sender-query string for a v2 payjoin request. */
std::string BuildOriginalPayloadQuery(bool disable_output_substitution);

/** Serialize the Original PSBT body as required by BIP 77 Message A. */
std::vector<uint8_t> SerializeOriginalPayload(const PartiallySignedTransaction& psbt,
                                             std::string_view query_params);

/** Parse a decrypted BIP 77 Message A body. */
std::optional<OriginalPayload> DeserializeOriginalPayload(std::span<const uint8_t> plaintext);

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_ORIGINAL_H

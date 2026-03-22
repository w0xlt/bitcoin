// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_ORIGINAL_H
#define BITCOIN_PAYJOIN_ORIGINAL_H

#include <policy/feerate.h>
#include <psbt.h>

#include <optional>
#include <span>
#include <string_view>
#include <string>
#include <vector>

namespace payjoin {

struct SenderFeeContribution {
    CAmount max_additional_fee_contribution{0};
    size_t additional_fee_output_index{0};
};

struct OriginalPayloadParams {
    bool disable_output_substitution{false};
    std::optional<SenderFeeContribution> additional_fee_contribution;
    CFeeRate min_fee_rate{};
};

struct OriginalPayload {
    PartiallySignedTransaction psbt;
    std::string query_params;
    OriginalPayloadParams params;
};

/** Build the Message A sender-query string for a v2 payjoin request. */
std::string BuildOriginalPayloadQuery(bool disable_output_substitution);

/** Parse the Message A sender-query string for a v2 payjoin request. */
std::optional<OriginalPayloadParams> ParseOriginalPayloadQuery(std::string_view query_params);

/** Serialize the Original PSBT body as required by BIP 77 Message A. */
std::vector<uint8_t> SerializeOriginalPayload(const PartiallySignedTransaction& psbt,
                                             std::string_view query_params);

/** Parse a decrypted BIP 77 Message A body. */
std::optional<OriginalPayload> DeserializeOriginalPayload(std::span<const uint8_t> plaintext);

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_ORIGINAL_H

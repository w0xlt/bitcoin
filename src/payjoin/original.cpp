// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/original.h>

#include <psbt.h>
#include <streams.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace payjoin {

namespace {

static std::vector<uint8_t> SerializePSBT(const PartiallySignedTransaction& psbt)
{
    DataStream ds;
    ds << psbt;
    std::vector<uint8_t> result(ds.size());
    std::memcpy(result.data(), ds.data(), ds.size());
    return result;
}

} // namespace

std::string BuildOriginalPayloadQuery(bool disable_output_substitution)
{
    std::string query = "v=2";
    if (disable_output_substitution) {
        query += "&disableoutputsubstitution=true";
    }
    return query;
}

std::vector<uint8_t> SerializeOriginalPayload(const PartiallySignedTransaction& psbt,
                                              std::string_view query_params)
{
    const auto psbt_bytes = SerializePSBT(psbt);
    std::string payload = EncodeBase64(std::span<const unsigned char>(psbt_bytes.data(), psbt_bytes.size()));
    payload += "\n";
    payload += query_params;
    return std::vector<uint8_t>(payload.begin(), payload.end());
}

std::optional<OriginalPayload> DeserializeOriginalPayload(std::span<const uint8_t> plaintext)
{
    const auto newline = std::find(plaintext.begin(), plaintext.end(), static_cast<uint8_t>('\n'));
    if (newline == plaintext.end()) return std::nullopt;

    const auto newline_index = std::distance(plaintext.begin(), newline);
    const std::string base64_psbt(reinterpret_cast<const char*>(plaintext.data()), newline_index);

    std::string query_params;
    if (newline_index + 1 < static_cast<decltype(newline_index)>(plaintext.size())) {
        query_params.assign(reinterpret_cast<const char*>(plaintext.data() + newline_index + 1),
                            plaintext.size() - newline_index - 1);
        while (!query_params.empty() && query_params.back() == '\0') {
            query_params.pop_back();
        }
    }

    PartiallySignedTransaction psbt;
    std::string error;
    if (!DecodeBase64PSBT(psbt, base64_psbt, error)) return std::nullopt;

    return OriginalPayload{std::move(psbt), std::move(query_params)};
}

} // namespace payjoin

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/original.h>

#include <payjoin/psbt_sanitize.h>

#include <policy/policy.h>
#include <psbt.h>
#include <streams.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace payjoin {

namespace {

static std::vector<uint8_t> SerializePSBT(const PartiallySignedTransaction& psbt)
{
    auto sanitized = psbt;
    StripUnneededPSBTFields(sanitized);

    DataStream ds;
    ds << sanitized;
    std::vector<uint8_t> result(ds.size());
    std::memcpy(result.data(), ds.data(), ds.size());
    return result;
}

std::optional<size_t> ParseSize(std::string_view value)
{
    if (value.empty()) return std::nullopt;

    size_t result{0};
    for (const char ch : value) {
        if (ch < '0' || ch > '9') return std::nullopt;
        if (result > (std::numeric_limits<size_t>::max() - static_cast<size_t>(ch - '0')) / 10) {
            return std::nullopt;
        }
        result = result * 10 + static_cast<size_t>(ch - '0');
    }
    return result;
}

std::optional<CAmount> ParseAmountSats(std::string_view value)
{
    if (value.empty()) return std::nullopt;

    CAmount result{0};
    for (const char ch : value) {
        if (ch < '0' || ch > '9') return std::nullopt;
        if (result > (std::numeric_limits<CAmount>::max() - (ch - '0')) / 10) {
            return std::nullopt;
        }
        result = result * 10 + (ch - '0');
    }
    return result;
}

std::optional<CFeeRate> ParseSenderMinFeeRate(std::string_view value)
{
    int64_t sats_per_vb_e8{0};
    if (!ParseFixedPoint(value, /*decimals=*/8, &sats_per_vb_e8) || sats_per_vb_e8 < 0) {
        return std::nullopt;
    }

    static constexpr int64_t SCALE{100'000'000};
    const int64_t sats_per_kvb = (sats_per_vb_e8 * 1000 + SCALE - 1) / SCALE;
    return CFeeRate{sats_per_kvb};
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

std::optional<OriginalPayloadParams> ParseOriginalPayloadQuery(std::string_view query_params)
{
    OriginalPayloadParams params;
    params.min_fee_rate = CFeeRate{DEFAULT_MIN_RELAY_TX_FEE};

    bool saw_version{false};
    std::optional<size_t> additional_fee_output_index;
    std::optional<CAmount> max_additional_fee_contribution;

    while (!query_params.empty()) {
        const size_t next_amp = query_params.find('&');
        const std::string_view pair = query_params.substr(0, next_amp);
        query_params = next_amp == std::string_view::npos ? std::string_view{} : query_params.substr(next_amp + 1);
        if (pair.empty()) continue;

        const size_t eq = pair.find('=');
        const std::string_view key = pair.substr(0, eq);
        const std::string_view value = eq == std::string_view::npos ? std::string_view{} : pair.substr(eq + 1);

        if (key == "v") {
            if (value != "2") return std::nullopt;
            saw_version = true;
        } else if (key == "disableoutputsubstitution") {
            params.disable_output_substitution = value == "true";
        } else if (key == "additionalfeeoutputindex") {
            additional_fee_output_index = ParseSize(value);
        } else if (key == "maxadditionalfeecontribution") {
            max_additional_fee_contribution = ParseAmountSats(value);
        } else if (key == "minfeerate") {
            auto fee_rate = ParseSenderMinFeeRate(value);
            if (!fee_rate) return std::nullopt;
            params.min_fee_rate = *fee_rate;
        }
    }

    if (!saw_version) return std::nullopt;

    if (additional_fee_output_index && max_additional_fee_contribution) {
        params.additional_fee_contribution = SenderFeeContribution{
            .max_additional_fee_contribution = *max_additional_fee_contribution,
            .additional_fee_output_index = *additional_fee_output_index,
        };
    }

    return params;
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

    auto params = ParseOriginalPayloadQuery(query_params);
    if (!params) return std::nullopt;

    return OriginalPayload{std::move(psbt), std::move(query_params), *params};
}

} // namespace payjoin

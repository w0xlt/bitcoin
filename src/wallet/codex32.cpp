// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/codex32.h>

#include <bech32.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <array>
#include <cassert>
#include <cstring>
#include <optional>

namespace wallet {
namespace {

struct ChecksumEngine {
    std::array<uint8_t, 15> generator;
    std::array<uint8_t, 15> residue;
    std::array<uint8_t, 15> target;
    size_t len;
    size_t max_payload_len;
};

static constexpr std::array<ChecksumEngine, 2> INITIAL_ENGINE_CSUM{{
    {
        {25, 27, 17, 8, 0, 25, 25, 25, 31, 27, 24, 16, 16, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
        {16, 25, 24, 3, 25, 11, 16, 23, 29, 3, 25, 17, 10, 0, 0},
        13,
        74,
    },
    {
        {15, 10, 25, 26, 9, 25, 21, 6, 23, 21, 6, 5, 22, 4, 23},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        {16, 25, 24, 3, 25, 11, 16, 23, 29, 3, 25, 17, 10, 25, 6},
        15,
        103,
    },
}};

static constexpr uint8_t LOGI[32] = {
    0, 0, 1, 14, 2, 28, 15, 22,
    3, 5, 29, 26, 16, 7, 23, 11,
    4, 25, 6, 10, 30, 13, 27, 21,
    17, 18, 8, 19, 24, 9, 12, 20,
};

static constexpr uint8_t LOG_INV[31] = {
    1, 2, 4, 8, 16, 9, 18, 13,
    26, 29, 19, 15, 30, 21, 3, 6,
    12, 24, 25, 27, 31, 23, 7, 14,
    28, 17, 11, 22, 5, 10, 20,
};

inline void AdditionGF32(uint8_t& x, uint8_t y)
{
    x ^= y;
}

inline void MultiplyGF32(uint8_t& x, uint8_t y)
{
    if (x == 0 || y == 0) {
        x = 0;
    } else {
        x = LOG_INV[(LOGI[x] + LOGI[y]) % 31];
    }
}

void InputFE(const std::array<uint8_t, 15>& generator, std::array<uint8_t, 15>& residue, uint8_t e, size_t len)
{
    uint8_t xn = residue[0];

    for (size_t i = 1; i < len; ++i) {
        residue[i - 1] = residue[i];
    }

    residue[len - 1] = e;

    for (size_t i = 0; i < len; ++i) {
        uint8_t x = generator[i];
        MultiplyGF32(x, xn);
        AdditionGF32(residue[i], x);
    }
}

void InputHRP(const std::array<uint8_t, 15>& generator, std::array<uint8_t, 15>& residue, const std::string& hrp, size_t len)
{
    for (const char c : hrp) {
        InputFE(generator, residue, c >> 5, len);
    }
    InputFE(generator, residue, 0, len); // separator
    for (const char c : hrp) {
        InputFE(generator, residue, c & 0x1f, len);
    }
}

void InputDataStr(const std::array<uint8_t, 15>& generator, std::array<uint8_t, 15>& residue, const std::string& data_str, size_t len)
{
    for (const char c : data_str) {
        InputFE(generator, residue, bech32::CHARSET_REV[static_cast<int>(c)], len);
    }
}

void InputOwnTarget(const std::array<uint8_t, 15>& generator, std::array<uint8_t, 15>& residue, const std::array<uint8_t, 15>& target, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        InputFE(generator, residue, target[i], len);
    }
}

bool ChecksumVerify(const std::string& hrp, const std::string& codex_data_str, const ChecksumEngine& initial_engine)
{
    ChecksumEngine engine = initial_engine;

    InputHRP(engine.generator, engine.residue, hrp, engine.len);
    InputDataStr(engine.generator, engine.residue, codex_data_str, engine.len);

    return std::memcmp(engine.target.data(), engine.residue.data(), engine.len) == 0;
}

void CalculateChecksum(const std::string& hrp, std::string& checksum, const std::string& codex_data_str, const ChecksumEngine& initial_engine)
{
    ChecksumEngine engine = initial_engine;

    InputHRP(engine.generator, engine.residue, hrp, engine.len);
    InputDataStr(engine.generator, engine.residue, codex_data_str, engine.len);
    InputOwnTarget(engine.generator, engine.residue, engine.target, engine.len);

    checksum.clear();
    for (size_t i = 0; i < engine.len; ++i) {
        checksum += bech32::CHARSET[engine.residue[i]];
    }
}

std::vector<uint8_t> DecodePayload(const std::string& payload)
{
    std::vector<uint8_t> ret;
    ret.reserve((payload.length() * 5 + 7) / 8);

    uint8_t next_byte = 0;
    uint8_t rem = 0;

    for (const char c : payload) {
        const uint8_t fe = bech32::CHARSET_REV[static_cast<int>(c)];

        if (rem < 3) {
            next_byte |= fe << (3 - rem);
        } else if (rem == 3) {
            ret.push_back(next_byte | fe);
            next_byte = 0;
        } else {
            const uint8_t overshoot = rem - 3;
            assert(overshoot > 0);
            ret.push_back(next_byte | (fe >> overshoot));
            next_byte = (fe << (8 - overshoot)) & 0xff;
        }

        rem = (rem + 5) % 8;
    }

    if (rem > 4) {
        return {};
    }
    if (rem != 0 && next_byte != 0) {
        return {};
    }

    return ret;
}

std::optional<std::pair<std::string, size_t>> Bech32CaseFixup(const std::string& codex32_str)
{
    std::string result = codex32_str;
    size_t sep_pos = std::string::npos;
    bool was_upper = false;

    if (!result.empty() && result[0] >= 'A' && result[0] <= 'Z') {
        was_upper = true;
    }

    for (size_t i = 0; i < result.length(); ++i) {
        int c = result[i];

        if (c == '1') {
            if (sep_pos != std::string::npos) {
                return std::nullopt;
            }
            sep_pos = i;
            continue;
        }

        if (c < 0 || c > 127) {
            return std::nullopt;
        }

        if (was_upper) {
            if (c >= 'a' && c <= 'z') {
                return std::nullopt;
            }
            result[i] = ToLower(c);
            c = result[i];
        } else if (c >= 'A' && c <= 'Z') {
            return std::nullopt;
        }

        if (bech32::CHARSET_REV[c] == -1) {
            return std::nullopt;
        }
    }

    return std::make_pair(result, sep_pos);
}

} // namespace

std::optional<Codex32> Codex32Decode(const std::string& hrp, const std::string& codex32_str, std::string& error_str)
{
    Codex32 parts;

    const auto fixup_result = Bech32CaseFixup(codex32_str);
    if (!fixup_result) {
        error_str = "Not a valid bech32 string!";
        return std::nullopt;
    }

    const std::string& normalized_str = fixup_result->first;
    const size_t sep_pos = fixup_result->second;

    if (sep_pos == std::string::npos) {
        error_str = "Separator doesn't exist!";
        return std::nullopt;
    }

    parts.hrp = normalized_str.substr(0, sep_pos);
    if (!hrp.empty() && parts.hrp != hrp) {
        error_str = "Invalid hrp " + parts.hrp + "!";
        return std::nullopt;
    }

    const std::string codex_data_str = normalized_str.substr(sep_pos + 1);
    const size_t maxlen = codex_data_str.length();

    const ChecksumEngine& checksum_engine = INITIAL_ENGINE_CSUM[maxlen >= 96 ? 1 : 0];
    if (!ChecksumVerify(parts.hrp, codex_data_str, checksum_engine)) {
        error_str = "Invalid checksum!";
        return std::nullopt;
    }

    if (codex_data_str.length() < 1 + 4 + 1 + checksum_engine.len) {
        error_str = "Too short!";
        return std::nullopt;
    }

    const char threshold_char = codex_data_str[0];
    std::memcpy(parts.id.data(), codex_data_str.data() + 1, 4);
    parts.id[4] = '\0';
    parts.share_idx = codex_data_str[5];

    const size_t payload_len = codex_data_str.length() - 6 - checksum_engine.len;
    if (payload_len > checksum_engine.max_payload_len) {
        error_str = "Invalid length!";
        return std::nullopt;
    }

    const std::string payload_str = codex_data_str.substr(6, payload_len);
    parts.payload = DecodePayload(payload_str);
    if (parts.payload.empty() && !payload_str.empty()) {
        error_str = "Invalid payload!";
        return std::nullopt;
    }

    parts.type = parts.share_idx == 's' ? Codex32Encoding::SECRET : Codex32Encoding::SHARE;

    parts.threshold = threshold_char - '0';
    if (parts.threshold == 1 || parts.threshold > 9) {
        error_str = "Invalid threshold!";
        return std::nullopt;
    }

    if (parts.threshold == 0 && parts.type != Codex32Encoding::SECRET) {
        error_str = "Expected share index s for threshold 0!";
        return std::nullopt;
    }

    return parts;
}

std::string Codex32SecretEncode(
    const std::string& hrp,
    const std::string& id,
    uint32_t threshold,
    const std::vector<uint8_t>& seed,
    std::string& error_str)
{
    assert(hrp.length() == 2);

    if (threshold == 1 || threshold > 9) {
        error_str = "Invalid threshold " + util::ToString(threshold);
        return "";
    }

    if (id.length() != 4) {
        error_str = "Invalid id: must be 4 characters";
        return "";
    }

    for (const char c : id) {
        if (c & 0x80) {
            error_str = "Invalid id: must be ASCII";
            return "";
        }

        const int8_t rev = bech32::CHARSET_REV[static_cast<int>(c)];
        if (rev == -1) {
            error_str = "Invalid id: must be valid bech32 string";
            return "";
        }
        if (bech32::CHARSET[rev] != c) {
            error_str = "Invalid id: must be lower-case";
            return "";
        }
    }

    std::string bip93 = hrp + "1" + util::ToString(threshold) + id + "s";

    uint8_t next_u5 = 0;
    uint8_t rem = 0;

    for (const uint8_t byte : seed) {
        const uint8_t u5 = ((next_u5 << (5 - rem)) | (byte >> (3 + rem))) & 0x1f;
        bip93 += bech32::CHARSET[u5];
        next_u5 = byte & ((1 << (3 + rem)) - 1);

        if (rem >= 2) {
            bip93 += bech32::CHARSET[next_u5 >> (rem - 2)];
            next_u5 &= (1 << (rem - 2)) - 1;
        }
        rem = (rem + 8) % 5;
    }
    if (rem > 0) {
        bip93 += bech32::CHARSET[(next_u5 << (5 - rem)) & 0x1f];
    }

    const size_t payload_len = bip93.size() - hrp.size() - 7;
    const ChecksumEngine& checksum_engine = INITIAL_ENGINE_CSUM[payload_len > INITIAL_ENGINE_CSUM[0].max_payload_len ? 1 : 0];
    std::string checksum;
    CalculateChecksum(hrp, checksum, bip93.substr(3), checksum_engine);
    bip93 += checksum;

    return bip93;
}

} // namespace wallet

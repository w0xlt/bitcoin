// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_CODEX32_H
#define BITCOIN_WALLET_CODEX32_H

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wallet {

enum class Codex32Encoding {
    SHARE,
    SECRET,
};

struct Codex32
{
    //! Human-readable part, e.g. "ms"
    std::string hrp;
    //! Threshold, either 0 or 2-9
    uint8_t threshold;
    //! 4-character identifier plus null terminator
    std::array<char, 5> id;
    //! Share index character, or 's' for a secret
    char share_idx;
    //! Raw decoded payload bytes
    std::vector<uint8_t> payload;
    //! Whether this encodes a share or a full secret
    Codex32Encoding type;
};

std::optional<Codex32> Codex32Decode(const std::string& hrp, const std::string& codex32_str, std::string& error_str);

std::string Codex32SecretEncode(
    const std::string& hrp,
    const std::string& id,
    uint32_t threshold,
    const std::vector<uint8_t>& seed,
    std::string& error_str);

} // namespace wallet

#endif // BITCOIN_WALLET_CODEX32_H

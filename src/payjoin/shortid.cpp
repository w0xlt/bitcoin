// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/shortid.h>

#include <crypto/sha256.h>
#include <pubkey.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace payjoin {

// Bech32 charset (lowercase); we'll uppercase for BIP 77 wire format
static const char* BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

ShortId DeriveShortId(const CPubKey& pubkey)
{
    // SHA256(compressed_pubkey)[0..8]
    uint8_t hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(hash);

    ShortId id;
    std::copy(hash, hash + SHORT_ID_SIZE, id.begin());
    return id;
}

std::string EncodeShortId(const ShortId& id)
{
    // Convert 8 bytes to 5-bit groups using ConvertBits, then map to bech32 charset
    std::vector<uint8_t> base32;
    ConvertBits<8, 5, true>([&](uint8_t c) { base32.push_back(c); }, id.begin(), id.end());

    std::string result;
    result.reserve(base32.size());
    for (uint8_t v : base32) {
        char c = BECH32_CHARSET[v];
        // Uppercase for BIP 77
        if (c >= 'a' && c <= 'z') c -= 32;
        result += c;
    }
    return result;
}

std::string MailboxUrl(const std::string& directory_base, const CPubKey& pubkey)
{
    ShortId id = DeriveShortId(pubkey);
    std::string encoded = EncodeShortId(id);

    // Trim trailing slash from base URL if present
    std::string base = directory_base;
    if (!base.empty() && base.back() == '/') {
        base.pop_back();
    }
    return base + "/" + encoded;
}

} // namespace payjoin

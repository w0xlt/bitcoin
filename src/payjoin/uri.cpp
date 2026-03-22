// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/uri.h>

#include <consensus/amount.h>
#include <key_io.h>
#include <ohttp/ohttp.h>
#include <payjoin/net.h>
#include <pubkey.h>
#include <secp256k1.h>
#include <util/moneystr.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace payjoin {

// Bech32 charset (lowercase for decoding, uppercase for BIP 77 wire format)
static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t BECH32_CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
};

// ---------------------------------------------------------------------------
// Bech32 charset encoding/decoding (no checksum, no HRP separator)
// Used for BIP 77 fragment parameters
// ---------------------------------------------------------------------------

/** Encode raw bytes as bech32-charset string (no checksum). Returns uppercase. */
static std::string Bech32CharsetEncode(std::span<const uint8_t> data)
{
    std::vector<uint8_t> base32;
    ConvertBits<8, 5, true>([&](uint8_t c) { base32.push_back(c); }, data.begin(), data.end());

    std::string result;
    result.reserve(base32.size());
    for (uint8_t v : base32) {
        char c = BECH32_CHARSET[v];
        if (c >= 'a' && c <= 'z') c -= 32; // uppercase
        result += c;
    }
    return result;
}

/** Decode bech32-charset string (no checksum) to raw bytes. Case-insensitive. */
static std::optional<std::vector<uint8_t>> Bech32CharsetDecode(const std::string& str)
{
    std::vector<uint8_t> base32;
    for (char c : str) {
        uint8_t uc = static_cast<uint8_t>(c);
        if (uc >= 128) return std::nullopt;
        int8_t val = BECH32_CHARSET_REV[uc];
        if (val < 0) return std::nullopt;
        base32.push_back(static_cast<uint8_t>(val));
    }

    std::vector<uint8_t> result;
    if (!ConvertBits<5, 8, false>([&](uint8_t c) { result.push_back(c); }, base32.begin(), base32.end())) {
        return std::nullopt;
    }
    return result;
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/** Percent-decode a string (e.g., %23 -> #). */
static std::string PercentDecode(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int hi = HexDigit(s[i + 1]);
            int lo = HexDigit(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        out += s[i];
    }
    return out;
}

/** Percent-encode the '#' character for URI query values. */
static std::string PercentEncodeFragment(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '#') {
            out += "%23";
        } else {
            out += c;
        }
    }
    return out;
}

/** Parse query string into key-value pairs. Expects input without leading '?'. */
static std::map<std::string, std::string> ParseQueryString(const std::string& query)
{
    std::map<std::string, std::string> params;
    size_t start = 0;
    while (start < query.size()) {
        size_t end = query.find('&', start);
        if (end == std::string::npos) end = query.size();
        std::string pair = query.substr(start, end - start);
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = pair.substr(0, eq);
            std::string val = pair.substr(eq + 1);
            params[key] = val;
        }
        start = end + 1;
    }
    return params;
}

/** Extract scheme + authority from a mailbox endpoint URL with exactly one path segment. */
std::optional<std::string> DirectoryUrlFromMailboxUrl(const std::string& mailbox_url)
{
    if (!IsCleartextHttpUrl(mailbox_url)) return std::nullopt;

    size_t scheme_end = mailbox_url.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0) return std::nullopt;

    size_t authority_start = scheme_end + 3;
    size_t path_start = mailbox_url.find('/', authority_start);
    if (path_start == std::string::npos || path_start == authority_start) return std::nullopt;

    size_t query_pos = mailbox_url.find('?', path_start);
    if (query_pos != std::string::npos) return std::nullopt;

    std::string path = mailbox_url.substr(path_start);
    if (path.size() <= 1) return std::nullopt;
    if (path.back() == '/') return std::nullopt;
    if (path.find('/', 1) != std::string::npos) return std::nullopt;

    return mailbox_url.substr(0, path_start);
}

// ---------------------------------------------------------------------------
// BIP 77 fragment parsing
// ---------------------------------------------------------------------------

/** Parse BIP 77 fragment parameters from a string like "EX1<data>-OH1<data>-RK1<data>".
 *  Fragment must be uppercase. Parameters separated by '-' or '+'. */
static std::optional<std::map<std::string, std::string>> ParseFragment(const std::string& fragment)
{
    // Fragment must be uppercase
    for (char c : fragment) {
        if (c >= 'a' && c <= 'z') return std::nullopt;
    }

    std::map<std::string, std::string> params;
    size_t start = 0;
    while (start < fragment.size()) {
        size_t end = fragment.find_first_of("-+", start);
        if (end == std::string::npos) end = fragment.size();
        std::string token = fragment.substr(start, end - start);
        if (!token.empty()) {
            // Find the '1' separator between HRP and data
            size_t sep = token.find('1');
            if (sep != std::string::npos && sep > 0) {
                std::string hrp = token.substr(0, sep);
                std::string data = token.substr(sep + 1);
                params[hrp] = data;
            }
        }
        start = end + 1;
    }
    return params;
}

/** Decode the EX (expiration) parameter: bech32 charset -> 4 bytes -> uint32 big-endian. */
static std::optional<int64_t> DecodeExpiration(const std::string& data)
{
    auto bytes = Bech32CharsetDecode(data);
    if (!bytes || bytes->size() != 4) return std::nullopt;
    uint32_t ts = (static_cast<uint32_t>((*bytes)[0]) << 24) |
                  (static_cast<uint32_t>((*bytes)[1]) << 16) |
                  (static_cast<uint32_t>((*bytes)[2]) << 8) |
                  static_cast<uint32_t>((*bytes)[3]);
    return static_cast<int64_t>(ts);
}

/** Decode the OH (OHTTP keys) parameter: bech32 charset -> key_id(1) + compressed_pubkey(33) = 34 bytes. */
static std::optional<ohttp::KeyConfig> DecodeOhttpKeys(const std::string& data)
{
    auto bytes = Bech32CharsetDecode(data);
    if (!bytes || bytes->size() != 34) return std::nullopt;

    ohttp::KeyConfig cfg;
    cfg.key_id = (*bytes)[0];
    cfg.kem_id = ohttp::KEM_SECP256K1;

    // Decompress the 33-byte compressed pubkey to 65-byte uncompressed for KeyConfig
    CPubKey compressed(std::span<const uint8_t>(bytes->data() + 1, 33));
    if (!compressed.IsValid() || !compressed.IsCompressed()) return std::nullopt;

    CPubKey decompressed(compressed);
    if (!decompressed.Decompress()) return std::nullopt;
    if (decompressed.size() != 65) return std::nullopt;

    std::copy(decompressed.data(), decompressed.data() + 65, cfg.pkR.begin());

    // Fixed symmetric suite per BIP 77
    cfg.syms.push_back({ohttp::KDF_HKDF_SHA256, ohttp::AEAD_CHACHA20POLY1305});
    return cfg;
}

/** Decode the RK (receiver key) parameter: bech32 charset -> 33-byte compressed pubkey. */
static std::optional<CPubKey> DecodeReceiverKey(const std::string& data)
{
    auto bytes = Bech32CharsetDecode(data);
    if (!bytes || bytes->size() != 33) return std::nullopt;

    std::span<const uint8_t> key_span{bytes->data(), bytes->size()};
    CPubKey pk(key_span);
    if (!pk.IsValid() || !pk.IsCompressed()) return std::nullopt;
    return pk;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::optional<PayjoinUri> ParsePayjoinUri(const std::string& uri_str)
{
    // 1. Parse BIP 21 URI scheme
    const std::string prefix = "bitcoin:";
    std::string lower_uri = uri_str;
    // Case-insensitive scheme check
    std::string scheme_part = uri_str.substr(0, prefix.size());
    std::transform(scheme_part.begin(), scheme_part.end(), scheme_part.begin(), ::tolower);
    if (scheme_part != prefix) return std::nullopt;

    std::string body = uri_str.substr(prefix.size());

    // 2. Split address from query parameters
    std::string address_str;
    std::string query_str;
    size_t qpos = body.find('?');
    if (qpos != std::string::npos) {
        address_str = body.substr(0, qpos);
        query_str = body.substr(qpos + 1);
    } else {
        address_str = body;
    }

    // 3. Parse address
    PayjoinUri result;
    result.address = DecodeDestination(address_str);
    if (!IsValidDestination(result.address)) return std::nullopt;

    // 4. Parse query parameters
    auto params = ParseQueryString(query_str);

    // Amount (optional)
    auto it_amount = params.find("amount");
    if (it_amount != params.end()) {
        auto amount = ParseMoney(it_amount->second);
        if (amount) {
            result.amount = *amount;
        }
    }

    // Output substitution (pjos)
    auto it_pjos = params.find("pjos");
    if (it_pjos != params.end()) {
        result.output_substitution = (it_pjos->second != "0");
    }

    // 5. Parse pj parameter (required for payjoin)
    auto it_pj = params.find("pj");
    if (it_pj == params.end()) return std::nullopt;

    // Percent-decode the pj value to recover the '#' fragment separator
    std::string pj_value = PercentDecode(it_pj->second);

    // 6. Split pj value into URL and fragment at '#'
    size_t hash_pos = pj_value.find('#');
    if (hash_pos == std::string::npos) return std::nullopt;

    std::string mailbox_url = pj_value.substr(0, hash_pos);
    std::string fragment = pj_value.substr(hash_pos + 1);

    if (!DirectoryUrlFromMailboxUrl(mailbox_url)) return std::nullopt;
    result.pj.mailbox_url = mailbox_url;

    // 7. Parse fragment parameters
    auto frag_params = ParseFragment(fragment);
    if (!frag_params) return std::nullopt;

    // EX (expiration) - required
    auto it_ex = frag_params->find("EX");
    if (it_ex == frag_params->end()) return std::nullopt;
    auto expiration = DecodeExpiration(it_ex->second);
    if (!expiration) return std::nullopt;
    result.pj.expiration = *expiration;

    // OH (OHTTP keys) - required
    auto it_oh = frag_params->find("OH");
    if (it_oh == frag_params->end()) return std::nullopt;
    auto ohttp_keys = DecodeOhttpKeys(it_oh->second);
    if (!ohttp_keys) return std::nullopt;
    result.pj.ohttp_keys = *ohttp_keys;

    // RK (receiver key) - required
    auto it_rk = frag_params->find("RK");
    if (it_rk == frag_params->end()) return std::nullopt;
    auto receiver_key = DecodeReceiverKey(it_rk->second);
    if (!receiver_key) return std::nullopt;
    result.pj.receiver_key = *receiver_key;

    return result;
}

// ---------------------------------------------------------------------------
// Build URI
// ---------------------------------------------------------------------------

/** Encode uint32 as 4-byte big-endian, then bech32 charset. */
static std::string EncodeExpiration(int64_t timestamp)
{
    uint32_t ts = static_cast<uint32_t>(timestamp);
    std::array<uint8_t, 4> bytes = {
        static_cast<uint8_t>((ts >> 24) & 0xFF),
        static_cast<uint8_t>((ts >> 16) & 0xFF),
        static_cast<uint8_t>((ts >> 8) & 0xFF),
        static_cast<uint8_t>(ts & 0xFF)};
    return Bech32CharsetEncode(bytes);
}

/** Encode OHTTP KeyConfig: key_id(1) + compressed_pubkey(33) -> bech32 charset. */
static std::string EncodeOhttpKeys(const ohttp::KeyConfig& cfg)
{
    // Compress the 65-byte uncompressed pkR to 33-byte compressed form
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, cfg.pkR.data(), cfg.pkR.size())) {
        return {};
    }
    std::array<uint8_t, 33> compressed;
    size_t clen = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, compressed.data(), &clen, &pubkey, SECP256K1_EC_COMPRESSED);

    std::vector<uint8_t> data;
    data.reserve(34);
    data.push_back(cfg.key_id);
    data.insert(data.end(), compressed.begin(), compressed.end());
    return Bech32CharsetEncode(data);
}

/** Encode receiver key: compressed_pubkey(33) -> bech32 charset. */
static std::string EncodeReceiverKey(const CPubKey& pk)
{
    return Bech32CharsetEncode(std::span<const uint8_t>(pk.data(), pk.size()));
}

std::string BuildPayjoinUri(const PayjoinUri& uri)
{
    std::string result = "bitcoin:";
    result += EncodeDestination(uri.address);
    result += "?";

    // Amount
    if (uri.amount) {
        // Format amount. Use simple integer formatting for sats.
        // Bitcoin Core amounts are in satoshis; convert to BTC string
        int64_t sats = *uri.amount;
        int64_t whole = sats / 100000000;
        int64_t frac = sats % 100000000;
        result += "amount=";
        result += std::to_string(whole);
        if (frac > 0) {
            result += ".";
            std::string frac_str = std::to_string(frac);
            // Pad to 8 digits
            while (frac_str.size() < 8) frac_str = "0" + frac_str;
            // Trim trailing zeros
            while (!frac_str.empty() && frac_str.back() == '0') frac_str.pop_back();
            result += frac_str;
        }
        result += "&";
    }

    // Output substitution
    if (!uri.output_substitution) {
        result += "pjos=0&";
    }

    // Build pj parameter with fragment
    std::string fragment;
    fragment += "EX1" + EncodeExpiration(uri.pj.expiration);
    fragment += "-";
    fragment += "OH1" + EncodeOhttpKeys(uri.pj.ohttp_keys);
    fragment += "-";
    fragment += "RK1" + EncodeReceiverKey(uri.pj.receiver_key);

    result += "pj=";
    result += PercentEncodeFragment(uri.pj.mailbox_url + "#" + fragment);

    return result;
}

} // namespace payjoin

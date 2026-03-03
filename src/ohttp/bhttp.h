// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef BITCOIN_OHTTP_BHTTP_H
#define BITCOIN_OHTTP_BHTTP_H

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <optional>
#include <utility>

namespace bhttp {

// Minimal request shape for Payjoin v2
struct Request {
    std::string method;    // e.g. "POST"
    std::string scheme;    // "https" or "http"
    std::string authority; // host[:port]
    std::string path;      // absolute path + optional query, e.g. "/payjoin?..."
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
};

// Minimal response shape
struct Response {
    uint64_t status{0};    // 200..599
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
};

// Encode a known-length bHTTP Request (RFC 9292 §§3.1, 3.3, 3.4, 3.6, 3.7).
std::optional<std::vector<uint8_t>> EncodeKnownLengthRequest(const Request& r);

/**
 * Encode a known-length bHTTP Request padded to a target size.
 * The buffer is pre-filled with random bytes, then the bHTTP encoding is
 * written at the start. Remaining random bytes act as safe padding per
 * RFC 9292 §3.8 (padding after trailers is ignored by decoders).
 * Returns nullopt if the encoded request exceeds target_size.
 */
std::optional<std::vector<uint8_t>> EncodeKnownLengthRequestPadded(const Request& r, size_t target_size);

// Decode a known-length bHTTP Request (RFC 9292 §§3.1, 3.3, 3.4, 3.6, 3.7).
std::optional<Request> DecodeKnownLengthRequest(std::span<const uint8_t> in);

// Decode a known-length bHTTP Response (RFC 9292 §§3.1, 3.3, 3.5, 3.6, 3.7).
std::optional<Response> DecodeKnownLengthResponse(std::span<const uint8_t> in);

// Encode a known-length bHTTP Response (mirror of the decoder; useful for tests).
std::optional<std::vector<uint8_t>> EncodeKnownLengthResponse(const Response& r);

} // namespace bhttp

#endif // BITCOIN_OHTTP_BHTTP_H

// Copyright (c) 2025
// SPDX-License-Identifier: MIT

#ifndef BITCOIN_PROTOCOL_BHTTP_H
#define BITCOIN_PROTOCOL_BHTTP_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <utility>
#include <stdexcept>

namespace bhttp {

// --------- RFC 9292 helpers (known-length mode only) ---------
// Varint is the QUIC varint (1/2/4/8 bytes) per RFC 9292 §3; values < 2^62.
// We only need encode/decode for fields used here.  (Headers & content blocks).
// See RFC 9292 §3.1, §3.3, §3.6.  This is a small, safe implementation.  :contentReference[oaicite:4]{index=4}

struct VarintError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

void WriteVarint(uint64_t v, std::vector<uint8_t>& out);
bool ReadVarint(const uint8_t*& p, const uint8_t* end, uint64_t& out);

// Field line: name/value as length-prefixed byte-strings (QUIC varint lengths).
struct HeaderField {
    std::string name;
    std::string value;
};

using HeaderList = std::vector<HeaderField>;

struct Request {
    std::string method;     // e.g., "POST", "GET"
    std::string scheme;     // "https" or "http"
    std::string authority;  // "host[:port]"
    std::string path;       // "/foo"
    HeaderList headers;     // regular header fields (no pseudo-fields)
    std::vector<uint8_t> body; // request body
};

struct Response {
    uint32_t status = 0;        // 200..599 per RFC 9292 §3.5 (QUIC varint encoded)  :contentReference[oaicite:5]{index=5}
    HeaderList headers;
    std::vector<uint8_t> body;
};

// Known-length request encoder (framing indicator = 0). RFC 9292 §3.1/§3.4/§3.6. :contentReference[oaicite:6]{index=6}
std::vector<uint8_t> EncodeKnownLengthRequest(const Request& req);

// Known-length response decoder (framing indicator = 1). Minimal subset for Payjoin.
Response DecodeKnownLengthResponse(const std::vector<uint8_t>& buf);

// Utility
inline void AddHeader(HeaderList& h, std::string name, std::string value) {
    h.push_back({std::move(name), std::move(value)});
}

} // namespace bhttp

#endif // BITCOIN_PROTOCOL_BHTTP_H

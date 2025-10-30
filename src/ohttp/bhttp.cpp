// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ohttp/bhttp.h>

#include <algorithm>
#include <cstring> // memcpy

namespace bhttp {

// ---------------- QUIC varint (RFC 9000 §16) as used by bHTTP ----------------
// 1-byte: 00xxxxxx (0..63)
// 2-byte: 01xxxxxxxx xxxxxxxx (0..16383)
// 4-byte: 10........ ........ ........ ........ (0..1073741823)
// 8-byte: 11........ ........ ........ ........ ........ ........ ........ ........ (0..2^62-1)

static void WriteVarInt(uint64_t v, std::vector<uint8_t>& out)
{
    if (v <= 0x3F) {
        out.push_back(static_cast<uint8_t>(v));
    } else if (v <= 0x3FFF) {
        uint8_t b0 = 0x40 | static_cast<uint8_t>((v >> 8) & 0x3F);
        uint8_t b1 = static_cast<uint8_t>(v);
        out.push_back(b0); out.push_back(b1);
    } else if (v <= 0x3FFF'FFFF) {
        uint8_t b0 = 0x80 | static_cast<uint8_t>((v >> 24) & 0x3F);
        uint8_t b1 = static_cast<uint8_t>(v >> 16);
        uint8_t b2 = static_cast<uint8_t>(v >> 8);
        uint8_t b3 = static_cast<uint8_t>(v);
        out.insert(out.end(), {b0,b1,b2,b3});
    } else if (v <= 0x3FFF'FFFF'FFFF'FFFFULL) {
        uint8_t b0 = 0xC0 | static_cast<uint8_t>((v >> 56) & 0x3F);
        uint8_t b1 = static_cast<uint8_t>(v >> 48);
        uint8_t b2 = static_cast<uint8_t>(v >> 40);
        uint8_t b3 = static_cast<uint8_t>(v >> 32);
        uint8_t b4 = static_cast<uint8_t>(v >> 24);
        uint8_t b5 = static_cast<uint8_t>(v >> 16);
        uint8_t b6 = static_cast<uint8_t>(v >> 8);
        uint8_t b7 = static_cast<uint8_t>(v);
        out.insert(out.end(), {b0,b1,b2,b3,b4,b5,b6,b7});
    } else {
        // out of range for QUIC varint
        // (bHTTP caps sections at 2^62-1 bytes; treat as failure at callsite)
    }
}

static bool ReadVarInt(const uint8_t*& p, const uint8_t* end, uint64_t& v)
{
    if (p >= end) return false;
    const uint8_t b0 = *p++;
    const uint8_t tag = b0 >> 6;
    if (tag == 0) {
        v = static_cast<uint64_t>(b0 & 0x3F);
        return true;
    }
    if (tag == 1) {
        if (end - p < 1) return false;
        const uint8_t b1 = *p++;
        v = (static_cast<uint64_t>(b0 & 0x3F) << 8)
          | static_cast<uint64_t>(b1);
        return true;
    }
    if (tag == 2) {
        if (end - p < 3) return false;
        const uint8_t b1 = *p++;
        const uint8_t b2 = *p++;
        const uint8_t b3 = *p++;
        v = (static_cast<uint64_t>(b0 & 0x3F) << 24)
          | (static_cast<uint64_t>(b1) << 16)
          | (static_cast<uint64_t>(b2) << 8)
          |  static_cast<uint64_t>(b3);
        return true;
    }
    // tag == 3 (8-byte)
    if (end - p < 7) return false;
    const uint8_t b1 = *p++;
    const uint8_t b2 = *p++;
    const uint8_t b3 = *p++;
    const uint8_t b4 = *p++;
    const uint8_t b5 = *p++;
    const uint8_t b6 = *p++;
    const uint8_t b7 = *p++;
    v = (static_cast<uint64_t>(b0 & 0x3F) << 56)
      | (static_cast<uint64_t>(b1) << 48)
      | (static_cast<uint64_t>(b2) << 40)
      | (static_cast<uint64_t>(b3) << 32)
      | (static_cast<uint64_t>(b4) << 24)
      | (static_cast<uint64_t>(b5) << 16)
      | (static_cast<uint64_t>(b6) << 8)
      |  static_cast<uint64_t>(b7);
    return true;
}

// Serialize a Known-Length Field Section from header pairs
static std::vector<uint8_t> SerializeFieldSection(const std::vector<std::pair<std::string,std::string>>& headers)
{
    std::vector<uint8_t> fields;
    for (const auto& [name, value] : headers) {
        if (name.empty()) continue; // bHTTP requires Name Length >= 1
        WriteVarInt(name.size(), fields);
        fields.insert(fields.end(), name.begin(), name.end());
        WriteVarInt(value.size(), fields);
        fields.insert(fields.end(), value.begin(), value.end());
    }
    std::vector<uint8_t> out;
    WriteVarInt(fields.size(), out); // Known-Length Field Section length
    out.insert(out.end(), fields.begin(), fields.end());
    return out;
}

std::optional<std::vector<uint8_t>> EncodeKnownLengthRequest(const Request& r)
{
    // bHTTP known-length request layout (RFC 9292 §3.1, §3.4, §3.6). Framing=0. :contentReference[oaicite:5]{index=5}
    if (r.method.empty() || r.scheme.empty() || r.path.empty()) return std::nullopt;

    std::vector<uint8_t> out;
    // Framing Indicator = 0 (request, known-length)
    WriteVarInt(0, out);

    // Request Control Data: Method, Scheme, Authority, Path (each length-prefixed) (RFC 9292 §3.4). :contentReference[oaicite:6]{index=6}
    WriteVarInt(r.method.size(), out);    out.insert(out.end(), r.method.begin(), r.method.end());
    WriteVarInt(r.scheme.size(), out);    out.insert(out.end(), r.scheme.begin(), r.scheme.end());
    WriteVarInt(r.authority.size(), out); out.insert(out.end(), r.authority.begin(), r.authority.end()); // 0-length allowed
    WriteVarInt(r.path.size(), out);      out.insert(out.end(), r.path.begin(), r.path.end());

    // Header Section (Known-Length Field Section)
    auto hdr = SerializeFieldSection(r.headers);
    out.insert(out.end(), hdr.begin(), hdr.end());

    // Content (Known-Length Content)
    WriteVarInt(r.body.size(), out);
    out.insert(out.end(), r.body.begin(), r.body.end());

    // Trailer Section (empty Known-Length Field Section)
    WriteVarInt(0, out);

    // No padding.
    return out;
}

static bool ParseFieldSection_Known(const uint8_t*& p, const uint8_t* end,
                                    std::vector<std::pair<std::string,std::string>>& out_headers)
{
    uint64_t section_len = 0;
    if (!ReadVarInt(p, end, section_len)) return false;
    if (section_len > static_cast<uint64_t>(end - p)) return false;

    const uint8_t* q = p;
    const uint8_t* qend = p + section_len;

    while (q < qend) {
        uint64_t name_len = 0;
        if (!ReadVarInt(q, qend, name_len)) return false;
        if (name_len == 0 || name_len > static_cast<uint64_t>(qend - q)) return false;
        std::string name(reinterpret_cast<const char*>(q), reinterpret_cast<const char*>(q + name_len));
        q += name_len;

        uint64_t value_len = 0;
        if (!ReadVarInt(q, qend, value_len)) return false;
        if (value_len > static_cast<uint64_t>(qend - q)) return false;
        std::string value(reinterpret_cast<const char*>(q), reinterpret_cast<const char*>(q + value_len));
        q += value_len;

        out_headers.emplace_back(std::move(name), std::move(value));
    }

    p = qend;
    return true;
}

std::optional<Response> DecodeKnownLengthResponse(std::span<const uint8_t> in)
{
    const uint8_t* p = in.data();
    const uint8_t* end = in.data() + in.size();

    // Framing Indicator must be 1 (response, known-length). (RFC 9292 §3.3) :contentReference[oaicite:7]{index=7}
    uint64_t framing = 0;
    if (!ReadVarInt(p, end, framing)) return std::nullopt;
    if (framing != 1) return std::nullopt; // Only known-length responses are supported here.

    // Skip zero or more informational responses (100..199): each = control data (status) + header section. (RFC 9292 §3.5.1) :contentReference[oaicite:8]{index=8}
    while (true) {
        uint64_t code = 0;
        const uint8_t* save = p;
        if (!ReadVarInt(p, end, code)) return std::nullopt;
        if (code >= 200 && code <= 599) {
            // Final status; rewind to reuse code below.
            p = save; break;
        }
        if (code < 100 || code > 199) return std::nullopt; // invalid
        // consume header section for this informational response
        std::vector<std::pair<std::string,std::string>> discard;
        if (!ParseFieldSection_Known(p, end, discard)) return std::nullopt;
    }

    // Final Response Control Data: Status Code (varint) (RFC 9292 §3.5). :contentReference[oaicite:9]{index=9}
    uint64_t status = 0;
    if (!ReadVarInt(p, end, status)) return std::nullopt;
    if (status < 200 || status > 599) return std::nullopt;

    // Header Section
    std::vector<std::pair<std::string,std::string>> headers;
    if (!ParseFieldSection_Known(p, end, headers)) return std::nullopt;

    // Content
    uint64_t content_len = 0;
    if (!ReadVarInt(p, end, content_len)) return std::nullopt;
    if (content_len > static_cast<uint64_t>(end - p)) return std::nullopt;
    std::vector<uint8_t> body(content_len);
    if (content_len) { std::memcpy(body.data(), p, content_len); }
    p += content_len;

    // Trailer Section (ignore)
    std::vector<std::pair<std::string,std::string>> trailers;
    if (!ParseFieldSection_Known(p, end, trailers)) return std::nullopt;

    // Any remaining bytes are padding; safe to ignore (RFC 9292 §3.8).
    return Response{status, std::move(headers), std::move(body)};
}

std::optional<std::vector<uint8_t>> EncodeKnownLengthResponse(const Response& r)
{
    // bHTTP known-length response (RFC 9292 §3.3, §3.5, §3.6): Framing=1. Status 200..599.
    if (r.status < 200 || r.status > 599) return std::nullopt;

    std::vector<uint8_t> out;
    // Framing Indicator = 1 (response, known-length)
    WriteVarInt(1, out);

    // Final status code
    WriteVarInt(r.status, out);

    // Header Section (Known-Length Field Section)
    auto hdr = SerializeFieldSection(r.headers);
    out.insert(out.end(), hdr.begin(), hdr.end());

    // Content
    WriteVarInt(r.body.size(), out);
    out.insert(out.end(), r.body.begin(), r.body.end());

    // Trailer Section (empty)
    WriteVarInt(0, out);

    return out;
}

} // namespace bhttp

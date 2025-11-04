// Copyright (c) 2025
// SPDX-License-Identifier: MIT

#include <payjoin/bhttp.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace bhttp {

// --- QUIC varint (RFC 9292 uses QUIC varints) ---
void WriteVarint(uint64_t v, std::vector<uint8_t>& out) {
    // Per QUIC varint encoding (2 MSBs length marker).
    if (v <= 0x3F) { // 1 byte: 00
        out.push_back(static_cast<uint8_t>(v & 0x3F));
    } else if (v <= 0x3FFF) { // 2 bytes: 01
        uint16_t w = 0x4000 | static_cast<uint16_t>(v);
        out.push_back(static_cast<uint8_t>(w >> 8));
        out.push_back(static_cast<uint8_t>(w));
    } else if (v <= 0x3FFF'FFFF) { // 4 bytes: 10
        uint32_t w = 0x8000'0000u | static_cast<uint32_t>(v);
        out.push_back(static_cast<uint8_t>(w >> 24));
        out.push_back(static_cast<uint8_t>(w >> 16));
        out.push_back(static_cast<uint8_t>(w >> 8));
        out.push_back(static_cast<uint8_t>(w));
    } else if (v <= 0x3FFF'FFFF'FFFF'FFFFull) { // 8 bytes: 11
        uint64_t w = 0xC000'0000'0000'0000ull | v;
        for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>(w >> (i*8)));
    } else {
        throw VarintError("bhttp varint too large");
    }
}

bool ReadVarint(const uint8_t*& p, const uint8_t* end, uint64_t& out) {
    if (p >= end) return false;
    uint8_t first = *p;
    if ((first & 0xC0) == 0x00) {
        // 1 byte
        out = (first & 0x3F);
        ++p;
        return true;
    } else if ((first & 0xC0) == 0x40) {
        // 2 bytes
        if (end - p < 2) return false;
        uint16_t w = (static_cast<uint16_t>(p[0]) << 8) | p[1];
        out = (w & 0x3FFF);
        p += 2;
        return true;
    } else if ((first & 0xC0) == 0x80) {
        // 4 bytes
        if (end - p < 4) return false;
        uint32_t w = (static_cast<uint32_t>(p[0]) << 24) |
                     (static_cast<uint32_t>(p[1]) << 16) |
                     (static_cast<uint32_t>(p[2]) << 8) | p[3];
        out = (w & 0x3FFF'FFFFu);
        p += 4;
        return true;
    } else {
        // 8 bytes
        if (end - p < 8) return false;
        uint64_t w = 0;
        for (int i = 0; i < 8; ++i) w = (w << 8) | p[i];
        out = (w & 0x3FFF'FFFF'FFFF'FFFFull);
        p += 8;
        return true;
    }
}

// ---- Helpers ----
static void WLenPref(std::string_view s, std::vector<uint8_t>& out) {
    WriteVarint(s.size(), out);
    out.insert(out.end(), s.begin(), s.end());
}
static void WLenPref(const std::vector<uint8_t>& v, std::vector<uint8_t>& out) {
    WriteVarint(v.size(), out);
    out.insert(out.end(), v.begin(), v.end());
}

static void WriteFieldSection(const HeaderList& fields, std::vector<uint8_t>& out) {
    // We need a length prefix for the field section (sum of encoded field lines).
    std::vector<uint8_t> tmp;
    tmp.reserve(128);
    for (const auto& f : fields) {
        if (f.name.empty())
            throw std::runtime_error("bhttp header name empty");
        WLenPref(std::string_view{f.name}, tmp);
        WLenPref(std::string_view{f.value}, tmp);
    }
    WriteVarint(tmp.size(), out);
    out.insert(out.end(), tmp.begin(), tmp.end());
}

std::vector<uint8_t> EncodeKnownLengthRequest(const Request& req) {
    // Known-length request (framing indicator = 0). RFC 9292 §3.1 / §3.4. :contentReference[oaicite:7]{index=7}
    std::vector<uint8_t> out;
    out.reserve(64 + req.body.size());

    // Framing Indicator (i) = 0
    WriteVarint(0, out);

    // Request Control Data: Method, Scheme, Authority, Path (len-prefixed strings)
    WLenPref(std::string_view{req.method}, out);
    WLenPref(std::string_view{req.scheme}, out);
    WLenPref(std::string_view{req.authority}, out);
    WLenPref(std::string_view{req.path}, out);

    // Known-Length Header Section
    WriteFieldSection(req.headers, out);

    // Known-Length Content
    WLenPref(req.body, out);

    // Known-Length Trailer Section (empty)
    WriteVarint(0, out); // 0-length field section

    // No padding (optional)
    return out;
}

static std::string ReadLenString(const uint8_t*& p, const uint8_t* end) {
    uint64_t n = 0;
    if (!ReadVarint(p, end, n)) throw std::runtime_error("bhttp: bad varint (string length)");
    if (static_cast<uint64_t>(end - p) < n) throw std::runtime_error("bhttp: truncated string");
    std::string s(reinterpret_cast<const char*>(p), reinterpret_cast<const char*>(p) + n);
    p += n;
    return s;
}
static std::vector<uint8_t> ReadLenBytes(const uint8_t*& p, const uint8_t* end) {
    uint64_t n = 0;
    if (!ReadVarint(p, end, n)) throw std::runtime_error("bhttp: bad varint (bytes length)");
    if (static_cast<uint64_t>(end - p) < n) throw std::runtime_error("bhttp: truncated bytes");
    std::vector<uint8_t> v(p, p + n);
    p += n;
    return v;
}

Response DecodeKnownLengthResponse(const std::vector<uint8_t>& buf) {
    // Known-length response (framing indicator = 1). Minimal subset: no informational responses.
    const uint8_t* p = buf.data();
    const uint8_t* end = p + buf.size();

    uint64_t framing = 0;
    if (!ReadVarint(p, end, framing)) throw std::runtime_error("bhttp: empty buffer");
    if (framing != 1) throw std::runtime_error("bhttp: not a known-length response");

    // Final Response Control Data: Status Code (varint)
    uint64_t status = 0;
    if (!ReadVarint(p, end, status)) throw std::runtime_error("bhttp: missing status");
    if (status < 200 || status > 599) throw std::runtime_error("bhttp: invalid status");

    // Header section (length-prefixed block of field lines)
    uint64_t hdr_len = 0;
    if (!ReadVarint(p, end, hdr_len)) throw std::runtime_error("bhttp: missing header length");
    if (static_cast<uint64_t>(end - p) < hdr_len) throw std::runtime_error("bhttp: truncated header section");
    const uint8_t* hp = p;
    const uint8_t* hend = p + hdr_len;
    p = hend;

    HeaderList headers;
    while (hp < hend) {
        // Each header field line = Name (len-str), Value (len-bytes)
        std::string name = ReadLenString(hp, hend);
        std::string value = ReadLenString(hp, hend);
        headers.push_back({std::move(name), std::move(value)});
    }

    // Content: Known-Length Content { Content Length (i), Content (..) }
    std::vector<uint8_t> body = ReadLenBytes(p, end);

    // Trailer section (we ignore, but consume length and skip)
    uint64_t trailer_len = 0;
    if (!ReadVarint(p, end, trailer_len)) throw std::runtime_error("bhttp: missing trailer length");
    if (static_cast<uint64_t>(end - p) < trailer_len) throw std::runtime_error("bhttp: truncated trailer");
    p += trailer_len;

    Response r;
    r.status = static_cast<uint32_t>(status);
    r.headers = std::move(headers);
    r.body = std::move(body);
    return r;
}

} // namespace bhttp

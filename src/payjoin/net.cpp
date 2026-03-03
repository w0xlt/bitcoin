// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/net.h>

#include <logging.h>
#include <netbase.h>
#include <ohttp/ohttp.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace payjoin {

// ---------------------------------------------------------------------------
// URL parsing helper
// ---------------------------------------------------------------------------

struct ParsedUrl {
    std::string scheme;   // "http" or "https"
    std::string host;
    uint16_t port{0};
    std::string path;     // includes query string
};

static std::optional<ParsedUrl> ParseUrl(const std::string& url)
{
    ParsedUrl result;

    // Scheme
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) return std::nullopt;
    result.scheme = url.substr(0, scheme_end);
    std::transform(result.scheme.begin(), result.scheme.end(), result.scheme.begin(), ::tolower);

    size_t authority_start = scheme_end + 3;
    size_t path_start = url.find('/', authority_start);
    std::string authority;
    if (path_start == std::string::npos) {
        authority = url.substr(authority_start);
        result.path = "/";
    } else {
        authority = url.substr(authority_start, path_start - authority_start);
        result.path = url.substr(path_start);
    }

    // Host and port
    size_t colon = authority.rfind(':');
    // Handle IPv6 addresses in brackets
    size_t bracket_close = authority.rfind(']');
    if (colon != std::string::npos && (bracket_close == std::string::npos || colon > bracket_close)) {
        result.host = authority.substr(0, colon);
        try {
            result.port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1)));
        } catch (...) {
            return std::nullopt;
        }
    } else {
        result.host = authority;
        result.port = (result.scheme == "https") ? 443 : 80;
    }

    // Remove brackets from IPv6
    if (!result.host.empty() && result.host.front() == '[' && result.host.back() == ']') {
        result.host = result.host.substr(1, result.host.size() - 2);
    }

    if (result.host.empty()) return std::nullopt;
    return result;
}

// ---------------------------------------------------------------------------
// HTTP response parsing
// ---------------------------------------------------------------------------

static std::optional<HttpResponse> ParseHttpResponse(const std::vector<uint8_t>& raw)
{
    // Find end of headers (\r\n\r\n)
    const std::string separator = "\r\n\r\n";
    auto it = std::search(raw.begin(), raw.end(), separator.begin(), separator.end());
    if (it == raw.end()) return std::nullopt;

    size_t header_end = std::distance(raw.begin(), it);
    std::string header_block(raw.begin(), raw.begin() + header_end);

    HttpResponse resp;

    // Parse status line
    size_t first_line_end = header_block.find("\r\n");
    std::string status_line = header_block.substr(0, first_line_end);

    // "HTTP/1.1 200 OK"
    size_t sp1 = status_line.find(' ');
    if (sp1 == std::string::npos) return std::nullopt;
    size_t sp2 = status_line.find(' ', sp1 + 1);
    std::string code_str = (sp2 != std::string::npos) ?
        status_line.substr(sp1 + 1, sp2 - sp1 - 1) :
        status_line.substr(sp1 + 1);
    try {
        resp.status_code = std::stoi(code_str);
    } catch (...) {
        return std::nullopt;
    }

    // Parse headers
    size_t pos = first_line_end + 2;
    while (pos < header_block.size()) {
        size_t line_end = header_block.find("\r\n", pos);
        if (line_end == std::string::npos) line_end = header_block.size();
        std::string line = header_block.substr(pos, line_end - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            // Trim leading whitespace from value
            size_t val_start = value.find_first_not_of(" \t");
            if (val_start != std::string::npos) value = value.substr(val_start);
            // Lowercase header name for case-insensitive lookup
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            resp.headers[name] = value;
        }
        pos = line_end + 2;
    }

    // Body starts after \r\n\r\n
    size_t body_start = header_end + 4;
    auto it_cl = resp.headers.find("content-length");
    if (it_cl != resp.headers.end()) {
        size_t content_length = 0;
        try {
            content_length = std::stoul(it_cl->second);
        } catch (...) {
            content_length = raw.size() - body_start;
        }
        size_t available = raw.size() - body_start;
        size_t to_copy = std::min(content_length, available);
        resp.body.assign(raw.begin() + body_start, raw.begin() + body_start + to_copy);
    } else {
        // No Content-Length: take everything after headers
        resp.body.assign(raw.begin() + body_start, raw.end());
    }

    return resp;
}

// ---------------------------------------------------------------------------
// HttpClient implementation
// ---------------------------------------------------------------------------

HttpClient::HttpClient(const Proxy& tor_proxy, int timeout_ms)
    : m_proxy(tor_proxy), m_timeout_ms(timeout_ms) {}

static std::optional<HttpResponse> DoRequest(const Proxy& proxy, int /*timeout_ms*/,
                                              const std::string& url,
                                              const std::string& method,
                                              std::span<const uint8_t> body,
                                              const std::map<std::string, std::string>& headers)
{
    auto parsed = ParseUrl(url);
    if (!parsed) return std::nullopt;

    // Connect through Tor SOCKS5 proxy
    bool proxy_failed = false;
    auto sock = ConnectThroughProxy(proxy, parsed->host, parsed->port, proxy_failed);
    if (!sock) {
        LogPrintf("payjoin: Failed to connect through proxy to %s:%d (proxy_failed=%d)\n",
                  parsed->host, parsed->port, proxy_failed);
        return std::nullopt;
    }

    // Build HTTP/1.1 request
    std::string authority = parsed->host;
    if ((parsed->scheme == "https" && parsed->port != 443) ||
        (parsed->scheme == "http" && parsed->port != 80)) {
        authority += ":" + std::to_string(parsed->port);
    }

    std::ostringstream req;
    req << method << " " << parsed->path << " HTTP/1.1\r\n";
    req << "Host: " << authority << "\r\n";

    for (const auto& [name, value] : headers) {
        req << name << ": " << value << "\r\n";
    }

    if (!body.empty()) {
        req << "Content-Length: " << body.size() << "\r\n";
    }

    req << "Connection: close\r\n";
    req << "\r\n";

    std::string request_str = req.str();

    // Send request header
    CThreadInterrupt interrupt;
    try {
        sock->SendComplete(
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(request_str.data()),
                request_str.size()),
            std::chrono::milliseconds(30000),
            interrupt);

        // Send body if present
        if (!body.empty()) {
            sock->SendComplete(
                std::span<const unsigned char>(body.data(), body.size()),
                std::chrono::milliseconds(30000),
                interrupt);
        }
    } catch (const std::runtime_error& e) {
        LogPrintf("payjoin: Send failed: %s\n", e.what());
        return std::nullopt;
    }

    // Read response (read until connection closes since we sent Connection: close)
    std::vector<uint8_t> response_data;
    response_data.reserve(16384);

    uint8_t buf[4096];
    while (true) {
        // Wait for data with a timeout
        Sock::Event occurred = 0;
        if (!sock->Wait(std::chrono::milliseconds(30000), Sock::RECV, &occurred)) {
            break; // wait error
        }
        if (!(occurred & Sock::RECV)) {
            break; // timeout
        }

        ssize_t n = sock->Recv(buf, sizeof(buf), 0);
        if (n <= 0) break; // connection closed or error
        response_data.insert(response_data.end(), buf, buf + n);

        // Safety limit: don't read more than 1MB
        if (response_data.size() > 1024 * 1024) break;
    }

    if (response_data.empty()) return std::nullopt;

    return ParseHttpResponse(response_data);
}

std::optional<HttpResponse> HttpClient::Get(const std::string& url,
                                             const std::map<std::string, std::string>& headers)
{
    return DoRequest(m_proxy, m_timeout_ms, url, "GET", {}, headers);
}

std::optional<HttpResponse> HttpClient::Post(const std::string& url,
                                              std::span<const uint8_t> body,
                                              const std::string& content_type,
                                              const std::map<std::string, std::string>& extra_headers)
{
    std::map<std::string, std::string> headers = extra_headers;
    headers["Content-Type"] = content_type;
    return DoRequest(m_proxy, m_timeout_ms, url, "POST", body, headers);
}

// ---------------------------------------------------------------------------
// FetchOhttpKeys
// ---------------------------------------------------------------------------

std::optional<ohttp::KeyConfig> FetchOhttpKeys(HttpClient& client,
                                                const std::string& directory_url)
{
    // Trim trailing slash
    std::string base = directory_url;
    if (!base.empty() && base.back() == '/') base.pop_back();

    std::string keys_url = base + "/.well-known/ohttp-gateway";
    auto resp = client.Get(keys_url);
    if (!resp || resp->status_code != 200) return std::nullopt;
    if (resp->body.empty()) return std::nullopt;

    auto configs = ohttp::ParseKeyConfigList(resp->body);
    if (configs.empty()) return std::nullopt;

    // Return the first supported config
    return configs[0];
}

} // namespace payjoin

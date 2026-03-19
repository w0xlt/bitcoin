// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_NET_H
#define BITCOIN_PAYJOIN_NET_H

#include <netbase.h>
#include <ohttp/ohttp.h>

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace payjoin {

struct HttpResponse {
    int status_code{0};
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;
};

/**
 * Minimal HTTP/1.1 client that routes all traffic through a Tor SOCKS5 proxy.
 *
 * Provides only the operations needed for BIP 77 payjoin:
 *  - GET with optional headers
 *  - POST with binary body and content type
 *
 * No TLS: Tor provides transport encryption for .onion addresses, and Tor
 * exit nodes handle TLS for clearnet HTTPS addresses. We send plain HTTP
 * through the SOCKS5 proxy.
 */
class HttpClient {
    Proxy m_proxy;
    int m_timeout_ms;

public:
    /**
     * @param[in] tor_proxy  Tor SOCKS5 proxy (from -proxy= or -onion= settings)
     * @param[in] timeout_ms  Connection/read timeout in milliseconds (default 30s)
     */
    HttpClient(const Proxy& tor_proxy, int timeout_ms = 30000);

    /** HTTP GET request. */
    std::optional<HttpResponse> Get(const std::string& url,
                                    const std::map<std::string, std::string>& headers = {});

    /** HTTP POST request with binary body. */
    std::optional<HttpResponse> Post(const std::string& url,
                                     std::span<const uint8_t> body,
                                     const std::string& content_type,
                                     const std::map<std::string, std::string>& extra_headers = {});

    /** Check if the proxy is configured. */
    bool IsValid() const { return m_proxy.IsValid(); }
};

/**
 * Return the RFC 9540 OHTTP gateway URL for a directory origin.
 * Appends `/.well-known/ohttp-gateway` after trimming any trailing slash.
 */
std::string OhttpGatewayUrl(const std::string& directory_url);

/**
 * Fetch OHTTP KeyConfig from a directory's well-known endpoint.
 * GETs {directory_url}/.well-known/ohttp-gateway and parses the
 * application/ohttp-keys response.
 */
std::optional<ohttp::KeyConfig> FetchOhttpKeys(HttpClient& client,
                                                const std::string& directory_url);

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_NET_H

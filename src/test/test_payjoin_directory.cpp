// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Minimal OHTTP-aware mock payjoin directory for functional tests.
// Generates a secp256k1 keypair, listens on TCP, handles:
//   GET /.well-known/ohttp-gateway -> OHTTP KeyConfig (plain)
//   POST / with Content-Type: message/ohttp-req -> OHTTP gateway flow
// Prints "READY <port>" to stdout when listening.

#include <key.h>
#include <ohttp/bhttp.h>
#include <ohttp/ohttp.h>
#include <random.h>
#include <crypto/sha256.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static void CloseSock(int fd) {
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

// Simple HTTP request parser
struct SimpleHttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;
};

static bool ParseSimpleHttp(const std::vector<uint8_t>& raw, SimpleHttpRequest& out)
{
    // Find end of headers
    const std::string sep = "\r\n\r\n";
    auto it = std::search(raw.begin(), raw.end(), sep.begin(), sep.end());
    if (it == raw.end()) return false;

    size_t header_end = std::distance(raw.begin(), it);
    std::string header_block(raw.begin(), raw.begin() + header_end);

    // Parse request line
    size_t first_line_end = header_block.find("\r\n");
    std::string request_line = header_block.substr(0, first_line_end);

    size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = request_line.find(' ', sp1 + 1);
    out.method = request_line.substr(0, sp1);
    out.path = (sp2 != std::string::npos) ?
        request_line.substr(sp1 + 1, sp2 - sp1 - 1) :
        request_line.substr(sp1 + 1);

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
            size_t val_start = value.find_first_not_of(" \t");
            if (val_start != std::string::npos) value = value.substr(val_start);
            // Lowercase header name
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            out.headers[name] = value;
        }
        pos = line_end + 2;
    }

    // Body
    size_t body_start = header_end + 4;
    auto cl_it = out.headers.find("content-length");
    if (cl_it != out.headers.end()) {
        size_t content_length = std::stoul(cl_it->second);
        size_t available = raw.size() - body_start;
        size_t to_copy = std::min(content_length, available);
        out.body.assign(raw.begin() + body_start, raw.begin() + body_start + to_copy);
    } else {
        out.body.assign(raw.begin() + body_start, raw.end());
    }

    return true;
}

static std::string BuildHttpResponse(int status, const std::string& content_type,
                                      const std::vector<uint8_t>& body)
{
    std::string status_text;
    switch (status) {
    case 200: status_text = "OK"; break;
    case 202: status_text = "Accepted"; break;
    case 400: status_text = "Bad Request"; break;
    case 404: status_text = "Not Found"; break;
    case 500: status_text = "Internal Server Error"; break;
    default: status_text = "Unknown"; break;
    }

    std::string resp;
    resp += "HTTP/1.1 " + std::to_string(status) + " " + status_text + "\r\n";
    resp += "Content-Type: " + content_type + "\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n";
    resp += "\r\n";
    return resp;
}

// Mailbox storage
static std::mutex g_mailbox_mutex;
static std::map<std::string, std::vector<uint8_t>> g_mailboxes;

// Gateway key material
static CKey g_gateway_key;
static uint8_t g_key_id = 0;

static std::vector<uint8_t> GetOhttpKeyConfig()
{
    ohttp::KeyConfig cfg;
    cfg.key_id = g_key_id;
    cfg.kem_id = ohttp::KEM_SECP256K1;

    CPubKey pk = g_gateway_key.GetPubKey();
    std::copy(pk.begin(), pk.end(), cfg.pkR.begin());

    cfg.syms.push_back({ohttp::KDF_HKDF_SHA256, ohttp::AEAD_CHACHA20POLY1305});
    return ohttp::SerializeKeyConfigList({cfg});
}

static void HandleClient(int client_fd)
{
    // Read the full request
    std::vector<uint8_t> raw;
    raw.reserve(16384);
    uint8_t buf[4096];

    // Read until we have headers + body
    while (true) {
        ssize_t n = recv(client_fd, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n <= 0) break;
        raw.insert(raw.end(), buf, buf + n);

        // Check if we have the full request
        std::string sep = "\r\n\r\n";
        auto it = std::search(raw.begin(), raw.end(), sep.begin(), sep.end());
        if (it != raw.end()) {
            // Check Content-Length
            std::string header_str(raw.begin(), it);
            std::string cl_lower = "content-length:";
            size_t cl_pos = header_str.find(cl_lower);
            if (cl_pos == std::string::npos) {
                // Also try with capital C
                cl_lower = "Content-Length:";
                cl_pos = header_str.find(cl_lower);
            }
            if (cl_pos != std::string::npos) {
                size_t val_start = cl_pos + cl_lower.size();
                size_t line_end = header_str.find("\r\n", val_start);
                std::string val = header_str.substr(val_start, line_end - val_start);
                size_t content_length = std::stoul(val);
                size_t header_end = std::distance(raw.begin(), it) + 4;
                if (raw.size() >= header_end + content_length) break;
            } else {
                break; // No content-length, assume we have everything
            }
        }

        if (raw.size() > 1024 * 1024) break; // Safety limit
    }

    SimpleHttpRequest req;
    if (!ParseSimpleHttp(raw, req)) {
        CloseSock(client_fd);
        return;
    }

    std::vector<uint8_t> response_body;
    int status = 500;
    std::string content_type = "application/octet-stream";

    if (req.method == "GET" && req.path == "/.well-known/ohttp-gateway") {
        // Return OHTTP KeyConfig in plain
        response_body = GetOhttpKeyConfig();
        status = 200;
        content_type = "application/ohttp-keys";
    } else if (req.method == "POST") {
        // Check if this is an OHTTP request
        auto ct_it = req.headers.find("content-type");
        bool is_ohttp = (ct_it != req.headers.end() && ct_it->second == "message/ohttp-req");

        if (is_ohttp) {
            // OHTTP gateway flow
            ohttp::GatewayRequestContext gw_ctx;
            std::span<const uint8_t> skR(
                reinterpret_cast<const uint8_t*>(g_gateway_key.data()),
                g_gateway_key.size());

            auto inner_bytes = ohttp::Gateway::DecapsulateRequest(
                req.body, g_key_id, skR, gw_ctx);

            if (!inner_bytes) {
                status = 400;
                response_body = {};
            } else {
                // Parse inner bHTTP request
                auto inner_req = bhttp::DecodeKnownLengthRequest(*inner_bytes);
                if (!inner_req) {
                    status = 400;
                    response_body = {};
                } else {
                    // Route based on inner method + path
                    bhttp::Response inner_resp;

                    if (inner_req->method == "POST") {
                        // Store in mailbox
                        std::lock_guard<std::mutex> lock(g_mailbox_mutex);
                        g_mailboxes[inner_req->path] = inner_req->body;
                        inner_resp.status = 200;
                    } else if (inner_req->method == "GET") {
                        // Retrieve from mailbox
                        std::lock_guard<std::mutex> lock(g_mailbox_mutex);
                        auto mb_it = g_mailboxes.find(inner_req->path);
                        if (mb_it != g_mailboxes.end() && !mb_it->second.empty()) {
                            inner_resp.status = 200;
                            inner_resp.body = mb_it->second;
                            inner_resp.headers.push_back({"Content-Type", "message/payjoin+psbt"});
                            // Clear the mailbox after retrieval
                            g_mailboxes.erase(mb_it);
                        } else {
                            inner_resp.status = 202;
                        }
                    } else {
                        inner_resp.status = 400;
                    }

                    // Encode bHTTP response
                    auto bhttp_resp = bhttp::EncodeKnownLengthResponse(inner_resp);
                    if (bhttp_resp) {
                        // OHTTP encapsulate response
                        auto ohttp_resp = ohttp::Gateway::EncapsulateResponse(gw_ctx, *bhttp_resp);
                        response_body = ohttp_resp;
                        status = 200;
                        content_type = "message/ohttp-res";
                    } else {
                        status = 500;
                    }
                }
            }
        } else {
            // Plain POST - just store (shouldn't be used in real flow)
            status = 200;
        }
    } else if (req.method == "GET") {
        status = 404;
    }

    std::string resp_header = BuildHttpResponse(status, content_type, response_body);

    // Send response header + body
    send(client_fd, resp_header.c_str(), resp_header.size(), 0);
    if (!response_body.empty()) {
        send(client_fd, reinterpret_cast<const char*>(response_body.data()),
             response_body.size(), 0);
    }

    CloseSock(client_fd);
}

int main(int argc, char* argv[])
{
    // Initialize crypto
    SHA256AutoDetect();
    RandomInit();
    ECC_Context ecc_context;

    // Parse --port argument
    int port = 0;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--port" && i + 1 < argc) {
            port = std::atoi(argv[++i]);
        }
    }
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Usage: %s --port <port>\n", argv[0]);
        return 1;
    }

    // Generate gateway keypair
    g_gateway_key.MakeNewKey(/*fCompressed=*/false);

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    // Create listening socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        fprintf(stderr, "socket() failed\n");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        fprintf(stderr, "bind() failed on port %d\n", port);
        CloseSock(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 16) < 0) {
        fprintf(stderr, "listen() failed\n");
        CloseSock(listen_fd);
        return 1;
    }

    // Signal readiness to the test framework
    printf("READY %d\n", port);
    fflush(stdout);

    // Accept loop
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) continue;

        // Handle synchronously (test traffic is sequential)
        HandleClient(client_fd);
    }

    CloseSock(listen_fd);
    return 0;
}

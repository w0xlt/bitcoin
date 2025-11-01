// SPDX-License-Identifier: MIT
#ifndef BITCOIN_PROTOCOL_OHTTP_H
#define BITCOIN_PROTOCOL_OHTTP_H

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

namespace ohttp {

struct SymmetricSuite { uint16_t kdf_id; uint16_t aead_id; };

struct KeyConfig {
    uint8_t  key_id = 0;
    uint16_t kem_id = 0;
    std::vector<uint8_t> pkR;                 // recipient pubkey (compressed or uncompressed)
    std::vector<SymmetricSuite> suites;

    std::optional<SymmetricSuite> SelectDefault() const;
};

struct OhttpKeys { std::vector<KeyConfig> configs; };

class ParseError : public std::runtime_error { public: using std::runtime_error::runtime_error; };

OhttpKeys ParseOhttpKeys(const std::vector<uint8_t>& blob);

// ---------- OHTTP request/response (client) ----------

struct EncapsulatedRequest {
    std::vector<uint8_t> header;            // key_id|kem_id|kdf_id|aead_id (7 bytes)
    std::vector<uint8_t> enc;               // KEM encapsulated value (our ephemeral pubkey)
    std::vector<uint8_t> ct;                // AEAD-protected BHTTP request
    std::vector<uint8_t> exporter_secret;   // HPKE exporter_secret (32 bytes for HKDF-SHA256)
};

struct EncapsulatedResponse {
    std::vector<uint8_t> response_nonce;    // length = max(Nk,Nn) = 32 for ChaCha20-Poly1305
    std::vector<uint8_t> ct;                // AEAD-protected BHTTP response
};

struct OhttpError : public std::runtime_error { using std::runtime_error::runtime_error; };

EncapsulatedRequest EncapsulateRequest(const KeyConfig& cfg, const std::vector<uint8_t>& bhttp_request);

// Uses the exporter secret captured in the request context
std::vector<uint8_t> DecapsulateResponse(const KeyConfig& cfg,
                                         const EncapsulatedRequest& req_ctx,
                                         const EncapsulatedResponse& enc_res);

} // namespace ohttp

#endif // BITCOIN_PROTOCOL_OHTTP_H

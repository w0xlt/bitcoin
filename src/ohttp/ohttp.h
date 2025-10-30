// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OHTTP_OHTTP_H
#define BITCOIN_OHTTP_OHTTP_H

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <dhkem_secp256k1.h> // HPKE (secp256k1 KEM + HKDF-SHA256 + ChaCha20-Poly1305)

/** Oblivious HTTP (RFC 9458) minimal primitives for Payjoin v2.
 *
 * This module implements:
 *  - KeyConfig (single) and collection parsing/serialization (application/ohttp-keys).
 *  - Client request encapsulation ("message/ohttp-req") and response decapsulation ("message/ohttp-res").
 *  - Gateway request decapsulation and response encapsulation.
 *
 * Constraints / design:
 *  - HPKE suite is fixed to { KEM=0x0016 (secp256k1), KDF=0x0001 (HKDF-SHA256), AEAD=0x0003 (ChaCha20-Poly1305) }.
 *  - Base mode only (no PSK), per Payjoin v2 needs.
 *  - Binary HTTP (bHTTP) bytes are passed in/out opaque; this module does no HTTP parsing.
 *
 * Format references: RFC 9458 §§3, 4.1–4.4; RFC 9180 §5.3 (Export).
 */

namespace ohttp {

// ---- Suite identifiers we support (fixed to the HPKE code you added) ----
static constexpr uint16_t KEM_SECP256K1 = 0x0016; // matches SUITE_ID in dhkem_secp256k1.h :contentReference[oaicite:6]{index=6}
static constexpr uint16_t KDF_HKDF_SHA256 = 0x0001;
static constexpr uint16_t AEAD_CHACHA20POLY1305 = 0x0003;

struct SymmetricAlg {
    uint16_t kdf_id;
    uint16_t aead_id;
};

struct KeyConfig {
    uint8_t  key_id;             // RFC 9458 §3.1: Key Identifier (8-bit)
    uint16_t kem_id;             // RFC 9458 §3.1
    std::array<uint8_t, dhkem_secp256k1::NPK> pkR; // uncompressed 65-byte HPKE public key
    std::vector<SymmetricAlg> syms; // at least one (KDF, AEAD) pair

    // Serialize the single KeyConfig (without length prefix).
    std::vector<uint8_t> Serialize() const;

    // Validate against what this implementation supports.
    bool IsSupported() const {
        if (kem_id != KEM_SECP256K1) return false;
        if (pkR.size() != dhkem_secp256k1::NPK) return false;
        bool ok = false;
        for (const auto& s : syms) {
            if (s.kdf_id == KDF_HKDF_SHA256 && s.aead_id == AEAD_CHACHA20POLY1305) { ok = true; break; }
        }
        return ok;
    }
};

// Parse a collection in application/ohttp-keys format:
// sequence of (uint16_be length | KeyConfig bytes). RFC 9458 §3.2
std::vector<KeyConfig> ParseKeyConfigList(std::span<const uint8_t> data);

// Serialize a collection (application/ohttp-keys).
std::vector<uint8_t> SerializeKeyConfigList(const std::vector<KeyConfig>& list);

// ------------- Client side -------------
class ClientContext {
    // HPKE context material for decrypting the response (RFC 9458 §4.4 via RFC 9180 §5.3).
    // Stored in optional so this class remains default-constructible (Core style).
    std::optional<dhkem_secp256k1::Context> m_hpke;      // key, base_nonce, exporter_secret (Base mode)
    std::array<uint8_t, dhkem_secp256k1::NENC> m_enc; // sender's encapsulated key to include in salt for response
    uint8_t m_key_id{0};
    // Selected suite ids (validated to match what we support).
    uint16_t m_kem_id{KEM_SECP256K1}, m_kdf_id{KDF_HKDF_SHA256}, m_aead_id{AEAD_CHACHA20POLY1305};

public:
    ClientContext() = default;

    // Encapsulate a bHTTP request payload into message/ohttp-req.
    // Returns serialized Encapsulated Request (hdr || enc || ct) or nullopt.
    std::optional<std::vector<uint8_t>> EncapsulateRequest(const KeyConfig& cfg,
                                                           std::span<const uint8_t> bhttp_request);

    // Open a message/ohttp-res (response) using the stored HPKE exporter.
    // Returns the decrypted bHTTP response or nullopt.
    std::optional<std::vector<uint8_t>> OpenResponse(std::span<const uint8_t> enc_response) const;
};

// ------------- Gateway side -------------
struct GatewayRequestContext {
    // Values the gateway needs to encapsulate the response.
    // Optional so the struct is default-constructible (Context has no default ctor).
    std::optional<dhkem_secp256k1::Context> hpke; // set by DecapsulateRequest on success
    std::array<uint8_t, dhkem_secp256k1::NENC> enc; // encapsulated key from the request (for salt derivation)
    uint16_t kdf_id{KDF_HKDF_SHA256};
    uint16_t aead_id{AEAD_CHACHA20POLY1305};
};

class Gateway {
public:
    // Decapsulate an Encapsulated Request to obtain the bHTTP request.
    // skR is the HPKE private key corresponding to the KeyConfig key_id (managed by the caller).
    // On success, fills ctx for later response encapsulation.
    static std::optional<std::vector<uint8_t>> DecapsulateRequest(std::span<const uint8_t> enc_request,
                                                                  uint8_t expected_key_id,
                                                                  std::span<const uint8_t> skR,
                                                                  GatewayRequestContext& ctx);

    // Encapsulate a bHTTP response into message/ohttp-res using ctx from DecapsulateRequest.
    static std::vector<uint8_t> EncapsulateResponse(const GatewayRequestContext& ctx,
                                                    std::span<const uint8_t> bhttp_response);
};

} // namespace ohttp

#endif // BITCOIN_OHTTP_OHTTP_H

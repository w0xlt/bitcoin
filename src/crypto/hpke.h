#ifndef BITCOIN_CRYPTO_HPKE_H
#define BITCOIN_CRYPTO_HPKE_H

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <optional>

#include <secp256k1.h>
#include <span.h>

namespace hpke_secp256k1_sha256_chachapoly {

// Constants for DHKEM(secp256k1, HKDF-SHA256) with ChaCha20-Poly1305 AEAD
constexpr uint16_t KEM_ID = 0x0016;
constexpr uint16_t KDF_ID = 0x0001; // HKDF-SHA256
constexpr uint16_t AEAD_ID = 0x0003; // ChaCha20-Poly1305

constexpr size_t Npk = 65; // Size of serialized public key
constexpr size_t Nsk = 32; // Size of secret key
constexpr size_t Nenc = 65; // Size of encapsulated key (pkE)
constexpr size_t Nsecret = 32; // Size of KEM shared secret / exporter_secret
constexpr size_t Nx = 32; // Size of elliptic curve x-coordinate
constexpr size_t POINT_SERIALIZED_SIZE = Npk;
constexpr size_t SK_SIZE = Nsk;

// AEAD ChaCha20Poly1305 specific
constexpr size_t AEAD_KEY_LEN = 32; // Nk
constexpr size_t AEAD_NONCE_LEN = 12; // Nn
constexpr size_t AEAD_TAG_LEN = 16; // ChaCha20Poly1305::TAGLEN or Poly1305::TAGLEN

// HPKE Modes as per RFC9180 Section 4
enum class Mode : uint8_t {
    BASE = 0x00,
    PSK = 0x01,
    AUTH = 0x02,
    AUTH_PSK = 0x03,
};

using Bytes = std::vector<uint8_t>;
using SecretKey = std::array<uint8_t, SK_SIZE>;
using PublicKey = std::array<uint8_t, POINT_SERIALIZED_SIZE>; // Uncompressed

struct KeyPair {
    SecretKey sk;
    PublicKey pk;
};

struct HpkeContext {
    Bytes key;
    Bytes base_nonce;
    Bytes exporter_secret;
    uint64_t seq_num{0};
};

struct EncapResult {
    Bytes shared_secret;
    Bytes enc; // Serialized ephemeral public key pkE
};

// --- Core KEM Operations ---
std::optional<KeyPair> DeriveKeyPair(std::span<const uint8_t> ikm, secp256k1_context* ctx);
Bytes DH(const SecretKey& sk_bytes, const PublicKey& pk_bytes, secp256k1_context* ctx);

// --- HPKE Operations ---
std::optional<EncapResult> Encap(const PublicKey& pkR, std::span<const uint8_t> ikmE, secp256k1_context* ctx);
std::optional<Bytes> Decap(const Bytes& enc, const KeyPair& recipient_key_pair, secp256k1_context* ctx);
std::optional<EncapResult> AuthEncap(const PublicKey& pkR, std::span<const uint8_t> ikmE, const KeyPair& sender_auth_key_pair, secp256k1_context* ctx);
std::optional<Bytes> AuthDecap(const Bytes& enc, const KeyPair& recipient_key_pair, const PublicKey& pkS, secp256k1_context* ctx);
std::optional<HpkeContext> KeySchedule(Mode mode, const Bytes& shared_secret, std::span<const uint8_t> info,
    std::span<const uint8_t> psk, std::span<const uint8_t> psk_id);
std::optional<Bytes> Seal(HpkeContext& context, std::span<const uint8_t> aad, std::span<const uint8_t> ptxt);
std::optional<Bytes> Open(HpkeContext& context, std::span<const uint8_t> aad, std::span<const uint8_t> ctxt);

} // namespace hpke_secp256k1_sha256_chachapoly

#endif // BITCOIN_CRYPTO_HPKE_H
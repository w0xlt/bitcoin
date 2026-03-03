// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/messages.h>

#include <crypto/chacha20poly1305.h>
#include <crypto/common.h> // ReadLE32, ReadLE64
#include <dhkem_secp256k1.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace payjoin {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Decompress a CPubKey to 65-byte uncompressed SEC1 format. */
static std::optional<std::array<uint8_t, 65>> DecompressPubKey(const CPubKey& pk)
{
    if (!pk.IsValid()) return std::nullopt;

    if (!pk.IsCompressed()) {
        // Already uncompressed
        if (pk.size() != 65) return std::nullopt;
        std::array<uint8_t, 65> out;
        std::memcpy(out.data(), pk.data(), 65);
        return out;
    }

    CPubKey decompressed(pk);
    if (!decompressed.Decompress()) return std::nullopt;
    if (decompressed.size() != 65) return std::nullopt;

    std::array<uint8_t, 65> out;
    std::memcpy(out.data(), decompressed.data(), 65);
    return out;
}

/** Extract the 32-byte raw private key from a CKey. */
static std::array<uint8_t, 32> GetPrivKeyBytes(const CKey& key)
{
    std::array<uint8_t, 32> out;
    std::memcpy(out.data(), key.data(), 32);
    return out;
}

/** Convert a 12-byte base_nonce vector to ChaCha20::Nonce96. */
static ChaCha20::Nonce96 NonceFromBytes(const std::vector<uint8_t>& nonce_bytes)
{
    return {ReadLE32(nonce_bytes.data()), ReadLE64(nonce_bytes.data() + 4)};
}

// ---------------------------------------------------------------------------
// EncryptMessageA  (sender -> receiver, HPKE Base mode)
// ---------------------------------------------------------------------------

std::optional<std::array<uint8_t, PADDED_MESSAGE_BYTES>>
EncryptMessageA(std::span<const uint8_t> body,
                const CPubKey& reply_pk,
                const CPubKey& receiver_pk)
{
    dhkem_secp256k1::InitContext();

    // Validate inputs
    if (body.size() > PADDED_PLAINTEXT_A) return std::nullopt;
    if (!reply_pk.IsValid() || !reply_pk.IsCompressed()) return std::nullopt;
    if (!receiver_pk.IsValid()) return std::nullopt;

    // Decompress receiver pubkey to 65-byte uncompressed for HPKE
    auto pkR = DecompressPubKey(receiver_pk);
    if (!pkR) return std::nullopt;

    // Generate ephemeral keypair (uncompressed for HPKE internal use)
    CKey skE;
    skE.MakeNewKey(/*fCompressed=*/false);
    CPubKey pkE = skE.GetPubKey();
    if (pkE.size() != dhkem_secp256k1::NENC) return std::nullopt;

    // ElligatorSwift encoding of ephemeral pubkey for wire (64 bytes)
    std::array<unsigned char, 32> entropy;
    GetRandBytes(entropy);
    std::array<std::byte, 32> entropy_bytes;
    std::memcpy(entropy_bytes.data(), entropy.data(), 32);
    EllSwiftPubKey ellswift = skE.EllSwiftCreate(entropy_bytes);

    // Extract raw key bytes for HPKE
    auto skE_bytes = GetPrivKeyBytes(skE);
    std::array<uint8_t, 65> enc;
    std::memcpy(enc.data(), pkE.data(), 65);

    // HPKE KEM Encap (Base mode)
    auto shared_secret = dhkem_secp256k1::Encap(*pkR, skE_bytes, enc);
    memory_cleanse(skE_bytes.data(), skE_bytes.size());
    if (!shared_secret) return std::nullopt;

    // HPKE KeySchedule (Base mode = 0x00)
    std::vector<uint8_t> ss_vec(shared_secret->begin(), shared_secret->end());
    std::vector<uint8_t> info(INFO_A, INFO_A + std::strlen(INFO_A));
    auto ctx = dhkem_secp256k1::KeySchedule(/*mode=*/0x00, ss_vec, info);
    memory_cleanse(ss_vec.data(), ss_vec.size());
    if (!ctx) return std::nullopt;

    // Build plaintext: reply_pk_compressed(33) || body || zero_padding
    // Total plaintext size = COMPRESSED_PK_SIZE + PADDED_PLAINTEXT_A = 33 + 7055 = 7088
    constexpr size_t FULL_PLAINTEXT = COMPRESSED_PK_SIZE + PADDED_PLAINTEXT_A;
    std::vector<uint8_t> plaintext(FULL_PLAINTEXT, 0x00);
    std::memcpy(plaintext.data(), reply_pk.data(), COMPRESSED_PK_SIZE);
    std::memcpy(plaintext.data() + COMPRESSED_PK_SIZE, body.data(), body.size());
    // Remaining bytes are already zero (padding)

    // AEAD Seal with seq=0 nonce
    auto nonce_vec = dhkem_secp256k1::ComputeNonce(ctx->base_nonce, 0);
    auto nonce = NonceFromBytes(nonce_vec);
    auto ciphertext = dhkem_secp256k1::Seal(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ctx->key.data()), ctx->key.size()),
        nonce,
        /*aad=*/{},
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(plaintext.data()), plaintext.size()));
    memory_cleanse(plaintext.data(), plaintext.size());

    // Wire format: ElligatorSwift(64) || ciphertext(7104) = 7168
    if (ELLSWIFT_SIZE + ciphertext.size() != PADDED_MESSAGE_BYTES) return std::nullopt;

    std::array<uint8_t, PADDED_MESSAGE_BYTES> result;
    std::memcpy(result.data(), ellswift.data(), ELLSWIFT_SIZE);
    std::memcpy(result.data() + ELLSWIFT_SIZE, ciphertext.data(), ciphertext.size());
    return result;
}

// ---------------------------------------------------------------------------
// DecryptMessageA
// ---------------------------------------------------------------------------

std::optional<std::pair<std::vector<uint8_t>, CPubKey>>
DecryptMessageA(std::span<const uint8_t> message_a,
                const CKey& receiver_sk)
{
    dhkem_secp256k1::InitContext();

    if (message_a.size() != PADDED_MESSAGE_BYTES) return std::nullopt;
    if (!receiver_sk.IsValid()) return std::nullopt;

    // Split wire format: ElligatorSwift(64) || ciphertext(7104)
    EllSwiftPubKey ellswift(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(message_a.data()), ELLSWIFT_SIZE));
    std::span<const uint8_t> ciphertext(message_a.data() + ELLSWIFT_SIZE,
                                         PADDED_MESSAGE_BYTES - ELLSWIFT_SIZE);

    // Decode ElligatorSwift -> compressed CPubKey -> uncompressed 65 bytes
    CPubKey pkE_compressed = ellswift.Decode();
    auto pkE_uncompressed = DecompressPubKey(pkE_compressed);
    if (!pkE_uncompressed) return std::nullopt;

    // HPKE KEM Decap (Base mode)
    auto skR_bytes = GetPrivKeyBytes(receiver_sk);
    auto shared_secret = dhkem_secp256k1::Decap(*pkE_uncompressed, skR_bytes);
    memory_cleanse(skR_bytes.data(), skR_bytes.size());
    if (!shared_secret) return std::nullopt;

    // HPKE KeySchedule (Base mode = 0x00)
    std::vector<uint8_t> ss_vec(shared_secret->begin(), shared_secret->end());
    std::vector<uint8_t> info(INFO_A, INFO_A + std::strlen(INFO_A));
    auto ctx = dhkem_secp256k1::KeySchedule(/*mode=*/0x00, ss_vec, info);
    memory_cleanse(ss_vec.data(), ss_vec.size());
    if (!ctx) return std::nullopt;

    // AEAD Open with seq=0
    auto nonce_vec = dhkem_secp256k1::ComputeNonce(ctx->base_nonce, 0);
    auto nonce = NonceFromBytes(nonce_vec);
    auto plaintext = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ctx->key.data()), ctx->key.size()),
        nonce,
        /*aad=*/{},
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ciphertext.data()), ciphertext.size()));
    if (!plaintext) return std::nullopt;

    // Expected plaintext size: COMPRESSED_PK_SIZE + PADDED_PLAINTEXT_A = 7088
    constexpr size_t FULL_PLAINTEXT = COMPRESSED_PK_SIZE + PADDED_PLAINTEXT_A;
    if (plaintext->size() != FULL_PLAINTEXT) return std::nullopt;

    // Extract reply public key (first 33 bytes)
    CPubKey reply_pk(std::span<const uint8_t>(plaintext->data(), COMPRESSED_PK_SIZE));
    if (!reply_pk.IsValid()) return std::nullopt;

    // Extract padded body (remaining PADDED_PLAINTEXT_A bytes)
    std::vector<uint8_t> body(plaintext->begin() + COMPRESSED_PK_SIZE, plaintext->end());

    return std::make_pair(std::move(body), reply_pk);
}

// ---------------------------------------------------------------------------
// EncryptMessageB  (receiver -> sender, HPKE Auth mode)
// ---------------------------------------------------------------------------

std::optional<std::array<uint8_t, PADDED_MESSAGE_BYTES>>
EncryptMessageB(std::span<const uint8_t> body,
                const CKey& receiver_sk,
                const CPubKey& receiver_pk,
                const CPubKey& sender_reply_pk)
{
    dhkem_secp256k1::InitContext();

    // Validate inputs
    if (body.size() > PADDED_PLAINTEXT_B) return std::nullopt;
    if (!receiver_sk.IsValid()) return std::nullopt;
    if (!receiver_pk.IsValid()) return std::nullopt;
    if (!sender_reply_pk.IsValid()) return std::nullopt;

    // Decompress sender's reply pubkey to 65 bytes (this is pkR for HPKE)
    auto pkR = DecompressPubKey(sender_reply_pk);
    if (!pkR) return std::nullopt;

    // Generate ephemeral keypair (uncompressed)
    CKey skE;
    skE.MakeNewKey(/*fCompressed=*/false);
    CPubKey pkE = skE.GetPubKey();
    if (pkE.size() != dhkem_secp256k1::NENC) return std::nullopt;

    // ElligatorSwift encoding for wire
    std::array<unsigned char, 32> entropy;
    GetRandBytes(entropy);
    std::array<std::byte, 32> entropy_bytes;
    std::memcpy(entropy_bytes.data(), entropy.data(), 32);
    EllSwiftPubKey ellswift = skE.EllSwiftCreate(entropy_bytes);

    // Extract raw key bytes
    auto skE_bytes = GetPrivKeyBytes(skE);
    auto skS_bytes = GetPrivKeyBytes(receiver_sk); // sender's static key in HPKE terms
    std::array<uint8_t, 65> enc;
    std::memcpy(enc.data(), pkE.data(), 65);

    // HPKE KEM AuthEncap (Auth mode)
    // pkR = sender_reply_pk (recipient), skS = receiver_sk (sender/authenticator)
    auto shared_secret = dhkem_secp256k1::AuthEncap(*pkR, skS_bytes, skE_bytes, enc);
    memory_cleanse(skE_bytes.data(), skE_bytes.size());
    memory_cleanse(skS_bytes.data(), skS_bytes.size());
    if (!shared_secret) return std::nullopt;

    // HPKE KeySchedule (Auth mode = 0x02)
    std::vector<uint8_t> ss_vec(shared_secret->begin(), shared_secret->end());
    std::vector<uint8_t> info(INFO_B, INFO_B + std::strlen(INFO_B));
    auto ctx = dhkem_secp256k1::KeySchedule(/*mode=*/0x02, ss_vec, info);
    memory_cleanse(ss_vec.data(), ss_vec.size());
    if (!ctx) return std::nullopt;

    // Build plaintext: body || zero_padding to PADDED_PLAINTEXT_B bytes
    std::vector<uint8_t> plaintext(PADDED_PLAINTEXT_B, 0x00);
    std::memcpy(plaintext.data(), body.data(), body.size());

    // AEAD Seal with seq=0
    auto nonce_vec = dhkem_secp256k1::ComputeNonce(ctx->base_nonce, 0);
    auto nonce = NonceFromBytes(nonce_vec);
    auto ciphertext = dhkem_secp256k1::Seal(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ctx->key.data()), ctx->key.size()),
        nonce,
        /*aad=*/{},
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(plaintext.data()), plaintext.size()));
    memory_cleanse(plaintext.data(), plaintext.size());

    // Wire format: ElligatorSwift(64) || ciphertext(7104) = 7168
    if (ELLSWIFT_SIZE + ciphertext.size() != PADDED_MESSAGE_BYTES) return std::nullopt;

    std::array<uint8_t, PADDED_MESSAGE_BYTES> result;
    std::memcpy(result.data(), ellswift.data(), ELLSWIFT_SIZE);
    std::memcpy(result.data() + ELLSWIFT_SIZE, ciphertext.data(), ciphertext.size());
    return result;
}

// ---------------------------------------------------------------------------
// DecryptMessageB
// ---------------------------------------------------------------------------

std::optional<std::vector<uint8_t>>
DecryptMessageB(std::span<const uint8_t> message_b,
                const CPubKey& receiver_pk,
                const CKey& sender_reply_sk)
{
    dhkem_secp256k1::InitContext();

    if (message_b.size() != PADDED_MESSAGE_BYTES) return std::nullopt;
    if (!receiver_pk.IsValid()) return std::nullopt;
    if (!sender_reply_sk.IsValid()) return std::nullopt;

    // Split wire format: ElligatorSwift(64) || ciphertext(7104)
    EllSwiftPubKey ellswift(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(message_b.data()), ELLSWIFT_SIZE));
    std::span<const uint8_t> ciphertext(message_b.data() + ELLSWIFT_SIZE,
                                         PADDED_MESSAGE_BYTES - ELLSWIFT_SIZE);

    // Decode ElligatorSwift -> uncompressed 65-byte enc
    CPubKey pkE_compressed = ellswift.Decode();
    auto enc = DecompressPubKey(pkE_compressed);
    if (!enc) return std::nullopt;

    // Decompress receiver's pubkey (pkS in HPKE Auth terms)
    auto pkS = DecompressPubKey(receiver_pk);
    if (!pkS) return std::nullopt;

    // HPKE KEM AuthDecap
    // skR = sender_reply_sk (recipient), pkS = receiver_pk (authenticated sender)
    auto skR_bytes = GetPrivKeyBytes(sender_reply_sk);
    auto shared_secret = dhkem_secp256k1::AuthDecap(*enc, skR_bytes, *pkS);
    memory_cleanse(skR_bytes.data(), skR_bytes.size());
    if (!shared_secret) return std::nullopt;

    // HPKE KeySchedule (Auth mode = 0x02)
    std::vector<uint8_t> ss_vec(shared_secret->begin(), shared_secret->end());
    std::vector<uint8_t> info(INFO_B, INFO_B + std::strlen(INFO_B));
    auto ctx = dhkem_secp256k1::KeySchedule(/*mode=*/0x02, ss_vec, info);
    memory_cleanse(ss_vec.data(), ss_vec.size());
    if (!ctx) return std::nullopt;

    // AEAD Open with seq=0
    auto nonce_vec = dhkem_secp256k1::ComputeNonce(ctx->base_nonce, 0);
    auto nonce = NonceFromBytes(nonce_vec);
    auto plaintext = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ctx->key.data()), ctx->key.size()),
        nonce,
        /*aad=*/{},
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ciphertext.data()), ciphertext.size()));
    if (!plaintext) return std::nullopt;

    if (plaintext->size() != PADDED_PLAINTEXT_B) return std::nullopt;
    return *plaintext;
}

} // namespace payjoin

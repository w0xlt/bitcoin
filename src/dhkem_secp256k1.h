// Distributed under the MIT software license (see accompanying file COPYING).

#ifndef BITCOIN_CRYPTO_DHKEM_SECP256K1_H
#define BITCOIN_CRYPTO_DHKEM_SECP256K1_H

#include <cstdlib>
#include <cstdint>
#include <secp256k1.h>
#include <span>
#include <array>
#include <optional>
#include <vector>
#include <crypto/chacha20poly1305.h>  // for AEADChaCha20Poly1305 and Nonce96

/**
 * secp256k1-based DHKEM for HPKE (Hybrid Public Key Encryption)
 * 
 * Provides functions for key pair derivation, serialization, and Diffie-Hellman 
 * encapsulation/decapsulation (including authenticated modes) as specified in 
 * draft-wahby-cfrg-hpke-kem-secp256k1-01【2†】.
 */
namespace dhkem_secp256k1 {

using ::secp256k1_pubkey;
using ::secp256k1_ec_pubkey_serialize;
using ::secp256k1_context_create;
using ::secp256k1_context;

static const size_t NSECRET = 32;        //!< Length of KEM shared secret (Nsecret = 32 bytes)【3†】 
static const size_t NENC = 65;           //!< Length of encapsulated key (ephemeral public key), uncompressed SEC1 (65 bytes)【4†】
static const size_t NPK = 65;            //!< Length of public key serialization, uncompressed (65 bytes)【5†】
static const size_t NSK = 32;            //!< Length of private key serialization (32 bytes)【6†*/

// Labeled prefix "HPKE-v1" and suite ID for KEM(secp256k1, HKDF-SHA256)【20†】
static const unsigned char LABEL_PREFIX[] = {'H','P','K','E','-','v','1'};
/* static const unsigned char SUITE_ID[]    = {'K','E','M', 0x00, 0x16}; // "KEM\x00\x16" */
static const unsigned char SUITE_ID[] = {'H','P','K','E', 0x00, 0x16, 0x00, 0x01, 0x00, 0x03}; // example: KEM=0x0016, KDF=0x0001, AEAD=0x0003

/**
 * DeriveKeyPair(IKM): Derive a secp256k1 key pair from input keying material.
 * 
 * Follows RFC 9180 Section 7.1.3 algorithm with rejection sampling【7†】【8†】:
 *   - HKDF-Extract with salt="", label="dkp_prk"
 *   - Loop: HKDF-Expand labeled "candidate" until a valid scalar in [1, order-1] is found.
 *   - The bitmask 0xff is applied to the first byte (no effective change for secp256k1)【9†】.
 * 
 * @param ikm        Input keying material (IKM) bytes.
 * @param outPrivKey (output) Derived private key, 32 bytes.
 * @param outPubKey  (output) Derived public key, 65 bytes uncompressed format (0x04 || X || Y).
 * @return true on success, false if derivation failed (e.g., after 256 attempts).
 */
bool DeriveKeyPair(std::span<const uint8_t> ikm,
                   std::array<uint8_t, 32>& outPrivKey,
                   std::array<uint8_t, 65>& outPubKey);

/**
 * Encap(pkR): Perform HPKE KEM encapsulation to the recipient's public key (Base mode).
 * 
 * Generates a random ephemeral key pair and produces:
 *   - enc: the ephemeral public key (65 bytes, uncompressed)
 *   - shared_secret: 32-byte KEM shared secret
 * 
 * Implements DHKEM Base mode using secp256k1 ECDH:
 *   dh = x-coordinate of (skE * pkR)【17†】,
 *   kem_context = enc || pkR,
 *   shared_secret = HKDF-Extract & Expand(dh, "shared secret")【18†】.
 * 
 * @param pkR  Recipient's public key (65-byte uncompressed).
 * @param skE  Ephemeral secret key (32-byte secret).
 * @param enc  ephemeral public key (65-byte uncompressed).
 * @return 32-byte shared secret and ephemeral public key (65-byte uncompressed) on success (std::nullopt if failure).
 */
std::optional<std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 65>>>
Encap(std::span<const uint8_t> pkR, const std::array<uint8_t, 32>& skE, const std::array<uint8_t, 65>& enc);

/**
 * Decap(enc, skR): Perform HPKE KEM decapsulation using the recipient's private key (Base mode).
 * 
 * Given the encapsulated key (ephemeral public key) and recipient's private key, 
 * computes the same 32-byte shared secret as Encap(). Returns std::nullopt if input keys are invalid.
 * 
 * @param enc  Ephemeral public key (65-byte uncompressed).
 * @param skR  Recipient's private key (32-byte scalar).
 * @return 32-byte shared secret on success (std::nullopt if validation fails).
 */
std::optional<std::array<uint8_t, 32>>
Decap(std::span<const uint8_t> enc, std::span<const uint8_t> skR);

/** Initialize the internal secp256k1 context (must be called before other operations). */
void InitContext();

/** 
 * LabeledExpand(prk, label, info, L): HKDF-Expand with a label, per RFC 9180.
 * Constructs the info as: length (2 bytes) || "HPKE-v1" || suite_id || label || info.
 * Returns an output keying material of length L bytes.
 */
std::vector<uint8_t> LabeledExpand(const std::vector<uint8_t>& prk,
                                   const std::vector<uint8_t>& label,
                                   const std::vector<uint8_t>& info,
                                   size_t L);

/** 
 * LabeledExtract(salt, label, ikm): HKDF-Extract with a label, per RFC 9180.
 * Constructs the input keying material as: "HPKE-v1" || suite_id || label || ikm.
 * Returns the pseudorandom key (PRK) as a 32-byte vector.
 */
std::vector<uint8_t> LabeledExtract(const std::vector<uint8_t>& salt,
                                    const std::vector<uint8_t>& label,
                                    const std::vector<uint8_t>& ikm);

/**
 * AuthEncap(pkR, skS): Authenticated encapsulation using sender's static key.
 * 
 * Outputs:
 *  - shared_secret: 32-byte KEM shared secret
 * 
 * Uses the recipient’s public key (pkR) and sender’s private key (skS). Implements DHKEM in auth mode:
 *   DH1 = x-coordinate of (skE * pkR)
 *   DH2 = x-coordinate of (skS * pkR)
 *   kem_context = enc || pkR || pkS
 *   shared_secret = HKDF based on DH1 || DH2 and kem_context.
 */
bool AuthEncap(std::array<uint8_t, 32>& shared_secret,
               const std::array<uint8_t, 32>& skE,
               const std::array<uint8_t, 65>& enc,
               const std::array<uint8_t, 65>& pkR,
               const std::array<uint8_t, 32>& skS);

/**
 * AuthDecap(enc, skR, pkS): Authenticated decapsulation using sender’s static public key.
 * 
 * Given the encapsulated ephemeral public key (enc), receiver’s private key (skR), 
 * and sender’s static public key (pkS), computes the 32-byte shared secret (matching AuthEncap).
 * Returns false if any input is invalid.
 */
bool AuthDecap(std::array<uint8_t, 32>& shared_secret,
               const std::array<uint8_t, 65>& enc,
               const std::array<uint8_t, 32>& skR,
               const std::array<uint8_t, 65>& pkS);

/**
 * Seal(key, nonce, aad, plaintext): AEAD encryption with ChaCha20-Poly1305.
 * 
 * Encrypts the plaintext with a 32-byte key, 96-bit nonce, and associated data (AAD).
 * Returns a vector containing the ciphertext followed by the 16-byte authentication tag.
 */
std::vector<uint8_t> Seal(std::span<const std::byte> key, ChaCha20::Nonce96 nonce,
                          std::span<const std::byte> aad, std::span<const std::byte> plaintext);

/**
 * Open(key, nonce, aad, ciphertext): AEAD decryption with ChaCha20-Poly1305.
 * 
 * Decrypts the ciphertext (including its 16-byte authentication tag) using the given key, nonce, and AAD.
 * Returns the plaintext on success, or std::nullopt if authentication fails (e.g., if ciphertext or tag are modified).
 */
std::optional<std::vector<uint8_t>> Open(std::span<const std::byte> key, ChaCha20::Nonce96 nonce,
                                         std::span<const std::byte> aad, std::span<const std::byte> ciphertext);


} // namespace dhkem_secp256k1

#endif // BITCOIN_CRYPTO_DHKEM_SECP256K1_H

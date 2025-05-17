// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_DHKEM_SECP256K1_H
#define BITCOIN_CRYPTO_DHKEM_SECP256K1_H

#include <cstdlib>
#include <cstdint>
#include <secp256k1.h>

/** 
 * secp256k1-based DHKEM for HPKE (Hybrid Public Key Encryption)
 * 
 * Provides functions for key pair derivation, serialization, and Diffie-Hellman 
 * encapsulation/decapsulation (including authenticated modes) as specified in 
 * draft-wahby-cfrg-hpke-kem-secp256k1-01:contentReference[oaicite:2]{index=2}.
 */
namespace dhkem_secp256k1 {

using ::secp256k1_pubkey;
using ::secp256k1_ec_pubkey_serialize;

static const size_t NSECRET = 32;        //!< Length of KEM shared secret (Nsecret = 32 bytes):contentReference[oaicite:3]{index=3} 
static const size_t NENC = 65;           //!< Length of encapsulated key (ephemeral public key), uncompressed SEC1 (65 bytes):contentReference[oaicite:4]{index=4}
static const size_t NPK = 65;            //!< Length of public key serialization, uncompressed (65 bytes):contentReference[oaicite:5]{index=5}
static const size_t NSK = 32;            //!< Length of private key serialization (32 bytes):contentReference[oaicite:6]{index=6}

// Labeled prefix "HPKE-v1" and suite ID for KEM(secp256k1, HKDF-SHA256):contentReference[oaicite:20]{index=20}
static const unsigned char LABEL_PREFIX[] = {'H','P','K','E','-','v','1'};
static const unsigned char SUITE_ID[]    = {'K','E','M', 0x00, 0x16}; // "KEM\x00\x16"

/**
 * DeriveKeyPair(IKM): Derive a secp256k1 key pair from input keying material.
 * 
 * Follows RFC 9180 Section 7.1.3 algorithm with rejection sampling:contentReference[oaicite:7]{index=7}:contentReference[oaicite:8]{index=8}:
 *   - HKDF-Extract with salt="", label="dkp_prk"
 *   - Loop: HKDF-Expand labeled "candidate" until a valid scalar in [1, order-1] is found.
 *   - The bitmask 0xff is applied to the first byte (no effective change for secp256k1):contentReference[oaicite:9]{index=9}.
 * 
 * @param ikm    Input keying material (IKM) bytes.
 * @param ikm_len Length of IKM.
 * @param out_sk (output) Derived private key, 32 bytes.
 * @param out_pk (output) Derived public key, 65 bytes uncompressed format (0x04 || X || Y).
 * @return true on success, false if derivation failed (e.g., after 256 attempts).
 */
bool DeriveKeyPair(const uint8_t* ikm, size_t ikm_len, uint8_t out_sk[NSK], uint8_t out_pk[NPK]);

/**
 * SerializePublicKey(pub): Encode a secp256k1 public key to 65-byte uncompressed form:contentReference[oaicite:10]{index=10}.
 * 
 * @param pub    Input secp256k1_pubkey object.
 * @param out65  (output) Buffer of length 65 to receive uncompressed public key bytes.
 * @return true on success.
 */
bool SerializePublicKey(const struct secp256k1_pubkey& pub, uint8_t out65[NPK]);

/**
 * DeserializePublicKey(bytes): Parse a 65-byte uncompressed public key into internal form:contentReference[oaicite:11]{index=11}.
 * 
 * Deserialized keys are validated (must lie on curve and not be infinity) similar to NIST-P256 validation:contentReference[oaicite:12]{index=12}.
 * 
 * @param in65   65-byte input (should start with 0x04).
 * @param pub_out (output) secp256k1_pubkey object.
 * @return true if the input is a valid uncompressed secp256k1 public key.
 */
bool DeserializePublicKey(const uint8_t in65[NPK], struct secp256k1_pubkey& pub_out);

/**
 * SerializePrivateKey(priv): Convert a private key integer to 32-byte big-endian octet string:contentReference[oaicite:13]{index=13}.
 * 
 * If the private key integer is outside [0, order-1], it is reduced modulo the curve order:contentReference[oaicite:14]{index=14}.
 * 
 * @param priv32 Input 32-byte private key (interpreted as big-endian number).
 * @param out32  (output) 32-byte big-endian representation in [0, order-1].
 */
void SerializePrivateKey(const uint8_t priv32[NSK], uint8_t out32[NSK]);

/**
 * DeserializePrivateKey(bytes): Convert a 32-byte big-endian octet string to a private key field element:contentReference[oaicite:15]{index=15}.
 * 
 * If the octets represent an integer outside [0, order-1], it will be reduced mod order:contentReference[oaicite:16]{index=16}.
 * 
 * @param in32   32-byte big-endian input.
 * @param out_sk (output) 32-byte private key (valid scalar in [0, order-1]).
 */
void DeserializePrivateKey(const uint8_t in32[NSK], uint8_t out_sk[NSK]);

/**
 * Encap(pkR): Perform HPKE KEM encapsulation to recipient's public key (Base mode).
 * 
 * Generates a random ephemeral key pair and produces:
 *   - enc: the ephemeral public key (65 bytes, uncompressed).
 *   - shared_secret: 32-byte KEM shared secret.
 * 
 * Implements DHKEM Base mode using secp256k1 ECDH:
 *   dh = x-coordinate of (skE * pkR):contentReference[oaicite:17]{index=17},
 *   kem_context = enc || pkR,
 *   shared_secret = HKDF-Extract&Expand(dh, "hpke shared secret"):contentReference[oaicite:18]{index=18}.
 * 
 * @param pkR_bytes  Recipient's public key (65-byte uncompressed).
 * @param out_shared_secret (output) 32-byte shared secret.
 * @param out_enc    (output) Ephemeral public key (65-byte uncompressed).
 * @return true on success.
 */
bool Encap(const uint8_t pkR_bytes[NPK], uint8_t out_shared_secret[NSECRET], uint8_t out_enc[NPK]);

/**
 * Decap(enc, skR): Perform HPKE KEM decapsulation using recipient's private key (Base mode).
 * 
 * Given the encapsulated key (ephemeral pubkey) and recipient's private key, computes the same 32-byte shared secret as Encap().
 * Returns false if input keys are invalid.
 * 
 * @param enc_bytes  Ephemeral public key (65-byte uncompressed).
 * @param skR_bytes  Recipient's private key (32-byte scalar).
 * @param out_shared_secret (output) 32-byte shared secret.
 * @return true on success (false if validation fails).
 */
bool Decap(const uint8_t enc_bytes[NPK], const uint8_t skR_bytes[NSK], uint8_t out_shared_secret[NSECRET]);

/**
 * AuthEncap(pkR, skS): Authenticated KEM Encapsulation (mode_auth), using sender's static key.
 * 
 * Computes a shared secret that authenticates the holder of skS to the recipient:
 *   dh1 = x-coordinate of (skE * pkR)
 *   dh2 = x-coordinate of (skS * pkR):contentReference[oaicite:19]{index=19}
 *   kem_context = enc || pkR || pkS
 *   shared_secret = HKDF-Extract&Expand( concat(dh1,dh2), "hpke shared secret" )
 * 
 * @param pkR_bytes Recipient’s public key (65 bytes).
 * @param skS_bytes Sender’s static private key (32 bytes).
 * @param out_shared_secret (output) 32-byte shared secret.
 * @param out_enc   (output) Ephemeral public key (65 bytes).
 * @return true on success.
 */
bool AuthEncap(const uint8_t pkR_bytes[NPK], const uint8_t skS_bytes[NSK], 
               uint8_t out_shared_secret[NSECRET], uint8_t out_enc[NPK]);

/**
 * AuthDecap(enc, skR, pkS): Authenticated KEM Decapsulation, with sender's public key.
 * 
 * Verifies and decapsulates an authenticated encapsulated key:
 *   dh1 = x-coordinate of (skR * pkE)
 *   dh2 = x-coordinate of (skR * pkS)
 *   kem_context = enc || pkR || pkS
 *   shared_secret = HKDF-Extract&Expand( concat(dh1,dh2), "hpke shared secret" )
 * 
 * Returns false if inputs are invalid or authentication fails (i.e., pkS not on curve).
 * 
 * @param enc_bytes Ephemeral public key from sender (65 bytes).
 * @param skR_bytes Recipient’s private key (32 bytes).
 * @param pkS_bytes Sender’s static public key (65 bytes).
 * @param out_shared_secret (output) 32-byte shared secret.
 * @return true on success.
 */
bool AuthDecap(const uint8_t enc_bytes[NPK], const uint8_t skR_bytes[NSK], const uint8_t pkS_bytes[NPK],
               uint8_t out_shared_secret[NSECRET]);

void HKDF_Extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t out_prk[32]);

void HKDF_Expand32(const uint8_t prk[32], const uint8_t* info_data, size_t info_len, uint8_t out_okm[], size_t L);

} // namespace dhkem_secp256k1
#endif // BITCOIN_CRYPTO_DHKEM_SECP256K1_H

// Copyright (c) 2023- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_HKDF_SHA256_H
#define BITCOIN_CRYPTO_HKDF_SHA256_H

#include <span.h>    // For std::span
#include <vector>   // For std::vector
#include <cstdint>  // For uint8_t, size_t

namespace crypto {

/**
 * HKDF-Extract as defined in RFC 5869, using HMAC-SHA256.
 *
 * The "extract" step takes the input keying material (IKM) and an optional
 * salt to produce a pseudorandom key (PRK).
 *
 * @param salt Optional salt value. If the span is empty, a salt of
 *             CHMAC_SHA256::OUTPUT_SIZE zeros is used, as per RFC 5869.
 * @param ikm Input Keying Material.
 * @return The pseudorandom key (PRK) of CHMAC_SHA256::OUTPUT_SIZE bytes.
 */
[[nodiscard]] std::vector<unsigned char> HKDF_Extract_SHA256(
    std::span<const unsigned char> salt,
    std::span<const unsigned char> ikm);

/**
 * HKDF-Expand as defined in RFC 5869, using HMAC-SHA256.
 *
 * The "expand" step takes the pseudorandom key (PRK), an optional info
 * context, and a desired output length (L) to produce the output keying
 * material (OKM).
 *
 * @param prk A pseudorandom key, typically the output from HKDF-Extract.
 *            Must be at least CHMAC_SHA256::OUTPUT_SIZE bytes long.
 * @param info Optional context and application-specific information.
 * @param length Length of output keying material (OKM) in bytes.
 *               Maximum allowed length is 255 * CHMAC_SHA256::OUTPUT_SIZE (8160 bytes for SHA-256).
 * @return The output keying material (OKM) of 'length' bytes.
 *         Returns an empty vector if 'length' is too large, 'prk' is too short,
 *         or 'length' is 0.
 */
[[nodiscard]] std::vector<unsigned char> HKDF_Expand_SHA256(
    std::span<const unsigned char> prk,
    std::span<const unsigned char> info,
    size_t length);

/**
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as defined in RFC 5869.
 * Uses HMAC-SHA256 as the hash function.
 *
 * This function combines HKDF-Extract and HKDF-Expand.
 *
 * @param salt Optional salt value. If the span is empty, a salt of
 *             CHMAC_SHA256::OUTPUT_SIZE zeros is used.
 * @param ikm Input Keying Material.
 * @param info Optional context and application-specific information.
 * @param length Length of output keying material (OKM) in bytes.
 *               Maximum allowed length is 255 * CHMAC_SHA256::OUTPUT_SIZE (8160 bytes for SHA-256).
 * @return The output keying material (OKM) of 'length' bytes.
 *         Returns an empty vector if 'length' is too large or 'length' is 0.
 */
[[nodiscard]] std::vector<unsigned char> HKDF_SHA256(
    std::span<const unsigned char> salt,
    std::span<const unsigned char> ikm,
    std::span<const unsigned char> info,
    size_t length);

} // namespace crypto

#endif // BITCOIN_CRYPTO_HKDF_SHA256_H

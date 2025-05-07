// Copyright (c) 2023- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/hkdf_sha256.h>
#include <crypto/hmac_sha256.h> // For CHMAC_SHA256 and CHMAC_SHA256::OUTPUT_SIZE
#include <cstring>              // For std::memset, std::memcpy (though not strictly needed with vector ops)
#include <algorithm>            // For std::min
#include <array>                // For std::array

// Statically assert that the HMAC-SHA256 output size is what we expect (32 bytes).
// This is a fundamental constant for HKDF-SHA256.
static_assert(CHMAC_SHA256::OUTPUT_SIZE == 32, "HMAC-SHA256 output size must be 32 bytes for HKDF-SHA256");

namespace crypto {

std::vector<unsigned char> HKDF_Extract_SHA256(
    std::span<const unsigned char> salt,
    std::span<const unsigned char> ikm)
{
    std::vector<unsigned char> prk_output(CHMAC_SHA256::OUTPUT_SIZE);

    if (salt.empty()) {
        // RFC 5869, Section 2.2: If salt is not provided, it is set to a string of HashLen zeros.
        std::array<unsigned char, CHMAC_SHA256::OUTPUT_SIZE> zero_salt;
        std::memset(zero_salt.data(), 0, zero_salt.size());
        CHMAC_SHA256 hmac_ctx(zero_salt.data(), zero_salt.size());
        hmac_ctx.Write(ikm.data(), ikm.size());
        hmac_ctx.Finalize(prk_output.data());
    } else {
        CHMAC_SHA256 hmac_ctx(salt.data(), salt.size());
        hmac_ctx.Write(ikm.data(), ikm.size());
        hmac_ctx.Finalize(prk_output.data());
    }
    return prk_output;
}

std::vector<unsigned char> HKDF_Expand_SHA256(
    std::span<const unsigned char> prk,
    std::span<const unsigned char> info,
    size_t length)
{
    const size_t hash_len = CHMAC_SHA256::OUTPUT_SIZE;

    // RFC 5869, Section 2.3: "L must be less than or equal to 255 * HashLen"
    if (length > 255 * hash_len) {
        return {}; // Output length too large
    }

    // RFC 5869, Section 2.2: "PRK must be at least HashLen octets long."
    if (prk.size() < hash_len) {
        return {}; // Pseudorandom key is too short
    }

    if (length == 0) {
        return {}; // No output requested is typically an empty vector
    }

    std::vector<unsigned char> okm;
    okm.reserve(length); // Pre-allocate memory

    std::vector<unsigned char> t_prev; // T(0) is an empty string for the first iteration

    // N = ceil(L / HashLen)
    size_t num_blocks = (length + hash_len - 1) / hash_len;

    for (uint8_t i = 1; i <= num_blocks; ++i) {
        CHMAC_SHA256 hmac_iter(prk.data(), prk.size()); // Key for HMAC is PRK

        // Input to HMAC: T_prev | info | counter
        if (!t_prev.empty()) {
            hmac_iter.Write(t_prev.data(), t_prev.size());
        }
        if (!info.empty()) {
            hmac_iter.Write(info.data(), info.size());
        }
        hmac_iter.Write(&i, 1); // Append the single byte counter 'i'

        std::array<unsigned char, CHMAC_SHA256::OUTPUT_SIZE> t_current_block;
        hmac_iter.Finalize(t_current_block.data());

        // Append the generated block (or part of it) to OKM
        size_t bytes_to_add = std::min(hash_len, length - okm.size());
        okm.insert(okm.end(), t_current_block.begin(), t_current_block.begin() + bytes_to_add);

        if (okm.size() == length) {
            break; // OKM is complete
        }

        // For the next iteration, T(i) becomes T_prev
        // No need to copy full t_current_block if only part was used, but RFC implies full block T(i) is used.
        t_prev.assign(t_current_block.begin(), t_current_block.end());
    }

    return okm;
}

std::vector<unsigned char> HKDF_SHA256(
    std::span<const unsigned char> salt,
    std::span<const unsigned char> ikm,
    std::span<const unsigned char> info,
    size_t length)
{
    std::vector<unsigned char> prk = HKDF_Extract_SHA256(salt, ikm);
    // HKDF_Extract_SHA256 always returns a vector of CHMAC_SHA256::OUTPUT_SIZE,
    // so no need to check prk.empty() unless the underlying HMAC can fail in a way that returns empty.
    // Given the CHMAC_SHA256 interface, prk will be valid if inputs are.
    return HKDF_Expand_SHA256(prk, info, length);
}

} // namespace crypto

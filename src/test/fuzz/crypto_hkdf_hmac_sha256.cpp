// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/hkdf_sha256.h> 
#include <crypto/hmac_sha256.h>
#include <span.h>                  // For std::span
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h> // For ConsumeRandomLengthByteVector

#include <cstdint>
#include <string>
#include <vector>
#include <cstring> // For strlen

FUZZ_TARGET(crypto_hkdf_sha256) // Renamed target to reflect general HKDF usage
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    // 1. Consume IKM and Salt
    const std::vector<uint8_t> initial_key_material = ConsumeRandomLengthByteVector(fuzzed_data_provider);
    const std::string salt_str = fuzzed_data_provider.ConsumeRandomLengthString(1024);

    // Create Spans for HKDF functions
    const std::span<const unsigned char> ikm_span(initial_key_material);
    const std::span<const unsigned char> salt_span(reinterpret_cast<const unsigned char*>(salt_str.data()), salt_str.length());


    // 2. Perform HKDF-Extract to get PRK
    // HKDF_Extract_SHA256 returns std::vector<unsigned char>
    const std::vector<unsigned char> prk_vec = crypto::HKDF_Extract_SHA256(salt_span, ikm_span);

    // Check if PRK is valid (should be 32 bytes if extract was successful, or empty if ikm was too problematic - though extract doesn't have many failure modes)
    // The current HKDF_Extract_SHA256 always returns 32 bytes or an empty vector if an underlying HMAC could fail (not expected for CHMAC_SHA256).
    // For fuzzing, if PRK is empty, we might as well stop, or proceed knowing expand will fail.
    // Assuming prk_vec will be 32 bytes unless IKM or salt leads to an unexpected CHMAC_SHA256 issue.
    // For robustness, let's handle the case where prk_vec might not be 32 bytes if underlying extract could somehow fail to produce that.
    // However, our current HKDF_Extract_SHA256 always produces 32 bytes.
    if (prk_vec.size() != CHMAC_SHA256::OUTPUT_SIZE) {
        // This case should ideally not be hit if IKM/salt are just random bytes.
        // If it is, it might indicate an issue in HKDF_Extract_SHA256's error handling or CHMAC_SHA256 for certain inputs.
        // For now, we can just return, as expand would fail anyway.
        return;
    }
    const std::span<const unsigned char> prk_span(prk_vec);


    // 3. Loop for HKDF-Expand
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000) {
        const std::string info_str = fuzzed_data_provider.ConsumeRandomLengthString(128);
        const std::span<const unsigned char> info_span(reinterpret_cast<const unsigned char*>(info_str.data()), info_str.length());

        // Call HKDF_Expand_SHA256 to get 32 bytes of output
        // HKDF_Expand_SHA256 returns std::vector<unsigned char>
        std::vector<unsigned char> okm_vec = crypto::HKDF_Expand_SHA256(prk_span, info_span, 32);

        // We can check if okm_vec.size() is 32.
        // If HKDF_Expand_SHA256 failed (e.g., PRK was too short, though we checked above, or length was invalid),
        // okm_vec would be empty.
        // The fuzz target doesn't explicitly check the output `out.data()` previously,
        // it just calls the function. So, we'll just call it here too.
        // If okm_vec is empty, it's a valid outcome for certain error conditions of HKDF_Expand.
        // The purpose of the fuzzer is to find crashes or hangs, not necessarily logical errors unless asserted.
        (void)okm_vec; // Suppress unused variable warning if not checking its content.
                       // In a real scenario, you'd use okm_vec.
    }

    // No explicit cleansing of prk_vec here, as it's a fuzz target and its lifetime ends.
    // Fuzzers are primarily for finding crashes, hangs, memory errors (ASan/MSan), undefined behavior (UBSan).
}
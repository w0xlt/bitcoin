// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA512_256_H
#define BITCOIN_CRYPTO_SHA512_256_H

#include <cstdint>
#include <cstdlib>

/** A hasher class for SHA-512/256 (FIPS 180-4). */
class CSHA512_256
{
private:
    uint64_t s[8];
    unsigned char buf[128];
    uint64_t bytes{0};

public:
    static constexpr size_t OUTPUT_SIZE = 32;

    CSHA512_256();
    CSHA512_256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA512_256& Reset();
    uint64_t Size() const { return bytes; }
};

#endif // BITCOIN_CRYPTO_SHA512_256_H

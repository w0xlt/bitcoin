// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324.h>

#include <chainparams.h>
#include <crypto/chacha20.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/hkdf_sha256.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <span.h>
#include <support/cleanse.h>
#include <uint256.h>

#include <algorithm>
#include <assert.h>
#include <cstdint>
#include <cstddef>
#include <iterator>
#include <string>

BIP324Cipher::BIP324Cipher(const CKey& key, std::span<const std::byte> ent32) noexcept
    : m_key(key)
{
    m_our_pubkey = m_key.EllSwiftCreate(ent32);
}

BIP324Cipher::BIP324Cipher(const CKey& key, const EllSwiftPubKey& pubkey) noexcept :
    m_key(key), m_our_pubkey(pubkey) {}

void BIP324Cipher::Initialize(const EllSwiftPubKey& their_pubkey, bool initiator, bool self_decrypt) noexcept
{
    // Determine salt (fixed string + network magic bytes)
    const auto& message_header = Params().MessageStart();
    std::string salt_str = std::string{"bitcoin_v2_shared_secret"} + std::string(std::begin(message_header), std::end(message_header));
    const std::span<const unsigned char> salt_span(UCharCast(salt_str.data()), salt_str.length());

    // Perform ECDH to derive shared secret.
    ECDHSecret ecdh_secret = m_key.ComputeBIP324ECDHSecret(their_pubkey, m_our_pubkey, initiator);
    const std::span<const unsigned char> ecdh_secret_span(UCharCast(ecdh_secret.data()), ecdh_secret.size());

    // 1. Extract PRK once
    std::vector<unsigned char> prk_material = crypto::HKDF_Extract_SHA256(salt_span, ecdh_secret_span);
    const std::span<const unsigned char> prk_span(prk_material);

    // Helper lambda for repeated Expand calls
    auto expand_to_buffer = [&](const char* info_literal, std::span<std::byte> out_buffer) {
        assert(out_buffer.size() == 32);
        const std::span<const unsigned char> info_s(UCharCast(info_literal), strlen(info_literal));
        std::vector<unsigned char> okm_vec = crypto::HKDF_Expand_SHA256(prk_span, info_s, 32);
        assert(okm_vec.size() == 32);
        std::transform(okm_vec.begin(), okm_vec.end(), out_buffer.begin(),
                        [](unsigned char c) { return static_cast<std::byte>(c); });
        // okm_vec is local and will be destroyed; its contents are copied.
        // If okm_vec itself contained sensitive data that wasn't copied but only used via span,
    };

    bool side = (initiator != self_decrypt);
    std::array<std::byte, 32> current_okm_buffer;

    expand_to_buffer("initiator_L", current_okm_buffer);
    (side ? m_send_l_cipher : m_recv_l_cipher).emplace(current_okm_buffer, REKEY_INTERVAL);

    expand_to_buffer("initiator_P", current_okm_buffer);
    (side ? m_send_p_cipher : m_recv_p_cipher).emplace(current_okm_buffer, REKEY_INTERVAL);

    expand_to_buffer("responder_L", current_okm_buffer);
    (side ? m_recv_l_cipher : m_send_l_cipher).emplace(current_okm_buffer, REKEY_INTERVAL);

    expand_to_buffer("responder_P", current_okm_buffer);
    (side ? m_recv_p_cipher : m_send_p_cipher).emplace(current_okm_buffer, REKEY_INTERVAL);

    expand_to_buffer("garbage_terminators", current_okm_buffer);
    std::copy(std::begin(current_okm_buffer), std::begin(current_okm_buffer) + GARBAGE_TERMINATOR_LEN,
        (initiator ? m_send_garbage_terminator : m_recv_garbage_terminator).begin());
    std::copy(std::end(current_okm_buffer) - GARBAGE_TERMINATOR_LEN, std::end(current_okm_buffer),
        (initiator ? m_recv_garbage_terminator : m_send_garbage_terminator).begin());

    // Derive session id from shared secret.
    std::span<std::byte> session_id_span(m_session_id.data(), m_session_id.size());
    assert(session_id_span.size() == 32);
    expand_to_buffer("session_id", session_id_span);

    // Wipe all variables that contain information which could be used to re-derive encryption keys.
    memory_cleanse(ecdh_secret.data(), ecdh_secret.size());
    memory_cleanse(current_okm_buffer.data(), current_okm_buffer.size());
    memory_cleanse(prk_material.data(), prk_material.size()); // Cleanse the PRK
    
    m_key = CKey();
}

void BIP324Cipher::Encrypt(std::span<const std::byte> contents, std::span<const std::byte> aad, bool ignore, std::span<std::byte> output) noexcept
{
    assert(output.size() == contents.size() + EXPANSION);

    // Encrypt length.
    std::byte len[LENGTH_LEN];
    len[0] = std::byte{(uint8_t)(contents.size() & 0xFF)};
    len[1] = std::byte{(uint8_t)((contents.size() >> 8) & 0xFF)};
    len[2] = std::byte{(uint8_t)((contents.size() >> 16) & 0xFF)};
    m_send_l_cipher->Crypt(len, output.first(LENGTH_LEN));

    // Encrypt plaintext.
    std::byte header[HEADER_LEN] = {ignore ? IGNORE_BIT : std::byte{0}};
    m_send_p_cipher->Encrypt(header, contents, aad, output.subspan(LENGTH_LEN));
}

uint32_t BIP324Cipher::DecryptLength(std::span<const std::byte> input) noexcept
{
    assert(input.size() == LENGTH_LEN);

    std::byte buf[LENGTH_LEN];
    // Decrypt length
    m_recv_l_cipher->Crypt(input, buf);
    // Convert to number.
    return uint32_t(buf[0]) + (uint32_t(buf[1]) << 8) + (uint32_t(buf[2]) << 16);
}

bool BIP324Cipher::Decrypt(std::span<const std::byte> input, std::span<const std::byte> aad, bool& ignore, std::span<std::byte> contents) noexcept
{
    assert(input.size() + LENGTH_LEN == contents.size() + EXPANSION);

    std::byte header[HEADER_LEN];
    if (!m_recv_p_cipher->Decrypt(input, aad, header, contents)) return false;

    ignore = (header[0] & IGNORE_BIT) == IGNORE_BIT;
    return true;
}

// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ohttp/ohttp.h>

#include <algorithm>
#include <cstring>
#include <support/cleanse.h>

#include <crypto/chacha20poly1305.h>  // AEAD (Nk=32, Nn=12 for ChaCha20-Poly1305) :contentReference[oaicite:9]{index=9}
#include <dhkem_secp256k1.h>          // HPKE building blocks (Base mode, KeySchedule, Exporter) :contentReference[oaicite:10]{index=10}

// Core headers for keys, endianness helpers, RNG, HMAC:
#include <key.h>                      // CKey / CPubKey
#include <crypto/common.h>            // ReadLE32 / ReadLE64
#include <crypto/hmac_sha256.h>       // CHMAC_SHA256
#include <random.h>                   // GetRandBytes

namespace ohttp {

static inline void WriteBE16(uint8_t* out, uint16_t v) {
    out[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[1] = static_cast<uint8_t>(v & 0xFF);
}

// RFC 9458 §3.1 single KeyConfig (without the 2-byte length) serialization.
std::vector<uint8_t> KeyConfig::Serialize() const
{
    // HPKE Symmetric Algorithms vector
    std::vector<uint8_t> syms_bytes;
    syms_bytes.reserve(syms.size() * 4);
    for (const auto& s : syms) {
        uint8_t tmp[2];
        WriteBE16(tmp, s.kdf_id); syms_bytes.insert(syms_bytes.end(), tmp, tmp+2);
        WriteBE16(tmp, s.aead_id); syms_bytes.insert(syms_bytes.end(), tmp, tmp+2);
    }
    uint16_t syms_len = static_cast<uint16_t>(syms_bytes.size());

    std::vector<uint8_t> out;
    out.reserve(1 + 2 + dhkem_secp256k1::NPK + 2 + syms_len);
    out.push_back(key_id);
    uint8_t be16[2];
    WriteBE16(be16, kem_id); out.insert(out.end(), be16, be16+2);
    out.insert(out.end(), pkR.begin(), pkR.end());
    WriteBE16(be16, syms_len); out.insert(out.end(), be16, be16+2);
    out.insert(out.end(), syms_bytes.begin(), syms_bytes.end());
    return out;
}

static inline bool ReadBE16(const uint8_t*& p, const uint8_t* end, uint16_t& out)
{
    if (end - p < 2) return false;
    out = (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
    p += 2;
    return true;
}

// RFC 9458 §3.2 application/ohttp-keys list
std::vector<KeyConfig> ParseKeyConfigList(std::span<const uint8_t> data)
{
    std::vector<KeyConfig> out;
    const uint8_t* p = data.data();
    const uint8_t* end = data.data() + data.size();
    while (p < end) {
        uint16_t len = 0;
        if (!ReadBE16(p, end, len)) return {}; // strict: discard on encoding error (§3.2)
        if (end - p < len) return {};
        const uint8_t* q = p;
        const uint8_t* qend = p + len;

        KeyConfig cfg;
        {
            const size_t need = size_t{1} + 2u + dhkem_secp256k1::NPK + 2u;
            if (static_cast<size_t>(qend - q) < need) return {};
        }
        cfg.key_id = *q++;                             // 8-bit Key Identifier (§3.1)
        ReadBE16(q, qend, cfg.kem_id);
        std::copy(q, q + dhkem_secp256k1::NPK, cfg.pkR.begin()); q += dhkem_secp256k1::NPK;
        uint16_t syms_len = 0; ReadBE16(q, qend, syms_len);
        if (qend - q != syms_len) return {};
        if (syms_len % 4) return {};
        for (; q < qend; ) {
            SymmetricAlg s{};
            if (!ReadBE16(q, qend, s.kdf_id)) return {};
            if (!ReadBE16(q, qend, s.aead_id)) return {};
            cfg.syms.push_back(s);
        }
        if (!cfg.IsSupported()) {
            // Ignore unsupported keys per RFC guidance; but for strictness in Core,
            // we only push supported configs.
        } else {
            out.push_back(cfg);
        }
        p += len;
    }
    return out;
}

std::vector<uint8_t> SerializeKeyConfigList(const std::vector<KeyConfig>& list)
{
    std::vector<uint8_t> out;
    for (const auto& cfg : list) {
        const auto k = cfg.Serialize();
        uint16_t len = static_cast<uint16_t>(k.size());
        uint8_t be16[2]; WriteBE16(be16, len);
        out.insert(out.end(), be16, be16+2);
        out.insert(out.end(), k.begin(), k.end());
    }
    return out;
}

// ----- Internals for request/response processing -----

// Build the RFC 9458 request info:
// concat(ASCII "message/bhttp request", 0x00, hdr), where
// hdr = key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2). (§4.3)
static std::vector<uint8_t> BuildRequestInfo(uint8_t key_id, uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id)
{
    static const char kInfoStr[] = "message/bhttp request";
    std::vector<uint8_t> hdr;
    hdr.reserve(1 + 2 + 2 + 2);
    hdr.push_back(key_id);
    uint8_t be16[2];
    WriteBE16(be16, kem_id);  hdr.insert(hdr.end(), be16, be16+2);
    WriteBE16(be16, kdf_id);  hdr.insert(hdr.end(), be16, be16+2);
    WriteBE16(be16, aead_id); hdr.insert(hdr.end(), be16, be16+2);

    std::vector<uint8_t> info;
    info.insert(info.end(), (const uint8_t*)kInfoStr, (const uint8_t*)kInfoStr + sizeof(kInfoStr) - 1);
    info.push_back(0x00);
    info.insert(info.end(), hdr.begin(), hdr.end());
    return info;
}

// Export secret from HPKE context with exporter_context = "message/bhttp response" and L=max(Nn,Nk). (§4.4; RFC 9180 §5.3)
static std::array<uint8_t, 32> ExportResponseSecret(const dhkem_secp256k1::Context& hpke_ctx)
{
    static const char kRespStr[] = "message/bhttp response";
    // Context.Export(exporter_context, L) == LabeledExpand(exporter_secret, "sec", exporter_context, L) (RFC 9180 §5.3) :contentReference[oaicite:11]{index=11}
    const std::vector<uint8_t> lbl_sec{'s','e','c'};
    std::vector<uint8_t> exporter(hpke_ctx.exporter_secret.begin(), hpke_ctx.exporter_secret.end());
    std::vector<uint8_t> info; info.insert(info.end(), (const uint8_t*)kRespStr, (const uint8_t*)kRespStr + sizeof(kRespStr) - 1);
    
    // L = max(Nn,Nk) = 32 for ChaCha20-Poly1305 (Nk=32, Nn=12)
    constexpr size_t L = 32;
    auto out = dhkem_secp256k1::LabeledExpand(exporter, lbl_sec, info, L);
    std::array<uint8_t, 32> ret{};
    std::copy(out.begin(), out.end(), ret.begin());
    memory_cleanse(out.data(), out.size());
    return ret;
}

// Local HKDF-Extract/Expand (SHA-256) for response AEAD keynonce (RFC 9458 §4.4),
// implemented with Core's CHMAC_SHA256 to avoid relying on non-exported symbols.
static void HKDF_Extract_32(const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm, size_t ikm_len,
                            uint8_t out_prk[32]) {
    static const uint8_t zero_salt[32] = {0};
    const uint8_t* key = salt_len ? salt : zero_salt;
    size_t key_len = salt_len ? salt_len : sizeof(zero_salt);
    CHMAC_SHA256 hmac(key, key_len);
    hmac.Write(ikm, ikm_len);
    hmac.Finalize(out_prk);
}

static void HKDF_Expand_N(const uint8_t prk[32], const char* label, size_t out_len, uint8_t* out)
{
    // Single-block HKDF-Expand (L <= 32) : HMAC(prk, info || 0x01)
    CHMAC_SHA256 hmac(prk, 32);
    for (const char* p = label; *p; ++p) {
        const uint8_t b = static_cast<uint8_t>(*p);
        hmac.Write(&b, 1);
    }
    const uint8_t ctr = 0x01;
    hmac.Write(&ctr, 1);
    unsigned char block[32];
    hmac.Finalize(block);
    std::memcpy(out, block, out_len);
}

// ----- Client -----

std::optional<std::vector<uint8_t>> ClientContext::EncapsulateRequest(const KeyConfig& cfg,
                                                                      std::span<const uint8_t> bhttp_request)
{
    if (!cfg.IsSupported()) return std::nullopt;

    m_key_id = cfg.key_id;
    m_kem_id = cfg.kem_id;
    // Choose the only suite we support
    m_kdf_id = KDF_HKDF_SHA256;
    m_aead_id = AEAD_CHACHA20POLY1305;

    // Build header and info (RFC 9458 §4.3).
    std::vector<uint8_t> info = BuildRequestInfo(m_key_id, m_kem_id, m_kdf_id, m_aead_id); // §4.3 :contentReference[oaicite:15]{index=15}

    // Generate ephemeral keypair for HPKE (secp256k1). The HPKE Encap you added
    // expects both skE (32) and enc (65) supplied by the caller. :contentReference[oaicite:16]{index=16}
    CKey skE; skE.MakeNewKey(/*fCompressed=*/false);
    CPubKey pkE = skE.GetPubKey();
    if (pkE.size() != dhkem_secp256k1::NENC) return std::nullopt;

    std::array<uint8_t, dhkem_secp256k1::NENC> enc{};
    std::copy(pkE.begin(), pkE.end(), enc.begin());

    std::array<uint8_t, dhkem_secp256k1::NSK> skE_arr{};
    std::copy((const uint8_t*)skE.data(), (const uint8_t*)skE.data()+skE.size(), skE_arr.begin());

    // Recipient public key from KeyConfig
    std::array<uint8_t, dhkem_secp256k1::NPK> pkR = cfg.pkR;

    // HPKE KEM: Encap (Base mode). Returns 32-byte shared secret. :contentReference[oaicite:17]{index=17}
    auto kem_ss = dhkem_secp256k1::Encap(pkR, skE_arr, enc);
    if (!kem_ss.has_value()) return std::nullopt;

    // HPKE KeySchedule(Base) -> AEAD key, base_nonce, exporter_secret. :contentReference[oaicite:18]{index=18}
    std::vector<uint8_t> ss_vec(kem_ss->begin(), kem_ss->end());
    auto ks = dhkem_secp256k1::KeySchedule(/*mode=*/0x00, ss_vec, info);
    if (!ks.has_value()) return std::nullopt;
    m_hpke = *ks; // store for response processing

    // AEAD encrypt request using seq=0 with ChaCha20-Poly1305 per HPKE §5.2. :contentReference[oaicite:19]{index=19}
    // Nonce := base_nonce XOR I2OSP(seq, Nn); here seq=0 -> equals base_nonce.
    ChaCha20::Nonce96 nonce;
    const auto& bn = m_hpke->base_nonce;
    nonce.first  = ReadLE32(bn.data());
    nonce.second = ReadLE64(bn.data() + 4);
    auto ct = dhkem_secp256k1::Seal(
        std::span<const std::byte>((const std::byte*)m_hpke->key.data(), m_hpke->key.size()),
        nonce,
        /*aad=*/{},
        std::span<const std::byte>((const std::byte*)bhttp_request.data(), bhttp_request.size())
    ); // :contentReference[oaicite:20]{index=20}

    // Serialize Encapsulated Request = hdr || enc || ct (RFC 9458 §4.3)
    // hdr = key_id (1) || kem_id (2) || kdf_id (2) || aead_id (2)
    std::vector<uint8_t> out;
    out.reserve(1 + 2 + 2 + 2 + enc.size() + ct.size());
    out.push_back(m_key_id);
    uint8_t be16[2];
    WriteBE16(be16, m_kem_id);  out.insert(out.end(), be16, be16+2);
    WriteBE16(be16, m_kdf_id);  out.insert(out.end(), be16, be16+2);
    WriteBE16(be16, m_aead_id); out.insert(out.end(), be16, be16+2);
    out.insert(out.end(), enc.begin(), enc.end());
    out.insert(out.end(), ct.begin(), ct.end());

    m_enc = enc; // keep for response salt
    return out;
}

std::optional<std::vector<uint8_t>> ClientContext::OpenResponse(std::span<const uint8_t> enc_response) const
{
    if (!m_hpke.has_value()) return std::nullopt; // defensive: must have called EncapsulateRequest
    // Parse Encapsulated Response = response_nonce || ct (RFC 9458 §4.4).
    // For ChaCha20-Poly1305, max(Nn,Nk)=32, so response_nonce is 32 bytes.
    if (enc_response.size() < 32 + AEADChaCha20Poly1305::EXPANSION) return std::nullopt;
    const uint8_t* p = enc_response.data();
    std::array<uint8_t, 32> response_nonce{};
    std::copy(p, p+32, response_nonce.begin()); p += 32;
    std::span<const uint8_t> ct(p, enc_response.data() + enc_response.size());

    // secret := HPKE.Export("message/bhttp response", 32). :contentReference[oaicite:21]{index=21}
    const auto secret = ExportResponseSecret(*m_hpke);

    // salt := enc || response_nonce
    std::vector<uint8_t> salt; salt.reserve(m_enc.size() + response_nonce.size());
    salt.insert(salt.end(), m_enc.begin(), m_enc.end());
    salt.insert(salt.end(), response_nonce.begin(), response_nonce.end());

    // prk = HKDF-Extract(salt, secret)
    uint8_t prk[32];
    HKDF_Extract_32(salt.data(), salt.size(), secret.data(), secret.size(), prk);

    // key = HKDF-Expand(prk, "key", Nk=32), nonce = HKDF-Expand(prk, "nonce", Nn=12). (§4.4)
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce_bytes{};
    HKDF_Expand_N(prk, "key",   key.size(), key.data());
    HKDF_Expand_N(prk, "nonce", nonce_bytes.size(), nonce_bytes.data());

    ChaCha20::Nonce96 nonce{ ReadLE32(nonce_bytes.data()), ReadLE64(nonce_bytes.data()+4) };

    auto pt = dhkem_secp256k1::Open(
        std::span<const std::byte>((const std::byte*)key.data(), key.size()),
        nonce,
        /*aad=*/{},
        std::span<const std::byte>((const std::byte*)ct.data(), ct.size())
    ); // :contentReference[oaicite:22]{index=22}

    memory_cleanse(prk, sizeof(prk));
    if (!pt.has_value()) return std::nullopt;
    return *pt;
}

// ----- Gateway -----

static bool ParseRequestHeader(const uint8_t*& p, const uint8_t* end,
                               uint8_t& key_id, uint16_t& kem_id, uint16_t& kdf_id, uint16_t& aead_id)
{
    if (end - p < 1 + 2 + 2 + 2) return false;
    key_id = *p++;
    if (!ReadBE16(p, end, kem_id)) return false;
    if (!ReadBE16(p, end, kdf_id)) return false;
    if (!ReadBE16(p, end, aead_id)) return false;
    return true;
}

std::optional<std::vector<uint8_t>> Gateway::DecapsulateRequest(std::span<const uint8_t> enc_request,
                                                                uint8_t expected_key_id,
                                                                std::span<const uint8_t> skR,
                                                                GatewayRequestContext& ctx)
{
    const uint8_t* p = enc_request.data();
    const uint8_t* end = enc_request.data() + enc_request.size();

    uint8_t  key_id = 0;
    uint16_t kem_id = 0, kdf_id = 0, aead_id = 0;
    if (!ParseRequestHeader(p, end, key_id, kem_id, kdf_id, aead_id)) return std::nullopt;

    // Basic policy checks per §4.3/§4.4.
    if (key_id != expected_key_id) return std::nullopt;
    if (kem_id != KEM_SECP256K1 || kdf_id != KDF_HKDF_SHA256 || aead_id != AEAD_CHACHA20POLY1305) return std::nullopt;

    // Next: enc (fixed length Nenc) then ciphertext bytes (§4.3).
    if (end - p < (int)dhkem_secp256k1::NENC + (int)AEADChaCha20Poly1305::EXPANSION) return std::nullopt;
    std::array<uint8_t, dhkem_secp256k1::NENC> enc{};
    std::copy(p, p + dhkem_secp256k1::NENC, enc.begin()); p += dhkem_secp256k1::NENC;
    std::span<const uint8_t> ct(p, end);

    // info := "message/bhttp request" 0x00 hdr (§4.3).
    std::vector<uint8_t> info = BuildRequestInfo(key_id, kem_id, kdf_id, aead_id); // :contentReference[oaicite:23]{index=23}

    // HPKE Decap (Base) -> shared secret. :contentReference[oaicite:24]{index=24}
    auto kem_ss = dhkem_secp256k1::Decap(enc, skR);
    if (!kem_ss.has_value()) return std::nullopt;

    std::vector<uint8_t> ss_vec(kem_ss->begin(), kem_ss->end());
    auto ks = dhkem_secp256k1::KeySchedule(/*mode=*/0x00, ss_vec, info);
    if (!ks.has_value()) return std::nullopt;
    ctx.hpke = *ks;
    ctx.enc = enc;
    ctx.kdf_id = kdf_id;
    ctx.aead_id = aead_id;

    // AEAD decrypt with seq=0 (HPKE §5.2). :contentReference[oaicite:25]{index=25}
    ChaCha20::Nonce96 nonce;
    const auto& bn = ctx.hpke->base_nonce;
    nonce.first  = ReadLE32(bn.data());
    nonce.second = ReadLE64(bn.data() + 4);
    auto pt = dhkem_secp256k1::Open(
        std::span<const std::byte>((const std::byte*)ctx.hpke->key.data(), ctx.hpke->key.size()),
        nonce,
        /*aad=*/{},
        std::span<const std::byte>((const std::byte*)ct.data(), ct.size())
    ); // :contentReference[oaicite:26]{index=26}
    if (!pt.has_value()) return std::nullopt;
    return *pt;
}

std::vector<uint8_t> Gateway::EncapsulateResponse(const GatewayRequestContext& ctx,
                                                  std::span<const uint8_t> bhttp_response)
{
    // secret := Export("message/bhttp response", 32) (§4.4)
    assert(ctx.hpke.has_value());
    const auto secret = ExportResponseSecret(*ctx.hpke);

    // response_nonce := random(32)  [max(Nn,Nk)=32 for ChaCha20-Poly1305]
    std::array<uint8_t, 32> response_nonce{};
    GetRandBytes(response_nonce); // Core RNG

    // salt := enc || response_nonce
    std::vector<uint8_t> salt; salt.reserve(ctx.enc.size() + response_nonce.size());
    salt.insert(salt.end(), ctx.enc.begin(), ctx.enc.end());
    salt.insert(salt.end(), response_nonce.begin(), response_nonce.end());

    // prk = HKDF-Extract(salt, secret); then Expand "key" (32) and "nonce" (12). (§4.4)
    uint8_t prk[32]; HKDF_Extract_32(salt.data(), salt.size(), secret.data(), secret.size(), prk);

    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce_bytes{};
    HKDF_Expand_N(prk, "key",   key.size(), key.data());
    HKDF_Expand_N(prk, "nonce", nonce_bytes.size(), nonce_bytes.data());

    ChaCha20::Nonce96 nonce{ ReadLE32(nonce_bytes.data()), ReadLE64(nonce_bytes.data()+4) };

    auto ct = dhkem_secp256k1::Seal(
        std::span<const std::byte>((const std::byte*)key.data(), key.size()),
        nonce,
        /*aad=*/{},
        std::span<const std::byte>((const std::byte*)bhttp_response.data(), bhttp_response.size())
    );

    memory_cleanse(prk, sizeof(prk));

    // Encapsulated Response := response_nonce || ct (§4.4).
    std::vector<uint8_t> out;
    out.reserve(response_nonce.size() + ct.size());
    out.insert(out.end(), response_nonce.begin(), response_nonce.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

} // namespace ohttp

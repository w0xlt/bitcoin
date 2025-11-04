// SPDX-License-Identifier: MIT

#include <payjoin/ohttp.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include <crypto/hmac_sha256.h>
#include <random.h>                               // GetRandBytes
#include <secp256k1.h>                            // parse/serialize pubkeys for 33→65 conversion
#include <payjoin/dhkem_secp256k1.h>

namespace ohttp {

// ---------------- KeyConfig parsing (updated for Payjoin v2) ----------------
//
// Payjoin v2 directories sometimes return a *single* KeyConfig object
// (no 2‑byte length prefix), whereas RFC 9458 "application/ohttp-keys"
// is a *collection* of length‑prefixed KeyConfig encodings. Support both.
static bool ParseOneKeyConfig(const uint8_t* kp, const uint8_t* kend, KeyConfig& cfg) {
    if (kp + 1 + 2 > kend) return false; // key_id + kem_id
    cfg.key_id = kp[0]; kp += 1;
    cfg.kem_id = (uint16_t(kp[0]) << 8) | uint16_t(kp[1]); kp += 2;

    // Minimal tail: pk (33 or 65) + sym_len(2) + at least one suite (4)
    if (size_t(kend - kp) < 33 + 2 + 4) return false;

    // Accept compressed (33) or uncompressed (65) SEC1
    for (size_t npk : {33u, 65u}) {
        if (size_t(kend - kp) < npk + 2) continue;
        const uint8_t* pkp = kp;
        const uint8_t* after_pk = kp + npk;
        uint16_t sym_len = (uint16_t(after_pk[0]) << 8) | uint16_t(after_pk[1]);
        const uint8_t* symp = after_pk + 2;

        // Structure must be exact and sym_len a multiple of 4 (pairs of uint16)
        if (after_pk + 2 + sym_len != kend) continue;
        if (sym_len < 4 || (sym_len % 4) != 0) continue;

        cfg.pkR.assign(pkp, pkp + npk);
        cfg.suites.clear();
        for (size_t i = 0; i < sym_len; i += 4) {
            SymmetricSuite s;
            s.kdf_id  = (uint16_t(symp[i])     << 8) | uint16_t(symp[i + 1]);
            s.aead_id = (uint16_t(symp[i + 2]) << 8) | uint16_t(symp[i + 3]);
            cfg.suites.push_back(s);
        }
        return true;
    }
    return false;
}

OhttpKeys ParseOhttpKeys(const std::vector<uint8_t>& blob) {
    OhttpKeys out;
    const uint8_t* p   = blob.data();
    const uint8_t* end = p + blob.size();

    auto Fail = [](const char* m){ return ParseError(m); };

    // First try the strict RFC 9458 collection: each entry has a 2-byte BE length.
    // Only take this path if the first length fits in the buffer.
    if (end - p >= 2) {
        const uint16_t first_len = (uint16_t(p[0]) << 8) | uint16_t(p[1]);
        if (size_t(first_len) <= size_t(end - (p + 2))) {
            const uint8_t* q = p;
            while (q + 2 <= end) {
                uint16_t klen = (uint16_t(q[0]) << 8) | uint16_t(q[1]); q += 2;
                if (klen == 0) throw Fail("ohttp-keys zero-length entry");
                if (q + klen > end) throw Fail("ohttp-keys truncated entry");
                KeyConfig cfg;
                if (!ParseOneKeyConfig(q, q + klen, cfg)) throw Fail("ohttp-keys invalid structure");
                out.configs.push_back(std::move(cfg));
                q += klen;
            }
            if (q != end) throw Fail("ohttp-keys trailing junk");
            if (out.configs.empty()) throw Fail("ohttp-keys: empty collection");
            return out;
        }
    }

    // Payjoin v2 compatibility: treat the whole blob as a single KeyConfig (no length prefix).
    {
        KeyConfig cfg;
        if (!ParseOneKeyConfig(p, end, cfg)) {
            // Preserve legacy wording for callers that expect this message.
            throw Fail("ohttp-keys truncated entry");
        }
        out.configs.push_back(std::move(cfg));
        return out;
    }
}

std::optional<SymmetricSuite> KeyConfig::SelectDefault() const {
    // Payjoin: HKDF-SHA256 (0x0001) + ChaCha20-Poly1305 (0x0003)
    for (const auto& s : suites) {
        if (s.kdf_id == 0x0001 && s.aead_id == 0x0003) return s;
    }
    return std::nullopt;
}

// ---------------- small helpers ----------------

static uint32_t ReadLE32u(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t ReadLE64u(const uint8_t* p) {
    return (uint64_t)p[0]
        | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
        | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static void HKDF_Extract(const std::vector<uint8_t>& salt,
                         const std::vector<uint8_t>& ikm,
                         std::vector<uint8_t>& prk_out)
{
    unsigned char out[32];
    const uint8_t* salt_ptr = salt.empty() ? nullptr : salt.data();
    size_t salt_len = salt.empty() ? 0 : salt.size();
    CHMAC_SHA256 h(salt_ptr, salt_len);
    h.Write(ikm.data(), ikm.size());
    h.Finalize(out);
    prk_out.assign(out, out + 32);
}

static void HKDF_Expand(const std::vector<uint8_t>& prk,
                        const std::vector<uint8_t>& info,
                        size_t L,
                        std::vector<uint8_t>& okm)
{
    okm.clear();
    unsigned char T[32];
    std::vector<uint8_t> prev;
    uint8_t counter = 1;
    while (okm.size() < L) {
        CHMAC_SHA256 h(prk.data(), prk.size());
        if (!prev.empty()) h.Write(prev.data(), prev.size());
        if (!info.empty()) h.Write(info.data(), info.size());
        h.Write(&counter, 1);
        h.Finalize(T);
        size_t take = std::min(L - okm.size(), sizeof(T));
        okm.insert(okm.end(), T, T + take);
        prev.assign(T, T + sizeof(T));
        counter++;
    }
}

// Ensure public key is 65-byte uncompressed (DHKEM expects NPK=65)  :contentReference[oaicite:3]{index=3}
static std::vector<uint8_t> EnsureUncompressed65(const std::vector<uint8_t>& in)
{
    if (in.size() == 65 && in[0] == 0x04) return in;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, in.data(), in.size())) {
        secp256k1_context_destroy(ctx);
        throw OhttpError("invalid secp256k1 public key from directory");
    }
    uint8_t out[65];
    size_t len = 65;
    if (!secp256k1_ec_pubkey_serialize(ctx, out, &len, &pub, SECP256K1_EC_UNCOMPRESSED) || len != 65) {
        secp256k1_context_destroy(ctx);
        throw OhttpError("failed to serialize uncompressed secp256k1 key");
    }
    secp256k1_context_destroy(ctx);
    return std::vector<uint8_t>(out, out + 65);
}

// ---------------- OHTTP (client) ----------------

EncapsulatedRequest EncapsulateRequest(const KeyConfig& cfg, const std::vector<uint8_t>& bhttp_request)
{
    auto suite = cfg.SelectDefault();
    if (!suite) throw OhttpError("OHTTP: no supported KDF/AEAD suite");

    // Build RFC 9458 request header = key_id(8) | kem_id(16) | kdf_id(16) | aead_id(16)
    EncapsulatedRequest out;
    out.header.reserve(7);
    out.header.push_back(cfg.key_id);
    out.header.push_back(uint8_t(cfg.kem_id >> 8)); out.header.push_back(uint8_t(cfg.kem_id));
    out.header.push_back(uint8_t(suite->kdf_id >> 8)); out.header.push_back(uint8_t(suite->kdf_id));
    out.header.push_back(uint8_t(suite->aead_id >> 8)); out.header.push_back(uint8_t(suite->aead_id));

    // info = "message/bhttp request" || 0x00 || header
    static const char kInfoReq[] = "message/bhttp request";
    std::vector<uint8_t> info;
    info.insert(info.end(), kInfoReq, kInfoReq + sizeof(kInfoReq) - 1);
    info.push_back(0x00);
    info.insert(info.end(), out.header.begin(), out.header.end());

    // Ensure pkR is 65-byte uncompressed for the KEM
    std::vector<uint8_t> pkR65 = EnsureUncompressed65(cfg.pkR);

    // Generate an ephemeral key pair via DeriveKeyPair(random IKM)  :contentReference[oaicite:4]{index=4}
    std::array<uint8_t, 32> skE;
    std::array<uint8_t, 65> pkE;
    {
        std::vector<uint8_t> ikm(32);
        GetRandBytes(ikm);
        bool ok = dhkem_secp256k1::DeriveKeyPair(std::span<const uint8_t>(ikm.data(), ikm.size()), skE, pkE);
        if (!ok) throw OhttpError("ephemeral keygen failed");
    }

    // KEM: Encap(pkR, skE, pkE) -> shared_secret  :contentReference[oaicite:5]{index=5}
    auto ss_opt = dhkem_secp256k1::Encap(std::span<const uint8_t>(pkR65.data(), pkR65.size()), skE, pkE);
    if (!ss_opt) throw OhttpError("KEM encap failed");
    std::vector<uint8_t> shared_secret(ss_opt->begin(), ss_opt->end());

    // HPKE KeySchedule(Base) -> key, base_nonce, exporter_secret  :contentReference[oaicite:6]{index=6}
    auto ks_opt = dhkem_secp256k1::KeySchedule(/*mode=*/0x00, shared_secret, info);
    if (!ks_opt) throw OhttpError("HPKE key schedule failed");
    const auto& ks = *ks_opt;

    // AEAD (ChaCha20-Poly1305) seal of the BHTTP request using Nonce=base_nonce (sequence=0)
    if (ks.base_nonce.size() != 12 || ks.key.size() != 32) throw OhttpError("unexpected key/nonce sizes");
    ChaCha20::Nonce96 n;
    n.first  = ReadLE32u(ks.base_nonce.data());
    n.second = ReadLE64u(ks.base_nonce.data() + 4);
    std::vector<std::byte> aad; // empty
    std::vector<std::byte> pt(bhttp_request.size());
    std::memcpy(pt.data(), bhttp_request.data(), bhttp_request.size());
    out.ct = dhkem_secp256k1::Seal(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ks.key.data()), ks.key.size()),
        n,
        std::span<const std::byte>(aad.data(), aad.size()),
        std::span<const std::byte>(pt.data(), pt.size())
    );

    // Output enc (our ephemeral pubkey) and exporter_secret (for response)
    out.enc.assign(pkE.begin(), pkE.end());
    out.exporter_secret = ks.exporter_secret; // 32 bytes

    return out;
}

std::vector<uint8_t> DecapsulateResponse(const KeyConfig& /*cfg*/,
                                         const EncapsulatedRequest& req_ctx,
                                         const EncapsulatedResponse& enc_res)
{
    // RFC 9458 §4.4 response key schedule:
    //   secret = Export("message/bhttp response", L=max(Nk,Nn)=32)  [Export = LabeledExpand(exporter_secret, "sec", ...)]
    //   salt   = enc || response_nonce
    //   prk    = HKDF-Extract(salt, secret)
    //   key    = HKDF-Expand(prk, "key",   32)
    //   nonce  = HKDF-Expand(prk, "nonce", 12)
    const size_t Nk = 32, Nn = 12, L = 32;

    if (req_ctx.exporter_secret.size() != 32) throw OhttpError("missing exporter secret");
    if (enc_res.response_nonce.size() != L)    throw OhttpError("bad response nonce length");
    if (req_ctx.enc.empty())                   throw OhttpError("missing enc");

    // HPKE Export from exporter_secret  → secret(L)
    static const std::vector<uint8_t> label_sec{'s','e','c'};
    static const std::vector<uint8_t> info_res{
        'm','e','s','s','a','g','e','/','b','h','t','t','p',' ','r','e','s','p','o','n','s','e'
    };
    std::vector<uint8_t> secret =
        dhkem_secp256k1::LabeledExpand(req_ctx.exporter_secret, label_sec, info_res, L);  // :contentReference[oaicite:7]{index=7}

    // salt = enc || response_nonce
    std::vector<uint8_t> salt;
    salt.reserve(req_ctx.enc.size() + enc_res.response_nonce.size());
    salt.insert(salt.end(), req_ctx.enc.begin(), req_ctx.enc.end());
    salt.insert(salt.end(), enc_res.response_nonce.begin(), enc_res.response_nonce.end());

    // HKDF-Extract / Expand (plain HKDF over SHA-256)
    std::vector<uint8_t> prk, key, nonce;
    HKDF_Extract(salt, secret, prk);
    static const std::vector<uint8_t> lbl_key{'k','e','y'};
    static const std::vector<uint8_t> lbl_nonce{'n','o','n','c','e'};
    HKDF_Expand(prk, lbl_key, Nk, key);
    HKDF_Expand(prk, lbl_nonce, Nn, nonce);

    // AEAD Open with derived key/nonce (AAD empty)
    ChaCha20::Nonce96 n96;
    n96.first  = ReadLE32u(nonce.data());
    n96.second = ReadLE64u(nonce.data() + 4);

    auto maybe_pt = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key.data()), key.size()),
        n96,
        // std::span<const std::byte>(nullptr, 0), // empty AAD
        {},
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(enc_res.ct.data()), enc_res.ct.size())
    );
    if (!maybe_pt) throw OhttpError("AEAD open failed");

    // Return raw BHTTP bytes
    std::vector<uint8_t> pt(maybe_pt->begin(), maybe_pt->end());
    return pt;
}

} // namespace ohttp

#include <dhkem_secp256k1.h>

#include <crypto/hkdf_sha256_32.h>
#include <crypto/hmac_sha256.h>
#include <random.h>
#include <secp256k1.h>
#include <span>
#include <array>
#include <cassert>
#include <cstring>
#include <support/allocators/secure.h>

// Global secp256k1 context for crypto operations (ensure ECC_Init has been called).
// static secp256k1_context* g_secp256k1_ctx = nullptr;
namespace dhkem_secp256k1 {

static secp256k1_context* g_secp256k1_ctx = nullptr;

/** Static secp256k1 curve parameters */
static const unsigned char SECP256K1_ORDER[32] = {
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B, 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

/** Ensure global secp256k1 context is initialized. */
static void InitCtx() {
    if (g_secp256k1_ctx == nullptr) {
        // Combine flags for both signing (to allow pubkey create) and verification (for pubkey parse)
        // g_secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        g_secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        assert(g_secp256k1_ctx != nullptr);

        {
            // Pass in a random blinding seed to the secp256k1 context.
            std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
            GetRandBytes(vseed);
            bool ret = secp256k1_context_randomize(g_secp256k1_ctx, vseed.data());
            assert(ret);
        }
    }
}

void InitContext() {
    InitCtx();
}

/** Internal helper: perform ECDH (scalar * pubkey) and output 32-byte X coordinate. 
 *  Returns true on success, false if pubkey or scalar are invalid. */
static bool ECDH_xcoord(const uint8_t priv[NSK], const secp256k1_pubkey& pub, uint8_t out_x[32]) {
    // Verify secret key validity
    if (secp256k1_ec_seckey_verify(secp256k1_context_static, priv) != 1) {
        return false;
    }
    // Make a copy of pubkey to apply multiplication
    secp256k1_pubkey pub_mul = pub;
    if (secp256k1_ec_pubkey_tweak_mul(secp256k1_context_static, &pub_mul, priv) != 1) {
        return false; // tweak_mul can fail if priv is 0 or pub is invalid
    }
    // Serialize resulting point and extract X coordinate
    unsigned char ser[33];
    size_t ser_len = sizeof(ser);
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, ser, &ser_len, &pub_mul, SECP256K1_EC_COMPRESSED);
    // Compressed format: 1-byte prefix + 32-byte X coordinate
    std::memcpy(out_x, ser + 1, 32);
    return true;
}

void HKDF_Extract(const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len,
                         uint8_t out_prk[32]) {
    // If salt is not provided, HMAC_SHA256 will treat empty key as zero-padded:contentReference[oaicite:21]{index=21}.
    CHMAC_SHA256 hmac((salt_len > 0 ? salt : nullptr), salt_len);
    hmac.Write(ikm, ikm_len);
    hmac.Finalize(out_prk);
}

void HKDF_Expand32(const uint8_t prk[32], const uint8_t* info_data, size_t info_len,
                          uint8_t out_okm[], size_t L) {
    // Only one round (L <= 32 bytes)
    unsigned char one = 0x01;
    CHMAC_SHA256 hmac(prk, 32);
    hmac.Write(info_data, info_len);
    hmac.Write(&one, 1);
    unsigned char full_block[32];
    hmac.Finalize(full_block);
    std::memcpy(out_okm, full_block, L);
}

bool DeriveKeyPair(const uint8_t* ikm, size_t ikm_len, uint8_t out_sk[NSK], uint8_t out_pk[NPK]) {
    
    // 1. Compute dkp_prk = HKDF-Extract(salt="", labeled_ikm=("dkp_prk" label || IKM))
    // Build labeled IKM: concat("HPKE-v1", suite_id, "dkp_prk", ikm)
    const char* label = "dkp_prk";
    uint8_t labeled_ikm[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 6 /*label length*/ + 256 /*ikm max*/];
    size_t labeled_len = 0;
    // Concatenate prefix
    std::memcpy(labeled_ikm + labeled_len, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    labeled_len += sizeof(LABEL_PREFIX);
    // suite_id
    std::memcpy(labeled_ikm + labeled_len, SUITE_ID, sizeof(SUITE_ID));
    labeled_len += sizeof(SUITE_ID);
    // label "dkp_prk"
    while (*label) { labeled_ikm[labeled_len++] = (uint8_t)*label++; }
    // append IKM
    if (ikm_len > 0) {
        std::memcpy(labeled_ikm + labeled_len, ikm, ikm_len);
        labeled_len += ikm_len;
    }
    uint8_t prk[32];
    HKDF_Extract(nullptr, 0, labeled_ikm, labeled_len, prk);

    // 2. Derive key material until valid scalar found (up to 256 tries):contentReference[oaicite:22]{index=22}
    const char* cand_label = "candidate";
    for (uint8_t counter = 0; counter < 255; ++counter) {
        // info = concat("HPKE-v1", suite_id, "candidate", I2OSP(counter,1))
        uint8_t info[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 9]; // "candidate" (9 chars including null) 
        size_t info_len = 0;
        // prefix and suite
        std::memcpy(info, LABEL_PREFIX, sizeof(LABEL_PREFIX));
        info_len += sizeof(LABEL_PREFIX);
        std::memcpy(info + info_len, SUITE_ID, sizeof(SUITE_ID));
        info_len += sizeof(SUITE_ID);
        // label "candidate"
        const char* cand = cand_label;
        while (*cand) { info[info_len++] = (uint8_t)*cand++; }
        // append counter byte
        info[info_len++] = counter;
        // Expand prk with info to 32-byte candidate secret
        uint8_t candidate[32];
        HKDF_Expand32(prk, info, info_len, candidate, 32);
        // Apply bitmask to first byte (0xFF for secp256k1 means no change):contentReference[oaicite:23]{index=23}
        candidate[0] &= 0xFF;
        // Interpret as big-endian and check if in [1, order-1]
        if (secp256k1_ec_seckey_verify(g_secp256k1_ctx, candidate) == 1) {
            // Valid secret key
            std::memcpy(out_sk, candidate, 32);
            // Compute public key
            secp256k1_pubkey pub;
            int ret = secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pub, out_sk);
            assert(ret);
            size_t len = NPK;
            secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, out_pk, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
            return true;
        }
    }
    // Failed to find a valid key (extremely unlikely)
    return false;
}

bool SerializePublicKey(const secp256k1_pubkey& pub, uint8_t out65[NPK]) {
    
    size_t len = NPK;
    return secp256k1_ec_pubkey_serialize(secp256k1_context_static, out65, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
}

bool DeserializePublicKey(const uint8_t in65[NPK], secp256k1_pubkey& pub_out) {
    
    if (in65[0] != 0x04) { // expected uncompressed format
        return false;
    }
    if (secp256k1_ec_pubkey_parse(secp256k1_context_static, &pub_out, in65, NPK) != 1) {
        return false;
    }
    // secp256k1_ec_pubkey_parse already rejects invalid points (not on curve or infinity).
    return true;
}

void SerializePrivateKey(const uint8_t priv32[NSK], uint8_t out32[NSK]) {
    // Reduce priv32 mod order (if out of range):contentReference[oaicite:24]{index=24}
    // Interpret priv32 as big-endian integer
    // We subtract the order once if priv >= order (since 2^256 > 2*order)
    int cmp = std::memcmp(priv32, SECP256K1_ORDER, 32);
    if (cmp >= 0) {
        // priv_mod = priv32 - order (big-endian subtraction)
        unsigned int borrow = 0;
        for (int i = 31; i >= 0; --i) {
            unsigned int a = priv32[i];
            unsigned int b = SECP256K1_ORDER[i];
            unsigned int sub = a - b - borrow;
            // Compute borrow for next byte
            borrow = (a < b + borrow) ? 1 : 0;
            out32[i] = sub & 0xFF;
        }
    } else {
        std::memcpy(out32, priv32, 32);
    }
}

void DeserializePrivateKey(const uint8_t in32[NSK], uint8_t out_sk[NSK]) {
    // Octet-String-to-Field-Element conversion, reduce mod order if needed:contentReference[oaicite:25]{index=25}
    SerializePrivateKey(in32, out_sk);
    // If result is 0x00...00, it means input was a multiple of order; 
    // we leave it as 0 (though 0 is not a valid private key for usage).
}

bool Encap(const uint8_t pkR_bytes[NPK], uint8_t out_shared_secret[NSECRET], uint8_t out_enc[NPK]) {
    
    // Validate recipient public key
    secp256k1_pubkey pkR;
    if (!DeserializePublicKey(pkR_bytes, pkR)) {
        return false;
    }
    // Generate a random ephemeral private key skE in [1, order-1]
    uint8_t skE[32];
    do {
        GetStrongRandBytes(skE);
    } while (secp256k1_ec_seckey_verify(secp256k1_context_static, skE) != 1);
    // Compute ephemeral public key enc = pk(skE)
    secp256k1_pubkey pubE;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_static, &pubE, skE);
    assert(ret);
    size_t enclen = NPK;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, out_enc, &enclen, &pubE, SECP256K1_EC_UNCOMPRESSED);
    // DH: x-coordinate of (skE * pkR)
    uint8_t dh[32];
    if (!ECDH_xcoord(skE, pkR, dh)) {
        return false;
    }
    // KEM context = enc || pkR (concatenate 65-byte values)
    uint8_t kem_context[2 * NPK];
    std::memcpy(kem_context, out_enc, NPK);
    std::memcpy(kem_context + NPK, pkR_bytes, NPK);
    // shared_secret = ExtractAndExpand(dh, kem_context):contentReference[oaicite:26]{index=26}
    // i.e., eae_prk = HKDF-Extract("", "eae_prk"||dh), then HKDF-Expand(eae_prk, "shared_secret"||kem_context, 32)
    // Build labeled input for eae_prk extract
    const char* eae_label = "eae_prk";
    uint8_t labeled_dh[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 7 + 32];
    size_t labeled_dh_len = 0;
    std::memcpy(labeled_dh, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    labeled_dh_len += sizeof(LABEL_PREFIX);
    std::memcpy(labeled_dh + labeled_dh_len, SUITE_ID, sizeof(SUITE_ID));
    labeled_dh_len += sizeof(SUITE_ID);
    while (*eae_label) { labeled_dh[labeled_dh_len++] = (uint8_t)*eae_label++; }
    std::memcpy(labeled_dh + labeled_dh_len, dh, 32);
    labeled_dh_len += 32;
    // HKDF-Extract with salt=""
    uint8_t eae_prk[32];
    HKDF_Extract(nullptr, 0, labeled_dh, labeled_dh_len, eae_prk);
    // Build labeled info for "shared_secret"
    const char* ss_label = "shared_secret";
    uint8_t labeled_info[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 13 + 2 * NPK];
    size_t info_len = 0;
    std::memcpy(labeled_info, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    info_len += sizeof(LABEL_PREFIX);
    std::memcpy(labeled_info + info_len, SUITE_ID, sizeof(SUITE_ID));
    info_len += sizeof(SUITE_ID);
    while (*ss_label) { labeled_info[info_len++] = (uint8_t)*ss_label++; }
    // append kem_context
    std::memcpy(labeled_info + info_len, kem_context, 2 * NPK);
    info_len += 2 * NPK;
    // HKDF-Expand to 32-byte shared_secret
    HKDF_Expand32(eae_prk, labeled_info, info_len, out_shared_secret, NSECRET);
    return true;
}

bool Decap(const uint8_t enc_bytes[NPK], const uint8_t skR_bytes[NSK], uint8_t out_shared_secret[NSECRET]) {
    
    // Validate inputs
    secp256k1_pubkey pubE;
    if (!DeserializePublicKey(enc_bytes, pubE)) {
        return false;
    }
    if (secp256k1_ec_seckey_verify(secp256k1_context_static, skR_bytes) != 1) {
        return false;
    }
    // Compute pkR (to use in kem_context)
    secp256k1_pubkey pubR;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_static, &pubR, skR_bytes);
    assert(ret);
    uint8_t pkR_bytes[NPK];
    size_t pkR_len = NPK;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, pkR_bytes, &pkR_len, &pubR, SECP256K1_EC_UNCOMPRESSED);
    // DH: x-coordinate of (skR * pubE)
    uint8_t dh[32];
    if (!ECDH_xcoord(skR_bytes, pubE, dh)) {
        return false;
    }
    // kem_context = enc || pkR
    uint8_t kem_context[2 * NPK];
    std::memcpy(kem_context, enc_bytes, NPK);
    std::memcpy(kem_context + NPK, pkR_bytes, NPK);
    // Extract and Expand as in Encap
    const char* eae_label = "eae_prk";
    uint8_t labeled_dh[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 7 + 32];
    size_t labeled_dh_len = 0;
    std::memcpy(labeled_dh, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    labeled_dh_len += sizeof(LABEL_PREFIX);
    std::memcpy(labeled_dh + labeled_dh_len, SUITE_ID, sizeof(SUITE_ID));
    labeled_dh_len += sizeof(SUITE_ID);
    while (*eae_label) { labeled_dh[labeled_dh_len++] = (uint8_t)*eae_label++; }
    std::memcpy(labeled_dh + labeled_dh_len, dh, 32);
    labeled_dh_len += 32;
    uint8_t eae_prk[32];
    HKDF_Extract(nullptr, 0, labeled_dh, labeled_dh_len, eae_prk);
    const char* ss_label = "shared_secret";
    uint8_t labeled_info[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 13 + 2 * NPK];
    size_t info_len = 0;
    std::memcpy(labeled_info, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    info_len += sizeof(LABEL_PREFIX);
    std::memcpy(labeled_info + info_len, SUITE_ID, sizeof(SUITE_ID));
    info_len += sizeof(SUITE_ID);
    while (*ss_label) { labeled_info[info_len++] = (uint8_t)*ss_label++; }
    std::memcpy(labeled_info + info_len, kem_context, 2 * NPK);
    info_len += 2 * NPK;
    HKDF_Expand32(eae_prk, labeled_info, info_len, out_shared_secret, NSECRET);
    return true;
}

bool AuthEncap(const uint8_t pkR_bytes[NPK], const uint8_t skS_bytes[NSK], uint8_t out_shared_secret[NSECRET], uint8_t out_enc[NPK]) {
    
    secp256k1_pubkey pkR;
    if (!DeserializePublicKey(pkR_bytes, pkR)) {
        return false;
    }
    if (secp256k1_ec_seckey_verify(secp256k1_context_static, skS_bytes) != 1) {
        return false;
    }
    // Generate ephemeral key pair (skE, pkE)
    uint8_t skE[32];
    do {
        GetStrongRandBytes(skE);
    } while (secp256k1_ec_seckey_verify(secp256k1_context_static, skE) != 1);
    secp256k1_pubkey pubE;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_static, &pubE, skE);
    assert(ret);
    size_t enclen = NPK;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, out_enc, &enclen, &pubE, SECP256K1_EC_UNCOMPRESSED);
    // Compute sender's static public key pkS (65 bytes)
    secp256k1_pubkey pubS;
    ret = secp256k1_ec_pubkey_create(secp256k1_context_static, &pubS, skS_bytes);
    assert(ret);
    uint8_t pkS_bytes[NPK];
    size_t pkS_len = NPK;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, pkS_bytes, &pkS_len, &pubS, SECP256K1_EC_UNCOMPRESSED);
    // Compute dh values
    uint8_t dh1[32], dh2[32];
    if (!ECDH_xcoord(skE, pkR, dh1)) return false;
    if (!ECDH_xcoord(skS_bytes, pkR, dh2)) return false;
    // Concatenate dh1 || dh2 (64 bytes)
    uint8_t dh_concat[64];
    std::memcpy(dh_concat, dh1, 32);
    std::memcpy(dh_concat + 32, dh2, 32);
    // kem_context = enc || pkR || pkS
    uint8_t kem_context[3 * NPK];
    std::memcpy(kem_context, out_enc, NPK);
    std::memcpy(kem_context + NPK, pkR_bytes, NPK);
    std::memcpy(kem_context + 2 * NPK, pkS_bytes, NPK);
    // Extract&Expand with dh_concat and kem_context
    const char* eae_label = "eae_prk";
    uint8_t labeled_dh[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 7 + 64];
    size_t labeled_dh_len = 0;
    std::memcpy(labeled_dh, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    labeled_dh_len += sizeof(LABEL_PREFIX);
    std::memcpy(labeled_dh + labeled_dh_len, SUITE_ID, sizeof(SUITE_ID));
    labeled_dh_len += sizeof(SUITE_ID);
    while (*eae_label) { labeled_dh[labeled_dh_len++] = (uint8_t)*eae_label++; }
    std::memcpy(labeled_dh + labeled_dh_len, dh_concat, 64);
    labeled_dh_len += 64;
    uint8_t eae_prk[32];
    HKDF_Extract(nullptr, 0, labeled_dh, labeled_dh_len, eae_prk);
    const char* ss_label = "shared_secret";
    uint8_t labeled_info[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 13 + 3 * NPK];
    size_t info_len = 0;
    std::memcpy(labeled_info, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    info_len += sizeof(LABEL_PREFIX);
    std::memcpy(labeled_info + info_len, SUITE_ID, sizeof(SUITE_ID));
    info_len += sizeof(SUITE_ID);
    while (*ss_label) { labeled_info[info_len++] = (uint8_t)*ss_label++; }
    std::memcpy(labeled_info + info_len, kem_context, 3 * NPK);
    info_len += 3 * NPK;
    HKDF_Expand32(eae_prk, labeled_info, info_len, out_shared_secret, NSECRET);
    return true;
}

bool AuthDecap(const uint8_t enc_bytes[NPK], const uint8_t skR_bytes[NSK], const uint8_t pkS_bytes[NPK],
               uint8_t out_shared_secret[NSECRET]) {
    
    secp256k1_pubkey pubE, pubS;
    if (!DeserializePublicKey(enc_bytes, pubE)) {
        return false;
    }
    if (!DeserializePublicKey(pkS_bytes, pubS)) {
        return false;
    }
    if (secp256k1_ec_seckey_verify(secp256k1_context_static, skR_bytes) != 1) {
        return false;
    }
    // Compute pkR for context
    secp256k1_pubkey pubR;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_static, &pubR, skR_bytes);
    assert(ret);
    uint8_t pkR_bytes[NPK];
    size_t pkR_len = NPK;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, pkR_bytes, &pkR_len, &pubR, SECP256K1_EC_UNCOMPRESSED);
    // Compute DHs
    uint8_t dh1[32], dh2[32];
    if (!ECDH_xcoord(skR_bytes, pubE, dh1)) return false;
    if (!ECDH_xcoord(skR_bytes, pubS, dh2)) return false;
    // dh_concat
    uint8_t dh_concat[64];
    std::memcpy(dh_concat, dh1, 32);
    std::memcpy(dh_concat + 32, dh2, 32);
    // kem_context = enc || pkR || pkS
    uint8_t kem_context[3 * NPK];
    std::memcpy(kem_context, enc_bytes, NPK);
    std::memcpy(kem_context + NPK, pkR_bytes, NPK);
    std::memcpy(kem_context + 2 * NPK, pkS_bytes, NPK);
    // Extract&Expand (same as AuthEncap)
    const char* eae_label = "eae_prk";
    uint8_t labeled_dh[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 7 + 64];
    size_t labeled_dh_len = 0;
    std::memcpy(labeled_dh, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    labeled_dh_len += sizeof(LABEL_PREFIX);
    std::memcpy(labeled_dh + labeled_dh_len, SUITE_ID, sizeof(SUITE_ID));
    labeled_dh_len += sizeof(SUITE_ID);
    while (*eae_label) { labeled_dh[labeled_dh_len++] = (uint8_t)*eae_label++; }
    std::memcpy(labeled_dh + labeled_dh_len, dh_concat, 64);
    labeled_dh_len += 64;
    uint8_t eae_prk[32];
    HKDF_Extract(nullptr, 0, labeled_dh, labeled_dh_len, eae_prk);
    const char* ss_label = "shared_secret";
    uint8_t labeled_info[sizeof(LABEL_PREFIX) + sizeof(SUITE_ID) + 13 + 3 * NPK];
    size_t info_len = 0;
    std::memcpy(labeled_info, LABEL_PREFIX, sizeof(LABEL_PREFIX));
    info_len += sizeof(LABEL_PREFIX);
    std::memcpy(labeled_info + info_len, SUITE_ID, sizeof(SUITE_ID));
    info_len += sizeof(SUITE_ID);
    while (*ss_label) { labeled_info[info_len++] = (uint8_t)*ss_label++; }
    std::memcpy(labeled_info + info_len, kem_context, 3 * NPK);
    info_len += 3 * NPK;
    HKDF_Expand32(eae_prk, labeled_info, info_len, out_shared_secret, NSECRET);
    return true;
}


/**
 * Implements DeriveKeyPair() for secp256k1 as per RFC 9180 Section 7.1.3 and the 
 * secp256k1-based DHKEM draft. Uses HKDF-SHA256 and secp256k1 lib for key generation.
 */
bool DeriveKeyPair2(const unsigned char* ikm, size_t ikm_len,
                   unsigned char out_sk[32], unsigned char out_pk[65])
{
    // Domain separation constants for HPKE (suite ID for secp256k1 KEM and labels)
    static constexpr uint16_t KEM_ID_SECP256K1 = 0x0016;
    static constexpr unsigned char BITMASK = 0xFF; // bitmask = 0xff for secp256k1

    // Construct the labeled IKM: concat("HPKE-v1", suite_id, "dkp_prk", ikm)
    std::string labeled_ikm;
    labeled_ikm.reserve(7 /*"HPKE-v1"*/ + 5 /*"KEM"+kem_id*/ + 6 /*"dkp_prk"*/ + ikm_len);
    labeled_ikm += "HPKE-v1";
    labeled_ikm += "KEM";
    labeled_ikm.push_back(static_cast<char>(KEM_ID_SECP256K1 >> 8));      // high byte of kem_id
    labeled_ikm.push_back(static_cast<char>(KEM_ID_SECP256K1 & 0xFF));   // low byte of kem_id
    labeled_ikm += "dkp_prk";
    labeled_ikm.append(reinterpret_cast<const char*>(ikm), ikm_len);

    // HKDF-Extract with salt="", info="dkp_prk" labeling (yield dkp_prk of 32 bytes)
    const std::string salt_empty;
    CHKDF_HMAC_SHA256_L32 hkdf_extract(
        reinterpret_cast<const unsigned char*>(labeled_ikm.data()),
        labeled_ikm.size(),
        salt_empty
    );
    // Clear sensitive labeled IKM from memory as it's no longer needed
    // memory_cleanse(labeled_ikm.data(), labeled_ikm.size());
    memset(labeled_ikm.data(), 0, labeled_ikm.size());
    labeled_ikm.clear();

    // Prepare base info for HKDF-Expand: I2OSP(Nsk, 2) || "HPKE-v1" || suite_id || "candidate"
    // Nsk (private key length) = 32 bytes for secp256k1
    std::string base_info;
    base_info.reserve(2 + 7 + 3 + 2 + 9); // 23 bytes
    // I2OSP(32, 2) -> 0x00 0x20
    base_info.push_back('\x00');
    base_info.push_back('\x20');
    base_info += "HPKE-v1";
    base_info += "KEM";
    base_info.push_back(static_cast<char>(KEM_ID_SECP256K1 >> 8));
    base_info.push_back(static_cast<char>(KEM_ID_SECP256K1 & 0xFF));
    base_info += "candidate";

    unsigned char candidate[32];
    bool derived = false;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    // Iterate counter from 0 to 255 to derive a valid private key
    for (unsigned int counter = 0; counter < 256; ++counter) {
        // Build info = base_info || I2OSP(counter, 1)
        std::string info = base_info;
        info.push_back(static_cast<char>(counter));

        // HKDF-Expand to produce 32-byte candidate secret key material
        hkdf_extract.Expand32(info, candidate);
        // Apply bitmask to the first byte (0xFF, no-op for secp256k1, included for spec compliance)
        candidate[0] &= BITMASK;
        // Check if candidate forms a valid secp256k1 scalar (non-zero, < order)
        if (secp256k1_ec_seckey_verify(ctx, candidate) == 1) {
            // Valid key found: copy to output SK and derive corresponding public key
            memcpy(out_sk, candidate, 32);
            secp256k1_pubkey pubkey;
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, out_sk)) {
                // Should not happen if seckey is valid; treat as failure
                // memory_cleanse(out_sk, 32);
                // memory_cleanse(candidate, 32);
                memset(out_sk, 0, 32);
                memset(candidate, 0, 32);
                return false;
            }
            size_t publen = 65;
            if (!secp256k1_ec_pubkey_serialize(ctx, out_pk, &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
                // Unexpected failure in serialization
                // memory_cleanse(out_sk, 32);
                // memory_cleanse(candidate, 32);
                memset(out_sk, 0, 32);
                memset(candidate, 0, 32);
                return false;
            }
            assert(publen == 65);
            derived = true;
            break;
        }
        // Otherwise, try the next counter value
    }

    // Cleanse the candidate buffer and any remaining secret material
    // memory_cleanse(candidate, sizeof(candidate));
    memset(candidate, 0, 32);
    // No valid key found within 256 attempts
    if (!derived) {
        // memory_cleanse(out_sk, 32);
        // memory_cleanse(out_pk, 65);
        memset(out_sk, 0, 32);
        memset(out_pk, 0, 32);
        return false;
    }
    return true;
}

bool DeriveKeyPair_DHKEM_Secp256k1(std::span<const uint8_t> ikm,
                                   std::array<uint8_t, 32>& outPrivKey,
                                   std::array<uint8_t, 65>& outPubKey)
{
    // KEM context setup: suite ID for secp256k1 (kem_id = 0x0016)
    const uint16_t kem_id = 0x0016;
    const char hpke_label[] = "HPKE-v1";
    const char kem_label[] = "KEM";
    const char extract_label[] = "dkp_prk";

    // 1. HKDF-Extract with domain separation.
    // Build the labeled IKM: "HPKE-v1" || "KEM<kem_id>" || "dkp_prk" || IKM.
    std::string labeled_ikm;
    labeled_ikm.reserve(strlen(hpke_label) + strlen(kem_label) + 2 + strlen(extract_label) + ikm.size());
    labeled_ikm.append(hpke_label);
    labeled_ikm.append(kem_label);
    // Append kem_id as 2 bytes (big-endian)
    char kem_id_bytes[2] = {char(kem_id >> 8), char(kem_id & 0xFF)};
    labeled_ikm.append(kem_id_bytes, 2);
    labeled_ikm.append(extract_label);
    labeled_ikm.append(reinterpret_cast<const char*>(ikm.data()), ikm.size());

    // HKDF-Extract with empty salt to derive dkp_prk.
    std::string empty_salt; // empty salt = "" (treated as zero-length)
    CHKDF_HMAC_SHA256_L32 hkdf_extract(
        reinterpret_cast<const unsigned char*>(labeled_ikm.data()), labeled_ikm.size(),
        empty_salt  // salt as std::string (empty)
    );

    // 2. HKDF-Expand loop to derive a valid secret key.
    const char expand_label[] = "candidate";
    // Pre-build the info prefix for LabeledExpand: length (Nsk=32) + "HPKE-v1" + "KEM<kem_id>" + "candidate".
    unsigned char length_bytes[2] = {0x00, 0x20};  // I2OSP(32, 2) = 0x0020
    std::string info_prefix;
    info_prefix.reserve(2 + strlen(hpke_label) + strlen(kem_label) + 2 + strlen(expand_label));
    info_prefix.append(reinterpret_cast<const char*>(length_bytes), 2);
    info_prefix.append(hpke_label);
    info_prefix.append(kem_label);
    info_prefix.append(kem_id_bytes, 2);
    info_prefix.append(expand_label);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }
    
    unsigned char candidate[32];
    for (uint8_t counter = 0; counter < 0x099; ++counter) {
        // Construct info = info_prefix || I2OSP(counter, 1).
        std::string info = info_prefix;
        info.push_back(static_cast<char>(counter));
        // HKDF-Expand to produce a 32-byte candidate secret key.
        hkdf_extract.Expand32(info, candidate);
        // Mask the first byte with 0xFF (as required by spec – no-op for 0xFF, included for completeness).
        candidate[0] &= 0xFF;
        // Check if the candidate is a valid secret scalar (0 < key < order).
        if (secp256k1_ec_seckey_verify(ctx, candidate)) {
            // Derive the corresponding secp256k1 public key.
            secp256k1_pubkey pubkey;
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, candidate)) {
                // Should not happen if seckey is valid; continue to next in unlikely case.
                continue;
            }
            // Serialize the public key in uncompressed format: 65 bytes (0x04 | X-coordinate | Y-coordinate).
            size_t pub_len = outPubKey.size();
            secp256k1_ec_pubkey_serialize(ctx,
                                          outPubKey.data(), &pub_len,
                                          &pubkey, SECP256K1_EC_UNCOMPRESSED);
            assert(pub_len == outPubKey.size());
            // Copy the private key to output.
            std::memcpy(outPrivKey.data(), candidate, 32);
            return true;
        }
    }
    // If no valid key found in 256 attempts (negligibly improbable), return false.
    return false;
}
} // namespace dhkem_secp256k1
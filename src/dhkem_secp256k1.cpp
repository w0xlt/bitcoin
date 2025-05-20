#include <dhkem_secp256k1.h>

#include <crypto/hkdf_sha256_32.h>
#include <crypto/hmac_sha256.h>
#include <random.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <span>
#include <array>
#include <cassert>
#include <cstring>
#include <support/allocators/secure.h>
#include <optional>
#include <iostream>

// Global secp256k1 context for crypto operations (ensure ECC_Init has been called).
// static secp256k1_context* g_secp256k1_ctx = nullptr;
namespace dhkem_secp256k1 {

static secp256k1_context* g_secp256k1_ctx = nullptr;

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

bool DeriveKeyPair(std::span<const uint8_t> ikm,
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
        if (secp256k1_ec_seckey_verify(g_secp256k1_ctx, candidate)) {
            // Derive the corresponding secp256k1 public key.
            secp256k1_pubkey pubkey;
            if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pubkey, candidate)) {
                // Should not happen if seckey is valid; continue to next in unlikely case.
                continue;
            }
            // Serialize the public key in uncompressed format: 65 bytes (0x04 | X-coordinate | Y-coordinate).
            size_t pub_len = outPubKey.size();
            secp256k1_ec_pubkey_serialize(g_secp256k1_ctx,
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

std::optional<std::array<uint8_t, 32>> Decap(std::span<const uint8_t> enc, 
                                            std::span<const uint8_t> skR) 
// bool Decap(const uint8_t enc_bytes[NPK], const uint8_t skR_bytes[NSK], uint8_t out_shared_secret[NSECRET]) {                                           
{
    assert(enc.size() == 65 && skR.size() == 32);
    // 1. Parse ephemeral public key
    secp256k1_pubkey pkE;
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pkE, enc.data(), enc.size())) {
        return std::nullopt; // invalid enc key
    }
    // 2. ECDH (X coordinate only)
    if (!secp256k1_ec_seckey_verify(g_secp256k1_ctx, skR.data())) {
        return std::nullopt; // invalid secret key
    }
    unsigned char dh[32];
    // Custom hashfn that copies X coordinate
    auto copy_x = [](unsigned char *out, const unsigned char *x32, const unsigned char *y32, void*) {
        memcpy(out, x32, 32);
        return 1;
    };
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh, &pkE, skR.data(), copy_x, nullptr)) {
        return std::nullopt; // ECDH failed (invalid input)
    }

    // 3. Compute and serialize pkR
    secp256k1_pubkey pubR;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pubR, skR.data())) {
        return std::nullopt; // skR = 0 or out of range
    }
    unsigned char pkR[65]; size_t pkR_len = 65;
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, pkR, &pkR_len, &pubR, SECP256K1_EC_UNCOMPRESSED);
    // kem_context = enc || pkR
    uint8_t kem_context[130];
    memcpy(kem_context, enc.data(), 65);
    memcpy(kem_context + 65, pkR, 65);
    // 4a. HKDF-Extract with label "eae_prk"
    const uint8_t suite_id[5] = { 'K','E','M', 0x00, 0x16 };
    const char label_eae[] = "eae_prk";
    // Build labeled IKM = "HPKE-v1" || suite_id || label_eae || dh
    uint8_t labeled_ikm[7 + 5 + sizeof(label_eae) - 1 + 32]; // "-1" for null terminator of C-string
    size_t offset = 0;
    memcpy(labeled_ikm + offset, "HPKE-v1", 7);            offset += 7;
    memcpy(labeled_ikm + offset, suite_id, 5);             offset += 5;
    memcpy(labeled_ikm + offset, label_eae, sizeof(label_eae) - 1); offset += sizeof(label_eae) - 1;
    memcpy(labeled_ikm + offset, dh, 32);
    // HMAC-Extract (salt is empty => treated as zero key)
    CHMAC_SHA256 hmac_ext(nullptr, 0);
    hmac_ext.Write(labeled_ikm, sizeof(labeled_ikm));
    uint8_t eae_prk[32];
    hmac_ext.Finalize(eae_prk);
    // 4b. HKDF-Expand with label "shared_secret"
    const char label_ss[] = "shared_secret";
    // Build labeled info = length(2 bytes) || "HPKE-v1" || suite_id || label_ss || kem_context
    uint8_t length_bytes[2] = {0x00, 0x20};               // 32 in hex
    uint8_t labeled_info[2 + 7 + 5 + sizeof(label_ss) - 1 + sizeof(kem_context)];
    offset = 0;
    memcpy(labeled_info + offset, length_bytes, 2);       offset += 2;
    memcpy(labeled_info + offset, "HPKE-v1", 7);          offset += 7;
    memcpy(labeled_info + offset, suite_id, 5);           offset += 5;
    memcpy(labeled_info + offset, label_ss, sizeof(label_ss) - 1); offset += sizeof(label_ss) - 1;
    memcpy(labeled_info + offset, kem_context, sizeof(kem_context));
    // HMAC-Expand (single block, append counter 0x01)
    CHMAC_SHA256 hmac_exp(eae_prk, 32);
    hmac_exp.Write(labeled_info, sizeof(labeled_info));
    uint8_t ctr = 1;
    hmac_exp.Write(&ctr, 1);
    std::array<uint8_t, 32> shared_secret;
    hmac_exp.Finalize(shared_secret.data());
    return shared_secret;
}

std::optional<std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 65>>> Encap(std::span<const uint8_t> pkR) {
    // Expect recipient public key in uncompressed form (65 bytes: 0x04 || X(32) || Y(32))
    if (pkR.size() != 65) {
        return std::nullopt;
    }

    // 1. Generate ephemeral key pair from 32 bytes of random IKM
    uint8_t ikm[32];
    do {
        GetStrongRandBytes(ikm);
    } while (secp256k1_ec_seckey_verify(g_secp256k1_ctx, ikm) != 1);

    // DeriveKeyPair returns optional<{skE (32 bytes), pkE (secp256k1_pubkey or bytes)}>
    std::array<uint8_t, 32> skE;
    std::array<uint8_t, 65> enc;
    bool result = DeriveKeyPair(std::span<const uint8_t>(ikm, sizeof(ikm)), skE, enc);
    if(!result) {
        return std::nullopt; // Ephemeral key generation failed (should be rare)
    }

    /* auto maybe_keypair = DeriveKeyPair(ikm);  
    if (!maybe_keypair.has_value()) {
        return std::nullopt; // Ephemeral key generation failed (should be rare)
    } */
    // Extract skE and serialized pkE (encapsulation) from the derived key pair
    // const auto &[skE, pkE_struct] = *maybe_keypair;
    // If DeriveKeyPair gave us a secp256k1_pubkey object, serialize it to bytes:
    /* std::array<uint8_t, 65> enc;
    size_t enc_len = enc.size();
    if (!secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, enc.data(), &enc_len, &pkE_struct, SECP256K1_EC_UNCOMPRESSED) || enc_len != 65) {
        return std::nullopt; // Should not fail if pkE_struct is valid
    } */
    // If DeriveKeyPair instead provided pkE as bytes directly, we would just assign: enc = pkE_bytes.

    // 2. Parse recipient's public key bytes into secp256k1_pubkey object
    secp256k1_pubkey pubkeyR;
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pubkeyR, pkR.data(), pkR.size())) {
        return std::nullopt; // invalid public key format
    }

    // 3. Compute ECDH: dh = X-coordinate of (skE * pkR)
    unsigned char dh[32];
    // Custom hash function for secp256k1_ecdh that copies X coordinate
    auto copy_x_only = [](unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
        memcpy(output, x32, 32);
        return 1;
    };
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh, &pubkeyR, skE.data(), /**hashfp=*/copy_x_only, /*data=*/nullptr)) {
        return std::nullopt; // ECDH failed (invalid scalar or other error)
    }
    // Now dh contains 32-byte X coordinate shared secret

    // 4. Build kem_context = enc || pkR (130 bytes)
    uint8_t kem_context[130];
    memcpy(kem_context, enc.data(), 65);
    memcpy(kem_context + 65, pkR.data(), 65);

    // 5. HKDF-Extract: eae_prk = LabeledExtract("", "eae_prk", dh)
    // Construct labeled_ikm = "HPKE-v1" || suite_id || "eae_prk" || dh
    static const uint8_t LABEL_HPKE_V1[] = {'H','P','K','E','-','v','1'};          // 7 bytes
    static const uint8_t SUITE_ID[]     = {'K','E','M', 0x00, 0x16};               // "KEM" + 0x0016
    static const uint8_t LABEL_EAE_PRK[] = {'e','a','e','_','p','r','k'};          // 7 bytes
    // Assemble the input to HKDF-Extract
    uint8_t labeled_ikm[7 + 5 + 7 + 32];
    memcpy(labeled_ikm,               LABEL_HPKE_V1, sizeof(LABEL_HPKE_V1));       // "HPKE-v1"
    memcpy(labeled_ikm + 7,           SUITE_ID,      sizeof(SUITE_ID));            // "KEM<id>"
    memcpy(labeled_ikm + 7 + 5,       LABEL_EAE_PRK, sizeof(LABEL_EAE_PRK));       // "eae_prk"
    memcpy(labeled_ikm + 7 + 5 + 7,   dh,           sizeof(dh));                   // DH shared secret (32 bytes)

    uint8_t eae_prk[32];
    // Use CHMAC_SHA256 for HKDF-Extract: salt = zero-length (treated as 32 zero bytes)
    unsigned char zeroSalt[32] = {0};
    CHMAC_SHA256 hmac_extract(zeroSalt, sizeof(zeroSalt));
    hmac_extract.Write(labeled_ikm, sizeof(labeled_ikm));
    hmac_extract.Finalize(eae_prk);  // eae_prk is 32 bytes

    // 6. HKDF-Expand: shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, 32)
    static const uint8_t LABEL_SHARED_SECRET[] = {'s','h','a','r','e','d','_','s','e','c','r','e','t'}; // 13 bytes
    // Assemble labeled_info = I2OSP(L,2) || "HPKE-v1" || suite_id || "shared_secret" || kem_context
    uint8_t length_buf[2] = {0x00, 0x20};  // length 32 in big-endian
    uint8_t labeled_info[2 + 7 + 5 + 13 + 130];
    memcpy(labeled_info,            length_buf,    2);
    memcpy(labeled_info + 2,        LABEL_HPKE_V1, sizeof(LABEL_HPKE_V1));         // "HPKE-v1"
    memcpy(labeled_info + 2 + 7,    SUITE_ID,      sizeof(SUITE_ID));              // "KEM<id>"
    memcpy(labeled_info + 2 + 7 + 5, LABEL_SHARED_SECRET, sizeof(LABEL_SHARED_SECRET)); // "shared_secret"
    memcpy(labeled_info + 2 + 7 + 5 + 13, kem_context, sizeof(kem_context));       // kem_context (130 bytes)

    // HKDF-Expand to 32 bytes using one iteration (info || 0x01)
    unsigned char okm[32];
    unsigned char ctr = 0x01;
    CHMAC_SHA256 hmac_expand(eae_prk, sizeof(eae_prk));
    hmac_expand.Write(labeled_info, sizeof(labeled_info));
    hmac_expand.Write(&ctr, 1);
    hmac_expand.Finalize(okm);

    // 7. Prepare output
    std::array<uint8_t, 32> shared_secret;
    std::array<uint8_t, 65> encap_pub;
    memcpy(shared_secret.data(), okm, 32);
    memcpy(encap_pub.data(), enc.data(), 65);
    return std::make_pair(shared_secret, encap_pub);
}

std::vector<uint8_t> LabeledExpand(const std::vector<uint8_t>& prk, const std::vector<uint8_t>& label, const std::vector<uint8_t>& info, size_t L)
{
    // 1. Construct the "labeled_info" as:
    //    length (2 bytes, big-endian) || label_prefix || suite_id || label || info
    uint8_t length_bytes[2];
    length_bytes[0] = static_cast<uint8_t>((L >> 8) & 0xff);
    length_bytes[1] = static_cast<uint8_t>(L & 0xff);

    std::vector<uint8_t> labeled_info;
    // (a) L in 2-byte big-endian form
    labeled_info.insert(labeled_info.end(), length_bytes, length_bytes + 2);
    // (b) label_prefix
    labeled_info.insert(labeled_info.end(), std::begin((LABEL_PREFIX)), std::end((LABEL_PREFIX)));
    // (c) suite_id
    labeled_info.insert(labeled_info.end(), std::begin((SUITE_ID)), std::end((SUITE_ID)));
    // (d) label
    labeled_info.insert(labeled_info.end(), label.begin(), label.end());
    // (e) info
    labeled_info.insert(labeled_info.end(), info.begin(), info.end());

    // 2. Expand
    std::vector<uint8_t> out_okm(L, 0);
    HKDF_Expand32(prk.data(), labeled_info.data(), labeled_info.size(), out_okm.data(), L);

    return out_okm;
}

std::vector<uint8_t> LabeledExtract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& label, const std::vector<uint8_t>& ikm)
{
    // 1. Concatenate label_prefix + suite_id + label + ikm
    std::vector<uint8_t> labeled_ikm;

    labeled_ikm.insert(labeled_ikm.end(), std::begin((LABEL_PREFIX)), std::end((LABEL_PREFIX)));
    labeled_ikm.insert(labeled_ikm.end(), std::begin((SUITE_ID)), std::end((SUITE_ID)));
    labeled_ikm.insert(labeled_ikm.end(), label.begin(), label.end());
    labeled_ikm.insert(labeled_ikm.end(), ikm.begin(), ikm.end());

    // 2. Print labeled_ikm in hex (for debugging, like the Python print)
    /* std::cout << "labeled_ikm = ";
    for (uint8_t b : labeled_ikm) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl; */

    // 3. Call HKDF_Extract to get the PRK
    uint8_t out_prk[32];
    HKDF_Extract(salt.data(), salt.size(), labeled_ikm.data(), labeled_ikm.size(), out_prk);

    // 4. Return the PRK as a 32-byte vector
    return std::vector<uint8_t>(out_prk, out_prk + 32);
}

// Static helper for raw ECDH output (copies x-coordinate, 32 bytes, to output)
static int EcdhHashFunctionRaw(unsigned char* output, const unsigned char* x32, const unsigned char* y32, void* data) {
    // Copy the 32-byte X coordinate. Ignore Y to get raw ECDH output.
    memcpy(output, x32, 32);
    return 1;
}

bool AuthEncap(std::array<uint8_t, 65>& enc, std::array<uint8_t, 32>& shared_secret,
               const std::array<uint8_t, 65>& pkR, const std::array<uint8_t, 32>& skS)
{
    // Parse recipient public key (pkR)
    secp256k1_pubkey pubR;
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pubR, pkR.data(), pkR.size())) {
        return false; // invalid recipient public key
    }

    // Derive sender's public key (pkS) from skS for context
    secp256k1_pubkey pubS;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pubS, skS.data())) {
        return false; // invalid sender private key (out of range)
    }
    std::array<uint8_t, 65> pkS_bytes;
    size_t pkS_len = pkS_bytes.size();
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, pkS_bytes.data(), &pkS_len, &pubS, SECP256K1_EC_UNCOMPRESSED);

    // Generate an ephemeral key pair (skE, pkE)
    uint8_t skE[32];
    secp256k1_pubkey pubE;
    do {
        GetStrongRandBytes(skE);                    // cryptographically secure RNG
    } while (!secp256k1_ec_seckey_verify(g_secp256k1_ctx, skE) ||
             !secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pubE, skE));
    // Serialize ephemeral public key as uncompressed (65 bytes)
    size_t enc_len = enc.size();
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, enc.data(), &enc_len, &pubE, SECP256K1_EC_UNCOMPRESSED);

    // Perform two ECDH operations: DH1 = DH(skE, pkR), DH2 = DH(skS, pkR)
    std::array<uint8_t, 32> dh1, dh2;
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh1.data(), &pubR, skE, EcdhHashFunctionRaw, nullptr)) {
        return false;
    }
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh2.data(), &pubR, skS.data(), EcdhHashFunctionRaw, nullptr)) {
        return false;
    }

    // Concatenate DH values (32+32=64 bytes)
    uint8_t dh_concat[64];
    memcpy(dh_concat,       dh1.data(), 32);
    memcpy(dh_concat + 32,  dh2.data(), 32);

    // HPKE KEM context: concat(enc, pkR, pkS) as uncompressed bytes:contentReference[oaicite:1]{index=1}
    // We already have enc and pkS_bytes; pkR is provided as input (assumed uncompressed).
    const uint8_t* kem_context = nullptr;
    size_t kem_context_len = 0;
    uint8_t kem_context_buf[65*3];
    // Assemble kem_context = enc || pkR || pkS (each 65 bytes)
    memcpy(kem_context_buf,               enc.data(), enc.size());
    memcpy(kem_context_buf + 65,          pkR.data(), pkR.size());
    memcpy(kem_context_buf + 130,         pkS_bytes.data(), pkS_bytes.size());
    kem_context = kem_context_buf;
    kem_context_len = 65 * 3;

    // HKDF-Extract with salt="", info label "eae_prk"
    static const uint8_t LABEL_EAE[] = {'e','a','e','_','p','r','k'};
    static const uint8_t LABEL_SHARED[] = {'s','h','a','r','e','d','_','s','e','c','r','e','t'};
    static const uint8_t PREFIX[] = {'H','P','K','E','-','v','1'};
    // Suite ID for KEM: "KEM" + I2OSP(0x0016, 2)
    static const uint8_t SUITE_ID[] = {'K','E','M', 0x00, 0x16};

    // Build labeledIKM = "HPKE-v1" || "KEM<0016>" || "eae_prk" || dh_concat
    CHMAC_SHA256 hmac_extract((const uint8_t*)"", 0); // empty salt -> HMAC key = zeros
    hmac_extract.Write(PREFIX, sizeof(PREFIX));
    hmac_extract.Write(SUITE_ID, sizeof(SUITE_ID));
    hmac_extract.Write(LABEL_EAE, sizeof(LABEL_EAE));
    hmac_extract.Write(dh_concat, sizeof(dh_concat));
    std::array<uint8_t, 32> prk_eae;
    hmac_extract.Finalize(prk_eae.data());

    // HKDF-Expand to Nsecret=32 with info labeled "shared_secret"
    // labeledInfo = I2OSP(L,2) || "HPKE-v1" || suite_id || "shared_secret" || kem_context
    uint16_t L_secret = shared_secret.size();
    uint8_t Linfo[2] = {uint8_t(L_secret >> 8), uint8_t(L_secret & 0xFF)}; // big-endian length
    CHMAC_SHA256 hmac_expand(prk_eae.data(), prk_eae.size());
    hmac_expand.Write(Linfo, 2);
    hmac_expand.Write(PREFIX, sizeof(PREFIX));
    hmac_expand.Write(SUITE_ID, sizeof(SUITE_ID));
    hmac_expand.Write(LABEL_SHARED, sizeof(LABEL_SHARED));
    hmac_expand.Write(kem_context, kem_context_len);
    uint8_t counter = 0x01;
    hmac_expand.Write(&counter, 1);
    hmac_expand.Finalize(shared_secret.data());
    return true;
}

bool AuthDecap(std::array<uint8_t, 32>& shared_secret, 
               const std::array<uint8_t, 65>& enc, const std::array<uint8_t, 32>& skR, 
               const std::array<uint8_t, 65>& pkS)
{
    // Parse sender static public key (pkS) and encapsulated ephemeral public key (enc)
    secp256k1_pubkey pubS, pubE;
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pubS, pkS.data(), pkS.size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pubE, enc.data(), enc.size())) {
        return false;
    }

    // Perform two ECDH operations: DH1 = DH(skR, pkE), DH2 = DH(skR, pkS)
    std::array<uint8_t, 32> dh1, dh2;
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh1.data(), &pubE, skR.data(), EcdhHashFunctionRaw, nullptr)) {
        return false;
    }
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh2.data(), &pubS, skR.data(), EcdhHashFunctionRaw, nullptr)) {
        return false;
    }

    // Concatenate DH outputs (64 bytes)
    uint8_t dh_concat[64];
    memcpy(dh_concat,       dh1.data(), 32);
    memcpy(dh_concat + 32,  dh2.data(), 32);

    // Recreate kem_context = enc || pk(skR) || pkS for HKDF
    // Derive pkR (receiver pub) from skR
    secp256k1_pubkey pubR;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pubR, skR.data())) {
        return false;
    }
    std::array<uint8_t, 65> pkR_bytes;
    size_t pkR_len = pkR_bytes.size();
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, pkR_bytes.data(), &pkR_len, &pubR, SECP256K1_EC_UNCOMPRESSED);

    uint8_t kem_context[65*3];
    memcpy(kem_context,       enc.data(), enc.size());
    memcpy(kem_context + 65,  pkR_bytes.data(), pkR_bytes.size());
    memcpy(kem_context + 130, pkS.data(), pkS.size());
    size_t kem_context_len = 65 * 3;

    // HKDF-Extract with salt="", info label "eae_prk"
    static const uint8_t LABEL_EAE[] = {'e','a','e','_','p','r','k'};
    static const uint8_t LABEL_SHARED[] = {'s','h','a','r','e','d','_','s','e','c','r','e','t'};
    static const uint8_t PREFIX[] = {'H','P','K','E','-','v','1'};
    // Suite ID for KEM: "KEM" + I2OSP(0x0016, 2)
    static const uint8_t SUITE_ID[] = {'K','E','M', 0x00, 0x16};

    // HKDF-Extract with label "eae_prk"
    CHMAC_SHA256 hmac_extract((const uint8_t*)"", 0);
    hmac_extract.Write(PREFIX, sizeof(PREFIX));
    hmac_extract.Write(SUITE_ID, sizeof(SUITE_ID));
    hmac_extract.Write(LABEL_EAE, sizeof(LABEL_EAE));
    hmac_extract.Write(dh_concat, sizeof(dh_concat));
    std::array<uint8_t, 32> prk_eae;
    hmac_extract.Finalize(prk_eae.data());

    // HKDF-Expand with label "shared_secret"
    uint16_t L_secret = shared_secret.size();
    uint8_t Linfo[2] = {uint8_t(L_secret >> 8), uint8_t(L_secret & 0xFF)};
    CHMAC_SHA256 hmac_expand(prk_eae.data(), prk_eae.size());
    hmac_expand.Write(Linfo, 2);
    hmac_expand.Write(PREFIX, sizeof(PREFIX));
    hmac_expand.Write(SUITE_ID, sizeof(SUITE_ID));
    hmac_expand.Write(LABEL_SHARED, sizeof(LABEL_SHARED));
    hmac_expand.Write(kem_context, kem_context_len);
    uint8_t counter = 0x01;
    hmac_expand.Write(&counter, 1);
    hmac_expand.Finalize(shared_secret.data());
    return true;
}

// bool AuthEncap2(const CKey& skS, const std::vector<uint8_t>& pkR_bytes, std::vector<uint8_t>& shared_secret, std::vector<uint8_t>& enc) 
bool AuthEncap2(std::span<const uint8_t>& skS, const std::vector<uint8_t>& pkR_bytes, std::vector<uint8_t>& shared_secret, std::vector<uint8_t>& enc) 
{
    // 1. Parse recipient public key and derive sender public key
    if (pkR_bytes.size() != 65) return false;
    secp256k1_pubkey pkR;
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pkR, pkR_bytes.data(), pkR_bytes.size())) {
        return false; // invalid pkR
    }
    //assert(skS.IsValid());
    // const unsigned char* skS_bytes = skS.begin();  // 32-byte secret key
    const unsigned char* skS_bytes = skS.data();  // 32-byte secret key
    secp256k1_pubkey pkS;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pkS, skS_bytes)) {
        return false; // invalid skS (out of range)
    }

    // 2. Generate a random ephemeral key pair (skE, pkE)
    unsigned char skE_bytes[32];
    secp256k1_pubkey pkE;
    do {
        GetStrongRandBytes(skE_bytes);                        // secure random 32 bytes
    } while (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pkE, skE_bytes));   // repeat if skE is invalid (zero or >= order)

    // 3. Compute DH1 = ECDH(skE, pkR) and DH2 = ECDH(skS, pkR)
    unsigned char dh1[32], dh2[32];
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh1, &pkR, skE_bytes, nullptr, nullptr)) {
        return false; // ECDH failed (invalid pkR or skE)
    }
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh2, &pkR, skS_bytes, nullptr, nullptr)) {
        return false; // ECDH failed (should not happen if keys valid)
    }
    unsigned char dh[64];
    memcpy(dh,      dh1, 32);
    memcpy(dh + 32, dh2, 32);

    // 4. Serialize pkE (ephemeral public key) as enc (65-byte uncompressed)
    enc.resize(65);
    size_t enc_len = 65;
    if (!secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, enc.data(), &enc_len, &pkE, SECP256K1_EC_UNCOMPRESSED)) {
        return false;
    }
    assert(enc_len == 65);
    // Also serialize pkS to 65 bytes (uncompressed) for context
    unsigned char pkS_bytes[65];
    size_t pkS_len = 65;
    if (!secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, pkS_bytes, &pkS_len, &pkS, SECP256K1_EC_UNCOMPRESSED)) {
        return false;
    }
    assert(pkS_len == 65);
    // (pkR_bytes is already a 65-byte uncompressed representation of pkR)

    // 5. Build kem_context = enc || pkR || pkS (concatenate byte arrays)
    std::string kem_context;
    kem_context.reserve(65 * 3);
    kem_context.append(reinterpret_cast<const char*>(enc.data()), enc.size());
    kem_context.append(reinterpret_cast<const char*>(pkR_bytes.data()), pkR_bytes.size());
    kem_context.append(reinterpret_cast<const char*>(pkS_bytes), pkS_len);

    // 6. LabeledExtract with label "eae_prk" and empty salt
    // Construct suite_id = "KEM" || 0x0016 (KEM ID for secp256k1, big-endian)
    std::string suite_id = "KEM";
    suite_id.push_back(static_cast<char>(0x00));
    suite_id.push_back(static_cast<char>(0x16));
    // Prepare labeled IKM: "HPKE-v1" || suite_id || "eae_prk" || DH
    std::string labeled_ikm;
    labeled_ikm.reserve(7 + suite_id.size() + /*len("eae_prk")=*/7 + sizeof(dh));
    labeled_ikm += "HPKE-v1";
    labeled_ikm += suite_id;
    labeled_ikm += "eae_prk";
    labeled_ikm.append(reinterpret_cast<const char*>(dh), sizeof(dh));
    // HKDF-Extract with salt="", input=labeled_ikm -> yields eae_prk (stored inside HKDF object)
    CHKDF_HMAC_SHA256_L32 hkdf_extract(
        reinterpret_cast<const unsigned char*>(labeled_ikm.data()), labeled_ikm.size(),
        ""  // empty salt
    );

    // 7. LabeledExpand with label "shared_secret" to derive 32-byte shared secret
    // Prepare labeled info: I2OSP(L=32, 2 bytes) || "HPKE-v1" || suite_id || "shared_secret" || kem_context
    unsigned char L_bytes[2] = {0x00, 0x20};  // 32 in big-endian
    std::string labeled_info;
    labeled_info.reserve(2 + 7 + suite_id.size() + /*len("shared_secret")=*/13 + kem_context.size());
    labeled_info.append(reinterpret_cast<const char*>(L_bytes), 2);
    labeled_info += "HPKE-v1";
    labeled_info += suite_id;
    labeled_info += "shared_secret";
    labeled_info += kem_context;
    // HKDF-Expand to 32-byte output
    shared_secret.resize(32);
    hkdf_extract.Expand32(labeled_info, shared_secret.data());

    return true;  // success
}

// bool AuthDecap(const CKey& skR, const std::vector<uint8_t>& pkS_bytes, const std::vector<uint8_t>& enc_bytes, std::vector<uint8_t>& shared_secret) 
bool AuthDecap2(std::span<const uint8_t>& skR, const std::vector<uint8_t>& pkS_bytes, const std::vector<uint8_t>& enc_bytes, std::vector<uint8_t>& shared_secret) 
{
    // 1. Parse sender static pubkey and ephemeral pubkey; derive recipient pubkey
    if (pkS_bytes.size() != 65 || enc_bytes.size() != 65) return false;
    secp256k1_pubkey pkS, pkE;
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pkS, pkS_bytes.data(), pkS_bytes.size())) {
        return false; // invalid pkS
    }
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pkE, enc_bytes.data(), enc_bytes.size())) {
        return false; // invalid enc (ephemeral pubkey)
    }
    // assert(skR.IsValid());
    // const unsigned char* skR_bytes = skR.begin();
    const unsigned char* skR_bytes = skR.data();
    secp256k1_pubkey pkR;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pkR, skR_bytes)) {
        return false; // should not fail if skR is valid
    }

    // 2. Compute DH1 = ECDH(skR, pkE) and DH2 = ECDH(skR, pkS)
    unsigned char dh1[32], dh2[32];
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh1, &pkE, skR_bytes, nullptr, nullptr)) {
        return false; // ECDH failed (invalid pkE or skR)
    }
    if (!secp256k1_ecdh(g_secp256k1_ctx, dh2, &pkS, skR_bytes, nullptr, nullptr)) {
        return false; // ECDH failed (invalid pkS or skR)
    }
    unsigned char dh[64];
    memcpy(dh,      dh1, 32);
    memcpy(dh + 32, dh2, 32);

    // 3. Serialize pkR (recipient's pubkey) to 65 bytes for context
    unsigned char pkR_bytes[65];
    size_t pkR_len = 65;
    if (!secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, pkR_bytes, &pkR_len, &pkR, SECP256K1_EC_UNCOMPRESSED)) {
        return false;
    }
    assert(pkR_len == 65);

    // Build kem_context = enc || pkR || pkS
    std::string kem_context;
    kem_context.reserve(65 * 3);
    kem_context.append(reinterpret_cast<const char*>(enc_bytes.data()), enc_bytes.size());
    kem_context.append(reinterpret_cast<const char*>(pkR_bytes), pkR_len);
    kem_context.append(reinterpret_cast<const char*>(pkS_bytes.data()), pkS_bytes.size());

    // 4. LabeledExtract with "eae_prk"
    std::string suite_id = "KEM";
    suite_id.push_back(static_cast<char>(0x00));
    suite_id.push_back(static_cast<char>(0x16));
    std::string labeled_ikm;
    labeled_ikm.reserve(7 + suite_id.size() + 7 + sizeof(dh));
    labeled_ikm += "HPKE-v1";
    labeled_ikm += suite_id;
    labeled_ikm += "eae_prk";
    labeled_ikm.append(reinterpret_cast<const char*>(dh), sizeof(dh));
    CHKDF_HMAC_SHA256_L32 hkdf_extract(
        reinterpret_cast<const unsigned char*>(labeled_ikm.data()), labeled_ikm.size(),
        ""
    );

    // 5. LabeledExpand with "shared_secret"
    unsigned char L_bytes[2] = {0x00, 0x20};
    std::string labeled_info;
    labeled_info.reserve(2 + 7 + suite_id.size() + 13 + kem_context.size());
    labeled_info.append(reinterpret_cast<const char*>(L_bytes), 2);
    labeled_info += "HPKE-v1";
    labeled_info += suite_id;
    labeled_info += "shared_secret";
    labeled_info += kem_context;
    shared_secret.resize(32);
    hkdf_extract.Expand32(labeled_info, shared_secret.data());

    return true;
}

} // namespace dhkem_secp256k1
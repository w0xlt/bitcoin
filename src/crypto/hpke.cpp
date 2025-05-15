#include <crypto/hpke_dhkem_secp256k1_sha256_chachapoly.h>

#include <crypto/hkdf_sha256_32.h>
#include <crypto/sha256.h>
#include <crypto/hmac_sha256.h> // For CHMAC_SHA256
#include <crypto/chacha20poly1305.h> // For AEADChaCha20Poly1305
#include <hash.h> 
#include <util/strencodings.h> // For HexStr (used in debug prints if any)
#include <assert.h>
#include <algorithm> // For std::copy, std::equal
#include <string_view> // For std::string_view

// Anonymous namespace for internal helper functions
namespace {

using namespace hpke_secp256k1_sha256_chachapoly; // To use Bytes, etc. without prefix

Bytes I2OSP(uint64_t value, size_t length) {
    Bytes result(length);
    for (size_t i = 0; i < length; ++i) {
        result[length - 1 - i] = (value >> (i * 8)) & 0xFF;
    }
    return result;
}

Bytes ConcatBytes(const std::vector<std::span<const uint8_t>>& vecs) {
    Bytes result;
    size_t total_len = 0;
    for (const auto& v_span : vecs) { // Renamed v to v_span for clarity
        total_len += v_span.size();
    }
    result.reserve(total_len);
    for (const auto& v_span : vecs) {
        result.insert(result.end(), v_span.begin(), v_span.end());
    }
    return result;
}

Bytes GetSuiteId() {
    // "HPKE" || I2OSP(KEM_ID, 2) || I2OSP(KDF_ID, 2) || I2OSP(AEAD_ID, 2)
    // Construct Spans directly
    static const std::string hpke_label = "HPKE";
    static const Bytes kem_id_bytes = I2OSP(KEM_ID, 2);
    static const Bytes kdf_id_bytes = I2OSP(KDF_ID, 2);
    static const Bytes aead_id_bytes = I2OSP(AEAD_ID, 2);

    static Bytes suite_id_cache = ConcatBytes({
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(hpke_label.data()), hpke_label.size()),
        std::span<const uint8_t>(kem_id_bytes),
        std::span<const uint8_t>(kdf_id_bytes),
        std::span<const uint8_t>(aead_id_bytes)
    });
    return suite_id_cache;
}

Bytes LabeledExtractInternal(std::span<const uint8_t> salt, std::span<const uint8_t> label_span, std::span<const uint8_t> ikm) {
    Bytes salt_val;
    if (salt.empty()) {
        salt_val.assign(CSHA256::OUTPUT_SIZE, 0); 
    } else {
        salt_val.assign(salt.begin(), salt.end());
    }
    
    static const std::string hpke_v1_label = "HPKE-v1";

    Bytes labeled_ikm = ConcatBytes({
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(hpke_v1_label.data()), hpke_v1_label.size()),
        std::span<const uint8_t>(GetSuiteId()), // GetSuiteId returns Bytes, construct Span from it
        label_span,
        ikm
    });

    std::array<uint8_t, CSHA256::OUTPUT_SIZE> prk_arr;
    CHMAC_SHA256(salt_val.data(), salt_val.size()).Write(labeled_ikm.data(), labeled_ikm.size()).Finalize(prk_arr.data());
    
    return Bytes(prk_arr.begin(), prk_arr.end());
}

Bytes LabeledExpandInternal(std::span<const uint8_t> prk, std::span<const uint8_t> label_span, std::span<const uint8_t> info_context, size_t L) {
    assert(L <= CSHA256::OUTPUT_SIZE); 

    Bytes L_bytes = I2OSP(L, 2);
    static const std::string hpke_v1_label = "HPKE-v1";

    Bytes labeled_info = ConcatBytes({
        std::span<const uint8_t>(L_bytes),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(hpke_v1_label.data()), hpke_v1_label.size()),
        std::span<const uint8_t>(GetSuiteId()),
        label_span,
        info_context
    });

    std::array<uint8_t, CSHA256::OUTPUT_SIZE> okm_arr;
    CHMAC_SHA256 hmac_expand(prk.data(), prk.size());
    hmac_expand.Write(labeled_info.data(), labeled_info.size());
    uint8_t ctr_byte = 0x01;
    hmac_expand.Write(&ctr_byte, 1);
    hmac_expand.Finalize(okm_arr.data());

    Bytes result(okm_arr.begin(), okm_arr.begin() + L);
    return result;
}

Bytes KdfExtractAndExpandInternal(std::span<const uint8_t> dh_input, std::span<const uint8_t> kem_context, std::span<const uint8_t> label_span, size_t L) {
    assert(L <= CSHA256::OUTPUT_SIZE);
    std::array<uint8_t, CSHA256::OUTPUT_SIZE> output_arr;
    CHKDF_SHA256_L32 hkdf;
    hkdf(output_arr.data(), kem_context.data(), kem_context.size(), dh_input.data(), dh_input.size(), label_span.data(), label_span.size());
    return Bytes(output_arr.begin(), output_arr.begin() + L);
}

int ecdh_hash_function_copy_x(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    memcpy(output, x32, Nx);
    return 1;
}

Bytes ComputeNonceInternal(const Bytes& base_nonce, uint64_t seq_num) {
    Bytes nonce = base_nonce;
    assert(nonce.size() == AEAD_NONCE_LEN);

    for (size_t i = 0; i < 8; ++i) { 
        size_t idx = AEAD_NONCE_LEN - 1 - i;
        if (idx < nonce.size()) { // Check idx is within bounds (always true if AEAD_NONCE_LEN >= 8)
             nonce[idx] ^= (seq_num >> (i * 8)) & 0xFF;
        }
    }
    return nonce;
}

} // anonymous namespace

namespace hpke_secp256k1_sha256_chachapoly {

// Helper for string literals to Span
template<size_t N>
std::span<const uint8_t> StringLiteralToSpan(const char (&str)[N]) {
    // N includes the null terminator, so size is N-1
    return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str), N - 1);
}


std::optional<KeyPair> DeriveKeyPair(std::span<const uint8_t> ikm, secp256k1_context* ctx) {
    Bytes dkp_prk = LabeledExtractInternal(Bytes{}, StringLiteralToSpan("dkp_prk"), ikm);

    for (uint8_t counter_val = 0; counter_val < 255; ++counter_val) {
        Bytes ctr_byte_vec = {counter_val};
        Bytes candidate_sk_material = LabeledExpandInternal(std::span<const uint8_t>(dkp_prk), StringLiteralToSpan("candidate"), std::span<const uint8_t>(ctr_byte_vec), Nsk);
        
        SecretKey sk_arr;
        assert(candidate_sk_material.size() == Nsk);
        std::copy(candidate_sk_material.begin(), candidate_sk_material.end(), sk_arr.begin());

        if (secp256k1_ec_seckey_verify(ctx, sk_arr.data()) == 1) {
            secp256k1_pubkey pk_struct;
            if (secp256k1_ec_pubkey_create(ctx, &pk_struct, sk_arr.data()) == 1) {
                PublicKey pk_arr;
                size_t len = POINT_SERIALIZED_SIZE;
                secp256k1_ec_pubkey_serialize(ctx, pk_arr.data(), &len, &pk_struct, SECP256K1_EC_UNCOMPRESSED);
                assert(len == POINT_SERIALIZED_SIZE);
                return KeyPair{sk_arr, pk_arr};
            }
        }
    }
    return std::nullopt;
}

Bytes DH(const SecretKey& sk_bytes, const PublicKey& pk_bytes, secp256k1_context* ctx) {
    secp256k1_pubkey pk_struct;
    if (secp256k1_ec_pubkey_parse(ctx, &pk_struct, pk_bytes.data(), pk_bytes.size()) != 1) {
        return {};
    }

    Bytes shared_x_coord(Nx);
    if (secp256k1_ecdh(ctx, shared_x_coord.data(), &pk_struct, sk_bytes.data(), ecdh_hash_function_copy_x, nullptr) != 1) {
        return {};
    }
    return shared_x_coord;
}

std::optional<EncapResult> Encap(const PublicKey& pkR, std::span<const uint8_t> ikmE, secp256k1_context* ctx) {
    auto ephemeral_kp_opt = DeriveKeyPair(ikmE, ctx);
    if (!ephemeral_kp_opt) return std::nullopt;
    KeyPair eph_kp = *ephemeral_kp_opt;

    Bytes dh_val = DH(eph_kp.sk, pkR, ctx);
    if (dh_val.empty()) return std::nullopt;

    Bytes enc_val(eph_kp.pk.begin(), eph_kp.pk.end());
    Bytes kem_context = ConcatBytes({std::span<const uint8_t>(enc_val), std::span<const uint8_t>(pkR)});
    
    Bytes shared_secret = KdfExtractAndExpandInternal(std::span<const uint8_t>(dh_val), std::span<const uint8_t>(kem_context), StringLiteralToSpan("shared_secret"), Nsecret);
    return EncapResult{shared_secret, enc_val};
}

std::optional<Bytes> Decap(const Bytes& enc, const KeyPair& recipient_key_pair, secp256k1_context* ctx) {
    if (enc.size() != Nenc) return std::nullopt;
    PublicKey pkE_arr;
    std::copy(enc.begin(), enc.end(), pkE_arr.begin());

    Bytes dh_val = DH(recipient_key_pair.sk, pkE_arr, ctx);
    if (dh_val.empty()) return std::nullopt;

    Bytes kem_context = ConcatBytes({std::span<const uint8_t>(enc), std::span<const uint8_t>(recipient_key_pair.pk)});
    
    return KdfExtractAndExpandInternal(std::span<const uint8_t>(dh_val), std::span<const uint8_t>(kem_context), StringLiteralToSpan("shared_secret"), Nsecret);
}

std::optional<EncapResult> AuthEncap(const PublicKey& pkR, std::span<const uint8_t> ikmE, const KeyPair& sender_auth_key_pair, secp256k1_context* ctx) {
    auto ephemeral_kp_opt = DeriveKeyPair(ikmE, ctx);
    if (!ephemeral_kp_opt) return std::nullopt;
    KeyPair eph_kp = *ephemeral_kp_opt;

    Bytes dh_eph_pkR = DH(eph_kp.sk, pkR, ctx);
    if (dh_eph_pkR.empty()) return std::nullopt;

    Bytes dh_auth_pkR = DH(sender_auth_key_pair.sk, pkR, ctx);
    if (dh_auth_pkR.empty()) return std::nullopt;

    Bytes dh_input = ConcatBytes({std::span<const uint8_t>(dh_eph_pkR), std::span<const uint8_t>(dh_auth_pkR)});
    
    Bytes enc_val(eph_kp.pk.begin(), eph_kp.pk.end());
    Bytes kem_context = ConcatBytes({std::span<const uint8_t>(enc_val), std::span<const uint8_t>(pkR), std::span<const uint8_t>(sender_auth_key_pair.pk)});
    
    Bytes shared_secret = KdfExtractAndExpandInternal(std::span<const uint8_t>(dh_input), std::span<const uint8_t>(kem_context), StringLiteralToSpan("shared_secret"), Nsecret);
    return EncapResult{shared_secret, enc_val};
}

std::optional<Bytes> AuthDecap(const Bytes& enc, const KeyPair& recipient_key_pair, const PublicKey& pkS, secp256k1_context* ctx) {
    if (enc.size() != Nenc) return std::nullopt;
    PublicKey pkE_arr;
    std::copy(enc.begin(), enc.end(), pkE_arr.begin());

    Bytes dh_rec_pkE = DH(recipient_key_pair.sk, pkE_arr, ctx);
    if (dh_rec_pkE.empty()) return std::nullopt;

    Bytes dh_rec_pkS = DH(recipient_key_pair.sk, pkS, ctx);
    if (dh_rec_pkS.empty()) return std::nullopt;

    Bytes dh_input = ConcatBytes({std::span<const uint8_t>(dh_rec_pkE), std::span<const uint8_t>(dh_rec_pkS)});

    Bytes kem_context = ConcatBytes({std::span<const uint8_t>(enc), std::span<const uint8_t>(recipient_key_pair.pk), std::span<const uint8_t>(pkS)});
    
    return KdfExtractAndExpandInternal(std::span<const uint8_t>(dh_input), std::span<const uint8_t>(kem_context), StringLiteralToSpan("shared_secret"), Nsecret);
}

std::optional<HpkeContext> KeySchedule(Mode mode, const Bytes& shared_secret, std::span<const uint8_t> info,
                                       std::span<const uint8_t> psk, std::span<const uint8_t> psk_id) {
    if (mode != Mode::BASE && mode != Mode::AUTH) {
        assert(false && "PSK modes not implemented");
        return std::nullopt;
    }
    assert(psk.empty() && psk_id.empty() && "PSK/PSK_ID must be empty for Base/Auth modes");
    
    Bytes mode_val_byte = {static_cast<uint8_t>(mode)};

    Bytes psk_id_hash = LabeledExtractInternal(Bytes{}, StringLiteralToSpan("psk_id_hash"), psk_id);
    Bytes info_hash = LabeledExtractInternal(Bytes{}, StringLiteralToSpan("info_hash"), info);

    Bytes key_schedule_context_bytes = ConcatBytes({ // Renamed to avoid conflict
        std::span<const uint8_t>(mode_val_byte),
        std::span<const uint8_t>(psk_id_hash),
        std::span<const uint8_t>(info_hash)
    });

    Bytes secret_intermediate = LabeledExtractInternal(std::span<const uint8_t>(shared_secret), StringLiteralToSpan("secret"), psk);

    HpkeContext context;
    context.key = LabeledExpandInternal(std::span<const uint8_t>(secret_intermediate), StringLiteralToSpan("key"), std::span<const uint8_t>(key_schedule_context_bytes), AEAD_KEY_LEN);
    context.base_nonce = LabeledExpandInternal(std::span<const uint8_t>(secret_intermediate), StringLiteralToSpan("base_nonce"), std::span<const uint8_t>(key_schedule_context_bytes), AEAD_NONCE_LEN);
    context.exporter_secret = LabeledExpandInternal(std::span<const uint8_t>(secret_intermediate), StringLiteralToSpan("exp"), std::span<const uint8_t>(key_schedule_context_bytes), Nsecret);
    context.seq_num = 0;

    return context;
}

std::optional<Bytes> Seal(HpkeContext& context, std::span<const uint8_t> aad, std::span<const uint8_t> ptxt) {
    if (context.seq_num == UINT64_MAX) return std::nullopt;

    Bytes nonce = ComputeNonceInternal(context.base_nonce, context.seq_num);
    
    Bytes ctxt(ptxt.size() + AEAD_TAG_LEN);
    // Use std::span<const uint8_t> for key, and std::span<uint8_t> for nonce for AEADChaCha20Poly1305
    AEADChaCha20Poly1305 aead_chacha(std::span<const uint8_t>(context.key).first(AEAD_KEY_LEN)); // Key is const
    if (!aead_chacha.Encrypt(ctxt, aad, ptxt, std::span<uint8_t>(nonce))) { // Nonce for encrypt might need to be non-const by some interfaces; Bitcoin's one is `std::span<const uint8_t> nonce`
        return std::nullopt; 
    }

    context.seq_num++;
    return ctxt;
}

std::optional<Bytes> Open(HpkeContext& context, std::span<const uint8_t> aad, std::span<const uint8_t> ctxt) {
    if (context.seq_num == UINT64_MAX) return std::nullopt;
    if (ctxt.size() < AEAD_TAG_LEN) return std::nullopt;

    Bytes nonce = ComputeNonceInternal(context.base_nonce, context.seq_num);
    
    Bytes ptxt(ctxt.size() - AEAD_TAG_LEN);
    AEADChaCha20Poly1305 aead_chacha(std::span<const uint8_t>(context.key).first(AEAD_KEY_LEN));
    if (!aead_chacha.Decrypt(ptxt, aad, ctxt, std::span<const uint8_t>(nonce))) { // Decrypt nonce is const
        return std::nullopt;
    }

    context.seq_num++;
    return ptxt;
}

} // namespace hpke_secp256k1_sha256_chachapoly
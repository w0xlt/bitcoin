#include <boost/test/unit_test.hpp>
#include <dhkem_secp256k1.h>
#include <key.h>  // for ECC context management
#include <test/util/json.h>
#include <test/data/dhkem_secp256k1_test_vectors.json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <vector>

using namespace dhkem_secp256k1;

BOOST_FIXTURE_TEST_SUITE(dhkem_secp256k1_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dhkem_secp256k1_chacha20poly1305_testvectors)
{
    UniValue test_vectors = read_json(json_tests::dhkem_secp256k1_test_vectors);
    BOOST_REQUIRE(test_vectors.isArray());

    dhkem_secp256k1::InitContext();

    for (size_t i = 0; i < test_vectors.size(); ++i) {

        const UniValue& tv = test_vectors[i];
        BOOST_REQUIRE(tv.isObject());
        uint8_t mode = tv["mode"].getInt<uint8_t>();

        // Parse hex inputs from JSON
        std::vector<unsigned char> info    = ParseHex(tv["info"].get_str());
        std::vector<unsigned char> ikmE    = ParseHex(tv["ikmE"].get_str());
        std::vector<unsigned char> ikmR    = ParseHex(tv["ikmR"].get_str());
        std::vector<unsigned char> exp_skEm = ParseHex(tv["skEm"].get_str());
        std::vector<unsigned char> exp_pkEm = ParseHex(tv["pkEm"].get_str());
        std::vector<unsigned char> exp_skRm = ParseHex(tv["skRm"].get_str());
        std::vector<unsigned char> exp_pkRm = ParseHex(tv["pkRm"].get_str());
        std::vector<unsigned char> psk, psk_id;
        if (mode == 0x01 || mode == 0x03) {
            psk    = ParseHex(tv["psk"].get_str());
            psk_id = ParseHex(tv["psk_id"].get_str());
        }
        std::vector<unsigned char> ikmS, exp_skSm, exp_pkSm;
        if (mode == 0x02 || mode == 0x03) {
            ikmS     = ParseHex(tv["ikmS"].get_str());
            exp_skSm = ParseHex(tv["skSm"].get_str());
            exp_pkSm = ParseHex(tv["pkSm"].get_str());
        }
        std::vector<unsigned char> exp_shared   = ParseHex(tv["shared_secret"].get_str());
        std::vector<unsigned char> exp_key      = ParseHex(tv["key"].get_str());
        std::vector<unsigned char> exp_nonce    = ParseHex(tv["base_nonce"].get_str());
        std::vector<unsigned char> exp_exporter = ParseHex(tv["exporter_secret"].get_str());
        
        // Derive key pairs and verify against expected (uses dhkem_secp256k1::DeriveKeyPair)
        std::array<uint8_t, 32> skEm;
        std::array<uint8_t, 65> pkEm;
        bool ok = dhkem_secp256k1::DeriveKeyPair(std::span<const uint8_t>(ikmE.data(), ikmE.size()), skEm, pkEm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skEm), HexStr(exp_skEm));
        BOOST_CHECK_EQUAL(HexStr(pkEm), HexStr(exp_pkEm));
        
        std::array<uint8_t, 32> skRm;
        std::array<uint8_t, 65> pkRm;
        ok = dhkem_secp256k1::DeriveKeyPair(std::span<const uint8_t>(ikmR.data(), ikmR.size()), skRm, pkRm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skRm), HexStr(exp_skRm));
        BOOST_CHECK_EQUAL(HexStr(pkRm), HexStr(exp_pkRm));

        std::span<const uint8_t> pkEm2(pkEm.data(), pkEm.size());
        std::span<const uint8_t> skRm2(skRm.data(), skRm.size());

        std::vector<unsigned char> ss_vec;

        // Perform KEM encapsulation/decapsulation depending on mode
        if (mode < 0x02) {

            auto result_enc = dhkem_secp256k1::Encap(pkRm, skEm, pkEm);
            BOOST_CHECK(result_enc.has_value());

            auto [shared_secret_enc, ss_pk_enc] = *result_enc;

            // Base mode: use Decap with recipient's SK and ephemeral PK
            std::optional<std::array<uint8_t,32>> shared_secret_dec = 
                dhkem_secp256k1::Decap(std::span(pkEm), std::span(skRm));
            BOOST_CHECK(shared_secret_dec.has_value());

            BOOST_CHECK_EQUAL(HexStr(*shared_secret_dec), HexStr(shared_secret_enc));
            BOOST_CHECK_EQUAL(HexStr(*shared_secret_dec), HexStr(exp_shared));
            // Convert shared secret to vector for KDF input
            ss_vec.assign(shared_secret_dec->begin(), shared_secret_dec->end());
        } else {

            std::array<uint8_t, 32> skSm;
            std::array<uint8_t, 65> pkSm;
            ok = dhkem_secp256k1::DeriveKeyPair(std::span<const uint8_t>(ikmS.data(), ikmS.size()), skSm, pkSm);
            BOOST_CHECK(ok);
            BOOST_CHECK_EQUAL(HexStr(skSm), HexStr(exp_skSm));
            BOOST_CHECK_EQUAL(HexStr(pkSm), HexStr(exp_pkSm));

            // Auth mode: use AuthEncap/AuthDecap
            std::array<uint8_t,32> ss_enc, ss_dec;
            BOOST_CHECK(dhkem_secp256k1::AuthEncap(ss_enc, skEm, pkEm, pkRm, skSm));
            BOOST_CHECK(dhkem_secp256k1::AuthDecap(ss_dec, pkEm, skRm, pkSm));
            BOOST_CHECK_EQUAL(HexStr(ss_enc), HexStr(ss_dec));
            BOOST_CHECK_EQUAL(HexStr(ss_dec), HexStr(exp_shared));
            ss_vec.assign(ss_dec.begin(), ss_dec.end());
        }

        // Derive HPKE context key, base_nonce, exporter_secret using key schedule (mode 0x00):contentReference[oaicite:33]{index=33}
        // default psk_id = default_psk = "" in Base mode
        std::vector<uint8_t> label_psk_id_hash = {'p', 's', 'k', '_', 'i', 'd', '_', 'h', 'a', 's', 'h'};
        // auto psk_id_hash = LabeledExtract({}, label_psk_id_hash, std::vector<unsigned char>());psk_id
        auto psk_id_hash = LabeledExtract({}, label_psk_id_hash, psk_id);

        std::vector<uint8_t> label_info_hash = {'i', 'n', 'f', 'o', '_', 'h', 'a', 's', 'h'};
        auto info_hash = LabeledExtract({}, label_info_hash, info);

        // key_schedule_context = mode || psk_id_hash || info_hash
        std::vector<unsigned char> context;
        context.push_back(mode);
        context.insert(context.end(), psk_id_hash.begin(), psk_id_hash.end());
        context.insert(context.end(), info_hash.begin(), info_hash.end());

        std::vector<uint8_t> label_secret = {'s', 'e', 'c', 'r', 'e', 't'};
        auto secret = LabeledExtract(ss_vec, label_secret, psk);

        // Derive key, base_nonce, exporter_secret
        std::vector<uint8_t> label_key = {'k','e','y'};
        std::vector<unsigned char> got_key   = dhkem_secp256k1::LabeledExpand(secret, label_key, context, 32);

        std::vector<uint8_t> label_base_nonce = {'b','a','s','e','_','n','o','n','c','e'};
        std::vector<unsigned char> got_nonce = dhkem_secp256k1::LabeledExpand(secret, label_base_nonce, context, 12);

        std::vector<uint8_t> label_exp = {'e','x','p'};
        std::vector<unsigned char> got_exporter = dhkem_secp256k1::LabeledExpand(secret, label_exp, context, exp_exporter.size());

        BOOST_CHECK_EQUAL(HexStr(got_key), HexStr(exp_key));
        BOOST_CHECK_EQUAL(HexStr(got_nonce), HexStr(exp_nonce));
        BOOST_CHECK_EQUAL(HexStr(got_exporter), HexStr(exp_exporter));

        std::vector<uint8_t> nonce(12);
        std::copy(got_nonce.begin(), got_nonce.end(), nonce.begin());

        // AEAD encryption/decryption tests for each entry in tv["encryptions"]
        const UniValue& encryptions = tv["encryptions"];
        BOOST_REQUIRE(encryptions.isArray());
        for (size_t j = 0; j < encryptions.size(); ++j) {

            const UniValue& encObj = encryptions[j];
            std::vector<unsigned char> exp_pt   = ParseHex(encObj["pt"].get_str());
            std::vector<unsigned char> exp_aad  = ParseHex(encObj["aad"].get_str());
            std::vector<unsigned char> exp_nonce_enc = ParseHex(encObj["nonce"].get_str());
            std::vector<unsigned char> exp_ct   = ParseHex(encObj["ct"].get_str());

            ChaCha20::Nonce96 nonce_val;
            nonce_val.first  = ReadLE32(nonce.data());       // first 4 bytes as little-endian uint32
            nonce_val.second = ReadLE64(nonce.data() + 4);  

            auto ciphertext = dhkem_secp256k1::Seal(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(got_key.data()), got_key.size()),
                nonce_val,
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(exp_aad.data()), exp_aad.size()),
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(exp_pt.data()), exp_pt.size())
            );
            BOOST_CHECK_EQUAL(HexStr(ciphertext), HexStr(exp_ct));

            auto decrypted = dhkem_secp256k1::Open(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(got_key.data()), got_key.size()),
                nonce_val,
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(exp_aad.data()), exp_aad.size()),
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(ciphertext.data()), ciphertext.size())
            );
            BOOST_CHECK(decrypted.has_value());
            BOOST_CHECK_EQUAL(HexStr(*decrypted), HexStr(exp_pt));

            // Compute nonce = base_nonce XOR I2OSP(seq, Nn) as per RFC 9180 §5.2 (seq = j)
            uint64_t seq_num = j + 1;
            nonce = dhkem_secp256k1::mix_nonce(got_nonce, seq_num);

            // The derived nonce should equal the expected nonce from test vector
            BOOST_CHECK_EQUAL(HexStr(nonce), HexStr(exp_nonce_enc));
        }
    }
}

BOOST_AUTO_TEST_CASE(dhkem_encap_decap)
{
    CKey skR;
    skR.MakeNewKey(false);
    CPubKey pkR = skR.GetPubKey();
    std::vector<uint8_t> pkR_bytes(pkR.begin(), pkR.end());
    BOOST_CHECK(pkR_bytes.size() == 65);

    CKey skE;
    skE.MakeNewKey(false);
    CPubKey pkE = skE.GetPubKey();
    assert(pkE.size() == 65);

    // Make a std::array and copy the bytes in
    std::array<uint8_t, 65> pkE_bytes;
    std::copy(pkE.begin(), pkE.end(), pkE_bytes.begin());

    std::span<const uint8_t> skE_span(reinterpret_cast<const uint8_t*>(skE.data()), skE.size());
    std::array<uint8_t, 32>  skE_array;
    std::copy(skE_span.begin(), skE_span.end(), skE_array.begin());

    dhkem_secp256k1::InitContext();

    // Perform encapsulation with the recipient's public key
    auto maybe_result = dhkem_secp256k1::Encap(pkR_bytes, skE_array, pkE_bytes);
    BOOST_CHECK(maybe_result.has_value()); // Encap should succeed

    std::span<const uint8_t> skR_span(reinterpret_cast<const uint8_t*>(skR.data()), skR.size());

    // Extract shared_secret_enc and enc (ephemeral public key bytes)
    auto [shared_secret_enc, enc3] = *maybe_result;
    // Decapsulate using the recipient's private key
    std::optional<std::array<uint8_t, 32>> maybe_shared_secret_dec = dhkem_secp256k1::Decap(enc3, skR_span);
    
    BOOST_CHECK(maybe_shared_secret_dec.has_value());
    BOOST_CHECK_EQUAL(HexStr(shared_secret_enc), HexStr(*maybe_shared_secret_dec));
}

BOOST_AUTO_TEST_CASE(dhkem_auth_encap_decap)
{
    // 1. Generate sender (skS) and recipient (skR) key pairs
    CKey skS;
    CKey skR;
    skS.MakeNewKey(/* compressed = */ false);
    skR.MakeNewKey(/* compressed = */ false);
    CPubKey pkS = skS.GetPubKey();
    CPubKey pkR = skR.GetPubKey();

    // 2. Generate ephemeral (skE) key pairs
    CKey skE;
    skE.MakeNewKey(false);
    CPubKey pkE = skE.GetPubKey();
    assert(pkE.size() == 65);

    // Make a std::array and copy the bytes in
    std::array<uint8_t, 65> enc;
    std::copy(pkE.begin(), pkE.end(), enc.begin());

    std::span<const uint8_t> skE_span(reinterpret_cast<const uint8_t*>(skE.data()), skE.size());
    std::array<uint8_t, 32>  skE_array;
    std::copy(skE_span.begin(), skE_span.end(), skE_array.begin());

    // 3. Convert CPubKey to std::array<uint8_t, 65> for use with AuthEncap/AuthDecap
    std::array<uint8_t, 65> pkR_array;
    std::copy(pkR.begin(), pkR.end(), pkR_array.begin());

    std::array<uint8_t, 65> pkS_array;
    std::copy(pkS.begin(), pkS.end(), pkS_array.begin());

    // 4. Convert CKey to std::array<uint8_t, 32> for use with AuthEncap/AuthDecap
    std::span<const uint8_t> skS_span(reinterpret_cast<const uint8_t*>(skS.data()), skS.size());
    std::array<uint8_t, 32> skS_array;
    std::copy(skS_span.begin(), skS_span.end(), skS_array.begin());

    std::span<const uint8_t> skR_span(reinterpret_cast<const uint8_t*>(skR.data()), skR.size());
    std::array<uint8_t, 32> skR_array;
    std::copy(skR_span.begin(), skR_span.end(), skR_array.begin());

    // 5. Prepare output containers for shared secrets and encapsulated key
    std::array<uint8_t, 32> shared_secret_enc{0};
    std::array<uint8_t, 32> shared_secret_dec{0};

    // 6. Perform authenticated encapsulation (sender side)
    BOOST_CHECK(dhkem_secp256k1::AuthEncap(shared_secret_enc, skE_array, enc, pkR_array, skS_array));

    // 7. Perform authenticated decapsulation (recipient side)
    BOOST_CHECK(dhkem_secp256k1::AuthDecap(shared_secret_dec, enc, skR_array, pkS_array));

    BOOST_CHECK_EQUAL(HexStr(shared_secret_enc), HexStr(shared_secret_dec));
}

BOOST_AUTO_TEST_CASE(dhkem_secp256k1_seal_open)
{
    // 1. Encryption/decryption with empty plaintext and non-empty AAD
    std::array<uint8_t, 32> key1 = {0};               // 32-byte key (all zeros)
    ChaCha20::Nonce96 nonce1 = {0, 0};                // 96-bit nonce = 0x000000000000000000000000
    std::vector<uint8_t> aad1 = {'T','e','s','t',' ','A','A','D'};  // example AAD
    std::vector<uint8_t> plaintext1;                  // empty plaintext
    // Seal: encrypt plaintext1
    auto ciphertext1 = dhkem_secp256k1::Seal(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key1.data()), key1.size()),
        nonce1,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad1.data()), aad1.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(plaintext1.data()), plaintext1.size()));
    // Ciphertext should be just the 16-byte tag (since plaintext is empty)
    BOOST_CHECK_EQUAL(ciphertext1.size(), AEADChaCha20Poly1305::EXPANSION);
    // Open: decrypt and check that we get the empty plaintext back
    auto decrypted1 = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key1.data()), key1.size()),
        nonce1,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad1.data()), aad1.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ciphertext1.data()), ciphertext1.size()));
    BOOST_CHECK(decrypted1.has_value());
    BOOST_CHECK(decrypted1->empty());  // plaintext1 was empty

    // 2. Encryption/decryption with non-empty plaintext and empty AAD
    std::array<uint8_t, 32> key2;
    for (size_t i = 0; i < key2.size(); ++i) key2[i] = static_cast<uint8_t>(i);  // key2 = 00 01 02 ... 1F
    ChaCha20::Nonce96 nonce2 = {1, 0};                // nonce with first part = 1, second = 0
    std::vector<uint8_t> aad2;                        // empty AAD
    std::vector<uint8_t> plaintext2 = {'H','e','l','l','o',',',' ','w','o','r','l','d','!'};  // "Hello, world!"
    auto ciphertext2 = dhkem_secp256k1::Seal(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key2.data()), key2.size()),
        nonce2,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad2.data()), aad2.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(plaintext2.data()), plaintext2.size()));
    // Ciphertext length = plaintext length + 16
    BOOST_CHECK_EQUAL(ciphertext2.size(), plaintext2.size() + AEADChaCha20Poly1305::EXPANSION);
    auto decrypted2 = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key2.data()), key2.size()),
        nonce2,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad2.data()), aad2.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ciphertext2.data()), ciphertext2.size()));
    BOOST_CHECK(decrypted2.has_value());
    BOOST_CHECK_EQUAL(decrypted2->size(), plaintext2.size());
    BOOST_CHECK(*decrypted2 == plaintext2);  // verify content matches original

    // 3. Encryption/decryption with non-empty plaintext and non-empty AAD
    ChaCha20::Nonce96 nonce3 = {0, 1};                // another distinct nonce
    std::vector<uint8_t> aad3(20);
    for (size_t i = 0; i < aad3.size(); ++i) aad3[i] = 0xFF - static_cast<uint8_t>(i);  // pattern: 0xFF, 0xFE, ...
    std::vector<uint8_t> plaintext3(80);
    for (size_t i = 0; i < plaintext3.size(); ++i) plaintext3[i] = static_cast<uint8_t>(i);  // 0x00, 0x01, ... 0x4F
    auto ciphertext3 = dhkem_secp256k1::Seal(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key2.data()), key2.size()),
        nonce3,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad3.data()), aad3.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(plaintext3.data()), plaintext3.size()));
    BOOST_CHECK_EQUAL(ciphertext3.size(), plaintext3.size() + AEADChaCha20Poly1305::EXPANSION);
    auto decrypted3 = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key2.data()), key2.size()),
        nonce3,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad3.data()), aad3.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ciphertext3.data()), ciphertext3.size()));
    BOOST_CHECK(decrypted3.has_value());
    BOOST_CHECK_EQUAL(decrypted3->size(), plaintext3.size());
    BOOST_CHECK(*decrypted3 == plaintext3);  // content matches

    // 4. Tampering tests: modify ciphertext or tag and verify decryption fails
    std::vector<uint8_t> tampered = ciphertext3;
    tampered[0] ^= 0x01;  // flip one byte in the ciphertext portion
    auto dec_fail1 = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key2.data()), key2.size()),
        nonce3,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad3.data()), aad3.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(tampered.data()), tampered.size()));
    BOOST_CHECK(!dec_fail1.has_value());  // authentication should fail

    tampered = ciphertext3;
    tampered.back() ^= 0x01;  // flip a byte in the tag (last 16 bytes of ciphertext3)
    auto dec_fail2 = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key2.data()), key2.size()),
        nonce3,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad3.data()), aad3.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(tampered.data()), tampered.size()));
    BOOST_CHECK(!dec_fail2.has_value());  // should fail due to tag mismatch

    // Try decrypting with the wrong key (should also fail authentication)
    std::array<uint8_t, 32> key_wrong = key2;
    key_wrong[0] ^= 0x01;  // slight modification to key2
    auto dec_fail3 = dhkem_secp256k1::Open(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(key_wrong.data()), key_wrong.size()),
        nonce3,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(aad3.data()), aad3.size()),
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(ciphertext3.data()), ciphertext3.size()));
    BOOST_CHECK(!dec_fail3.has_value());
}

BOOST_AUTO_TEST_SUITE_END()
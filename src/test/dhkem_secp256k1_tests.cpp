#include <boost/test/unit_test.hpp>
#include <dhkem_secp256k1.h>
#include <util/strencodings.h>
#include <key.h>  // for ECC context management
#include <vector>
#include <test/util/setup_common.h>

using namespace dhkem_secp256k1;

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

BOOST_FIXTURE_TEST_SUITE(dhkem_secp256k1_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dhkem_secp256k1_chacha20poly1305_testvectors)
{
    struct VectorBase {
        std::string info;
        std::string ikmE, skEm, pkEm;
        std::string ikmR, skRm, pkRm;
        std::string shared_secret;
        std::string key, base_nonce, exporter_secret;
    };
    struct VectorAuth {
        std::string ikmE, skEm, pkEm;
        std::string ikmR, skRm, pkRm;
        std::string ikmS, skSm, pkSm;
        std::string shared_secret;
        std::string key, base_nonce, exporter_secret;
    };

    // Test vectors from Appendix B.3.1 (Base mode):contentReference[oaicite:29]{index=29}:contentReference[oaicite:30]{index=30}
    std::vector<VectorBase> base_vecs = {
        {
            /* info (not directly in VectorBase, will use below) */ 
            "609dcb9844f8412343191f93add1177186c03a36",
            /* ikmE */  "77caf1617fb3723972a56cd2085081c9f66baae825ce5f363c0a86ec87013fa0",
            /* skEm */  "1300156862599d00ecbb066644bf4d4505b56a9b235eae7a8632defc4335d5c0",
            /* pkEm */  "0471788be0ccf916302c4f2225bba89a0ff3832df1fe50b48d8ccb910be74e30"
                        "241428ba6de731ccf538ded2913febdfe14b2648fafb8fdd35b8aa91804c706076",
            /* ikmR */  "71b530bed75fc3fa2f8e8bb163203e6ee676565cc61cd59d66352676341c0688",
            /* skRm */  "4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643",
            /* pkRm */  "04e660b55a28899c472ca023dce35f23da3cf16677dbdce9ed25353bd8b70cbb"
                        "8bee0abd2cc8936aee263a08d5b2a15d29a16d12b75fda63b9c614c477af165e2d",
            /* shared_secret */ "a81a3ccf56f48c699eb9f393e0701692836f9ac2e06b493ccbf99ac68a792bbe",
            /* key */          "4c260fe82e8c3737e7a70c3223cb16fc205682255389ad4bc3e7fae42c46b062",
            /* base_nonce */   "e035bbf3c39ff5a7196cfe84",
            /* exporter_secret */ "83e82aad90186ddd7e1db090c840ee70eb6cac7531b64dc52a12997462c8d0d8"
        },
        {
            "325c816adeee49bea410f0db92947892378f6e0c",
            "597ba1fe9a4db02225bbb3e4cd150ceb68636e84d80e728f1be6b22e8aeefcb0",
            "29e4ff54b558f0a5b3c8f7c016736f6b784ed71d1395bbee07ae4320919465d1",
            "04a3f4964462ee117c47ed7c129ce25c574d1cd97aa2fde60abdb8616be0f5c1"
            "a6fe12c847b07ffca907c8e3f7eb58fe94042b78a90f27318d5421e96af9acab7a",
            "9cabb8ddac5293c96ffcdaa3aa1c797ecba36f9c2d21ce27495f52ea80497a5c",
            "dad1397389c4ff7fa014068bcfbf0c2ea2e24d78b0395fa3de9e88802bc8a684",
            "04be3e5d3dfcc77e81f96f90c5fa3ce7f6f7f7005acaf39a2c3d7d47f1ac1cf1"
            "0bcd06191d07366e706a2ca77e2e0571e11bfc2cbd471904ef0d999af757939da1",
            "9edafcdb619dabc578d8f7b7b055ac66d5cfb6219b90f69d13d297ed49f3aaf3",
            "6e771cd99a23e82ddbd972ecc1b7d3bcd5d6f961370ac2ff785e6776b47b2d53",
            "208b33e382b39dfc1ebb2c95",
            "ead4fa0d88885cc36792039cbf75110d57eac32e883395eae3ccdeba0a53b3d4"
        },
        {
            "5d274e2436d921573ba466fb5ebef86bd5f77f34",
            "149db0ca6bd0bdabbfca4a61c4a6507efff33eedd844d9e1c299cbaab3a1d006",
            "a342069714f97f18a844495779cf41e82ffa7e98c197ffd1276a8d74823c2519",
            "0460cb3f0f85591f7b804fe91882b442837b9b535ea9c9fbd2d3adda128967d9"
            "374ba8c7da87e8af31a32a326da570bc96044a731e1857246b881051b8d86779ea",
            "2d00ee3b22d16bd33224c2cd32158437bd0e0e3c053307d697b70e55f578f009",
            "1ef5ec4b4482951fca257b0a0709f376f08c30a647cefa10f9b150a6839385ff",
            "04706fd6e62dbf8a440f9f77bc47eb0703177f0f80275ce4be175c9c86953677"
            "9a64806dff22c83ceb9b4a87302415a161b7d30a55521d181a6d01974c0648773e",
            "fffa60534552d71101540d8022cd1ffe896da801fe55e194b9d71f1ce882b6ff",
            "ebe85898642db23679f83ae4a81efdea5feb4103553b9834cb1f4f602bcef495",
            "ea1e6ce9451d45f9295189c2",
            "92ea7629022c39382b333c1dcdc2dbed9cd2de4fe1d57320125577231aa35203"
        }
    };

    // Helper lambdas for computing HPKE key schedule (for verification)
    /* auto LabeledExtract = [&](const std::vector<unsigned char>& salt, const std::string& label, const std::vector<unsigned char>& ikm) {
        std::vector<unsigned char> labeled;
        labeled.insert(labeled.end(), std::begin((LABEL_PREFIX)), std::end((LABEL_PREFIX)));
        labeled.insert(labeled.end(), std::begin((SUITE_ID)), std::end((SUITE_ID)));
        labeled.insert(labeled.end(), label.begin(), label.end());
        labeled.insert(labeled.end(), ikm.begin(), ikm.end());

        std::cout << "---> labeled_ikm: " << HexStr(labeled) << std::endl;

        std::array<unsigned char, 32> prk{};
        HKDF_Extract(salt.empty()? nullptr: salt.data(), salt.size(), labeled.data(), labeled.size(), prk.data());
        return prk;
    }; */

    

    auto LabeledExpand = [&](const std::array<unsigned char,32>& prk, const std::string& label, const std::vector<unsigned char>& info, size_t L) {
        // labeled info = "HPKE-v1"||suite_id||label||info
        std::vector<unsigned char> labeled_info;
        labeled_info.insert(labeled_info.end(), std::begin((LABEL_PREFIX)), std::end((LABEL_PREFIX)));
        labeled_info.insert(labeled_info.end(), std::begin((SUITE_ID)), std::end((SUITE_ID)));
        labeled_info.insert(labeled_info.end(), label.begin(), label.end());
        labeled_info.insert(labeled_info.end(), info.begin(), info.end());
        std::vector<unsigned char> okm(L);
        HKDF_Expand32(prk.data(), labeled_info.data(), labeled_info.size(), okm.data(), L);
        return okm;
    };

    // Process each Base mode test vector
    for (size_t i = 0; i < base_vecs.size(); ++i) {
        std::string info_hex = base_vecs[i].ikmE; // Actually the 'info' is stored separately above for each case
        // The "info" hex is given in the base_vecs as the first string (we placed the info hex in ikmE field for convenience)
        std::vector<unsigned char> info = ParseHex(base_vecs[i].info);
        std::vector<unsigned char> ikmE = ParseHex(base_vecs[i].ikmE);
        std::vector<unsigned char> ikmR = ParseHex(base_vecs[i].ikmR);
        std::vector<unsigned char> exp_skEm = ParseHex(base_vecs[i].skEm);
        std::vector<unsigned char> exp_pkEm = ParseHex(base_vecs[i].pkEm);
        std::vector<unsigned char> exp_skRm = ParseHex(base_vecs[i].skRm);
        std::vector<unsigned char> exp_pkRm = ParseHex(base_vecs[i].pkRm);
        std::vector<unsigned char> exp_shared = ParseHex(base_vecs[i].shared_secret);
        std::vector<unsigned char> exp_key = ParseHex(base_vecs[i].key);
        std::vector<unsigned char> exp_nonce = ParseHex(base_vecs[i].base_nonce);
        std::vector<unsigned char> exp_exporter = ParseHex(base_vecs[i].exporter_secret);

        // DeriveKeyPair for ephemeral (sender) and static (receiver)
        // uint8_t skEm[32], pkEm[65];
        std::array<uint8_t, 32> skEm;
        std::array<uint8_t, 65> pkEm;

        dhkem_secp256k1::InitContext();

        // bool ok = DeriveKeyPair(ikmE.data(), ikmE.size(), skEm, pkEm);
        bool ok = dhkem_secp256k1::DeriveKeyPair_DHKEM_Secp256k1(std::span<const uint8_t>(ikmE.data(), ikmE.size()), skEm, pkEm);

        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skEm), HexStr(exp_skEm));
        BOOST_CHECK_EQUAL(HexStr(pkEm), HexStr(exp_pkEm));
        // uint8_t skRm[32], pkRm[65];
        std::array<uint8_t, 32> skRm;
        std::array<uint8_t, 65> pkRm;
        //ok = DeriveKeyPair(ikmR.data(), ikmR.size(), skRm, pkRm);
        ok = dhkem_secp256k1::DeriveKeyPair_DHKEM_Secp256k1(std::span<const uint8_t>(ikmR.data(), ikmR.size()), skRm, pkRm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skRm), HexStr(exp_skRm));
        BOOST_CHECK_EQUAL(HexStr(pkRm), HexStr(exp_pkRm));

        // Test decapsulation: should reproduce shared_secret
        // uint8_t shared[32];
        // ok = Decap(pkEm, skRm, shared);

        std::span<const uint8_t> pkEm2(pkEm.data(), pkEm.size());
        std::span<const uint8_t> skRm2(skRm.data(), skRm.size());

        std::optional<std::array<uint8_t, 32>> maybe_shared_secret_dec = dhkem_secp256k1::Decap2(pkEm2, skRm2);
        BOOST_CHECK(maybe_shared_secret_dec.has_value());
        BOOST_CHECK_EQUAL(HexStr(*maybe_shared_secret_dec), HexStr(exp_shared));

        std::vector<unsigned char> ss_vec;
        ss_vec.assign(maybe_shared_secret_dec->begin(), maybe_shared_secret_dec->end());

        // Derive HPKE context key, base_nonce, exporter_secret using key schedule (mode 0x00):contentReference[oaicite:33]{index=33}
        uint8_t mode_base = 0x00;
        // default psk_id = default_psk = "" in Base mode
        std::vector<uint8_t> label_psk_id_hash = {'p', 's', 'k', '_', 'i', 'd', '_', 'h', 'a', 's', 'h'};
        // auto psk_id_hash = LabeledExtract({}, "psk_id_hash", std::vector<unsigned char>());  // empty ikm
        auto psk_id_hash = LabeledExtract({}, label_psk_id_hash, std::vector<unsigned char>());  // empty ikm

        std::cout << "---> psk_id_hash: " << HexStr(psk_id_hash) << std::endl;

        std::cout << "---> info: " << HexStr(info) << std::endl;

        std::vector<uint8_t> label_info_hash = {'i', 'n', 'f', 'o', '_', 'h', 'a', 's', 'h'};
        // auto info_hash = LabeledExtract({}, "info_hash", info);
        auto info_hash = LabeledExtract({}, label_info_hash, info);

        std::cout << "---> info_hash: " << HexStr(info_hash) << std::endl;

        // key_schedule_context = mode || psk_id_hash || info_hash
        std::vector<unsigned char> context;
        context.push_back(mode_base);
        context.insert(context.end(), psk_id_hash.begin(), psk_id_hash.end());
        context.insert(context.end(), info_hash.begin(), info_hash.end());

        std::cout << "---> context: " << HexStr(context) << std::endl;
        std::cout << "---> ss_vec: " << HexStr(ss_vec) << std::endl;

        std::vector<unsigned char> psk; // empty
        std::vector<uint8_t> label_secret = {'s', 'e', 'c', 'r', 'e', 't'};
        // auto secret = LabeledExtract(psk,"secret", ss_vec);
        auto secret = LabeledExtract(ss_vec, label_secret, psk);

        std::cout << "---> secret: " << HexStr(secret) << std::endl;
        // Derive key, base_nonce, exporter_secret
        /*  std::vector<unsigned char> got_key   = LabeledExpand(secret, "key", context, exp_key.size());
        std::vector<unsigned char> got_nonce = LabeledExpand(secret, "base_nonce", context, exp_nonce.size());
        std::vector<unsigned char> got_exporter = LabeledExpand(secret, "exp", context, exp_exporter.size());
        BOOST_CHECK_EQUAL(HexStr(got_key), HexStr(exp_key));
        BOOST_CHECK_EQUAL(HexStr(got_nonce), HexStr(exp_nonce));
        BOOST_CHECK_EQUAL(HexStr(got_exporter), HexStr(exp_exporter)); */
    }
}

BOOST_AUTO_TEST_CASE(dhkem_encap_decap)
{
    CKey skR;
    skR.MakeNewKey(false);
    CPubKey pkR = skR.GetPubKey();
    std::vector<uint8_t> pkR_bytes(pkR.begin(), pkR.end());
    assert(pkR_bytes.size() == 65);

    dhkem_secp256k1::InitContext();

    // Perform encapsulation with the recipient's public key
    auto maybe_result = dhkem_secp256k1::Encap2(pkR_bytes);
    assert(maybe_result.has_value()); // Encap should succeed

    std::span<const uint8_t> skR_span(reinterpret_cast<const uint8_t*>(skR.data()), skR.size());

    // Extract shared_secret_enc and enc (ephemeral public key bytes)
    auto [shared_secret_enc, enc3] = *maybe_result;
    // Decapsulate using the recipient's private key
    std::optional<std::array<uint8_t, 32>> maybe_shared_secret_dec = dhkem_secp256k1::Decap2(enc3, skR_span);
    
    BOOST_CHECK(maybe_shared_secret_dec.has_value());
    BOOST_CHECK_EQUAL(HexStr(shared_secret_enc), HexStr(*maybe_shared_secret_dec));
}

BOOST_AUTO_TEST_SUITE_END()
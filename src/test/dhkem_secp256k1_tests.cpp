#include <boost/test/unit_test.hpp>
#include <dhkem_secp256k1.h>
#include <util/strencodings.h>
#include <key.h>  // for ECC context management
#include <vector>
#include <test/util/setup_common.h>

using namespace dhkem_secp256k1;

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

    // Test vectors from Appendix B.3.2 (Auth mode):contentReference[oaicite:31]{index=31}:contentReference[oaicite:32]{index=32}
    /* std::vector<VectorAuth> auth_vecs = {
        {
            "f402a160b0dd43a5490e9315dd8ea386eb3b2bde9e252857e8a3132fa084506b",
            "338693112ca52e24b33c8211cf654ed6c9c44d1e74f344c724728cd9a4554053",
            "04de99438fc76aaec2117df2346593c16f0a70ea9695ca7651aff895463b91e3"
            "f3c846925784ddabd6b00b5094c10ba3b11bb9ff8b11ff2e853ac03373f09d9109",
            "d574268376eddb281b0dd1a5fda3f073d1b7b070a90387727e7433d87ec80d6d",
            "38aca581ad6a6a202fa89ac49f89650fac018b7f1d724a72040fea497ed95b84",
            "04a6e334bb434dcf340fa2a8267ed828b23632de1f346b8acd7a5b8e83b9bc3f"
            "58bbfabfc27dad4cbc30230de97bada0568c73f1ee877a885f5a3754bfc2287c84",
            "e9e68de251a00dcf0d91ca20883153bb69b912df0ba9c20938407c787f44ea67",
            "38aca581ad6a6a202fa89ac49f89650fac018b7f1d724a72040fea497ed95b84",
            "04a6e334bb434dcf340fa2a8267ed828b23632de1f346b8acd7a5b8e83b9bc3f"
            "58bbfabfc27dad4cbc30230de97bada0568c73f1ee877a885f5a3754bfc2287c84",
            "9b61edd3a878a5c4386bd6c42c4f2334a1ad4029e62b4cd24b16b3db41f4cb0f",
            "f18103a860ae1eee5147aec66c2111ccc937529f9e0ba499038471326daa205e",
            "a1172b6040d1f7da83916d94",
            "89125c238053ad3cefb2a0acdb8da1ce89785dba613a0ca83ed78035c51f3667"
        },
        {
            "744f6bf36c108984aab7c03eea5feb427c03f4f3ecc4dca500f70c3a467c5cdd",
            "3748d1306a790e7f3776fbd17ebaae45c849de2b0f9122cfe9d85779a7923c3f",
            "04be4687eb1e76e957285a08e4599cf31b4649e99b0b069bbb6f36572a6b366f"
            "1b835a507ee14d8a6580e25a2e4ae8d7d8f4df9243e801b888953f324b93686527",
            "d11ebff931558abd86811790816a9163fe2bdb6f3c07e8157510e2bf73d7c3de",
            "d61a862e6371a00a44b39f96cb754a14f53784c6458ee19f9a3613050a855613",
            "04bf9683977dc086e89d461f7b34134e5889fbc872faa34121f5c16f304f5532"
            "506c32882f37c2f7b0391daf6e2343191bc0ac639ff2d87fbedd0c9d71ef533ffa",
            "ea62965347a6e7dac5787b43623383a8e722f925bb81c88a58508433859847e8",
            "d61a862e6371a00a44b39f96cb754a14f53784c6458ee19f9a3613050a855613",
            "04bf9683977dc086e89d461f7b34134e5889fbc872faa34121f5c16f304f5532"
            "506c32882f37c2f7b0391daf6e2343191bc0ac639ff2d87fbedd0c9d71ef533ffa",
            "3d648a64012a0dff200489823e2bb9f6b84adedc651f276d2fba82ff45ac12b",
            "8219ab2ae96460b3de411fd8bb4e68a9cef0c307be1e4564cd8267fb98d204d3",
            "7b5ae3238d6fabb7ff4b8525",
            "a93e33fbd26a6fafd97e195432c553d8a08b08993e62d7442e1d44b89acc17cd"
        },
        {
            "682d4606d4d401bce174fd98c88e6a395f79b903216eb8b2a38b7b2081f6709b",
            "2f53e5ac16cbf332beefd34482c332fa41dc675b2caa616c8dc7e30ecfa4abea",
            "042624b24f16ad4366b316501472150f58e9d35e9c5e14781a5b7f79b69a7837"
            "4599c681b0629c35fcecd761424cf234deb2565173dbb3fadb8ad480f4cdbe5b6b",
            "c92d590379d06dfe53f19c4785248a21efda81f3e2b39acd30dc088e110b86f9",
            "647400c833f994714a1dea157305117729a832bb81a44748437e59ac2376c027",
            "044f69b9a4293a1c85504b724b33dcb690890c47d466ce49337942ad4551cc1b"
            "5c718f2752f8e1beb1de18486caa36eb35cb33b2f462c03a7fad719d39fe65101e",
            "d4954c6a2ffdd1e7e8a87798abeb92b7133b0813df1fe32d3a04eb048d9e3068",
            "647400c833f994714a1dea157305117729a832bb81a44748437e59ac2376c027",
            "044f69b9a4293a1c85504b724b33dcb690890c47d466ce49337942ad4551cc1b"
            "5c718f2752f8e1beb1de18486caa36eb35cb33b2f462c03a7fad719d39fe65101e",
            "1a114e3937dc06ca7244dd98ca0a6bf8a5f2670158bab5c5a4f1b405a1070923",
            "f05d8f2758709dc289c1b927f7962a57ba1f8c357e3ae39f091db11a0661a3ef",
            "819ca6581c15755e5253500f",
            "1468983239658659d90f6e257769b5fd561d68f8096496400fb6db635108a210"
        }
    };

    // Helper lambdas for computing HPKE key schedule (for verification)
    auto LabeledExtract = [&](const std::vector<unsigned char>& salt, const std::string& label, const std::vector<unsigned char>& ikm) {
        // salt may be empty = no salt
        uint8_t prk[32];
        // Build labeled IKM = "HPKE-v1" || suite_id || label || ikm
        std::vector<unsigned char> labeled;
        labeled.insert(labeled.end(), std::begin((LABEL_PREFIX)), std::end((LABEL_PREFIX)));
        labeled.insert(labeled.end(), std::begin((SUITE_ID)), std::end((SUITE_ID)));
        labeled.insert(labeled.end(), label.begin(), label.end());
        labeled.insert(labeled.end(), ikm.begin(), ikm.end());
        HKDF_Extract(salt.empty()? nullptr: salt.data(), salt.size(), labeled.data(), labeled.size(), prk);
        return std::array<unsigned char,32> { 
            prk[0], prk[1], prk[2], prk[3], prk[4], prk[5], prk[6], prk[7],
            prk[8], prk[9], prk[10], prk[11], prk[12], prk[13], prk[14], prk[15],
            prk[16], prk[17], prk[18], prk[19], prk[20], prk[21], prk[22], prk[23],
            prk[24], prk[25], prk[26], prk[27], prk[28], prk[29], prk[30], prk[31]
        };
    };

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
        std::vector<unsigned char> info = ParseHex(base_vecs[i].ikmE);
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
        uint8_t skEm[32], pkEm[65];
        bool ok = DeriveKeyPair(ikmE.data(), ikmE.size(), skEm, pkEm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skEm), HexStr(exp_skEm));
        BOOST_CHECK_EQUAL(HexStr(pkEm), HexStr(exp_pkEm));
        uint8_t skRm[32], pkRm[65];
        ok = DeriveKeyPair(ikmR.data(), ikmR.size(), skRm, pkRm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skRm), HexStr(exp_skRm));
        BOOST_CHECK_EQUAL(HexStr(pkRm), HexStr(exp_pkRm));

        // Test decapsulation: should reproduce shared_secret
        uint8_t shared[32];
        ok = Decap(pkEm, skRm, shared);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(shared), HexStr(exp_shared));

        // Derive HPKE context key, base_nonce, exporter_secret using key schedule (mode 0x00):contentReference[oaicite:33]{index=33}
        uint8_t mode_base = 0x00;
        // default psk_id = default_psk = "" in Base mode
        auto psk_id_hash = LabeledExtract({}, "psk_id_hash", std::vector<unsigned char>());  // empty ikm
        auto info_hash = LabeledExtract({}, "info_hash", info);
        // key_schedule_context = mode || psk_id_hash || info_hash
        std::vector<unsigned char> context;
        context.push_back(mode_base);
        context.insert(context.end(), psk_id_hash.begin(), psk_id_hash.end());
        context.insert(context.end(), info_hash.begin(), info_hash.end());
        // secret = LabeledExtract(shared_secret, "secret", psk="")
        std::vector<unsigned char> psk; // empty
        std::vector<unsigned char> ss_vec(shared, shared + 32);
        auto secret = LabeledExtract(ss_vec, "secret", psk);
        // Derive key, base_nonce, exporter_secret
        std::vector<unsigned char> got_key   = LabeledExpand(secret, "key", context, exp_key.size());
        std::vector<unsigned char> got_nonce = LabeledExpand(secret, "base_nonce", context, exp_nonce.size());
        std::vector<unsigned char> got_exporter = LabeledExpand(secret, "exp", context, exp_exporter.size());
        BOOST_CHECK_EQUAL(HexStr(got_key), HexStr(exp_key));
        BOOST_CHECK_EQUAL(HexStr(got_nonce), HexStr(exp_nonce));
        BOOST_CHECK_EQUAL(HexStr(got_exporter), HexStr(exp_exporter));
    }

    // Process each Auth mode test vector
    for (size_t i = 0; i < auth_vecs.size(); ++i) {
        // No separate "info" field provided in Auth vectors (assume default info = "" for these tests)
        std::vector<unsigned char> ikmE = ParseHex(auth_vecs[i].ikmE);
        std::vector<unsigned char> ikmR = ParseHex(auth_vecs[i].ikmR);
        std::vector<unsigned char> ikmS = ParseHex(auth_vecs[i].ikmS);
        std::vector<unsigned char> exp_skEm = ParseHex(auth_vecs[i].skEm);
        std::vector<unsigned char> exp_pkEm = ParseHex(auth_vecs[i].pkEm);
        std::vector<unsigned char> exp_skRm = ParseHex(auth_vecs[i].skRm);
        std::vector<unsigned char> exp_pkRm = ParseHex(auth_vecs[i].pkRm);
        std::vector<unsigned char> exp_skSm = ParseHex(auth_vecs[i].skSm);
        std::vector<unsigned char> exp_pkSm = ParseHex(auth_vecs[i].pkSm);
        std::vector<unsigned char> exp_shared = ParseHex(auth_vecs[i].shared_secret);
        std::vector<unsigned char> exp_key = ParseHex(auth_vecs[i].key);
        std::vector<unsigned char> exp_nonce = ParseHex(auth_vecs[i].base_nonce);
        std::vector<unsigned char> exp_exporter = ParseHex(auth_vecs[i].exporter_secret);

        // Derive ephemeral, receiver static, sender static keys
        uint8_t skEm[32], pkEm[65];
        bool ok = DeriveKeyPair(ikmE.data(), ikmE.size(), skEm, pkEm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skEm), HexStr(exp_skEm));
        BOOST_CHECK_EQUAL(HexStr(pkEm), HexStr(exp_pkEm));
        uint8_t skRm[32], pkRm[65];
        ok = DeriveKeyPair(ikmR.data(), ikmR.size(), skRm, pkRm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skRm), HexStr(exp_skRm));
        BOOST_CHECK_EQUAL(HexStr(pkRm), HexStr(exp_pkRm));
        uint8_t skSm[32], pkSm[65];
        ok = DeriveKeyPair(ikmS.data(), ikmS.size(), skSm, pkSm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skSm), HexStr(exp_skSm));
        BOOST_CHECK_EQUAL(HexStr(pkSm), HexStr(exp_pkSm));

        // Decapsulate (AuthDecap) and check shared_secret
        uint8_t shared[32];
        ok = AuthDecap(pkEm, skRm, pkSm, shared);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(shared), HexStr(exp_shared));

        // Compute HPKE key schedule for Auth mode (mode = 0x02):contentReference[oaicite:34]{index=34}
        uint8_t mode_auth = 0x02;
        std::vector<unsigned char> info; // default empty info
        // In Auth mode, no PSK (psk_id_hash and info_hash as in Base)
        auto psk_id_hash = LabeledExtract({}, "psk_id_hash", std::vector<unsigned char>());
        auto info_hash = LabeledExtract({}, "info_hash", info);
        // key_schedule_context = mode_auth || psk_id_hash || info_hash || pkS (only included in context for AuthPSK, but for Auth mode, see RFC9180)
        // Actually, in HPKE Auth mode (mode=2), the sender's public key is not directly appended in key_schedule_context (it is included via KEM context).
        // So key_schedule_context formula for mode_auth is same as base except mode byte = 2.
        std::vector<unsigned char> context;
        context.push_back(mode_auth);
        context.insert(context.end(), psk_id_hash.begin(), psk_id_hash.end());
        context.insert(context.end(), info_hash.begin(), info_hash.end());
        // secret = LabeledExtract(shared_secret, "secret", psk="")
        std::vector<unsigned char> ss_vec(shared, shared + 32);
        auto secret = LabeledExtract(ss_vec, "secret", std::vector<unsigned char>());
        // Derive key, base_nonce, exporter_secret
        std::vector<unsigned char> got_key   = LabeledExpand(secret, "key", context, exp_key.size());
        std::vector<unsigned char> got_nonce = LabeledExpand(secret, "base_nonce", context, exp_nonce.size());
        std::vector<unsigned char> got_exporter = LabeledExpand(secret, "exp", context, exp_exporter.size());
        BOOST_CHECK_EQUAL(HexStr(got_key), HexStr(exp_key));
        BOOST_CHECK_EQUAL(HexStr(got_nonce), HexStr(exp_nonce));
        BOOST_CHECK_EQUAL(HexStr(got_exporter), HexStr(exp_exporter));
    } */

    std::vector<unsigned char> ikmE = ParseHex("77caf1617fb3723972a56cd2085081c9f66baae825ce5f363c0a86ec87013fa0");

    unsigned char out_sk[32];
    memset(out_sk, 0, 32);

    unsigned char out_pk[32];
    memset(out_pk, 0, 32);

    bool ret = DeriveKeyPair2(ikmE.data(), ikmE.size(), out_sk, out_pk);
    BOOST_CHECK(ret);

}

BOOST_AUTO_TEST_SUITE_END()
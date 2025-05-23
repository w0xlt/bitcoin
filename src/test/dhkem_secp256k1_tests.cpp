#include <boost/test/unit_test.hpp>
#include <dhkem_secp256k1.h>
#include <util/strencodings.h>
#include <key.h>  // for ECC context management
#include <vector>
#include <test/util/setup_common.h>

using namespace dhkem_secp256k1;

BOOST_FIXTURE_TEST_SUITE(dhkem_secp256k1_tests, BasicTestingSetup)

struct VectorBase {
        uint8_t mode_base;
        std::string info;
        std::string ikmE, skEm, pkEm;
        std::string ikmR, skRm, pkRm;
        std::string psk, psk_id;
        std::string shared_secret;
        std::string key, base_nonce, exporter_secret;
    };
    struct VectorAuth {
        uint8_t mode_base;
        std::string info;
        std::string ikmE, skEm, pkEm;
        std::string ikmR, skRm, pkRm;
        std::string ikmS, skSm, pkSm;
        std::string psk, psk_id;
        std::string shared_secret;
        std::string key, base_nonce, exporter_secret;
    };

BOOST_AUTO_TEST_CASE(dhkem_secp256k1_chacha20poly1305_testvectors)
{
    // Test vectors from Appendix B.3.1 (Base mode):contentReference[oaicite:29]{index=29}:contentReference[oaicite:30]{index=30}
    std::vector<VectorBase> base_vecs = {
        {
            /* mode_base */ 0x00,
            /* info */ "609dcb9844f8412343191f93add1177186c03a36",
            /* ikmE */  "77caf1617fb3723972a56cd2085081c9f66baae825ce5f363c0a86ec87013fa0",
            /* skEm */  "1300156862599d00ecbb066644bf4d4505b56a9b235eae7a8632defc4335d5c0",
            /* pkEm */  "0471788be0ccf916302c4f2225bba89a0ff3832df1fe50b48d8ccb910be74e30"
                        "241428ba6de731ccf538ded2913febdfe14b2648fafb8fdd35b8aa91804c706076",
            /* ikmR */  "71b530bed75fc3fa2f8e8bb163203e6ee676565cc61cd59d66352676341c0688",
            /* skRm */  "4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643",
            /* pkRm */  "04e660b55a28899c472ca023dce35f23da3cf16677dbdce9ed25353bd8b70cbb"
                        "8bee0abd2cc8936aee263a08d5b2a15d29a16d12b75fda63b9c614c477af165e2d",
            /* psk */ "",
            /* psk_id */ "",
            /* shared_secret */ "a81a3ccf56f48c699eb9f393e0701692836f9ac2e06b493ccbf99ac68a792bbe",
            /* key */          "4c260fe82e8c3737e7a70c3223cb16fc205682255389ad4bc3e7fae42c46b062",
            /* base_nonce */   "e035bbf3c39ff5a7196cfe84",
            /* exporter_secret */ "83e82aad90186ddd7e1db090c840ee70eb6cac7531b64dc52a12997462c8d0d8"
        },
        {
            /* mode_base */ 0x00,
            "325c816adeee49bea410f0db92947892378f6e0c",
            "597ba1fe9a4db02225bbb3e4cd150ceb68636e84d80e728f1be6b22e8aeefcb0",
            "29e4ff54b558f0a5b3c8f7c016736f6b784ed71d1395bbee07ae4320919465d1",
            "04a3f4964462ee117c47ed7c129ce25c574d1cd97aa2fde60abdb8616be0f5c1"
            "a6fe12c847b07ffca907c8e3f7eb58fe94042b78a90f27318d5421e96af9acab7a",
            "9cabb8ddac5293c96ffcdaa3aa1c797ecba36f9c2d21ce27495f52ea80497a5c",
            "dad1397389c4ff7fa014068bcfbf0c2ea2e24d78b0395fa3de9e88802bc8a684",
            "04be3e5d3dfcc77e81f96f90c5fa3ce7f6f7f7005acaf39a2c3d7d47f1ac1cf1"
            "0bcd06191d07366e706a2ca77e2e0571e11bfc2cbd471904ef0d999af757939da1",
            /* psk */ "",
            /* psk_id */ "",
            "9edafcdb619dabc578d8f7b7b055ac66d5cfb6219b90f69d13d297ed49f3aaf3",
            "6e771cd99a23e82ddbd972ecc1b7d3bcd5d6f961370ac2ff785e6776b47b2d53",
            "208b33e382b39dfc1ebb2c95",
            "ead4fa0d88885cc36792039cbf75110d57eac32e883395eae3ccdeba0a53b3d4"
        },
        {
            /* mode_base */ 0x00,
            "5d274e2436d921573ba466fb5ebef86bd5f77f34",
            "149db0ca6bd0bdabbfca4a61c4a6507efff33eedd844d9e1c299cbaab3a1d006",
            "a342069714f97f18a844495779cf41e82ffa7e98c197ffd1276a8d74823c2519",
            "0460cb3f0f85591f7b804fe91882b442837b9b535ea9c9fbd2d3adda128967d9"
            "374ba8c7da87e8af31a32a326da570bc96044a731e1857246b881051b8d86779ea",
            "2d00ee3b22d16bd33224c2cd32158437bd0e0e3c053307d697b70e55f578f009",
            "1ef5ec4b4482951fca257b0a0709f376f08c30a647cefa10f9b150a6839385ff",
            "04706fd6e62dbf8a440f9f77bc47eb0703177f0f80275ce4be175c9c86953677"
            "9a64806dff22c83ceb9b4a87302415a161b7d30a55521d181a6d01974c0648773e",
            /* psk */ "",
            /* psk_id */ "",
            "fffa60534552d71101540d8022cd1ffe896da801fe55e194b9d71f1ce882b6ff",
            "ebe85898642db23679f83ae4a81efdea5feb4103553b9834cb1f4f602bcef495",
            "ea1e6ce9451d45f9295189c2",
            "92ea7629022c39382b333c1dcdc2dbed9cd2de4fe1d57320125577231aa35203"
        },
        // PDK test vector
        {
            /* mode_base */ 0x00,
            /* info */ "4f6465206f6e2061204772656369616e2055726e",
            /* ikmE */ "ea9f11f8dfb0ca08a8810f9ea39c3a6afb780859e8d8c7bc37b78e2f9b8d68d9",
            /* skEm */ "9558390641d55b914bb5543284ff3c24dcf059cacc3a269f471dace8b13b4f4a",
            /* pkEm */ "0405607e978f274af24b219c1d4866e37213694f1dc050a023cdcf5a7d994b377"
                       "7be96104361fd8ec62602756edbdbd2a36bf10c93011cbe949cfcb634325a7aea",
            /* ikmR */ "a22427226377cc867d51ad3f130af08ad13451de7160efa2b23076fd782de967",
            /* skRm */ "5d516211fd17a8916cbd4ab60cc52104ea8372aac6678220545fbdb542392cb7",
            /* pkRm */ "04fc04c64e4066b7996481f5f5e6e19ff7c6eded59e7fec49602146e4f3c92f6"
                       "c503acfc3ac970c668a48b5137b993319b5851484365ed7f42fdc7b7e3a8283483",
            /* psk */ "",
            /* psk_id */ "",
            /* shared_secret */ "64ba1219520c5d1b0450bf71a222b512e70dff05b6539292b5c402ff8e64f707",
            /* key */          "733fb0e7ce630c1712b629ddefb208fcc6572f6bcae5f15d93fc2984b4f325e5",
            /* base_nonce */   "7028e56372041618809a2566",
            /* exporter_secret */ "58732d8b645ec857be9847995103155b6c6276dda44c1e40b68f1463c03aabb7"
        },
        {
            /* mode_base */ 0x01,
            /* info */ "4f6465206f6e2061204772656369616e2055726e",

            /* ikmE */  "ca2f07a37c4b3903f3d30e29217ced84e4565a767abcde0c1f5583a9c9c77da5",
            /* skEm */  "89938ff5f0ae9151137de9d897e1cdb777fb4ea79cc0478fd4a15983003a2f3e",
            /* pkEm */  "0488478b83a7190b1ef0c00d7fa55089b79fbd58b51319895d872633bbd3418d1"
                        "f7fe30a6370bcf091a24bf1dcb734b91739534974df55a0839a27fe7052408491",

            /* ikmR */  "52f6d2dd43970164da3fc7b517b61024fcad5acd80e4e585902180d1eb16fd37",
            /* skRm */  "ae100b7f8a2a8c4b86d5f5d93470e147356ba135159ed0953fb4369c7eb998fb",
            /* pkRm */  "0432799cc0c65413358871f9b934499a0a444e6bc74dae9bf02b76d8d194cb3d"
                        "f7df7abecd7ac259d085e19f9870aee3fd1d9bc150b1ac0a507b3c05b4d8bebbc8",

            /* psk */ "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
            /* psk_id */ "456e6e796e20447572696e206172616e204d6f726961",

            /* shared_secret */ "fd01659e153a8df062db1ecaf9441a325eebe074c3d459aa2385641eda410657",
            /* key */          "ad68a1a1c02abf953c4c05ec0991b9267759af5b5a31ef1c5577fcef7d497074",
            /* base_nonce */   "96b92e10133d4c4342f99795",
            /* exporter_secret */ "8d2b23f021dfc021238609db86f5cf474c328386b475fdfbccc7948b3c63099e"
        },
    };

    std::vector<VectorAuth> auth_vecs = {
        {
            /* mode_base */ 0x02,
            /* info */ "4f6465206f6e2061204772656369616e2055726e",

            /* ikmE */  "f233ea84cdafd666d3ab072afee793a7e1468addb4648a6cec2e103200bd73e3",
            /* skEm */  "7e8c57054c078ec56372f5f455fba27f28941b66b02d55e0cf3cc0b9126157a4",
            /* pkEm */  "048059e7899fe0030119b69e7f9980e89ae068a2113f54dedd6b1b28c94d5c422"
                        "cdfda7716caad1b1c1bf3358dcfb1d94e31086840217825afc5d84b8bbc6c0c8e",

            /* ikmR */  "50cbce1763d8db5952384e4d1f429372d590cf23b4ce5ccbc44f249531de1a34",
            /* skRm */  "032527c68d81c0ce10727887a9e7f1752390e702ac9458f78ae5c0c7590f3b1c",
            /* pkRm */  "048ea2360c4ce337676835cc1110015ab2f3b888be2fdbd7296fff7ff4cd1d1d5"
                        "6fc16fb4addf026d5cee86bcb7e08c0a758c2fd9df3d26e4251561e04114c788a",

            /* ikmS */ "a9b766eeb01906ec0f0e106c69a98aded35b46a5b0c11da633a108cfe7868438",
            /* skSm */ "f2c020acf9e7372651b44562d6023ebf8f7bf8ffdb96cfa6076e6d68e2e919f6",
            /* pkSm */ "047952f02dc306715c007b1db525bbb18b2da71ab17727ed0f0f839d442c154c2"
                       "1499c385d5a08d2b26b3819d9d02ee678a7cd62c0a0d5ad825774945ff02ce7d3",

            /* psk */ "",
            /* psk_id */ "",

            /* shared_secret */ "c2a1e848a810e546725aae2b73b58f16c2920c6dd91ea87c56665c729f09fc9f",
            /* key */          "3ebf6debe59ba9b8ee324e5546517c811726b451f2855236a0697097fed07906",
            /* base_nonce */   "37d71b78ec28854c1d10f772",
            /* exporter_secret */ "4c5e54ba51ba00f5a69f2d9845bc992559e04b323dfc4425249c2a95df8e796f"
        },
        {
            /* mode_base */ 0x03,
            /* info */ "4f6465206f6e2061204772656369616e2055726e",

            /* ikmE */  "b7551f09c36295fc134841cb61597e9b9539a2e24216df735160553fe24a3a07",
            /* skEm */  "90f7591b4513f060acd0dbfb9cb8e90bba707e8a816ec9d6590476c9c27391ea",
            /* pkEm */  "04b731c0e4c863ddbf1f76ff519f639932bcb381d6367b6f556b8438a6d1b526"
                        "5a48263f1cf2e464ec368890a5babe843dc6a8d3bfab7f85dd0bcaa82a718b443d",

            /* ikmR */  "b61cab5a4a7bb893cf857860f20ade63672c7b992b6415115470d318fb93a26d",
            /* skRm */  "9b52cb6f815f9773d12f8321768deffd2d00c98371284efc8ac5a502d1839a5b",
            /* pkRm */  "043bd66624a9bb183a67685073a8d92a02add7ddd25a4d90a468616fed1062f1"
                        "9d7ca7417303eb7b3313db25a9f527d2391cb37018dc3ea4fe8c154be43e38d992",

            /* ikmS */ "352238e0397b79275da4b243ea3873628bba3301d637cd7ddc93d9cfac05fcf7",
            /* skSm */ "4a3ee85fa43d22c61e6d9b690f8cf3037fd0824454ea1f9dce28648084da2a56",
            /* pkSm */ "0430bc57878dc0b5ec7a0425adc3e6f89d2aa3e3713765eadbdd40dd524c1d126"
                       "155cea6c98a50364f1ca33ea6ded16572c4ae48edbb0d46fa348fa53f7a23a70e",

            /* psk */ "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
            /* psk_id */ "456e6e796e20447572696e206172616e204d6f726961",

            /* shared_secret */ "428446620a5fe475e23a36b6b977a658fd4530bd1572b78c1bce1c1e270083fe",
            /* key */          "50fcc3452a70efd3b8b19ce83a81fe8dc310853abe6dc19df909993e8d4370c5",
            /* base_nonce */   "9fd1def36fa6a402b1d05774",
            /* exporter_secret */ "25236189efcf44b566e8193bc6c790a1e3276bc933d3317735bcbb75af1d6a03"
        }

    };

    dhkem_secp256k1::InitContext();

    // Process each Base mode test vector
    for (size_t i = 0; i < base_vecs.size(); ++i) {
        uint8_t mode_base = base_vecs[i].mode_base;
        std::string info_hex = base_vecs[i].ikmE; // Actually the 'info' is stored separately above for each case
        // The "info" hex is given in the base_vecs as the first string (we placed the info hex in ikmE field for convenience)
        std::vector<unsigned char> info = ParseHex(base_vecs[i].info);
        std::vector<unsigned char> ikmE = ParseHex(base_vecs[i].ikmE);
        std::vector<unsigned char> ikmR = ParseHex(base_vecs[i].ikmR);
        std::vector<unsigned char> exp_skEm = ParseHex(base_vecs[i].skEm);
        std::vector<unsigned char> exp_pkEm = ParseHex(base_vecs[i].pkEm);
        std::vector<unsigned char> exp_skRm = ParseHex(base_vecs[i].skRm);
        std::vector<unsigned char> exp_pkRm = ParseHex(base_vecs[i].pkRm);
        std::vector<unsigned char> psk = ParseHex(base_vecs[i].psk);
        std::vector<unsigned char> psk_id = ParseHex(base_vecs[i].psk_id);
        std::vector<unsigned char> exp_shared = ParseHex(base_vecs[i].shared_secret);
        std::vector<unsigned char> exp_key = ParseHex(base_vecs[i].key);
        std::vector<unsigned char> exp_nonce = ParseHex(base_vecs[i].base_nonce);
        std::vector<unsigned char> exp_exporter = ParseHex(base_vecs[i].exporter_secret);

        // DeriveKeyPair for ephemeral (sender) and static (receiver)
        // uint8_t skEm[32], pkEm[65];
        std::array<uint8_t, 32> skEm;
        std::array<uint8_t, 65> pkEm;

        // bool ok = DeriveKeyPair(ikmE.data(), ikmE.size(), skEm, pkEm);
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

        std::optional<std::array<uint8_t, 32>> maybe_shared_secret_dec = dhkem_secp256k1::Decap(pkEm2, skRm2);
        BOOST_CHECK(maybe_shared_secret_dec.has_value());
        BOOST_CHECK_EQUAL(HexStr(*maybe_shared_secret_dec), HexStr(exp_shared));

        std::vector<unsigned char> ss_vec;
        ss_vec.assign(maybe_shared_secret_dec->begin(), maybe_shared_secret_dec->end());

        // Derive HPKE context key, base_nonce, exporter_secret using key schedule (mode 0x00):contentReference[oaicite:33]{index=33}
        // default psk_id = default_psk = "" in Base mode
        std::vector<uint8_t> label_psk_id_hash = {'p', 's', 'k', '_', 'i', 'd', '_', 'h', 'a', 's', 'h'};
        // auto psk_id_hash = LabeledExtract({}, label_psk_id_hash, std::vector<unsigned char>());psk_id
        auto psk_id_hash = LabeledExtract({}, label_psk_id_hash, psk_id);

        std::vector<uint8_t> label_info_hash = {'i', 'n', 'f', 'o', '_', 'h', 'a', 's', 'h'};
        auto info_hash = LabeledExtract({}, label_info_hash, info);

        // key_schedule_context = mode || psk_id_hash || info_hash
        std::vector<unsigned char> context;
        context.push_back(mode_base);
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
    }

    // Process each Auth mode test vector
    for (size_t i = 0; i < auth_vecs.size(); ++i) {
        // 1. Parse all hex inputs from the test vector
        uint8_t mode_base = auth_vecs[i].mode_base;
        std::vector<unsigned char> info      = ParseHex(auth_vecs[i].info);
        std::vector<unsigned char> ikmE      = ParseHex(auth_vecs[i].ikmE);
        std::vector<unsigned char> ikmR      = ParseHex(auth_vecs[i].ikmR);
        std::vector<unsigned char> ikmS      = ParseHex(auth_vecs[i].ikmS);

        std::vector<unsigned char> psk       = ParseHex(auth_vecs[i].psk);
        std::vector<unsigned char> psk_id    = ParseHex(auth_vecs[i].psk_id);

        std::vector<unsigned char> exp_skEm  = ParseHex(auth_vecs[i].skEm);
        std::vector<unsigned char> exp_pkEm  = ParseHex(auth_vecs[i].pkEm);

        std::vector<unsigned char> exp_skRm  = ParseHex(auth_vecs[i].skRm);
        std::vector<unsigned char> exp_pkRm  = ParseHex(auth_vecs[i].pkRm);

        std::vector<unsigned char> exp_skSm  = ParseHex(auth_vecs[i].skSm);
        std::vector<unsigned char> exp_pkSm  = ParseHex(auth_vecs[i].pkSm);

        std::vector<unsigned char> exp_shared= ParseHex(auth_vecs[i].shared_secret);
        std::vector<unsigned char> exp_key   = ParseHex(auth_vecs[i].key);
        std::vector<unsigned char> exp_nonce = ParseHex(auth_vecs[i].base_nonce);
        std::vector<unsigned char> exp_exporter = ParseHex(auth_vecs[i].exporter_secret);

        // 2. Derive ephemeral, receiver, and sender key pairs from ikm inputs and compare with expected sk/pk values
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

        std::array<uint8_t, 32> skSm;
        std::array<uint8_t, 65> pkSm;
        ok = dhkem_secp256k1::DeriveKeyPair(std::span<const uint8_t>(ikmS.data(), ikmS.size()), skSm, pkSm);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(HexStr(skSm), HexStr(exp_skSm));
        BOOST_CHECK_EQUAL(HexStr(pkSm), HexStr(exp_pkSm));

        // 3. Use dhkem_secp256k1::AuthEncap with pkR and skS to produce enc and shared_secret
        std::array<uint8_t, 65> enc;
        std::array<uint8_t, 32> shared_secret_enc;
        std::array<uint8_t, 32> shared_secret_dec;
        BOOST_CHECK(dhkem_secp256k1::AuthEncap(enc, shared_secret_enc, pkRm, skSm));

        // 4. Use dhkem_secp256k1::AuthDecap with enc, skR, pkS to decapsulate and get shared_secret
        BOOST_CHECK(dhkem_secp256k1::AuthDecap(shared_secret_dec, enc, skRm, pkSm));
        BOOST_CHECK_EQUAL(HexStr(shared_secret_enc), HexStr(shared_secret_dec));

        // 5. Derive psk_id_hash and info_hash via LabeledExtract
        // (using empty salt as per HPKE spec)
        std::vector<uint8_t> label_psk_id_hash = {'p','s','k','_','i','d','_','h','a','s','h'};
        auto psk_id_hash = LabeledExtract({}, label_psk_id_hash, psk_id);
        std::vector<uint8_t> label_info_hash = {'i','n','f','o','_','h','a','s','h'};
        auto info_hash = LabeledExtract({}, label_info_hash, info);

        // 6. Construct key schedule context as: mode || psk_id_hash || info_hash
        std::vector<unsigned char> context;
        context.push_back(mode_base);
        context.insert(context.end(), psk_id_hash.begin(), psk_id_hash.end());
        context.insert(context.end(), info_hash.begin(), info_hash.end());

        // 7. Extract secret from shared_secret and psk using label "secret"
        // Use the test vector's shared_secret (decapsulated using expected enc)
        std::array<uint8_t, 32> shared_secret_test;
        BOOST_CHECK(dhkem_secp256k1::AuthDecap(shared_secret_test, pkEm, skRm, pkSm));
        BOOST_CHECK_EQUAL(HexStr(shared_secret_test), HexStr(exp_shared));
        std::vector<unsigned char> ss_vec;
        ss_vec.assign(shared_secret_test.begin(), shared_secret_test.end());
        std::vector<uint8_t> label_secret = {'s','e','c','r','e','t'};
        auto secret = LabeledExtract(ss_vec, label_secret, psk);

        // 8. Expand the secret into key, base_nonce, and exporter_secret using labels "key", "base_nonce", and "exp"
        std::vector<uint8_t> label_key = {'k','e','y'};
        std::vector<unsigned char> got_key = dhkem_secp256k1::LabeledExpand(secret, label_key, context, 32);
        std::vector<uint8_t> label_base_nonce = {'b','a','s','e','_','n','o','n','c','e'};
        std::vector<unsigned char> got_nonce = dhkem_secp256k1::LabeledExpand(secret, label_base_nonce, context, 12);
        std::vector<uint8_t> label_exp = {'e','x','p'};
        std::vector<unsigned char> got_exporter = dhkem_secp256k1::LabeledExpand(secret, label_exp, context, exp_exporter.size());

        // Compare all outputs with expected test vector values
        BOOST_CHECK_EQUAL(HexStr(got_key), HexStr(exp_key));
        BOOST_CHECK_EQUAL(HexStr(got_nonce), HexStr(exp_nonce));
        BOOST_CHECK_EQUAL(HexStr(got_exporter), HexStr(exp_exporter));
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
    auto maybe_result = dhkem_secp256k1::Encap(pkR_bytes);
    assert(maybe_result.has_value()); // Encap should succeed

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

    // 2. Convert CPubKey to std::array<uint8_t, 65> for use with AuthEncap/AuthDecap
    std::array<uint8_t, 65> pkR_array;
    std::copy(pkR.begin(), pkR.end(), pkR_array.begin());

    std::array<uint8_t, 65> pkS_array;
    std::copy(pkS.begin(), pkS.end(), pkS_array.begin());

    // 3. Convert CKey to std::array<uint8_t, 32> for use with AuthEncap/AuthDecap
    std::span<const uint8_t> skS_span(reinterpret_cast<const uint8_t*>(skS.data()), skS.size());
    std::array<uint8_t, 32> skS_array;
    std::copy(skS_span.begin(), skS_span.end(), skS_array.begin());

    std::span<const uint8_t> skR_span(reinterpret_cast<const uint8_t*>(skR.data()), skR.size());
    std::array<uint8_t, 32> skR_array;
    std::copy(skR_span.begin(), skR_span.end(), skR_array.begin());

    // 4. Prepare output containers for shared secrets and encapsulated key
    std::array<uint8_t, 65> enc{0};
    std::array<uint8_t, 32> shared_secret_enc{0};
    std::array<uint8_t, 32> shared_secret_dec{0};

    // 4. Perform authenticated encapsulation (sender side)
    BOOST_CHECK(dhkem_secp256k1::AuthEncap(enc, shared_secret_enc, pkR_array, skS_array));

    // 5. Perform authenticated decapsulation (recipient side)
    BOOST_CHECK(dhkem_secp256k1::AuthDecap(shared_secret_dec, enc, skR_array, pkS_array));

    BOOST_CHECK_EQUAL(HexStr(shared_secret_enc), HexStr(shared_secret_dec));
}


BOOST_AUTO_TEST_SUITE_END()
// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/codex32.h>

#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(codex32_tests, BasicTestingSetup)

static std::string ConvertToClVariant(const Codex32& parts)
{
    std::string error;
    const std::string result = Codex32SecretEncode("cl", std::string(parts.id.data()), parts.threshold, parts.payload, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(!result.empty());
    return result;
}

BOOST_AUTO_TEST_CASE(codex32_encode_basic)
{
    const std::vector<uint8_t> seed = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };

    std::string error;
    const std::string encoded = Codex32SecretEncode("ms", "leet", 0, seed, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(encoded, "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma");
}

BOOST_AUTO_TEST_CASE(codex32_encode_invalid_inputs)
{
    const std::vector<uint8_t> seed{0x00};
    std::string error;

    BOOST_CHECK(Codex32SecretEncode("ms", "leet", 1, seed, error).empty());
    BOOST_CHECK_EQUAL(error, "Invalid threshold 1");

    error.clear();
    BOOST_CHECK(Codex32SecretEncode("ms", "leet", 10, seed, error).empty());
    BOOST_CHECK_EQUAL(error, "Invalid threshold 10");

    error.clear();
    BOOST_CHECK(Codex32SecretEncode("ms", "bad", 0, seed, error).empty());
    BOOST_CHECK_EQUAL(error, "Invalid id: must be 4 characters");

    error.clear();
    BOOST_CHECK(Codex32SecretEncode("ms", "abcd", 0, seed, error).empty());
    BOOST_CHECK_EQUAL(error, "Invalid id: must be valid bech32 string");

    error.clear();
    BOOST_CHECK(Codex32SecretEncode("ms", "Leet", 0, seed, error).empty());
    BOOST_CHECK_EQUAL(error, "Invalid id: must be lower-case");
}

BOOST_AUTO_TEST_CASE(codex32_test_vector_1)
{
    std::string error;
    const auto parts = Codex32Decode("", "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw", error);

    BOOST_REQUIRE(parts.has_value());
    BOOST_CHECK_EQUAL(parts->hrp, "ms");
    BOOST_CHECK_EQUAL(parts->threshold, 0);
    BOOST_CHECK_EQUAL(std::string(parts->id.data()), "test");
    BOOST_CHECK_EQUAL(parts->share_idx, 's');
    BOOST_CHECK_EQUAL(HexStr(parts->payload), "318c6318c6318c6318c6318c6318c631");

    const std::string cl_variant = ConvertToClVariant(*parts);
    BOOST_CHECK(!cl_variant.empty());
}

BOOST_AUTO_TEST_CASE(codex32_test_vector_2)
{
    std::string error;
    const auto parts = Codex32Decode("ms", "MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW", error);

    BOOST_REQUIRE(parts.has_value());
    BOOST_CHECK_EQUAL(HexStr(parts->payload), "d1808e096b35b209ca12132b264662a5");

    const std::string cl_variant = ConvertToClVariant(*parts);
    BOOST_CHECK(!cl_variant.empty());
}

BOOST_AUTO_TEST_CASE(codex32_test_vector_3)
{
    const std::vector<std::string> addresses = {
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln",
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r",
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qzfatvdwq5692k6",
        "ms13cashsllhdmn9m42vcsamx24zrxgs3qrsx6ydhed97jx2",
    };

    for (const auto& address : addresses) {
        std::string error;
        const auto parts = Codex32Decode("", address, error);

        BOOST_REQUIRE(parts.has_value());
        BOOST_CHECK_EQUAL(HexStr(parts->payload), "ffeeddccbbaa99887766554433221100");

        const std::string cl_variant = ConvertToClVariant(*parts);
        BOOST_CHECK(!cl_variant.empty());
    }
}

BOOST_AUTO_TEST_CASE(codex32_test_vector_4)
{
    const std::vector<std::string> addresses = {
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqpj82dp34u6lqtd",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqzsrs4pnh7jmpj5",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqrfcpap2w8dqezy",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqy5tdvphn6znrf0",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq9dsuypw2ragmel",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqx05xupvgp4v6qx",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq8k0h5p43c2hzsk",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqgum7hplmjtr8ks",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqf9q0lpxzt5clxq",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq28y48pyqfuu7le",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqt7ly0paesr8x0f",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqvrvg7pqydv5uyz",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqd6hekpea5n0y5j",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqwcnrwpmlkmt9dt",
        "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq0pgjxpzx0ysaam",
    };

    for (const auto& address : addresses) {
        std::string error;
        const auto parts = Codex32Decode("", address, error);

        BOOST_REQUIRE(parts.has_value());
        BOOST_CHECK_EQUAL(HexStr(parts->payload), "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");

        const std::string cl_variant = ConvertToClVariant(*parts);
        BOOST_CHECK(!cl_variant.empty());
    }
}

BOOST_AUTO_TEST_CASE(codex32_test_vector_5)
{
    const std::string long_codex = "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK";

    std::string error;
    const auto parts = Codex32Decode("", long_codex, error);

    BOOST_REQUIRE(parts.has_value());
    BOOST_CHECK_EQUAL(HexStr(parts->payload), "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9");

    const std::string cl_variant = ConvertToClVariant(*parts);
    BOOST_CHECK(!cl_variant.empty());
}

BOOST_AUTO_TEST_CASE(codex32_invalid_checksum)
{
    const std::vector<std::string> addresses = {
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghq",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghp",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxlk3yepcstwr",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx6pgnv7jnpcsp",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxx0cpvr7n4geq",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxm5252y7d3lr",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxrd9sukzl05ej",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxc55srw5jrm0",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxgc7rwhtudwc",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx4gy22afwghvs",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxe8yfm0",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvm597d",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pe0",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pew",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxqyadsp3nywm8a",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxzvg7ar4hgaejk",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcznau0advgxqe",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxch3jrc6j5040j",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx52gxl6ppv40mcv",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7g4g2nhhle8fk",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx63m45uj8ss4x8",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxy4r708q7kg65x",
    };

    for (const auto& address : addresses) {
        std::string error;
        const auto parts = Codex32Decode("", address, error);

        BOOST_CHECK(!parts.has_value());
        BOOST_CHECK_EQUAL(error, "Invalid checksum!");
    }
}

BOOST_AUTO_TEST_CASE(codex32_wrong_checksum_for_size)
{
    const std::vector<std::string> addresses = {
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxurfvwmdcmymdufv",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxcsyppjkd8lz4hx3",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxu6hwvl5p0l9xf3c",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxwqey9rfs6smenxa",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxv70wkzrjr4ntqet",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx3hmlrmpa4zl0v",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxrfggf88znkaup",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpt7l4aycv9qzj",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxus27z9xtyxyw3",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcwm4re8fs78vn",
    };

    for (const auto& address : addresses) {
        std::string error;
        const auto parts = Codex32Decode("", address, error);

        BOOST_CHECK(!parts.has_value());
        BOOST_CHECK(error == "Invalid checksum!" || error == "Invalid length!" || error == "Invalid payload!");
    }
}

BOOST_AUTO_TEST_CASE(codex32_improper_lengths)
{
    const std::vector<std::string> addresses = {
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxk4pavy5n46nea",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx9lrwar5zwng4w",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxr335l5tv88js3",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvu7q9nz8p7dj68v",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpq6k542scdxndq3",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxkmfw6jm270mz6ej",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx42cux6um92rz",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxarja5kqukdhy9",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxky0ua3ha84qk8",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9eheesxadh2n2n9",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9llwmgesfulcj2z",
        "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx02ev7caq6n9fgkf",
    };

    for (const auto& address : addresses) {
        std::string error;
        const auto parts = Codex32Decode("", address, error);

        BOOST_CHECK(!parts.has_value());
        BOOST_CHECK(error == "Invalid payload!" || error == "Invalid length!");
    }
}

BOOST_AUTO_TEST_CASE(codex32_invalid_threshold_share_combination)
{
    std::string error;
    const auto parts = Codex32Decode("", "ms10fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx0z26tfn0ulw3p", error);

    BOOST_CHECK(!parts.has_value());
    BOOST_CHECK_EQUAL(error, "Expected share index s for threshold 0!");
}

BOOST_AUTO_TEST_CASE(codex32_invalid_threshold_digit)
{
    std::string error;
    const auto parts = Codex32Decode("", "ms1fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxda3kr3s0s2swg", error);

    BOOST_CHECK(!parts.has_value());
    BOOST_CHECK_EQUAL(error, "Invalid threshold!");
}

BOOST_AUTO_TEST_CASE(codex32_invalid_prefix_separator)
{
    const std::vector<std::string> addresses = {
        "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
        "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
        "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxx8t28z74x8hs4l",
        "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxh9d0fhnvfyx3x",
    };

    for (const auto& address : addresses) {
        std::string error;
        const auto parts = Codex32Decode("ms", address, error);

        BOOST_CHECK(!parts.has_value());
        BOOST_CHECK(error.find("Invalid hrp ") != std::string::npos || error == "Separator doesn't exist!");
    }
}

BOOST_AUTO_TEST_CASE(codex32_mixed_case)
{
    const std::vector<std::string> addresses = {
        "Ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "mS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "MS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10FAUXsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10fauxSxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
        "ms10fauxsXXXXXXXXXXXXXXXXXXXXXXXXXXuqxkk05lyf3x2",
        "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxUQXKK05LYF3X2",
    };

    for (const auto& address : addresses) {
        std::string error;
        const auto parts = Codex32Decode("", address, error);

        BOOST_CHECK(!parts.has_value());
        BOOST_CHECK_EQUAL(error, "Not a valid bech32 string!");
    }
}

BOOST_AUTO_TEST_CASE(codex32_encode_test_specific_seed_1)
{
    const std::vector<uint8_t> seed = ParseHex("659dec01c6c731124084add1fabc04833d3aa6718f7696ba1faebb4fe1a7a8b6");

    std::string error;
    const std::string hrp{"cl"};
    const std::string encoded = Codex32SecretEncode(hrp, "werd", 0, seed, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(encoded, "cl10werdsvkw7cqwxcuc3ysyy4hgl40qysv7n4fn33amfdwsl46a5lcd84zmqr8mmr3gq62atn");

    const auto parts = Codex32Decode(hrp, encoded, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(parts.has_value());
    BOOST_CHECK_EQUAL(parts->hrp, hrp);
    BOOST_CHECK_EQUAL(parts->threshold, 0);
    BOOST_CHECK_EQUAL(std::string(parts->id.data()), "werd");
    BOOST_CHECK_EQUAL(parts->share_idx, 's');
    BOOST_CHECK_EQUAL(HexStr(parts->payload), "659dec01c6c731124084add1fabc04833d3aa6718f7696ba1faebb4fe1a7a8b6");
}

BOOST_AUTO_TEST_CASE(codex32_encode_test_specific_seed_2)
{
    const std::string seed_hex{"e208d110a84650d6ae8b27776eb82ccd7963318d9af777306a496198c13a1d2b"};
    const std::string hrp{"wr"};
    const std::string id{"f2tv"};
    const std::vector<uint8_t> seed = ParseHex(seed_hex);

    std::string error;
    const std::string encoded = Codex32SecretEncode(hrp, id, 0, seed, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(encoded, "wr10f2tvsugydzy9ggegddt5tyamkawpve4ukxvvdntmhwvr2f9se3sf6r54slxj9n4fxe7vmp");

    const auto parts = Codex32Decode(hrp, encoded, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(parts.has_value());
    BOOST_CHECK_EQUAL(parts->hrp, hrp);
    BOOST_CHECK_EQUAL(parts->threshold, 0);
    BOOST_CHECK_EQUAL(std::string(parts->id.data()), id);
    BOOST_CHECK_EQUAL(parts->share_idx, 's');
    BOOST_CHECK_EQUAL(HexStr(parts->payload), seed_hex);
}

BOOST_AUTO_TEST_CASE(codex32_encode_uses_long_checksum_at_47_byte_boundary)
{
    const std::string hrp{"ms"};
    const std::string id{"leet"};
    const std::vector<uint8_t> seed_47 = ParseHex("000102030405060708090a0b0c0d0e0f"
                                                  "101112131415161718191a1b1c1d1e1f"
                                                  "202122232425262728292a2b2c2d2e");
    const std::vector<uint8_t> seed_50 = ParseHex("000102030405060708090a0b0c0d0e0f"
                                                  "101112131415161718191a1b1c1d1e1f"
                                                  "202122232425262728292a2b2c2d2e2f"
                                                  "3031");

    std::string error;
    const std::string encoded_47 = Codex32SecretEncode(hrp, id, 0, seed_47, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(encoded_47.size(), hrp.size() + 1 + 6 + 76 + 15);
    auto parts = Codex32Decode(hrp, encoded_47, error);
    BOOST_CHECK(error.empty());
    BOOST_REQUIRE(parts.has_value());
    BOOST_CHECK_EQUAL(HexStr(parts->payload), HexStr(seed_47));

    const std::string encoded_50 = Codex32SecretEncode(hrp, id, 0, seed_50, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(encoded_50.size(), hrp.size() + 1 + 6 + 80 + 15);
    parts = Codex32Decode(hrp, encoded_50, error);
    BOOST_CHECK(error.empty());
    BOOST_REQUIRE(parts.has_value());
    BOOST_CHECK_EQUAL(HexStr(parts->payload), HexStr(seed_50));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compressor.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <stdint.h>

#include <boost/test/unit_test.hpp>

// amounts 0.00000001 .. 0.00100000
#define NUM_MULTIPLES_UNIT 100000

// amounts 0.01 .. 100.00
#define NUM_MULTIPLES_CENT 10000

// amounts 1 .. 10000
#define NUM_MULTIPLES_1BTC 10000

// amounts 50 .. 21000000
#define NUM_MULTIPLES_50BTC 420000

BOOST_FIXTURE_TEST_SUITE(compress_tests, BasicTestingSetup)

bool static TestEncode(uint64_t in) {
    return in == DecompressAmount(CompressAmount(in));
}

bool static TestDecode(uint64_t in) {
    return in == CompressAmount(DecompressAmount(in));
}

bool static TestPair(uint64_t dec, uint64_t enc) {
    return CompressAmount(dec) == enc &&
           DecompressAmount(enc) == dec;
}

BOOST_AUTO_TEST_CASE(compress_amounts)
{
    BOOST_CHECK(TestPair(            0,       0x0));
    BOOST_CHECK(TestPair(            1,       0x1));
    BOOST_CHECK(TestPair(         CENT,       0x7));
    BOOST_CHECK(TestPair(         COIN,       0x9));
    BOOST_CHECK(TestPair(      50*COIN,      0x32));
    BOOST_CHECK(TestPair(21000000*COIN, 0x1406f40));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_UNIT; i++)
        BOOST_CHECK(TestEncode(i));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_CENT; i++)
        BOOST_CHECK(TestEncode(i * CENT));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_1BTC; i++)
        BOOST_CHECK(TestEncode(i * COIN));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_50BTC; i++)
        BOOST_CHECK(TestEncode(i * 50 * COIN));

    for (uint64_t i = 0; i < 100000; i++)
        BOOST_CHECK(TestDecode(i));
}

BOOST_AUTO_TEST_CASE(compress_script_to_ckey_id)
{
    // case CKeyID
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();

    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(script.size(), 25U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 21U);
    BOOST_CHECK_EQUAL(out[0], 0x00);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 3, 20), 0); // compare the 20 relevant chars of the CKeyId in the script
}

BOOST_AUTO_TEST_CASE(compress_script_to_cscript_id)
{
    // case CScriptID
    CScript script, redeemScript;
    script << OP_HASH160 << ToByteVector(CScriptID(redeemScript)) << OP_EQUAL;
    BOOST_CHECK_EQUAL(script.size(), 23U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 21U);
    BOOST_CHECK_EQUAL(out[0], 0x01);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 20), 0); // compare the 20 relevant chars of the CScriptId in the script
}

BOOST_AUTO_TEST_CASE(compress_script_to_compressed_pubkey_id)
{
    CKey key = GenerateRandomKey(); // case compressed PubKeyID

    CScript script = CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG; // COMPRESSED_PUBLIC_KEY_SIZE (33)
    BOOST_CHECK_EQUAL(script.size(), 35U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 33U);
    BOOST_CHECK_EQUAL(memcmp(out.data(), script.data() + 1, 1), 0);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 32), 0); // compare the 32 chars of the compressed CPubKey
}

BOOST_AUTO_TEST_CASE(compress_script_to_uncompressed_pubkey_id)
{
    CKey key = GenerateRandomKey(/*compressed=*/false); // case uncompressed PubKeyID
    CScript script =  CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG; // PUBLIC_KEY_SIZE (65)
    BOOST_CHECK_EQUAL(script.size(), 67U);                   // 1 char code + 65 char pubkey + OP_CHECKSIG

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 33U);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 32), 0); // first 32 chars of CPubKey are copied into out[1:]
    BOOST_CHECK_EQUAL(out[0], 0x04 | (script[65] & 0x01)); // least significant bit (lsb) of last char of pubkey is mapped into out[0]
}

BOOST_AUTO_TEST_CASE(compress_p2pk_scripts_not_on_curve)
{
    XOnlyPubKey x_not_on_curve;
    do {
        x_not_on_curve = XOnlyPubKey(m_rng.randbytes(32));
    } while (x_not_on_curve.IsFullyValid());

    // Check that P2PK script with uncompressed pubkey [=> OP_PUSH65 <0x04 .....> OP_CHECKSIG]
    // which is not fully valid (i.e. point is not on curve) can't be compressed
    std::vector<unsigned char> pubkey_raw(65, 0);
    pubkey_raw[0] = 4;
    std::copy(x_not_on_curve.begin(), x_not_on_curve.end(), &pubkey_raw[1]);
    CPubKey pubkey_not_on_curve(pubkey_raw);
    assert(pubkey_not_on_curve.IsValid());
    assert(!pubkey_not_on_curve.IsFullyValid());
    CScript script = CScript() << ToByteVector(pubkey_not_on_curve) << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(script.size(), 67U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, false);

    // Check that compressed P2PK script with uncompressed pubkey that is not fully
    // valid (i.e. x coordinate of the pubkey is not on curve) can't be decompressed
    CompressedScript compressed_script(x_not_on_curve.begin(), x_not_on_curve.end());
    for (unsigned int compression_id : {4, 5}) {
        CScript uncompressed_script;
        bool success = DecompressScript(uncompressed_script, compression_id, compressed_script);
        BOOST_CHECK_EQUAL(success, false);
    }
}

namespace {
bool round_trip_compress_transaction(CMutableTransaction& tx)
{
    DataStream stream;
    stream << CTxCompressor(CTransaction(tx), codec_version_t::v1);

    CMutableTransaction ret;
    stream >> CTxCompressor(ret, codec_version_t::v1);

    stream << TX_WITH_WITNESS(tx);
    std::vector<unsigned char> original;
    stream >> original;
    stream.clear();

    stream << TX_WITH_WITNESS(ret);
    std::vector<unsigned char> round_tripped;
    stream >> round_tripped;
    stream.clear();

    BOOST_CHECK(round_tripped == original);
    if (round_tripped != original) {
        printf("=== round-tripped:\nlen=%d\n%s\n\n=== original:\nlen=%d\n%s\n\n"
            , int(round_tripped.size()), CTransaction(ret).ToString().c_str()
            , int(original.size()), CTransaction(tx).ToString().c_str());
    }
    return round_tripped == original;
}
}

BOOST_AUTO_TEST_CASE(compress_transaction_basic)
{
    CMutableTransaction outputm;
    outputm.version = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = CScript();

    round_trip_compress_transaction(outputm);
}

namespace
{
const unsigned char vchKey0[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
const unsigned char vchKey1[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0};
const unsigned char vchKey2[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0};

struct KeyData
{
    CKey key0, key0C, key1, key1C, key2, key2C;
    CPubKey pubkey0, pubkey0C, pubkey0H;
    CPubKey pubkey1, pubkey1C;
    CPubKey pubkey2, pubkey2C;

    KeyData()
    {
        key0.Set(vchKey0, vchKey0 + 32, false);
        key0C.Set(vchKey0, vchKey0 + 32, true);
        pubkey0 = key0.GetPubKey();
        pubkey0H = key0.GetPubKey();
        pubkey0C = key0C.GetPubKey();
        *const_cast<unsigned char*>(&pubkey0H[0]) = 0x06 | (pubkey0H[64] & 1);

        key1.Set(vchKey1, vchKey1 + 32, false);
        key1C.Set(vchKey1, vchKey1 + 32, true);
        pubkey1 = key1.GetPubKey();
        pubkey1C = key1C.GetPubKey();

        key2.Set(vchKey2, vchKey2 + 32, false);
        key2C.Set(vchKey2, vchKey2 + 32, true);
        pubkey2 = key2.GetPubKey();
        pubkey2C = key2C.GetPubKey();
    }
};
} // namespace

BOOST_AUTO_TEST_CASE(compress_transaction_with_scripts)
{
    const KeyData keys;

    CMutableTransaction outputm;
    outputm.nVersion = 1;
    outputm.vin.resize(2);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
    outputm.vin[1].prevout.SetNull();
    outputm.vin[1].scriptSig = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    outputm.vout.resize(2);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG;
    outputm.vout[1].nValue = 1;
    outputm.vout[1].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;

    round_trip_compress_transaction(outputm);
}

BOOST_AUTO_TEST_CASE(kn_coding)
{
    BOOST_CHECK(KNCoder(0, 0) == 3);
    BOOST_CHECK(KNCoder(0, 1) == 3);
    BOOST_CHECK(KNCoder(0, 2) == 4);
    BOOST_CHECK(KNCoder(0, 3) == 6);
    BOOST_CHECK(KNCoder(0, 4) == 9);
    BOOST_CHECK(KNCoder(0, 5) == 13);
    BOOST_CHECK(KNCoder(0, 6) == 18);
    BOOST_CHECK(KNCoder(0, 7) == 24);
    BOOST_CHECK(KNCoder(0, 8) == 31);
    BOOST_CHECK(KNCoder(0, 9) == 39);

    BOOST_CHECK(KNCoder(1, 0) == 0);
    BOOST_CHECK(KNCoder(1, 1) == 0);
    BOOST_CHECK(KNCoder(1, 2) == 1);
    BOOST_CHECK(KNCoder(1, 3) == 0);
    BOOST_CHECK(KNCoder(1, 4) == 0);
    BOOST_CHECK(KNCoder(1, 5) == 0);
    BOOST_CHECK(KNCoder(1, 6) == 0);
    BOOST_CHECK(KNCoder(1, 7) == 0);
    BOOST_CHECK(KNCoder(1, 8) == 0);
    BOOST_CHECK(KNCoder(1, 9) == 0);

    BOOST_CHECK(KNCoder(2, 0) == 0);
    BOOST_CHECK(KNCoder(2, 1) == 0);
    BOOST_CHECK(KNCoder(2, 2) == 2);
    BOOST_CHECK(KNCoder(2, 3) == 3);
    BOOST_CHECK(KNCoder(2, 4) == 4);
    BOOST_CHECK(KNCoder(2, 5) == 0);
    BOOST_CHECK(KNCoder(2, 6) == 0);
    BOOST_CHECK(KNCoder(2, 7) == 0);
    BOOST_CHECK(KNCoder(2, 8) == 0);
    BOOST_CHECK(KNCoder(2, 9) == 0);

    BOOST_CHECK(KNCoder(3, 0) == 0);
    BOOST_CHECK(KNCoder(3, 1) == 0);
    BOOST_CHECK(KNCoder(3, 2) == 0);
    BOOST_CHECK(KNCoder(3, 3) == 0);
    BOOST_CHECK(KNCoder(3, 4) == 5);
    BOOST_CHECK(KNCoder(3, 5) == 6);
    BOOST_CHECK(KNCoder(3, 6) == 0);
    BOOST_CHECK(KNCoder(3, 7) == 0);
    BOOST_CHECK(KNCoder(3, 8) == 0);
    BOOST_CHECK(KNCoder(3, 9) == 0);

    BOOST_CHECK(KNCoder(4, 0) == 7);
    BOOST_CHECK(KNCoder(4, 1) == 7);
    BOOST_CHECK(KNCoder(4, 2) == 8);
    BOOST_CHECK(KNCoder(4, 3) == 10);
    BOOST_CHECK(KNCoder(4, 4) == 13);
    BOOST_CHECK(KNCoder(4, 5) == 17);
    BOOST_CHECK(KNCoder(4, 6) == 22);
    BOOST_CHECK(KNCoder(4, 7) == 28);
    BOOST_CHECK(KNCoder(4, 8) == 35);
    BOOST_CHECK(KNCoder(4, 9) == 43);
}

valtype vec(int size)
{
    return valtype(size, std::uint8_t(size & 0xff));
}

BOOST_AUTO_TEST_CASE(encode_push_only_test)
{
    using r = std::pair<bool, std::vector<valtype>>;

    BOOST_CHECK(encode_push_only(CScript(OP_0)) == r(true, {{}}));
    BOOST_CHECK(encode_push_only(CScript() << 0) == r(true, {{}}));
    BOOST_CHECK(encode_push_only(CScript() << 1) == r(true, {{1}}));
    BOOST_CHECK(encode_push_only(CScript() << 2) == r(true, {{2}}));
    BOOST_CHECK(encode_push_only(CScript() << 16) == r(true, {{16}}));
    BOOST_CHECK(encode_push_only(CScript() << 17) == r(true, {{17}}));
    BOOST_CHECK(encode_push_only(CScript() << 127) == r(true, {{127}}));
    BOOST_CHECK(encode_push_only(CScript() << 0x81) == r(true, {{0x81, 0}}));
    BOOST_CHECK(encode_push_only(CScript() << 255) == r(true, {{255, 0}}));
    BOOST_CHECK(encode_push_only(CScript() << vec(2)) == r(true, {vec(2)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(3)) == r(true, {vec(3)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(4)) == r(true, {vec(4)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(5)) == r(true, {vec(5)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(6)) == r(true, {vec(6)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(75)) == r(true, {vec(75)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(76)) == r(true, {vec(76)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(255)) == r(true, {vec(255)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(256)) == r(true, {vec(256)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(65535)) == r(true, {vec(65535)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(65536)) == r(true, {vec(65536)}));
    BOOST_CHECK(encode_push_only(CScript(OP_1NEGATE)) == r(true, {{0x81}}));

    // an empty scripts are not considered push only, as they indicate a script
    // witness
    BOOST_CHECK(encode_push_only(CScript()) == r(false, {}));

    // combinations of push operations
    BOOST_CHECK(encode_push_only(CScript() << vec(65536) << 0) == r(true, {vec(65536), {}}));
    BOOST_CHECK(encode_push_only(CScript() << vec(5) << OP_0 << 255) == r(true, {vec(5), {}, {255, 0}}));
    BOOST_CHECK(encode_push_only(CScript() << 24 << 15 << vec(5) << OP_0 << 255)
        == r(true, {{24}, {15}, vec(5), {}, {255, 0}}));

    // this fails because operator<< does not encode the special case of a
    // single "1" as OP_1, and our encode_push_only() requires scripts to use the
    // optimal encoding
    BOOST_CHECK(encode_push_only(CScript() << vec(1)) == r(false, {}));

    // not a Push operation
    BOOST_CHECK(encode_push_only(CScript(OP_ROT)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_NOP)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_IF)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_ELSE)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_EQUAL)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_SIZE)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_DUP)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_INVALIDOPCODE)) == r(false, {}));

    // not a push operation, but the first one is still preserved in the output
    BOOST_CHECK(encode_push_only(CScript() << vec(2) << OP_DUP) == r(false, {vec(2)}));

    // "overlong" encoding. e.g. use OP_PUSHDATA2 when the size would fit in a
    // OP_PUSHDATA1
    {
        CScript s;
        s.insert(s.end(), OP_PUSHDATA2);
        std::array<uint8_t, 2> data;
        WriteLE16(data.data(), 130);
        s.insert(s.end(), data.begin(), data.end());
        auto test_vec = vec(130);
        s.insert(s.end(), test_vec.begin(), test_vec.end());

        // this fails because 130 bytes are expected to be pushed with
        // OP_PUSHDATA1, since 1 byte of length prefix is enough, but this test
        // use OP_PUSHDATA2, using 2 bytes length prefix
        BOOST_CHECK(encode_push_only(s) == r(false, {}));
    }

    // garbage
    {
        CScript s;
        valtype test_vec = {230, 45, 134,64,61,24,234,75,2,90};
        s.insert(s.end(), test_vec.begin(), test_vec.end());

        BOOST_CHECK(encode_push_only(s) == r(false, {}));
    }
}

void test_script_roundtrip(CScript const s)
{
    auto const ret = encode_push_only(s);
    BOOST_CHECK(ret.first);
    auto const script = decode_push_only(Span{ret.second});
    BOOST_CHECK(s == script);
}

BOOST_AUTO_TEST_CASE(decode_push_only_test)
{
    test_script_roundtrip(CScript(OP_0));
    test_script_roundtrip(CScript() << 0);
    test_script_roundtrip(CScript() << 1);
    test_script_roundtrip(CScript() << 2);
    test_script_roundtrip(CScript() << 16);
    test_script_roundtrip(CScript() << 17);
    test_script_roundtrip(CScript() << 127);
    test_script_roundtrip(CScript() << 0x81);
    test_script_roundtrip(CScript() << 255);
    test_script_roundtrip(CScript() << vec(2));
    test_script_roundtrip(CScript() << vec(3));
    test_script_roundtrip(CScript() << vec(4));
    test_script_roundtrip(CScript() << vec(5));
    test_script_roundtrip(CScript() << vec(6));
    test_script_roundtrip(CScript() << vec(75));
    test_script_roundtrip(CScript() << vec(76));
    test_script_roundtrip(CScript() << vec(255));
    test_script_roundtrip(CScript() << vec(256));
    test_script_roundtrip(CScript() << vec(65535));
    test_script_roundtrip(CScript() << vec(65536));
    test_script_roundtrip(CScript(OP_1NEGATE));
}

BOOST_AUTO_TEST_CASE(right_align_copy)
{
    using r = std::vector<uint8_t>;
    r const zero(10);
    r dest = zero;
    BOOST_CHECK(dest == (r{0,0,0,0,0,0,0,0,0,0}));

    // dest is larger than src
    right_align(Span{r{1, 2, 3, 4, 5}}, Span{dest});
    BOOST_CHECK(dest == (r{0, 0, 0, 0, 0, 1, 2, 3, 4, 5}));

    dest = zero;

    // src is larger than dest
    right_align(Span{r{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, Span{dest});
    BOOST_CHECK(dest == (r{2, 3, 4, 5, 6, 7, 8, 9, 10, 11}));

    dest = zero;

    // src same size as dest
    right_align(Span{r{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, Span{dest});
    BOOST_CHECK(dest == (r{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));
}

BOOST_AUTO_TEST_CASE(strip_sig)
{
    using r = valtype;
    // signature encoding:
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

    // R is 3 bytes long (10, 11, 12)
    // S is 4 bytes long (13, 14, 15, 16)
    // no sighash
    BOOST_CHECK(StripSig(r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 0}, false)
        == (r{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 14, 15, 16, 0}));

    // R is 3 bytes long (10, 11, 12)
    // S is 33 bytes lon
    // no sighash
    BOOST_CHECK(StripSig(r{0x30, 40
        , 0x02, 3, 10, 11, 12 // R
        , 0x02, 33, 0 // S
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0}, false)
        == (r{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0}));

    // R is 33 bytes long
    // S is 3 bytes lon
    // no sighash
    BOOST_CHECK(StripSig(r{0x30, 40
        , 0x02, 33, 0
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0x02, 3, 10, 11, 12
        , 0}, false)
        == (r{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 0}));

    // with sighash
    BOOST_CHECK(StripSig(r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 1}, true)
        == (r{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 14, 15, 16}));
}

BOOST_AUTO_TEST_CASE(pad_sig)
{
    using r = valtype;

    auto const padded0 = r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 0};
    auto const padded1 = r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 1};
    auto const padded3 = r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 3};

    // if sighashall is true, the flags *must* be 1
    BOOST_CHECK(PadSig(Span{StripSig(padded0, false)}, false) == padded0);
    BOOST_CHECK(PadSig(Span{StripSig(padded1, false)}, false) == padded1);
    BOOST_CHECK(PadSig(Span{StripSig(padded3, false)}, false) == padded3);
    BOOST_CHECK(PadSig(Span{StripSig(padded1, true)}, true) == padded1);

    {
    auto const padded = r{0x30, 40
        , 0x02, 3, 10, 11, 12 // R
        , 0x02, 33, 0 // S
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0};
    BOOST_CHECK(PadSig(Span{StripSig(padded, false)}, false) == padded);
    }

    {
    auto const padded = r{0x30, 40
        , 0x02, 33, 0
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0x02, 3, 10, 11, 12
        , 0};
    BOOST_CHECK(PadSig(Span{StripSig(padded, false)}, false) == padded);
    }

    {
    auto const padded = r{0x30, 40
        , 0x02, 33, 0
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0x02, 3, 10, 11, 12
        , 1};
    BOOST_CHECK(PadSig(Span{StripSig(padded, true)}, true) == padded);
    }
}

namespace {

valtype make_test_pubkey()
{
    static const std::string strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
    CKey bsecret1 = DecodeSecret(strSecret1);
    BOOST_CHECK(bsecret1.IsValid());
    CPubKey k = bsecret1.GetPubKey();
    return valtype(k.begin(), k.end());
}
}

BOOST_AUTO_TEST_CASE(valid_pubkey)
{
    valtype const pubkey = make_test_pubkey();

    BOOST_CHECK(IsValidPubKey(pubkey));

    {
        valtype broken = pubkey;
        broken.erase(broken.begin());
        BOOST_CHECK(!IsValidPubKey(broken));
    }

    {
        valtype broken = pubkey;
        broken.erase(broken.end() - 1);
        BOOST_CHECK(!IsValidPubKey(broken));
    }

    {
        valtype broken = pubkey;
        broken[0] -= 0x2;
        BOOST_CHECK(!IsValidPubKey(broken));
    }
}

BOOST_AUTO_TEST_CASE(strip_pubkey)
{
    {
    // matching the pattern for a regular public key
    valtype const pubkey = {
        0x04, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 1 };

    valtype const stripped = StripPubKey(pubkey);
    BOOST_CHECK(stripped == (valtype{
        0x03, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0 }));
    }

    {
    // does not have the LSB set in the last byte, store verbatim
    valtype const pubkey = {
        0x04, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0 };

    valtype const stripped = StripPubKey(pubkey);
    BOOST_CHECK(stripped == (valtype{
        0x02, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0 }));
    }

    {
    // is not 65 bytes long
    valtype const pubkey = {
        0x04, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0
        , 0 };

    valtype const stripped = StripPubKey(pubkey);
    BOOST_CHECK(stripped == (valtype{
        0x02, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0
        , 0 }));
    }

    {
    // roundtrip
    valtype const pubkey = make_test_pubkey();
    valtype stripped = StripPubKey(pubkey);
    // when we "decode" a pub key, we pass in the key prefix as an argument,
    // rather than it being the first byte in the key. So, we have to remove
    // it here, and pass it in as a separate argument.
    uint8_t const template_type = stripped[0];
    stripped.erase(stripped.begin());
    valtype const result = PadPubKey(Span{stripped}, template_type);
    BOOST_CHECK(result == pubkey);
    }
}

BOOST_AUTO_TEST_SUITE_END()

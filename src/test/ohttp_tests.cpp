// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license.

#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <ohttp/ohttp.h>
#include <ohttp/bhttp.h>
#include <dhkem_secp256k1.h>   // ensure HPKE context init & helpers are present :contentReference[oaicite:28]{index=28}
#include <key.h>
#include <util/strencodings.h>

using namespace ohttp;

BOOST_FIXTURE_TEST_SUITE(ohttp_tests, BasicTestingSetup)

// Build a single supported KeyConfig from a receiver keypair
static KeyConfig MakeKeyConfig(uint8_t key_id, const CPubKey& pkR)
{
    KeyConfig cfg;
    cfg.key_id = key_id;
    cfg.kem_id = KEM_SECP256K1;
    std::copy(pkR.begin(), pkR.end(), cfg.pkR.begin());
    cfg.syms.push_back({KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305});
    return cfg;
}

BOOST_AUTO_TEST_CASE(ohttp_roundtrip_client_gateway)
{
    // Receiver (Gateway) HPKE keypair
    CKey skR; skR.MakeNewKey(/*uncompressed*/false);
    CPubKey pkR = skR.GetPubKey();
    BOOST_CHECK(pkR.size() == dhkem_secp256k1::NPK);

    // KeyConfig (application-provided)
    KeyConfig cfg = MakeKeyConfig(/*key_id=*/1, pkR);
    BOOST_CHECK(cfg.IsSupported());

    // Serialize+parse the key list container (sanity)
    std::vector<KeyConfig> list{cfg};
    auto blob = SerializeKeyConfigList(list);
    auto parsed = ParseKeyConfigList(blob);
    BOOST_CHECK_EQUAL(parsed.size(), 1U);
    BOOST_CHECK(parsed[0].IsSupported());
    BOOST_CHECK_EQUAL(parsed[0].key_id, cfg.key_id);

    // Client builds Encapsulated Request over some bHTTP bytes.
    // (In real Payjoin v2, caller provides an actual bHTTP request.)
    std::vector<uint8_t> bhttp_req = ParseHex("0102030405");
    ClientContext client;
    auto enc_req = client.EncapsulateRequest(cfg, bhttp_req);
    BOOST_REQUIRE(enc_req.has_value());

    // Gateway decapsulates the request
    std::array<uint8_t, dhkem_secp256k1::NSK> skR_arr{};
    std::copy((const uint8_t*)skR.data(), (const uint8_t*)skR.data()+skR.size(), skR_arr.begin());
    GatewayRequestContext gwctx;
    auto got_req = Gateway::DecapsulateRequest(*enc_req, /*expected_key_id=*/1,
                                               std::span<const uint8_t>(skR_arr.data(), skR_arr.size()),
                                               gwctx);
    BOOST_REQUIRE(got_req.has_value());
    BOOST_CHECK_EQUAL(HexStr(*got_req), HexStr(bhttp_req));

    // Gateway produces Encapsulated Response for arbitrary bHTTP response bytes
    std::vector<uint8_t> bhttp_res = ParseHex("A0A1A2A3");
    auto enc_res = Gateway::EncapsulateResponse(gwctx, bhttp_res);

    // Client opens the Encapsulated Response
    auto got_res = client.OpenResponse(enc_res);
    BOOST_REQUIRE(got_res.has_value());
    BOOST_CHECK_EQUAL(HexStr(*got_res), HexStr(bhttp_res));
}

BOOST_AUTO_TEST_CASE(ohttp_roundtrip_client_gateway_with_bhttp)
{
    // Receiver (Gateway) HPKE keypair
    CKey skR; skR.MakeNewKey(/*uncompressed*/false);
    CPubKey pkR = skR.GetPubKey();
    BOOST_CHECK(pkR.size() == dhkem_secp256k1::NPK);

    // KeyConfig (application-provided)
    KeyConfig cfg = MakeKeyConfig(/*key_id=*/1, pkR);
    BOOST_CHECK(cfg.IsSupported());

    // Serialize+parse the key list container (sanity)
    std::vector<KeyConfig> list{cfg};
    auto blob = SerializeKeyConfigList(list);
    auto parsed = ParseKeyConfigList(blob);
    BOOST_CHECK_EQUAL(parsed.size(), 1U);
    BOOST_CHECK(parsed[0].IsSupported());
    BOOST_CHECK_EQUAL(parsed[0].key_id, cfg.key_id);

    // Build a real bHTTP known-length request (RFC 9292) to send via OHTTP.
    bhttp::Request inner_req;
    inner_req.method    = "POST";
    inner_req.scheme    = "https";
    inner_req.authority = "relay.example";     // any host
    inner_req.path      = "/payjoin/v2/mailbox";
    inner_req.headers   = {
        {"content-type", "application/payjoin"},
        {"accept",       "application/octet-stream"},
    };
    inner_req.body      = std::vector<uint8_t>{'P','J','-','R','E','Q'}; // example payload
    auto enc_req_body = bhttp::EncodeKnownLengthRequest(inner_req);
    BOOST_REQUIRE(enc_req_body.has_value());

    ClientContext client;
    auto enc_req = client.EncapsulateRequest(cfg, *enc_req_body);
    BOOST_REQUIRE(enc_req.has_value());

    // Gateway decapsulates the request
    GatewayRequestContext gwctx;
    auto got_req = Gateway::DecapsulateRequest(
        *enc_req,
        /*expected_key_id=*/1,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(skR.data()), skR.size()),
        gwctx);
    BOOST_REQUIRE(got_req.has_value());
    // Request bytes should match exactly what the client encoded.
    BOOST_CHECK_EQUAL_COLLECTIONS(got_req->begin(), got_req->end(), enc_req_body->begin(), enc_req_body->end());

    // Produce a real bHTTP known-length response and encapsulate it.
    bhttp::Response inner_res;
    inner_res.status  = 200;
    inner_res.headers = { {"content-type","application/octet-stream"} };
    inner_res.body    = std::vector<uint8_t>{'P','J','-','R','E','S'};
    auto enc_res_body = bhttp::EncodeKnownLengthResponse(inner_res);
    BOOST_REQUIRE(enc_res_body.has_value());
    auto enc_res = Gateway::EncapsulateResponse(gwctx, *enc_res_body);

    // Client opens the Encapsulated Response
    auto got_res = client.OpenResponse(enc_res);
    BOOST_REQUIRE(got_res.has_value());
    // And decodes the bHTTP response
    auto decoded = bhttp::DecodeKnownLengthResponse(*got_res);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->status, inner_res.status);
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded->body.begin(), decoded->body.end(),
        inner_res.body.begin(), inner_res.body.end());
}

BOOST_AUTO_TEST_SUITE_END()

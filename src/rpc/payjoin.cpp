// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/hex_base.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <rpc/util.h>
#include <rpc/server.h>

#include <curl/curl.h>
#include <payjoin/ohttp.h>

static size_t CurlWriteCB(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* v = static_cast<std::vector<uint8_t>*>(userdata);
    size_t n = size * nmemb;
    v->insert(v->end(), reinterpret_cast<uint8_t*>(ptr), reinterpret_cast<uint8_t*>(ptr) + n);
    return n;
}

static std::vector<uint8_t> HttpGetViaProxy(const std::string& proxy_url, const std::string& target_url) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl init failed");

    std::vector<uint8_t> body;
    struct curl_slist* headers = nullptr;

    curl_easy_setopt(curl, CURLOPT_URL, target_url.c_str());
    curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L); // Explicit CONNECT bootstrap
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);  // Do not follow redirects through relay

    headers = curl_slist_append(headers, "Accept: application/ohttp-keys");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &CurlWriteCB);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

    // Reasonable timeouts
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 20000L);

    // If the relay is https://, verify TLS (recommended)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("curl error: ") + curl_easy_strerror(res));
    }
    if (status < 200 || status >= 300) {
        throw std::runtime_error("unexpected status: " + std::to_string(status));
    }
    return body;
}

static UniValue KeyConfigToJSON(const ohttp::KeyConfig& cfg) {
    UniValue o(UniValue::VOBJ);
    o.pushKV("key_id", (int)cfg.key_id);
    o.pushKV("kem_id", (int)cfg.kem_id);
    o.pushKV("public_key", HexStr(cfg.pkR));
    UniValue arr(UniValue::VARR);
    for (const auto& s : cfg.suites) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("kdf_id", (int)s.kdf_id);
        e.pushKV("aead_id", (int)s.aead_id);
        arr.push_back(e);
    }
    o.pushKV("suites", arr);
    return o;
}

static RPCHelpMan fetchohttpkeys()
{
    return RPCHelpMan{
        "fetchohttpkeys",
        "Fetch OHTTP KeyConfig from the Payjoin Directory through an OHTTP Relay (HTTP CONNECT bootstrap).\n",
        {
            {"ohttp_relay", RPCArg::Type::STR, RPCArg::Default{"https://pj.bobspacebkk.com"}, "OHTTP Relay URL"},
            {"payjoin_directory", RPCArg::Type::STR, RPCArg::Default{"https://payjo.in"}, "Payjoin Directory origin"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "keys_raw_b64", "Raw KeyConfig or application/ohttp-keys body, base64-encoded"},
                {RPCResult::Type::ARR, "parsed", "Parsed KeyConfig entries (either one or many)",
                    {{RPCResult::Type::OBJ, "", "KeyConfig object"}},},
            }
        },
        RPCExamples{
            HelpExampleCli("fetchohttpkeys", "\"https://pj.bobspacebkk.com\" \"https://payjo.in\"") +
            HelpExampleRpc("fetchohttpkeys", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::string proxy = request.params[0].get_str();
            std::string directory = request.params[1].get_str();

            std::string url = directory;
            if (!url.empty() && url.back() == '/') url.pop_back();
            url += "/.well-known/ohttp-gateway"; // OHTTP key discovery

            std::vector<uint8_t> body = HttpGetViaProxy(proxy, url);

            // Updated parser: supports RFC 9458 collection and Payjoin v2 single-KeyConfig
            ohttp::OhttpKeys keys = ohttp::ParseOhttpKeys(body); // in ohttp.cpp

            UniValue arr(UniValue::VARR);
            for (const auto& k : keys.configs) arr.push_back(KeyConfigToJSON(k));

            UniValue result(UniValue::VOBJ);
            result.pushKV("keys_raw_b64", EncodeBase64(body));
            result.pushKV("parsed", arr);
            return result;
        },
    };
}

void RegisterPayjoinRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"payjoin", &fetchohttpkeys},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
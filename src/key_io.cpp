// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>

#include <base58.h>
#include <bech32.h>
#include <util/strencodings.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <assert.h>
#include <string.h>
#include <iomanip>
#include <regex>

/// Maximum witness length for Bech32 addresses.
static constexpr std::size_t BECH32_WITNESS_PROG_MAX_LEN = 40;

namespace {
class DestinationEncoder
{
private:
    const CChainParams& m_params;
    const bool m_silent_payment{false};
    const int32_t m_silent_payment_index{0};

public:
    explicit DestinationEncoder(const CChainParams& params, const bool silent_payment, const int32_t silent_payment_index) :
        m_params(params), m_silent_payment{silent_payment}, m_silent_payment_index{silent_payment_index} {}

    std::string operator()(const PKHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const ScriptHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const WitnessV0KeyHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(33);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV0ScriptHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV1Taproot& tap) const
    {
        std::vector<unsigned char> data = {1};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, tap.begin(), tap.end());

        std::string hrp = m_params.Bech32HRP();

        if (m_silent_payment) {
            hrp = m_params.SilentPaymentHRP();

            std::ostringstream ss;
            ss << std::setw(2) << std::setfill('0') << m_silent_payment_index;
            std::string formatted_current_index = ss.str();

            hrp = hrp + formatted_current_index;
        }

        return bech32::Encode(bech32::Encoding::BECH32M, hrp, data);
    }

    std::string operator()(const WitnessUnknown& id) const
    {
        if (id.version < 1 || id.version > 16 || id.length < 2 || id.length > 40) {
            return {};
        }
        std::vector<unsigned char> data = {(unsigned char)id.version};
        data.reserve(1 + (id.length * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.program, id.program + id.length);
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    std::string operator()(const CNoDestination& no) const { return {}; }
};

std::tuple<CTxDestination,bool,int32_t> DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str, std::vector<int>* error_locations)
{
    std::vector<unsigned char> data;
    uint160 hash;
    error_str = "";
    bool silent_payment{false};

    const auto& silent_payment_hrp = params.SilentPaymentHRP();
    auto dest_silent_payment_hrp = ToLower(std::string_view(str).substr(0, params.SilentPaymentHRP().size()));

    // Note this will be false if it is a valid Bech32 address for a different network
    bool is_bech32_or_sp = (ToLower(str.substr(0, params.Bech32HRP().size())) == params.Bech32HRP()) ||
        dest_silent_payment_hrp == silent_payment_hrp;

    if (!is_bech32_or_sp && DecodeBase58Check(str, data, 21)) {
        // base58-encoded Bitcoin addresses.
        // Public-key-hash-addresses have version 0 (or 111 testnet).
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return {PKHash(hash), false, 0};
        }
        // Script-hash-addresses have version 5 (or 196 testnet).
        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return {ScriptHash(hash), false, 0};
        }

        // If the prefix of data matches either the script or pubkey prefix, the length must have been wrong
        if ((data.size() >= script_prefix.size() &&
                std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) ||
            (data.size() >= pubkey_prefix.size() &&
                std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin()))) {
            error_str = "Invalid length for Base58 address";
        } else {
            error_str = "Invalid prefix for Base58-encoded address";
        }
        return {CNoDestination(),false, 0};
    } else if (!is_bech32_or_sp) {
        // Try Base58 decoding without the checksum, using a much larger max length
        if (!DecodeBase58(str, data, 100)) {
            error_str = "Not a valid Bech32 or Base58 encoding";
        } else {
            error_str = "Invalid checksum or length of Base58 address";
        }
        return {CNoDestination(), false, 0};
    }

    data.clear();
    const auto dec = bech32::Decode(str);
    auto dec_silent_payment_hrp = dec.hrp.substr(0, params.SilentPaymentHRP().size());

    if ((dec.encoding == bech32::Encoding::BECH32 || dec.encoding == bech32::Encoding::BECH32M) && dec.data.size() > 0) {
        // Bech32 decoding
        if (dec.hrp != params.Bech32HRP() && dec_silent_payment_hrp != silent_payment_hrp) {
            error_str = "Invalid prefix for Bech32 address";
            return {CNoDestination(), false, 0};
        }
        if (dec_silent_payment_hrp == silent_payment_hrp) {
            silent_payment = true;
        }
        int version = dec.data[0]; // The first 5 bit symbol is the witness version (0-16)
        if (version == 0 && dec.encoding != bech32::Encoding::BECH32) {
            error_str = "Version 0 witness address must use Bech32 checksum";
            return {CNoDestination(), false, 0};
        }
        if (version != 0 && dec.encoding != bech32::Encoding::BECH32M) {
            error_str = "Version 1+ witness address must use Bech32m checksum";
            return {CNoDestination(), false, 0};
        }
        // The rest of the symbols are converted witness program bytes.
        data.reserve(((dec.data.size() - 1) * 5) / 8);
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, dec.data.begin() + 1, dec.data.end())) {
            if (version == 0) {
                {
                    WitnessV0KeyHash keyid;
                    if (data.size() == keyid.size()) {
                        std::copy(data.begin(), data.end(), keyid.begin());
                        return {keyid, false, 0};
                    }
                }
                {
                    WitnessV0ScriptHash scriptid;
                    if (data.size() == scriptid.size()) {
                        std::copy(data.begin(), data.end(), scriptid.begin());
                        return {scriptid, false, 0};
                    }
                }

                error_str = "Invalid Bech32 v0 address data size";
                return {CNoDestination(), false, 0};
            }

            if (version == 1 && data.size() == WITNESS_V1_TAPROOT_SIZE) {
                static_assert(WITNESS_V1_TAPROOT_SIZE == WitnessV1Taproot::size());
                WitnessV1Taproot tap;
                std::copy(data.begin(), data.end(), tap.begin());

                int32_t hrp_index = 0;

                if (silent_payment) {
                    std::size_t pos = dec.hrp.find_last_of(params.SilentPaymentHRP()) + 1;

                    auto sp_index{dec.hrp.substr(pos)};
                    if (!ParseInt32(sp_index, &hrp_index)) {
                        error_str = "Unable to parse address identifier :" + sp_index;
                        return {CNoDestination(), false, 0};
                    }

                    if (hrp_index > wallet::SILENT_ADDRESS_MAXIMUM_IDENTIFIER) {
                        std::stringstream ss;
                        ss << wallet::SILENT_ADDRESS_MAXIMUM_IDENTIFIER;

                        error_str = "Silent Payment identifier must have a maximum value of " + ss.str();
                        return {CNoDestination(), false, 0};
                    }
                }

                return {tap, silent_payment, hrp_index};
            }

            if (version > 16) {
                error_str = "Invalid Bech32 address witness version";
                return {CNoDestination(), false, 0};
            }

            if (data.size() < 2 || data.size() > BECH32_WITNESS_PROG_MAX_LEN) {
                error_str = "Invalid Bech32 address data size";
                return {CNoDestination(), false, 0};
            }

            WitnessUnknown unk;
            unk.version = version;
            std::copy(data.begin(), data.end(), unk.program);
            unk.length = data.size();
            return {unk, false, 0};
        }
    }

    // Perform Bech32 error location
    auto res = bech32::LocateErrors(str);
    error_str = res.first;
    if (error_locations) *error_locations = std::move(res.second);
    return {CNoDestination(), false, 0};
}
} // namespace

CKey DecodeSecret(const std::string& str)
{
    CKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 34)) {
        const std::vector<unsigned char>& privkey_prefix = Params().Base58Prefix(CChainParams::SECRET_KEY);
        if ((data.size() == 32 + privkey_prefix.size() || (data.size() == 33 + privkey_prefix.size() && data.back() == 1)) &&
            std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
            bool compressed = data.size() == 33 + privkey_prefix.size();
            key.Set(data.begin() + privkey_prefix.size(), data.begin() + privkey_prefix.size() + 32, compressed);
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeSecret(const CKey& key)
{
    assert(key.IsValid());
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), key.begin(), key.end());
    if (key.IsCompressed()) {
        data.push_back(1);
    }
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey DecodeExtPubKey(const std::string& str)
{
    CExtPubKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtPubKey(const CExtPubKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    return ret;
}

CExtKey DecodeExtKey(const std::string& str)
{
    CExtKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtKey(const CExtKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

std::string EncodeDestination(const CTxDestination& dest, const bool silent_payment, const int32_t silent_payment_index)
{
    return std::visit(DestinationEncoder(Params(), silent_payment, silent_payment_index), dest);
}

CTxDestination DecodeDestination(const std::string& str, std::string& error_msg, std::vector<int>* error_locations)
{
    auto ret = DecodeDestination(str, Params(), error_msg, error_locations);
    return std::get<0>(ret);
}

CTxDestination DecodeDestination(const std::string& str)
{
    std::string error_msg;
    return DecodeDestination(str, error_msg);
}

std::tuple<CTxDestination,bool,int32_t> DecodeDestinationIndicatingSP(const std::string& str, std::string& error_msg)
{
    return DecodeDestination(str, Params(), error_msg, nullptr);
}

std::tuple<CTxDestination,bool,int32_t> DecodeDestinationIndicatingSP(const std::string& str)
{
    std::string error_msg;
    return DecodeDestination(str, Params(), error_msg, nullptr);
}

bool IsValidDestinationString(const std::string& str, const CChainParams& params)
{
    std::string error_msg;
    auto ret = DecodeDestination(str, params, error_msg, nullptr);
    return IsValidDestination(std::get<0>(ret));
}

bool IsValidDestinationString(const std::string& str)
{
    return IsValidDestinationString(str, Params());
}

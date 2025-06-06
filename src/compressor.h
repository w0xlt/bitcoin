// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPRESSOR_H
#define BITCOIN_COMPRESSOR_H

#include <prevector.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <span.h>
#include <hash.h>
#include <array>
#include <variant>

using valtype = std::vector<unsigned char>;
using stattype = std::span<uint64_t>;

enum class scriptSigTemplate : uint8_t {
    P2SH_P2WSH_OTHER,
    WIT_OTHER,
    NONWIT_OTHER,
    P2SH_UW,
    P2PK,
    P2PKH,
    P2WPKH,
    P2SH_P2WPKH,
    P2SH_P2WSH_P2PKH,
    MS,
    P2SH_MS,
    P2WSH_MS,
    P2SH_P2WSH_MS
};

const std::array<char const*, 13> scriptSigTemplateNames = {
    "P2SH_P2WSH_OTHER",
    "WIT_OTHER",
    "NONWIT_OTHER",
    "P2SH_UW",
    "P2PK",
    "P2PKH",
    "P2WPKH",
    "P2SH_P2WPKH",
    "P2SH_P2WSH_P2PKH",
    "MS",
    "P2SH_MS",
    "P2WSH_MS",
    "P2SH_P2WSH_MS"
};

/**
 * This saves us from making many heap allocations when serializing
 * and deserializing compressed scripts.
 *
 * This prevector size is determined by the largest .resize() in the
 * CompressScript function. The largest compressed script format is a
 * compressed public key, which is 33 bytes.
 */
using CompressedScript = prevector<33, unsigned char>;


bool CompressScript(const CScript& script, CompressedScript& out);
unsigned int GetSpecialScriptSize(unsigned int nSize);
bool DecompressScript(CScript& script, unsigned int nSize, const CompressedScript& in);

/**
 * Compress amount.
 *
 * nAmount is of type uint64_t and thus cannot be negative. If you're passing in
 * a CAmount (int64_t), make sure to properly handle the case where the amount
 * is negative before calling CompressAmount(...).
 *
 * @pre Function defined only for 0 <= nAmount <= MAX_MONEY.
 */
uint64_t CompressAmount(uint64_t nAmount);

uint64_t DecompressAmount(uint64_t nAmount);

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
struct ScriptCompression
{
    /**
     * make this static for now (there are only 6 special scripts defined)
     * this can potentially be extended together with a new version for
     * transactions, in which case this value becomes dependent on version
     * and nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    template<typename Stream>
    void Ser(Stream &s, const CScript& script) {
        CompressedScript compr;
        if (CompressScript(script, compr)) {
            s << std::span{compr};
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << std::span{script};
    }

    template<typename Stream>
    void Unser(Stream &s, CScript& script) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            CompressedScript vch(GetSpecialScriptSize(nSize), 0x00);
            s >> std::span{vch};
            DecompressScript(script, nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> std::span{script};
        }
    }
};

struct AmountCompression
{
    template<typename Stream, typename I> void Ser(Stream& s, I val)
    {
        s << VARINT(CompressAmount(val));
    }
    template<typename Stream, typename I> void Unser(Stream& s, I& val)
    {
        uint64_t v;
        s >> VARINT(v);
        val = DecompressAmount(v);
    }
};

/** wrapper for CTxOut that provides a more compact serialization */
struct TxOutCompression
{
    FORMATTER_METHODS(CTxOut, obj) { READWRITE(Using<AmountCompression>(obj.nValue), Using<ScriptCompression>(obj.scriptPubKey)); }
};

enum class LockTimeCode : uint8_t { zero, varint, raw };

enum class SequenceCode : uint8_t { zero, final_seq, final_less_one, last_encoded, raw};

std::pair<LockTimeCode, uint8_t> ParseTxHeader(uint8_t TxHeader);
uint8_t GenerateTxHeader(uint32_t lock_time, uint32_t version);

std::tuple<bool, uint8_t, SequenceCode> ParseTxInHeader(uint8_t TxInHeader);
uint8_t GenerateTxInHeader(bool last, CTxIn const& in, std::vector<uint32_t>& SequenceCache);

std::tuple<bool, uint8_t> ParseTxOutHeader(uint8_t TxOutHeader);
std::pair<uint8_t, valtype> GenerateTxOutHeader(bool last, CScript const& TxOutScriptPubKey);

bool IsFromScriptHashWitnessScriptHashOther(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsValidPubKey(valtype const& pubkey);
bool IsFromScriptHashWitnessScriptHash(std::span<valtype const> stack, std::span<valtype const> witnessstack);
bool IsFromMultisig(std::span<valtype const> stack, stattype statistic);
bool IsFromEmbeddedMultisig(std::span<valtype const> stack, stattype statistic);
bool IsFromPubKey(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromPubKeyHash(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromWitnessPubKeyHash(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromScriptHashWitnessPubKeyHash(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromRawMultisig(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromScriptHashMultisig(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromWitnessScriptHashMultisig(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromScriptHashWitnessScriptHashMultisig(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromScriptHashWitnessScriptHashPubKeyHash(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromNonWitnessOther(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsFromWitnessOther(std::span<valtype const> stack, std::span<valtype const> witnessstack, stattype statistic);
bool IsValidSignatureEncoding(const std::vector<unsigned char> &sig);

std::pair<bool, std::vector<valtype>> encode_push_only(const CScript &scriptSig);
bool IsToPubKeyHash(CScript const& scriptPubKey, valtype& smallscript);
bool IsToScriptHash(CScript const& scriptPubKey, valtype& smallscript);
bool IsToWitnessPubKeyHash(CScript const& scriptPubKey, valtype& smallscript);
bool IsToWitnessScriptHash(CScript const& scriptPubKey, valtype& smallscript);
bool IsToPubKey(CScript const& scriptPubKey, valtype& smallscript);
bool IsToWitnessUnknown(CScript const& scriptPubKey, valtype& smallscript);

// copies the right part of src into the right part of dst
void right_align(std::span<uint8_t const> src, std::span<uint8_t> dst);

std::pair<uint8_t, valtype> StripSigPubKey(std::span<valtype const> stack, bool sighashall);
valtype StripSig(const valtype &sig, bool sighashall);
valtype StripAllSigs(std::span<valtype const> stack, bool sighashall);
valtype StripPubKey(const valtype &pubkey);
void StripAllPubKeys(std::span<valtype const> stack, valtype &strippedpubkeys);
uint16_t KNCoder(uint64_t k, uint64_t n);
std::pair<uint16_t, valtype> GenerateScriptSigHeader(size_t txinindex, CTxIn const& in);
std::pair<scriptSigTemplate, uint16_t> ParseScriptSigHeader(uint16_t ScriptSigHeader, uint16_t lastCode);
scriptSigTemplate AnalyzeScriptSig(size_t txinindex, CTxIn const& in, stattype statistic);

CScript decode_push_only(std::span<valtype const> values);
valtype PadHash(std::span<unsigned char const> h, bool iswitnesshash);
valtype PadSig(std::span<unsigned char const> strippedsig, bool sighashall);
valtype PadPubKey(std::span<unsigned char const> strippedpubkey, uint16_t TemplateCode);
std::vector<valtype> PadSingleKeyStack(std::span<unsigned char const> strippedstack
    , uint16_t TemplateCode, scriptSigTemplate TemplateType, const bool sighashall);
std::vector<valtype> PadMultisig(valtype strippedstack, scriptSigTemplate templateType, uint16_t TemplateCode);
std::pair<uint8_t, uint8_t> KNDecoder(uint16_t kncode);
void PadAllPubkeys(valtype &strippedstack, std::vector<valtype>& paddedstack, uint8_t n);
void PadScriptPubKey(uint8_t TxOutCode, CScript &scriptPubKey);

template <typename Stream>
void decompressTransaction(Stream& s, CMutableTransaction& tx);

template <typename Stream>
void compressTransaction(Stream& s, CTransaction const& tx);

enum codec_version_t : std::uint8_t { none, v1, default_version = v1 };

struct CTxCompressor
{
    CTxCompressor(CTransactionRef& txin, codec_version_t v) : tx(&txin), codec_version(v) {}
    CTxCompressor(CTransaction const& txin, codec_version_t v) : tx(&txin), codec_version(v) {}
    CTxCompressor(CMutableTransaction &txin, codec_version_t v) : tx(&txin), codec_version(v) {}

    template<typename Stream>
    void Serialize(Stream& s) const {
        if (codec_version == codec_version_t::none) {
            if (std::holds_alternative<CTransactionRef*>(tx)) {
                s << TX_WITH_WITNESS(**std::get<CTransactionRef*>(tx));
            }
            else if (std::holds_alternative<CTransaction const*>(tx)) {
                s << TX_WITH_WITNESS(*std::get<CTransaction const*>(tx));
            }
            else {
                throw std::runtime_error("cannot serialize CMutableTransaction");
            }
        }
        else if (codec_version == codec_version_t::v1) {
            if (std::holds_alternative<CTransactionRef*>(tx)) {
                compressTransaction(s, **std::get<CTransactionRef*>(tx));
            }
            else if (std::holds_alternative<CTransaction const*>(tx)) {
                compressTransaction(s, *std::get<CTransaction const*>(tx));
            }
            else {
                throw std::runtime_error("cannot serialize CMutableTransaction");
            }
        }
        else {
            throw std::invalid_argument("Unsupported codec version " + std::to_string(codec_version));
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        if (codec_version == codec_version_t::none) {
            if (std::holds_alternative<CTransactionRef*>(tx)) {
                s >> TX_WITH_WITNESS(*std::get<CTransactionRef*>(tx));    
            }
            else if (std::holds_alternative<CMutableTransaction*>(tx)) {
              s >> TX_WITH_WITNESS(*std::get<CMutableTransaction*>(tx));
            }
            else {
                throw std::runtime_error("cannot un-serialize into CTransaction");
           }
        }
        else if (codec_version == codec_version_t::v1) {
            if (std::holds_alternative<CTransactionRef*>(tx)) {
                CMutableTransaction local_tx;
                decompressTransaction(s, local_tx);
                *std::get<CTransactionRef*>(tx) = MakeTransactionRef(std::move(local_tx));
            }
            else if (std::holds_alternative<CMutableTransaction*>(tx)) {
                decompressTransaction(s, *std::get<CMutableTransaction*>(tx));
            }
            else {
                throw std::runtime_error("cannot un-serialize into CTransaction");
            }
        }
        else {
            throw std::invalid_argument("Unsupported codec version " + std::to_string(codec_version));
        }
    }
private:
    std::variant<CMutableTransaction*, CTransaction const*, CTransactionRef*> tx;
    codec_version_t codec_version = codec_version_t::v1;
};

#endif // BITCOIN_COMPRESSOR_H

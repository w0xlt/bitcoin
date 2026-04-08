// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <span.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

BOOST_AUTO_TEST_SUITE(walletload_tests)

class DummyDescriptor final : public Descriptor {
private:
    std::string desc;
public:
    explicit DummyDescriptor(const std::string& descriptor) : desc(descriptor) {};
    ~DummyDescriptor() = default;

    std::string ToString(bool compat_format) const override { return desc; }
    std::optional<OutputType> GetOutputType() const override { return OutputType::UNKNOWN; }

    bool IsRange() const override { return false; }
    bool IsSolvable() const override { return false; }
    bool IsSingleType() const override { return true; }
    bool HavePrivateKeys(const SigningProvider&) const override { return false; }
    bool ToPrivateString(const SigningProvider& provider, std::string& out) const override { return false; }
    bool ToNormalizedString(const SigningProvider& provider, std::string& out, const DescriptorCache* cache = nullptr) const override { return false; }
    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const override { return false; };
    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const override { return false; }
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override {}
    std::optional<int64_t> ScriptSize() const override { return {}; }
    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }
    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }
    void GetPubKeys(std::set<CPubKey>& pubkeys, std::set<CExtPubKey>& ext_pubs) const override {}
    std::vector<std::string> Warnings() const override { return {}; }
    uint32_t GetMaxKeyExpr() const override { return 0; }
    size_t GetKeyCount() const override { return 0; }
};

static SerializeData SerializeHDRootKey(const std::string& key_type, const CExtPubKey& xpub)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());

    DataStream key_ss{};
    key_ss << std::make_pair(key_type, ser_xpub);
    return {key_ss.begin(), key_ss.end()};
}

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptors, TestingSetup)
{
    bilingual_str _error;
    std::vector<bilingual_str> _warnings;
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        // Write unknown active descriptor
        WalletBatch batch(*database);
        std::string unknown_desc = "trx(tpubD6NzVbkrYhZ4Y4S7m6Y5s9GD8FqEMBy56AGphZXuagajudVZEnYyBahZMgHNCTJc2at82YX6s8JiL1Lohu5A3v1Ur76qguNH4QVQ7qYrBQx/86'/1'/0'/0/*)#8pn8tzdt";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(unknown_desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256(), wallet_descriptor));
        BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::UNKNOWN), uint256(), false));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::UNKNOWN_DESCRIPTOR);
    }

    // Test 2
    // Now write a valid descriptor with an invalid ID.
    // As the software produces another ID for the descriptor, the loading process must be aborted.
    database = CreateMockableWalletDatabase();

    // Verify the error
    bool found = false;
    DebugLogHelper logHelper("The descriptor ID calculated by the wallet differs from the one in DB", [&](const std::string* s) {
        found = true;
        return false;
    });

    {
        // Write valid descriptor with invalid ID
        WalletBatch batch(*database);
        std::string desc = "wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#cjjspncu";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256::ONE, wallet_descriptor));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::CORRUPT);
        BOOST_CHECK(found); // The error must be logged
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_load_hd_root_seed_mismatched_xpub_and_seed, TestingSetup)
{
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();

    const CExtPubKey xpub = MasterKeyFromSeedHex("e208d110a84650d6ae8b27776eb82ccd7963318d9af777306a496198c13a1d2b").Neuter();
    const CKeyingMaterial mismatched_seed = SeedFromHex("659dec01c6c731124084add1fabc04833d3aa6718f7696ba1faebb4fe1a7a8b6");

    {
        WalletBatch batch(*database);
        BOOST_CHECK(batch.WriteHDRootSeed(xpub, mismatched_seed));
    }

    const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::CORRUPT);
}

BOOST_FIXTURE_TEST_CASE(wallet_unlock_partially_corrupt_hd_root_seeds, TestingSetup)
{
    static constexpr auto seed_hex_a{"e208d110a84650d6ae8b27776eb82ccd7963318d9af777306a496198c13a1d2b"};
    static constexpr auto seed_hex_b{"659dec01c6c731124084add1fabc04833d3aa6718f7696ba1faebb4fe1a7a8b6"};

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    }

    const CKeyingMaterial seed_a = SeedFromHex(seed_hex_a);
    const CKeyingMaterial seed_b = SeedFromHex(seed_hex_b);
    const CExtKey master_key_a = MasterKeyFromSeedHex(seed_hex_a);
    const CExtKey master_key_b = MasterKeyFromSeedHex(seed_hex_b);
    const CExtPubKey xpub_a = master_key_a.Neuter();
    const CExtPubKey xpub_b = master_key_b.Neuter();

    BOOST_CHECK(wallet.AddHDKey(master_key_a, seed_a));
    BOOST_CHECK(wallet.AddHDKey(master_key_b, seed_b));

    SecureString passphrase;
    passphrase = "pass";
    BOOST_CHECK(wallet.EncryptWallet(passphrase));

    std::unique_ptr<WalletDatabase> database = DuplicateMockDatabase(wallet.GetDatabase());
    auto& mock_db = dynamic_cast<MockableDatabase&>(*database);
    const CExtPubKey corrupt_xpub = xpub_a < xpub_b ? xpub_b : xpub_a;
    const SerializeData corrupt_key = SerializeHDRootKey(DBKeys::WALLETHDROOTCSEED, corrupt_xpub);
    const auto it = mock_db.m_records.find(corrupt_key);
    BOOST_REQUIRE(it != mock_db.m_records.end());
    BOOST_REQUIRE(!it->second.empty());
    it->second.back() ^= std::byte{1};

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    const std::shared_ptr<CWallet> loaded_wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    BOOST_CHECK_EQUAL(loaded_wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
    BOOST_CHECK_EXCEPTION(
        loaded_wallet->Unlock(passphrase),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string_view{e.what()}.find("some HD root seeds decrypt but not all") != std::string_view::npos;
        });
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

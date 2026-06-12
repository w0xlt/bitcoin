// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <script/solver.h>
#include <support/allocators/secure.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/test/util.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(scriptpubkeyman_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(DescriptorScriptPubKeyManTests)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet keystore(chain.get(), "", CreateMockableWalletDatabase());
    auto key_scriptpath = GenerateRandomKey();

    // Verify that a SigningProvider for a pubkey is only returned if its corresponding private key is available
    auto key_internal = GenerateRandomKey();
    std::string desc_str = "tr(" + EncodeSecret(key_internal) + ",pk(" + HexStr(key_scriptpath.GetPubKey()) + "))";
    auto spk_man1 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man1 != nullptr);
    auto signprov_keypath_spendable = spk_man1->GetSigningProvider(key_internal.GetPubKey());
    BOOST_CHECK(signprov_keypath_spendable != nullptr);

    desc_str = "tr(" + HexStr(XOnlyPubKey::NUMS_H) + ",pk(" + HexStr(key_scriptpath.GetPubKey()) + "))";
    auto spk_man2 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man2 != nullptr);
    auto signprov_keypath_nums_h = spk_man2->GetSigningProvider(XOnlyPubKey::NUMS_H.GetEvenCorrespondingCPubKey());
    BOOST_CHECK(signprov_keypath_nums_h == nullptr);
}

BOOST_AUTO_TEST_CASE(descriptor_spkm_getkey_encryption_states)
{
    CWallet keystore(m_node.chain.get(), "", CreateMockableWalletDatabase());

    CKey key = GenerateRandomKey();
    const CKeyID keyid{key.GetPubKey().GetID()};
    const CKeyID unknown_keyid{GenerateRandomKey().GetPubKey().GetID()};
    DescriptorScriptPubKeyMan* spk_man = CreateDescriptor(keystore, "wpkh(" + EncodeSecret(key) + ")", /*success=*/true);
    BOOST_REQUIRE(spk_man != nullptr);

    // Plain wallet: the key is served from the unencrypted key map.
    {
        LOCK2(keystore.cs_wallet, spk_man->cs_desc_man);
        BOOST_CHECK(spk_man->HasPrivKey(keyid));
        const auto plain_key = spk_man->GetKey(keyid);
        BOOST_REQUIRE(plain_key.has_value());
        BOOST_CHECK(*plain_key == key);
        BOOST_CHECK(!spk_man->GetKey(unknown_keyid).has_value());
    }

    // Encrypted and locked: the key is present but not retrievable.
    const SecureString pass{"passphrase"};
    BOOST_REQUIRE(keystore.EncryptWallet(pass));
    BOOST_REQUIRE(keystore.IsLocked());
    {
        LOCK2(keystore.cs_wallet, spk_man->cs_desc_man);
        BOOST_CHECK(spk_man->HasPrivKey(keyid));
        BOOST_CHECK(!spk_man->GetKey(keyid).has_value());
    }

    // Encrypted and unlocked: the key is decrypted on demand and matches.
    BOOST_REQUIRE(keystore.Unlock(pass));
    {
        LOCK2(keystore.cs_wallet, spk_man->cs_desc_man);
        const auto decrypted_key = spk_man->GetKey(keyid);
        BOOST_REQUIRE(decrypted_key.has_value());
        BOOST_CHECK(*decrypted_key == key);
        BOOST_CHECK(!spk_man->GetKey(unknown_keyid).has_value());
    }
}

BOOST_AUTO_TEST_CASE(desc_spkm_topup_fail)
{
    // Attempting to construct a DescriptorSPKM that cannot be topped up (hardened derivation without private keys)
    // should throw even though it is valid and can be parsed
    CExtKey extkey;
    extkey.SetSeed(std::array<std::byte, 32>{});
    CWallet keystore(m_node.chain.get(), "", CreateMockableWalletDatabase());
    BOOST_CHECK_EXCEPTION(
        CreateDescriptor(keystore, "wpkh(" + EncodeExtPubKey(extkey.Neuter()) + "/*h)", /*success=*/true),
        std::runtime_error, HasReason("Could not top up scriptPubKeys"));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

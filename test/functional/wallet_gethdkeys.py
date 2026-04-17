#!/usr/bin/env python3
# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet gethdkeys RPC."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    assert_not_equal,
    assert_greater_than,
)
from test_framework.wallet_util import WalletUnlock


class WalletGetHDKeyTest(BitcoinTestFramework):
    CODEX32_SECRET = "wr10f2tvsugydzy9ggegddt5tyamkawpve4ukxvvdntmhwvr2f9se3sf6r54slxj9n4fxe7vmp"
    CONFLICTING_CODEX32_SECRET = "wr10testsugydzy9ggegddt5tyamkawpve4ukxvvdntmhwvr2f9se3sf6r54s3kz2ghmwen0gc"
    CODEX32_SHARE = "wr12f2tvaugydzy9ggegddt5tyamkawpve4ukxvvdntmhwvr2f9se3sf6r54sphrw0fjgz8v2k"
    SHORT_CODEX32_SECRET = "wr10f2tvsqqqsyqcyq5rqwzqfpg9scrgwdljg3lns3gnzw"

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def ensure_wallet_loaded(self, wallet_name):
        if wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(wallet_name)
        return self.nodes[0].get_wallet_rpc(wallet_name)

    def run_test(self):
        self.test_basic_gethdkeys()
        self.test_ranged_imports()
        self.test_lone_key_imports()
        self.test_ranged_multisig()
        self.test_mixed_multisig()
        self.test_addhdkey()
        self.test_addhdkey_existing_descriptor()

    def test_basic_gethdkeys(self):
        self.log.info("Test gethdkeys basics")
        self.nodes[0].createwallet("basic")
        wallet = self.nodes[0].get_wallet_rpc("basic")
        xpub_info = wallet.gethdkeys()
        assert_equal(len(xpub_info), 1)
        assert_equal(xpub_info[0]["has_private"], True)
        # Auto-generated wallets do not retain codex32 secrets
        assert_equal(xpub_info[0]["has_codex32"], False)

        assert "xprv" not in xpub_info[0]
        xpub = xpub_info[0]["xpub"]

        assert_raises_rpc_error(-8, '"codex32" requires "private" to be true', wallet.gethdkeys, codex32=True)
        xpub_info = wallet.gethdkeys(private=True)
        xprv = xpub_info[0]["xprv"]
        assert_equal(xpub_info[0]["xpub"], xpub)
        assert_equal(xpub_info[0]["has_private"], True)

        descs = wallet.listdescriptors(True)
        for desc in descs["descriptors"]:
            assert xprv in desc["desc"]

        self.log.info("HD pubkey can be retrieved from encrypted wallets")
        prev_xprv = xprv
        wallet.encryptwallet("pass")
        # HD key is rotated on encryption, there should now be 2 HD keys
        assert_equal(len(wallet.gethdkeys()), 2)
        # New key is active, should be able to get only that one and its descriptors
        xpub_info = wallet.gethdkeys(active_only=True)
        assert_equal(len(xpub_info), 1)
        assert_not_equal(xpub_info[0]["xpub"], xpub)
        assert "xprv" not in xpub_info[0]
        assert_equal(xpub_info[0]["has_private"], True)

        self.log.info("HD privkey can be retrieved from encrypted wallets")
        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first", wallet.gethdkeys, private=True)
        with WalletUnlock(wallet, "pass"):
            xpub_info = wallet.gethdkeys(active_only=True, private=True)[0]
            assert_not_equal(xpub_info["xprv"], xprv)
            for desc in wallet.listdescriptors(True)["descriptors"]:
                if desc["active"]:
                    # After encrypting, HD key was rotated and should appear in all active descriptors
                    assert xpub_info["xprv"] in desc["desc"]
                else:
                    # Inactive descriptors should have the previous HD key
                    assert prev_xprv in desc["desc"]

    def test_ranged_imports(self):
        self.log.info("Keys of imported ranged descriptors appear in gethdkeys")
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet("imports")
        wallet = self.nodes[0].get_wallet_rpc("imports")

        xpub_info = wallet.gethdkeys()
        assert_equal(len(xpub_info), 1)
        active_xpub = xpub_info[0]["xpub"]
        assert_equal(xpub_info[0]["has_codex32"], False)

        import_xpub = def_wallet.gethdkeys(active_only=True)[0]["xpub"]
        desc_import = def_wallet.listdescriptors(True)["descriptors"]
        for desc in desc_import:
            desc["active"] = False
        wallet.importdescriptors(desc_import)
        assert_equal(wallet.gethdkeys(active_only=True), xpub_info)

        xpub_info = wallet.gethdkeys()
        assert_equal(len(xpub_info), 2)
        for x in xpub_info:
            if x["xpub"] == active_xpub:
                assert_equal(x["has_codex32"], False)
                for desc in x["descriptors"]:
                    assert_equal(desc["active"], True)
            elif x["xpub"] == import_xpub:
                assert_equal(x["has_codex32"], False)
                for desc in x["descriptors"]:
                    assert_equal(desc["active"], False)
            else:
                assert False


    def test_lone_key_imports(self):
        self.log.info("Non-HD keys do not appear in gethdkeys")
        self.nodes[0].createwallet("lonekey", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("lonekey")

        assert_equal(wallet.gethdkeys(), [])
        wallet.importdescriptors([{"desc": descsum_create("wpkh(cTe1f5rdT8A8DFgVWTjyPwACsDPJM9ff4QngFxUixCSvvbg1x6sh)"), "timestamp": "now"}])
        assert_equal(wallet.gethdkeys(), [])

        self.log.info("HD keys of non-ranged descriptors should appear in gethdkeys")
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        xpub_info = def_wallet.gethdkeys(private=True)
        xpub = xpub_info[0]["xpub"]
        xprv = xpub_info[0]["xprv"]
        prv_desc = descsum_create(f"wpkh({xprv})")
        pub_desc = descsum_create(f"wpkh({xpub})")
        assert_equal(wallet.importdescriptors([{"desc": prv_desc, "timestamp": "now"}])[0]["success"], True)
        xpub_info = wallet.gethdkeys()
        assert_equal(len(xpub_info), 1)
        assert_equal(xpub_info[0]["xpub"], xpub)
        assert_equal(xpub_info[0]["has_codex32"], False)
        assert_equal(len(xpub_info[0]["descriptors"]), 1)
        assert_equal(xpub_info[0]["descriptors"][0]["desc"], pub_desc)
        assert_equal(xpub_info[0]["descriptors"][0]["active"], False)

    def test_ranged_multisig(self):
        self.log.info("HD keys of a multisig appear in gethdkeys")

        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        outside_wallet_xpub = def_wallet.gethdkeys()[0]["xpub"]

        self.nodes[0].createwallet("ranged_multisig")
        wallet = self.nodes[0].get_wallet_rpc("ranged_multisig")

        hdkeys_info = wallet.gethdkeys(private=True)
        assert_equal(len(hdkeys_info), 1)
        within_wallet_xprv = hdkeys_info[0]["xprv"]
        within_wallet_xpub = hdkeys_info[0]["xpub"]

        prv_multi_desc = descsum_create(f"wsh(multi(2,{within_wallet_xprv}/*,{outside_wallet_xpub}/*))")
        pub_multi_desc = descsum_create(f"wsh(multi(2,{within_wallet_xpub}/*,{outside_wallet_xpub}/*))")
        assert_equal(wallet.importdescriptors([{"desc": prv_multi_desc, "timestamp": "now"}])[0]["success"], True)

        rpcs_req_resp = [[False, wallet.gethdkeys()], [True, wallet.gethdkeys(private=True)]]
        for rpc_req_resp in rpcs_req_resp:
            requested_private, hdkeys_response = rpc_req_resp
            assert_equal(len(hdkeys_response), 2)

            for hdkeys_info in hdkeys_response:
                if hdkeys_info["xpub"] == within_wallet_xpub:
                    assert_equal(hdkeys_info["has_private"], True)
                    assert_equal(hdkeys_info["has_codex32"], False)
                    if requested_private:
                        assert_equal(hdkeys_info["xprv"], within_wallet_xprv)
                    else:
                        assert_equal("xprv" not in hdkeys_info, True)
                    assert_greater_than(len(hdkeys_info["descriptors"]), 1) # within wallet xpub by default is part of multiple descriptors
                    found_desc = next((d for d in hdkeys_info["descriptors"] if d["desc"] == pub_multi_desc), None)
                elif hdkeys_info["xpub"] == outside_wallet_xpub:
                    assert_equal(hdkeys_info["has_private"], False)
                    assert_equal(hdkeys_info["has_codex32"], False)
                    assert_equal("xprv" not in hdkeys_info, True)
                    assert_equal(len(hdkeys_info["descriptors"]), 1) # outside wallet xpub is part of only the imported descriptor
                    found_desc = hdkeys_info["descriptors"][0]
                else:
                    assert False

                assert_equal(found_desc["desc"], pub_multi_desc)
                assert_equal(found_desc["active"], False)

    def test_mixed_multisig(self):
        self.log.info("Non-HD keys of a multisig do not appear in gethdkeys")
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet("single_multisig")
        wallet = self.nodes[0].get_wallet_rpc("single_multisig")

        xpub = wallet.gethdkeys()[0]["xpub"]
        xprv = wallet.gethdkeys(private=True)[0]["xprv"]
        pub = def_wallet.getaddressinfo(def_wallet.getnewaddress())["pubkey"]

        prv_multi_desc = descsum_create(f"wsh(multi(2,{xprv},{pub}))")
        pub_multi_desc = descsum_create(f"wsh(multi(2,{xpub},{pub}))")
        import_res = wallet.importdescriptors([{"desc": prv_multi_desc, "timestamp": "now"}])
        assert_equal(import_res[0]["success"], True)

        xpub_info = wallet.gethdkeys()
        assert_equal(len(xpub_info), 1)
        assert_equal(xpub_info[0]["xpub"], xpub)
        assert_equal(xpub_info[0]["has_codex32"], False)
        found_desc = next((d for d in xpub_info[0]["descriptors"] if d["desc"] == pub_multi_desc), None)
        assert found_desc is not None
        assert_equal(found_desc["active"], False)

    def test_addhdkey(self):
        self.log.info("Test addhdkey RPC")

        # Validation errors
        self.nodes[0].createwallet("addhdkey_validation", blank=True)
        validation_wallet = self.nodes[0].get_wallet_rpc("addhdkey_validation")
        assert_raises_rpc_error(-8, "Expected a codex32 secret, not a share", validation_wallet.addhdkey, self.CODEX32_SHARE)
        assert_raises_rpc_error(-8, "Expected a 16 to 64 byte seed, got 15 bytes", validation_wallet.addhdkey, self.SHORT_CODEX32_SECRET)

        self.nodes[0].createwallet("addhdkey_disabled", blank=True, disable_private_keys=True)
        disabled_wallet = self.nodes[0].get_wallet_rpc("addhdkey_disabled")
        assert_raises_rpc_error(-4, "Wallet private keys are disabled", disabled_wallet.addhdkey, self.CODEX32_SECRET)

        # Import into blank wallet creates descriptors
        self.nodes[0].createwallet("addhdkey_blank", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("addhdkey_blank")

        blank_xpub = wallet.addhdkey(self.CODEX32_SECRET)["xpub"]
        hdkeys_info = wallet.gethdkeys()
        assert_equal(len(hdkeys_info), 1)
        assert_equal(hdkeys_info[0]["xpub"], blank_xpub)
        assert_equal(hdkeys_info[0]["has_private"], True)
        assert_equal(hdkeys_info[0]["has_codex32"], True)
        assert_greater_than(len(hdkeys_info[0]["descriptors"]), 0)

        # Codex32 roundtrip
        hdkeys_info = wallet.gethdkeys(private=True, codex32=True)
        assert_equal(len(hdkeys_info), 1)
        exported_codex32 = hdkeys_info[0]["codex32"]
        self.nodes[0].createwallet("addhdkey_roundtrip", blank=True)
        roundtrip_wallet = self.nodes[0].get_wallet_rpc("addhdkey_roundtrip")
        assert_equal(roundtrip_wallet.addhdkey(exported_codex32)["xpub"], blank_xpub)

        # Duplicate import rejected
        assert_raises_rpc_error(-5, f"HD key {blank_xpub} is already known", wallet.addhdkey, self.CODEX32_SECRET)
        assert_raises_rpc_error(-8, "Unable to decode codex32 secret", wallet.addhdkey, "not-codex32")

        self.nodes[0].createwallet("addhdkey_nonblank")
        nonblank_wallet = self.nodes[0].get_wallet_rpc("addhdkey_nonblank")
        active_hdkeys = nonblank_wallet.gethdkeys(active_only=True)
        assert_raises_rpc_error(-4, "Cannot create default descriptors for a new HD key while the wallet already has active descriptors", nonblank_wallet.addhdkey, self.CODEX32_SECRET)
        assert_equal(nonblank_wallet.gethdkeys(active_only=True), active_hdkeys)

        # All default descriptor types were already created by addhdkey
        hdkeys_info = wallet.gethdkeys(active_only=True, private=True, codex32=True)
        assert_equal(len(hdkeys_info), 1)
        assert_equal(hdkeys_info[0]["xpub"], blank_xpub)
        assert_equal(hdkeys_info[0]["has_codex32"], True)
        assert_equal(hdkeys_info[0]["codex32"], exported_codex32)
        assert_greater_than(len(hdkeys_info[0]["descriptors"]), 1)

        # Import into encrypted blank wallet
        self.log.info("Imported HD roots can be stored in encrypted blank wallets")
        self.nodes[0].createwallet("addhdkey_encrypted", blank=True, passphrase="pass")
        wallet = self.nodes[0].get_wallet_rpc("addhdkey_encrypted")

        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.", wallet.addhdkey, self.CODEX32_SECRET)
        with WalletUnlock(wallet, "pass"):
            encrypted_xpub = wallet.addhdkey(self.CODEX32_SECRET)["xpub"]

        hdkeys_info = wallet.gethdkeys()
        assert_equal(len(hdkeys_info), 1)
        assert_equal(hdkeys_info[0]["xpub"], encrypted_xpub)
        assert_equal(hdkeys_info[0]["has_private"], True)
        assert_equal(hdkeys_info[0]["has_codex32"], True)

        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first", wallet.gethdkeys, private=True)
        with WalletUnlock(wallet, "pass"):
            hdkeys_info = wallet.gethdkeys(private=True, codex32=True)
            assert_equal(len(hdkeys_info), 1)
            assert "xprv" in hdkeys_info[0]
            assert "codex32" in hdkeys_info[0]

        # Restart persistence
        self.restart_node(0)
        wallet = self.ensure_wallet_loaded("addhdkey_blank")
        hdkeys_info = wallet.gethdkeys(private=True, codex32=True)
        assert_equal(len(hdkeys_info), 1)
        assert_equal(hdkeys_info[0]["xpub"], blank_xpub)
        assert_equal(hdkeys_info[0]["has_codex32"], True)
        assert "codex32" in hdkeys_info[0]

        wallet = self.ensure_wallet_loaded("addhdkey_encrypted")
        with WalletUnlock(wallet, "pass"):
            hdkeys_info = wallet.gethdkeys(private=True, codex32=True)
            assert_equal(len(hdkeys_info), 1)
            assert_equal(hdkeys_info[0]["has_codex32"], True)
            assert "codex32" in hdkeys_info[0]

    def test_addhdkey_existing_descriptor(self):
        self.log.info("addhdkey can associate a codex32 secret with an existing descriptor root")
        source_wallet = self.ensure_wallet_loaded("addhdkey_blank")
        source_info = source_wallet.gethdkeys(active_only=True, private=True, codex32=True)[0]

        self.nodes[0].createwallet("addhdkey_existing_descriptor", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("addhdkey_existing_descriptor")
        desc = descsum_create(f"wpkh({source_info['xprv']})")
        assert_equal(wallet.importdescriptors([{"desc": desc, "timestamp": "now"}])[0]["success"], True)

        hdkeys_info = wallet.gethdkeys(private=True, codex32=True)
        assert_equal(len(hdkeys_info), 1)
        assert_equal(hdkeys_info[0]["xpub"], source_info["xpub"])
        assert_equal(hdkeys_info[0]["has_codex32"], False)
        assert "codex32" not in hdkeys_info[0]

        assert_equal(wallet.addhdkey(source_info["codex32"])["xpub"], source_info["xpub"])

        hdkeys_info = wallet.gethdkeys(private=True, codex32=True)
        assert_equal(len(hdkeys_info), 1)
        assert_equal(hdkeys_info[0]["xpub"], source_info["xpub"])
        assert_equal(hdkeys_info[0]["has_codex32"], True)
        assert "codex32" in hdkeys_info[0]

        desc = descsum_create(f"sh(wpkh({source_info['xprv']}))")
        assert_equal(wallet.importdescriptors([{"desc": desc, "timestamp": "now"}])[0]["success"], True)
        assert_raises_rpc_error(-5, f"HD key {source_info['xpub']} already has a different codex32 secret", wallet.addhdkey, self.CONFLICTING_CODEX32_SECRET)
        assert_equal(wallet.addhdkey(source_info["codex32"])["xpub"], source_info["xpub"])


if __name__ == '__main__':
    WalletGetHDKeyTest(__file__).main()

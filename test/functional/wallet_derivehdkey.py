#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet derivehdkey RPC."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.descriptors import descsum_create
from test_framework.wallet_util import WalletUnlock


class WalletDeriveHDKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # Do not create wallet by default - we create them manually in tests
    def init_wallet(self, *, node):
        return

    def run_test(self):
        self.test_basic_derivehdkey()
        self.test_path_formats()
        self.test_noprivs_blank()
        self.test_export_import()

    def test_basic_derivehdkey(self):
        self.log.info("Test derivehdkey basics")
        self.nodes[0].createwallet("basic")
        wallet = self.nodes[0].get_wallet_rpc("basic")

        # Get the root xpub (empty path)
        xpub_info = wallet.derivehdkey("m")
        assert "xprv" not in xpub_info
        assert "fingerprint" not in xpub_info  # No fingerprint for empty path
        root_xpub = xpub_info["xpub"]

        # Get with private key
        xpub_info = wallet.derivehdkey("m", {"private": True})
        xprv = xpub_info["xprv"]
        assert_equal(xpub_info["xpub"], root_xpub)

        # Verify the xprv matches what's in descriptors
        descs = wallet.listdescriptors(True)
        for desc in descs["descriptors"]:
            if "range" in desc:
                assert xprv in desc["desc"]

        self.log.info("Test derived path with fingerprint and origin")
        derived_info = wallet.derivehdkey("m/84'/0'/0'")
        assert "xpub" in derived_info
        assert "fingerprint" in derived_info
        assert "origin" in derived_info
        # Origin should be in format [fingerprint/path]
        assert derived_info["origin"].startswith("[" + derived_info["fingerprint"])
        assert "/84'/0'/0'" in derived_info["origin"]

        self.log.info("Test derivehdkey on encrypted wallet")
        wallet.encryptwallet("pass")
        # After encryption, the HD key is rotated
        xpub_info_enc = wallet.derivehdkey("m")
        assert xpub_info_enc["xpub"] != root_xpub  # Key was rotated

        # Can still get xpub without unlocking (for empty path)
        assert "xpub" in xpub_info_enc

        # Need to unlock for hardened derivation
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", wallet.derivehdkey, "m/84'/0'/0'")

        # Need to unlock for private key
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", wallet.derivehdkey, "m", {"private": True})

        with WalletUnlock(wallet, "pass"):
            derived_enc = wallet.derivehdkey("m/84'/0'/0'", {"private": True})
            assert "xprv" in derived_enc
            assert "xpub" in derived_enc

    def test_path_formats(self):
        self.log.info("Test different path formats")
        self.nodes[0].createwallet("pathtest")
        wallet = self.nodes[0].get_wallet_rpc("pathtest")

        # Test both hardened markers: ' and h
        result_apostrophe = wallet.derivehdkey("m/84'/0'/0'")
        result_h = wallet.derivehdkey("m/84h/0h/0h")
        assert_equal(result_apostrophe["xpub"], result_h["xpub"])
        assert_equal(result_apostrophe["fingerprint"], result_h["fingerprint"])

        # Test non-hardened derivation (doesn't require private key)
        result_soft = wallet.derivehdkey("m/0/0/0")
        assert "xpub" in result_soft

        # Test invalid paths
        assert_raises_rpc_error(-8, "Invalid BIP32 keypath", wallet.derivehdkey, "invalid")
        assert_raises_rpc_error(-8, "Invalid BIP32 keypath", wallet.derivehdkey, "m/abc")
        assert_raises_rpc_error(-8, "Invalid BIP32 keypath", wallet.derivehdkey, "n/0/0")

    def test_noprivs_blank(self):
        self.log.info("Test derivehdkey on wallet without private keys")
        self.nodes[0].createwallet(wallet_name="noprivs", disable_private_keys=True)
        wallet = self.nodes[0].get_wallet_rpc("noprivs")
        assert_raises_rpc_error(-4, "does not have an active HD key", wallet.derivehdkey, "m")

        self.log.info("Test derivehdkey on blank wallet")
        self.nodes[0].createwallet(wallet_name="blank", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("blank")
        assert_raises_rpc_error(-4, "does not have an active HD key", wallet.derivehdkey, "m")

    def test_export_import(self):
        self.log.info("Test creating watch-only wallet using derived xpub")
        self.nodes[0].createwallet(wallet_name="signer")
        signer = self.nodes[0].get_wallet_rpc("signer")

        # Get the xpub for BIP 84 native SegWit account 0
        derived = signer.derivehdkey("m/84'/1'/0'")
        xpub = derived["xpub"]
        fingerprint = derived["fingerprint"]
        origin = derived["origin"]

        # Verify fingerprint format (4 bytes = 8 hex chars)
        assert len(fingerprint) == 8
        # Verify fingerprint is embedded in origin
        assert origin.startswith(f"[{fingerprint}/")

        self.log.info(f"Derived xpub: {xpub}")
        self.log.info(f"Origin: {origin}")

        # Create a watch-only wallet and import descriptors using the xpub
        self.nodes[1].createwallet(wallet_name="watcher", disable_private_keys=True)
        watcher = self.nodes[1].get_wallet_rpc("watcher")

        desc_receive = f"wpkh({origin}{xpub}/0/*)"
        desc_change = f"wpkh({origin}{xpub}/1/*)"

        result = watcher.importdescriptors([
            {"desc": descsum_create(desc_receive), "timestamp": "now", "active": True, "internal": False, "range": [0, 10]},
            {"desc": descsum_create(desc_change), "timestamp": "now", "active": True, "internal": True, "range": [0, 10]},
        ])
        assert result[0]["success"] and result[1]["success"]

        # Verify addresses match between signer and watcher
        # First, import the same descriptors into the signer wallet to compare addresses
        # The signer's default descriptors use different paths, so we import to make them active
        signer_derived = signer.derivehdkey("m/84'/1'/0'", {"private": True})
        signer_xprv = signer_derived["xprv"]

        desc_receive_priv = f"wpkh({origin}{signer_xprv}/0/*)"
        desc_change_priv = f"wpkh({origin}{signer_xprv}/1/*)"

        signer.importdescriptors([
            {"desc": descsum_create(desc_receive_priv), "timestamp": "now", "active": True, "internal": False, "range": [0, 10]},
            {"desc": descsum_create(desc_change_priv), "timestamp": "now", "active": True, "internal": True, "range": [0, 10]},
        ])

        # Now compare addresses
        signer_addr = signer.getnewaddress(address_type="bech32")
        watcher_addr = watcher.getnewaddress(address_type="bech32")
        assert_equal(signer_addr, watcher_addr)


if __name__ == '__main__':
    WalletDeriveHDKeyTest(__file__).main()

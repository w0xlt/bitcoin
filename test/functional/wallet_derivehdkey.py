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
        self.test_derivation_vectors()
        self.test_basic_derivehdkey()
        self.test_path_formats()
        self.test_noprivs_blank()
        self.test_export_import()

    def test_derivation_vectors(self):
        """Verify derivehdkey produces exact expected values from BIP32 test vectors.

        Uses BIP32 Test Vector 1 (seed: 000102030405060708090a0b0c0d0e0f) converted to regtest format.
        This ensures the derivation logic produces the correct keys at each path.
        """
        self.log.info("Test derivehdkey against BIP32 test vectors")

        # BIP32 Test Vector 1 - converted to regtest (tprv/tpub) format
        # Original seed: 000102030405060708090a0b0c0d0e0f
        MASTER_TPRV = "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m"
        MASTER_TPUB = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"

        DERIVATION_VECTORS = [
            # (path, expected_tpub, expected_tprv)
            ("m", MASTER_TPUB, MASTER_TPRV),
            ("m/0'",
             "tpubD8eQVK4Kdxg3gHrF62jGP7dKVCoYiEB8dFSpuTawkL5YxTus5j5pf83vaKnii4bc6v2NVEy81P2gYrJczYne3QNNwMTS53p5uzDyHvnw2jm",
             "tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9"),
            ("m/0'/1",
             "tpubDApXh6cD2fZ7WjtgpHd8yrWyYaneiFuRZa7fVjMkgxsmC1QzoXW8cgx9zQFJ81Jx4deRGfRE7yXA9A3STsxXj4CKEZJHYgpMYikkas9DBTP",
             "tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q"),
            ("m/0'/1/2'",
             "tpubDDRojdS4jYQXNugn4t2WLrZ7mjfAyoVQu7MLk4eurqFCbrc7cHLZX8W5YRS8ZskGR9k9t3PqVv68bVBjAyW4nWM9pTGRddt3GQftg6MVQsm",
             "tprv8gjmbDPpbAirVSezBEMuwSu1Ci9EpUJWKokZTYccSZSomNMLytWyLdtDNHRbucNaRJWWHANf9AzEdWVAqahfyRjVMKbNRhBmxAM8EJr7R15"),
        ]

        # Create a blank wallet and import the master key as an active descriptor
        self.nodes[0].createwallet(wallet_name="vectors", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("vectors")

        # Import descriptor with the known master tprv
        desc = f"wpkh({MASTER_TPRV}/0/*)"
        result = wallet.importdescriptors([{
            "desc": descsum_create(desc),
            "timestamp": "now",
            "active": True,
            "range": [0, 10],
        }])
        assert result[0]["success"]

        # Verify derivehdkey produces exact expected values at each path
        for path, expected_tpub, expected_tprv in DERIVATION_VECTORS:
            result = wallet.derivehdkey(path, {"private": True})
            assert_equal(result["xpub"], expected_tpub)
            assert_equal(result["xprv"], expected_tprv)
            self.log.info(f"  Path {path}: verified")

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

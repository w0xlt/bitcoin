#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
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

    def init_wallet(self, *, node):
        pass  # Don't create default wallet

    def run_test(self):
        self.test_derivation_vectors()
        self.test_basic_derivehdkey()
        self.test_path_formats()
        self.test_noprivs_blank()
        self.test_export_import_workflow()
        self.test_multisig_tutorial_workflow()

    def test_derivation_vectors(self):
        """Verify derivehdkey produces exact expected values from BIP32 test vectors."""
        self.log.info("Test derivehdkey against BIP32 test vectors")

        # BIP32 Test Vector 1 - converted to regtest (tprv/tpub) format
        MASTER_TPRV = "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m"
        MASTER_TPUB = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"

        DERIVATION_VECTORS = [
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
        assert_raises_rpc_error(-8, "Invalid BIP 32 keypath", wallet.derivehdkey, "invalid")
        assert_raises_rpc_error(-8, "Invalid BIP 32 keypath", wallet.derivehdkey, "m/abc")
        assert_raises_rpc_error(-8, "Invalid BIP 32 keypath", wallet.derivehdkey, "n/0/0")

    def test_noprivs_blank(self):
        self.log.info("Test derivehdkey on wallet without private keys")
        self.nodes[0].createwallet(wallet_name="noprivs", disable_private_keys=True)
        wallet = self.nodes[0].get_wallet_rpc("noprivs")
        assert_raises_rpc_error(-4, "does not have an active HD key", wallet.derivehdkey, "m")

        self.log.info("Test derivehdkey on blank wallet")
        self.nodes[0].createwallet(wallet_name="blank", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("blank")
        assert_raises_rpc_error(-4, "does not have an active HD key", wallet.derivehdkey, "m")

    def test_export_import_workflow(self):
        """Test the workflow: derive xpub, create descriptor, import for signing."""
        self.log.info("Test export/import workflow with derivehdkey")
        self.nodes[0].createwallet(wallet_name="signer")
        signer = self.nodes[0].get_wallet_rpc("signer")

        # Derive xpub at BIP 87 multisig path
        derived = signer.derivehdkey("m/87'/1'/0'", {"private": True})
        xpub = derived["xpub"]
        xprv = derived["xprv"]
        origin = derived["origin"]
        fingerprint = derived["fingerprint"]

        self.log.info(f"Derived key at m/87'/1'/0': {xpub}")
        self.log.info(f"Origin: {origin}")

        # Verify fingerprint format (4 bytes = 8 hex chars)
        assert len(fingerprint) == 8

        # Create a watch-only wallet on node 1 with xpub
        self.nodes[1].createwallet(wallet_name="watcher", disable_private_keys=True)
        watcher = self.nodes[1].get_wallet_rpc("watcher")

        desc_receive = f"wpkh({origin}{xpub}/0/*)"
        desc_change = f"wpkh({origin}{xpub}/1/*)"

        result = watcher.importdescriptors([
            {"desc": descsum_create(desc_receive), "timestamp": "now", "active": True, "internal": False, "range": [0, 10]},
            {"desc": descsum_create(desc_change), "timestamp": "now", "active": True, "internal": True, "range": [0, 10]},
        ])
        assert result[0]["success"] and result[1]["success"]

        # Import the same descriptor with xprv into signer for signing capability
        desc_receive_priv = f"wpkh({origin}{xprv}/0/*)"
        desc_change_priv = f"wpkh({origin}{xprv}/1/*)"

        result = signer.importdescriptors([
            {"desc": descsum_create(desc_receive_priv), "timestamp": "now", "active": True, "internal": False, "range": [0, 10]},
            {"desc": descsum_create(desc_change_priv), "timestamp": "now", "active": True, "internal": True, "range": [0, 10]},
        ])
        assert result[0]["success"] and result[1]["success"]

        # Verify addresses match between signer and watcher
        signer_addr = signer.getnewaddress(address_type="bech32")
        watcher_addr = watcher.getnewaddress(address_type="bech32")
        assert_equal(signer_addr, watcher_addr)

        self.log.info("Export/import workflow verified successfully")

    def test_multisig_tutorial_workflow(self):
        """Test the complete 2-of-3 multisig workflow from doc/multisig-tutorial.md.

        This replicates the tutorial process to verify it works correctly:
        1. Create 3 participant wallets
        2. Extract xpubs at BIP 87 path using derivehdkey
        3. Create sortedmulti descriptor and watch-only multisig wallet
        4. Import multisig descriptor with xprv into participant wallets for signing
        5. Fund the multisig wallet
        6. Create, sign, combine, finalize, and broadcast a PSBT
        """
        self.log.info("Test complete 2-of-3 multisig workflow from tutorial")
        node = self.nodes[0]

        # Step 1: Create 3 participant wallets
        self.log.info("Creating 3 participant wallets")
        participants = []
        for n in range(1, 4):
            wallet_name = f"participant_{n}"
            node.createwallet(wallet_name)
            participants.append(node.get_wallet_rpc(wallet_name))

        # Step 2: Extract xpubs and xprvs at BIP 87 multisig path using derivehdkey
        self.log.info("Extracting keys at BIP 87 path m/87'/1'/0'")
        participant_keys = []
        xpub_with_origins = []
        for n, wallet in enumerate(participants, 1):
            result = wallet.derivehdkey("m/87'/1'/0'", {"private": True})
            origin = result["origin"]
            xpub = result["xpub"]
            xprv = result["xprv"]
            participant_keys.append({"origin": origin, "xpub": xpub, "xprv": xprv})
            # Format: [fingerprint/path]xpub/<0;1>/*
            xpub_with_origins.append(f"{origin}{xpub}/<0;1>/*")
            self.log.info(f"  Participant {n}: {origin}{xpub[:20]}...")

        # Step 3: Define the multisig descriptor and create watch-only wallet
        self.log.info("Creating 2-of-3 multisig descriptor")
        multisig_desc = f"wsh(sortedmulti(2,{xpub_with_origins[0]},{xpub_with_origins[1]},{xpub_with_origins[2]}))"
        multisig_desc_with_checksum = descsum_create(multisig_desc)
        self.log.info(f"  Descriptor: {multisig_desc[:60]}...")

        # Create watch-only multisig wallet
        self.log.info("Creating watch-only multisig wallet")
        node.createwallet(wallet_name="multisig_wallet", disable_private_keys=True, blank=True)
        multisig_wallet = node.get_wallet_rpc("multisig_wallet")

        # Import the descriptor
        result = multisig_wallet.importdescriptors([{
            "desc": multisig_desc_with_checksum,
            "active": True,
            "timestamp": "now",
        }])
        assert result[0]["success"], f"Failed to import descriptor: {result}"

        # Verify wallet info
        wallet_info = multisig_wallet.getwalletinfo()
        assert wallet_info["private_keys_enabled"] == False

        # Step 4: Import multisig descriptor with xprv into each participant wallet
        self.log.info("Importing multisig descriptor with xprv into participant wallets")
        for n, wallet in enumerate(participants):
            # Use the xprv we already extracted in Step 2
            origin = participant_keys[n]["origin"]
            xprv = participant_keys[n]["xprv"]

            # Build descriptor with this participant's xprv and other participants' xpubs
            keys = []
            for i in range(3):
                if i == n:
                    keys.append(f"{origin}{xprv}/<0;1>/*")
                else:
                    keys.append(xpub_with_origins[i])

            priv_desc = f"wsh(sortedmulti(2,{keys[0]},{keys[1]},{keys[2]}))"
            priv_desc_with_checksum = descsum_create(priv_desc)

            result = wallet.importdescriptors([{
                "desc": priv_desc_with_checksum,
                "timestamp": "now",
            }])
            assert result[0]["success"], f"Failed to import descriptor for participant {n+1}: {result}"
            self.log.info(f"  Participant {n+1}: descriptor imported")

        # Step 5: Fund the multisig wallet
        self.log.info("Funding the multisig wallet")
        receiving_address = multisig_wallet.getnewaddress()
        self.log.info(f"  Multisig address: {receiving_address}")

        # Send from node's default wallet (need to create one first)
        node.createwallet("funder")
        funder = node.get_wallet_rpc("funder")
        funder_address = funder.getnewaddress()
        self.generatetoaddress(node, 101, funder_address)  # Mine blocks to funder wallet

        # Send 1 BTC to multisig
        txid = funder.sendtoaddress(receiving_address, 1.0)
        self.log.info(f"  Funded with txid: {txid}")
        self.generatetoaddress(node, 1, funder_address)  # Confirm the transaction

        # Verify balance
        balance = multisig_wallet.getbalance()
        assert balance == 1.0, f"Expected balance 1.0, got {balance}"
        self.log.info(f"  Multisig wallet balance: {balance} BTC")

        # Step 6: Create a PSBT
        self.log.info("Creating PSBT")
        destination_addr = participants[0].getnewaddress()
        amount = 0.5

        funded_psbt = multisig_wallet.walletcreatefundedpsbt(
            inputs=[],
            outputs=[{destination_addr: amount}],
        )["psbt"]
        self.log.info(f"  Created PSBT: {funded_psbt[:40]}...")

        # Analyze PSBT - should need signatures
        analysis = node.analyzepsbt(funded_psbt)
        assert analysis["next"] == "signer", f"Expected next step 'signer', got {analysis['next']}"

        # Step 7: Sign with participants (parallel workflow - each signs the original)
        self.log.info("Signing PSBT with participants 1 and 2 (2-of-3)")
        psbt_1 = participants[0].walletprocesspsbt(funded_psbt)["psbt"]
        psbt_2 = participants[1].walletprocesspsbt(funded_psbt)["psbt"]

        # Verify partial signatures
        analysis_1 = node.analyzepsbt(psbt_1)
        analysis_2 = node.analyzepsbt(psbt_2)
        self.log.info(f"  After participant 1 signing: next={analysis_1['next']}")
        self.log.info(f"  After participant 2 signing: next={analysis_2['next']}")

        # Step 8: Combine PSBTs
        self.log.info("Combining PSBTs")
        combined_psbt = node.combinepsbt([psbt_1, psbt_2])

        # Verify combined PSBT is ready for finalization
        analysis_combined = node.analyzepsbt(combined_psbt)
        assert analysis_combined["next"] == "finalizer", f"Expected next step 'finalizer', got {analysis_combined['next']}"
        self.log.info(f"  Combined PSBT ready for finalization")

        # Step 9: Finalize and broadcast
        self.log.info("Finalizing and broadcasting")
        finalized = node.finalizepsbt(combined_psbt)
        assert finalized["complete"], "PSBT finalization failed"
        final_tx_hex = finalized["hex"]

        txid = node.sendrawtransaction(final_tx_hex)
        self.log.info(f"  Broadcast transaction: {txid}")

        # Mine the transaction
        self.generatetoaddress(node, 1, funder_address)

        # Verify the transaction was confirmed
        tx_info = multisig_wallet.gettransaction(txid)
        assert tx_info["confirmations"] >= 1, "Transaction not confirmed"

        # Verify balances changed
        new_balance = multisig_wallet.getbalance()
        assert new_balance < 1.0, f"Expected balance to decrease, got {new_balance}"
        self.log.info(f"  Final multisig balance: {new_balance} BTC")

        # Step 10: Test alternative sequential signing workflow
        self.log.info("Testing alternative sequential signing workflow")

        # Create another PSBT
        destination_addr_2 = participants[1].getnewaddress()
        remaining = float(new_balance) - 0.001  # Leave some for fee

        funded_psbt_2 = multisig_wallet.walletcreatefundedpsbt(
            inputs=[],
            outputs=[{destination_addr_2: round(remaining * 0.5, 8)}],
        )["psbt"]

        # Sequential signing: participant 1 signs, then participant 2 signs the result
        psbt_seq_1 = participants[0].walletprocesspsbt(funded_psbt_2)["psbt"]
        psbt_seq_2 = participants[1].walletprocesspsbt(psbt_seq_1)["psbt"]

        # Should be complete after 2 signatures (next is finalizer or extractor if auto-finalized)
        analysis_seq = node.analyzepsbt(psbt_seq_2)
        assert analysis_seq["next"] in ["finalizer", "extractor"], f"Expected next step 'finalizer' or 'extractor', got {analysis_seq['next']}"

        finalized_seq = node.finalizepsbt(psbt_seq_2)
        assert finalized_seq["complete"], "Sequential PSBT finalization failed"

        txid_seq = node.sendrawtransaction(finalized_seq["hex"])
        self.log.info(f"  Sequential workflow transaction: {txid_seq}")

        self.generatetoaddress(node, 1, funder_address)

        self.log.info("Multisig tutorial workflow completed successfully")


if __name__ == '__main__':
    WalletDeriveHDKeyTest(__file__).main()

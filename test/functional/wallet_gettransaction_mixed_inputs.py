#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Test wallet history RPC accounting for mixed-input transactions."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, find_vout_for_address


class WalletGetTransactionMixedInputsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_mixed_fields(self, entry, wallet_debit, wallet_credit):
        assert_equal(entry["involves_mixed_inputs"], True)
        assert_equal(entry["wallet_debit"], wallet_debit)
        assert_equal(entry["wallet_credit"], wallet_credit)
        assert_equal(entry["fee_known"], False)
        assert "fee" not in entry

    def assert_summary_entry(self, entry, txid, expected_amount, wallet_debit, wallet_credit, include_txid):
        if include_txid:
            assert_equal(entry["txid"], txid)
        assert_equal(entry["category"], "mixed")
        assert_equal(entry["amount"], expected_amount)
        assert "address" not in entry
        assert "vout" not in entry
        self.assert_mixed_fields(entry, wallet_debit, wallet_credit)

    def assert_receive_entry(self, entry, txid, address, vout, amount, wallet_debit, wallet_credit, include_txid):
        if include_txid:
            assert_equal(entry["txid"], txid)
        assert_equal(entry["category"], "receive")
        assert_equal(entry["address"], address)
        assert_equal(entry["vout"], vout)
        assert_equal(entry["amount"], amount)
        self.assert_mixed_fields(entry, wallet_debit, wallet_credit)

    def assert_mixed_history_entries(self, entries, txid, expected_net, address, vout, wallet_debit, wallet_credit, include_txid=True):
        """Check that a mixed-input transaction is reported as a mixed summary entry
        carrying the negative wallet debit plus a receive entry for the wallet-owned
        output (and nothing else), with entry amounts summing to the wallet net change."""
        assert_equal(len(entries), 2)
        assert_equal(any(entry["category"] == "send" for entry in entries), False)
        assert_equal(sum(entry["amount"] for entry in entries), expected_net)

        mixed_entries = [entry for entry in entries if entry["category"] == "mixed"]
        assert_equal(len(mixed_entries), 1)
        self.assert_summary_entry(mixed_entries[0], txid, -wallet_debit, wallet_debit, wallet_credit, include_txid=include_txid)

        receive_entries = [entry for entry in entries if entry["category"] == "receive"]
        assert_equal(len(receive_entries), 1)
        self.assert_receive_entry(receive_entries[0], txid, address, vout, wallet_credit, wallet_debit, wallet_credit, include_txid=include_txid)

    def assert_wallet_view(self, wallet_name, wallet, txid, label, address, vout, wallet_debit, wallet_credit, before_blockhash):
        expected_amount = wallet_credit - wallet_debit

        tx_info = wallet.gettransaction(txid)
        assert_equal(tx_info["amount"], expected_amount)
        self.assert_mixed_fields(tx_info, wallet_debit, wallet_credit)
        self.assert_mixed_history_entries(tx_info["details"], txid, expected_amount, address, vout, wallet_debit, wallet_credit, include_txid=False)

        history = [entry for entry in wallet.listtransactions("*", 100) if entry["txid"] == txid]
        self.assert_mixed_history_entries(history, txid, expected_amount, address, vout, wallet_debit, wallet_credit)

        labeled_history = [entry for entry in wallet.listtransactions(label, 100) if entry["txid"] == txid]
        assert_equal(len(labeled_history), 1)
        self.assert_receive_entry(labeled_history[0], txid, address, vout, wallet_credit, wallet_debit, wallet_credit, include_txid=True)

        since = [entry for entry in wallet.listsinceblock(before_blockhash)["transactions"] if entry["txid"] == txid]
        self.assert_mixed_history_entries(since, txid, expected_amount, address, vout, wallet_debit, wallet_credit)

        self.log.debug("%s mixed-input wallet net amount: %s", wallet_name, expected_amount)

    def run_test(self):
        node = self.nodes[0]
        funder = node.get_wallet_rpc(self.default_wallet_name)

        node.createwallet("alice")
        node.createwallet("bob")
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")

        node.generatetoaddress(101, funder.getnewaddress(), called_by_framework=True)

        funder.sendtoaddress(alice.getnewaddress(), Decimal("1.0"))
        funder.sendtoaddress(bob.getnewaddress(), Decimal("1.0"))
        node.generatetoaddress(1, funder.getnewaddress(), called_by_framework=True)
        before_mixed_input_blockhash = node.getbestblockhash()

        alice_input = alice.listunspent()[0]
        bob_input = bob.listunspent()[0]
        alice_credit = Decimal("1.50000000")
        bob_credit = Decimal("0.49998000")
        alice_label = "alice_mixed"
        bob_label = "bob_mixed"
        alice_output = alice.getnewaddress(alice_label)
        bob_output = bob.getnewaddress(bob_label)

        raw_tx = node.createrawtransaction(
            inputs=[
                {"txid": alice_input["txid"], "vout": alice_input["vout"]},
                {"txid": bob_input["txid"], "vout": bob_input["vout"]},
            ],
            outputs={
                alice_output: alice_credit,
                bob_output: bob_credit,
            },
        )
        raw_tx = alice.signrawtransactionwithwallet(raw_tx)["hex"]
        raw_tx = bob.signrawtransactionwithwallet(raw_tx)["hex"]

        txid = node.sendrawtransaction(raw_tx)
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getmempoolentry(txid)["fees"]["base"], Decimal("0.00002000"))

        alice_vout = find_vout_for_address(node, txid, alice_output)
        bob_vout = find_vout_for_address(node, txid, bob_output)

        for wallet_name, wallet, label, address, vout, wallet_debit, wallet_credit in [
            ("alice", alice, alice_label, alice_output, alice_vout, alice_input["amount"], alice_credit),
            ("bob", bob, bob_label, bob_output, bob_vout, bob_input["amount"], bob_credit),
        ]:
            self.assert_wallet_view(
                wallet_name=wallet_name,
                wallet=wallet,
                txid=txid,
                label=label,
                address=address,
                vout=vout,
                wallet_debit=wallet_debit,
                wallet_credit=wallet_credit,
                before_blockhash=before_mixed_input_blockhash,
            )

        node.generatetoaddress(1, funder.getnewaddress(), called_by_framework=True)

        for wallet_name, wallet, label, address, vout, wallet_debit, wallet_credit in [
            ("alice", alice, alice_label, alice_output, alice_vout, alice_input["amount"], alice_credit),
            ("bob", bob, bob_label, bob_output, bob_vout, bob_input["amount"], bob_credit),
        ]:
            self.assert_wallet_view(
                wallet_name=wallet_name,
                wallet=wallet,
                txid=txid,
                label=label,
                address=address,
                vout=vout,
                wallet_debit=wallet_debit,
                wallet_credit=wallet_credit,
                before_blockhash=before_mixed_input_blockhash,
            )

        self.log.info("Test reorged mixed-input transactions appear in listsinceblock removed entries")
        reorged_blockhash = node.getbestblockhash()
        node.invalidateblock(reorged_blockhash)
        node.generatetoaddress(2, funder.getnewaddress(), called_by_framework=True)
        node.syncwithvalidationinterfacequeue()

        for wallet, address, vout, wallet_debit, wallet_credit in [
            (alice, alice_output, alice_vout, alice_input["amount"], alice_credit),
            (bob, bob_output, bob_vout, bob_input["amount"], bob_credit),
        ]:
            expected_net = wallet_credit - wallet_debit
            since = wallet.listsinceblock(reorged_blockhash)
            removed = [entry for entry in since["removed"] if entry["txid"] == txid]
            self.assert_mixed_history_entries(removed, txid, expected_net, address, vout, wallet_debit, wallet_credit)
            reincluded = [entry for entry in since["transactions"] if entry["txid"] == txid]
            self.assert_mixed_history_entries(reincluded, txid, expected_net, address, vout, wallet_debit, wallet_credit)


if __name__ == '__main__':
    WalletGetTransactionMixedInputsTest(__file__).main()

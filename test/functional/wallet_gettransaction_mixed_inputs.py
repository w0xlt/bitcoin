#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Test wallet history RPC accounting for mixed-input transactions."""

from decimal import Decimal

from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    SEQUENCE_FINAL,
    tx_from_hex,
)
from test_framework.script import CScript, OP_RETURN
from test_framework.script_util import PAY_TO_ANCHOR
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, find_vout_for_address


class WalletGetTransactionMixedInputsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_mixed_fields(self, entry, wallet_debit, wallet_credit, fee_known=False):
        assert_equal(entry["involves_mixed_inputs"], True)
        assert_equal(entry["wallet_debit"], wallet_debit)
        assert_equal(entry["wallet_credit"], wallet_credit)
        assert_equal(entry["fee_known"], fee_known)
        if not fee_known:
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

    def script_for_address(self, wallet, address):
        return CScript(bytes.fromhex(wallet.getaddressinfo(address)["scriptPubKey"]))

    def assert_wallet_funded_mixed_input_view(self, wallet, txid, external_address, wallet_debit, external_amount, burn_amount, fee):
        wallet_credit = Decimal("0.00000000")
        expected_amount = -(external_amount + burn_amount)

        tx_info = wallet.gettransaction(txid)
        assert_equal(tx_info["amount"], expected_amount)
        assert_equal(tx_info["fee"], -fee)
        self.assert_mixed_fields(tx_info, wallet_debit, wallet_credit, fee_known=True)
        assert_equal(any(detail["category"] == "mixed" for detail in tx_info["details"]), False)

        send_details = [entry for entry in tx_info["details"] if entry["category"] == "send"]
        assert_equal(len(send_details), 2)
        external_details = [entry for entry in send_details if entry.get("address") == external_address]
        burn_details = [entry for entry in send_details if "address" not in entry]
        assert_equal(len(external_details), 1)
        assert_equal(len(burn_details), 1)

        for entry, amount in [(external_details[0], external_amount), (burn_details[0], burn_amount)]:
            assert_equal(entry["amount"], -amount)
            assert_equal(entry["fee"], -fee)
            self.assert_mixed_fields(entry, wallet_debit, wallet_credit, fee_known=True)

        history = [entry for entry in wallet.listtransactions("*", 100) if entry["txid"] == txid]
        assert_equal(len(history), 2)
        assert_equal(any(entry["category"] == "mixed" for entry in history), False)
        assert_equal(sum(entry["amount"] for entry in history), expected_amount)

    def test_zero_value_foreign_anchor_input(self, node, wallet, external_wallet):
        self.log.info("Test zero-value foreign anchor inputs keep wallet fee/send accounting attributable")
        wallet_input = next(utxo for utxo in wallet.listunspent() if utxo["amount"] >= Decimal("1.00000000"))
        wallet_debit = wallet_input["amount"]
        wallet_debit_sat = int(wallet_debit * COIN)
        fee_sat = 1000
        burn_sat = 1
        fee = Decimal(fee_sat) / COIN
        burn_amount = Decimal(burn_sat) / COIN
        external_amount = Decimal(wallet_debit_sat - fee_sat - burn_sat) / COIN

        parent_address = wallet.getrawchangeaddress()
        parent_script = self.script_for_address(wallet, parent_address)

        parent_tx = CTransaction()
        parent_tx.version = 3
        parent_tx.vin.append(CTxIn(COutPoint(int(wallet_input["txid"], 16), wallet_input["vout"]), b"", SEQUENCE_FINAL))
        parent_tx.vout.append(CTxOut(wallet_debit_sat, parent_script))
        parent_tx.vout.append(CTxOut(0, PAY_TO_ANCHOR))
        parent_signed = wallet.signrawtransactionwithwallet(parent_tx.serialize().hex())
        assert_equal(parent_signed["complete"], True)
        parent_hex = parent_signed["hex"]
        parent_tx = tx_from_hex(parent_hex)
        parent_txid = parent_tx.txid_hex

        external_address = external_wallet.getnewaddress()
        external_script = self.script_for_address(external_wallet, external_address)
        child_tx = CTransaction()
        child_tx.version = 3
        child_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), 0), b"", SEQUENCE_FINAL))
        child_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), 1), b"", SEQUENCE_FINAL))
        child_tx.vout.append(CTxOut(wallet_debit_sat - fee_sat - burn_sat, external_script))
        child_tx.vout.append(CTxOut(burn_sat, CScript([OP_RETURN])))
        child_signed = wallet.signrawtransactionwithwallet(child_tx.serialize().hex(), [
            {"txid": parent_txid, "vout": 0, "scriptPubKey": parent_script.hex(), "amount": wallet_debit},
            {"txid": parent_txid, "vout": 1, "scriptPubKey": PAY_TO_ANCHOR.hex(), "amount": Decimal("0.00000000")},
        ])
        assert_equal(child_signed["complete"], True)
        child_hex = child_signed["hex"]
        child_tx = tx_from_hex(child_hex)

        submit_res = node.submitpackage([parent_hex, child_hex], maxburnamount=burn_amount)
        assert_equal(submit_res["package_msg"], "success")
        node.syncwithvalidationinterfacequeue()

        self.assert_wallet_funded_mixed_input_view(wallet, child_tx.txid_hex, external_address, wallet_debit, external_amount, burn_amount, fee)
        node.generatetoaddress(1, external_wallet.getnewaddress(), called_by_framework=True)
        self.assert_wallet_funded_mixed_input_view(wallet, child_tx.txid_hex, external_address, wallet_debit, external_amount, burn_amount, fee)

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

        self.test_zero_value_foreign_anchor_input(node, alice, funder)
        self.test_known_nonzero_foreign_input(node, funder, alice, bob)

    def test_known_nonzero_foreign_input(self, node, funder, alice, bob):
        self.log.info("Test known nonzero foreign input values keep accounting conservative")
        # Refill alice, then have alice fund bob so that the funding transaction
        # of bob's input is in alice's wallet and its value is known to alice.
        funder.sendtoaddress(alice.getnewaddress(), Decimal("1.0"))
        node.generatetoaddress(1, funder.getnewaddress(), called_by_framework=True)
        bob_funding_txid = alice.sendtoaddress(bob.getnewaddress(), Decimal("0.3"))
        node.generatetoaddress(1, funder.getnewaddress(), called_by_framework=True)
        before_blockhash = node.getbestblockhash()

        # Premise: alice's wallet contains the transaction funding bob's input
        assert_equal(alice.gettransaction(bob_funding_txid)["txid"], bob_funding_txid)

        alice_credit = Decimal("0.2")
        fee = Decimal("0.00002000")
        alice_input = next(u for u in alice.listunspent() if u["amount"] >= alice_credit)
        bob_input = next(u for u in bob.listunspent() if u["txid"] == bob_funding_txid)
        bob_credit = alice_input["amount"] + bob_input["amount"] - alice_credit - fee

        label = "alice_known_foreign"
        alice_output = alice.getnewaddress(label)
        bob_output = bob.getnewaddress()

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
        assert_equal(node.getmempoolentry(txid)["fees"]["base"], fee)

        # Although alice's wallet can compute the total fee (it knows every
        # input value), the wallet's fee share is still unattributable, so
        # the transaction must be reported with the conservative mixed view.
        alice_vout = find_vout_for_address(node, txid, alice_output)
        self.assert_wallet_view(
            wallet_name="alice",
            wallet=alice,
            txid=txid,
            label=label,
            address=alice_output,
            vout=alice_vout,
            wallet_debit=alice_input["amount"],
            wallet_credit=alice_credit,
            before_blockhash=before_blockhash,
        )

        node.generatetoaddress(1, funder.getnewaddress(), called_by_framework=True)
        self.assert_wallet_view(
            wallet_name="alice",
            wallet=alice,
            txid=txid,
            label=label,
            address=alice_output,
            vout=alice_vout,
            wallet_debit=alice_input["amount"],
            wallet_credit=alice_credit,
            before_blockhash=before_blockhash,
        )


if __name__ == '__main__':
    WalletGetTransactionMixedInputsTest(__file__).main()

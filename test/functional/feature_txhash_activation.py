#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP346 OP_TXHASH versionbits activation transition on regtest."""

from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_DROP,
    OP_TRUE,
    OP_TXHASH,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_not_equal,
)
from test_framework.wallet import MiniWallet


class TxHashActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            '-vbparams=txhash:0:9223372036854775807:0',
        ]]

    def create_txhash_funding_tx(self, amount_sat=50_000, fee_sat=1_000):
        utxo = self.wallet.get_utxo(confirmed_only=True)
        input_value = int(utxo["value"] * COIN)
        change_value = input_value - amount_sat - fee_sat
        assert change_value > 0

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [
            CTxOut(change_value, self.wallet.get_output_script()),
            CTxOut(amount_sat, self.txhash_taproot.scriptPubKey),
        ]
        self.wallet.sign_tx(tx)
        return tx

    def create_txhash_spend(self, funding_tx, *, selector):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, 1))]
        tx.vout = [CTxOut(funding_tx.vout[1].nValue - 500, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]

        witness_stack = []
        if selector is not None:
            witness_stack.append(selector)
        witness_stack.extend([self.txhash_leaf.script, self.txhash_control_block])
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack

        return tx

    def submit_test_block(self, txs):
        block = create_block(tmpl=self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS), txlist=txs)
        add_witness_commitment(block)
        block.solve()
        return block, self.nodes[0].submitblock(block.serialize().hex())

    def assert_txhash_deployment(self, *, status, status_next, active):
        deployment = self.nodes[0].getdeploymentinfo()["deployments"]["txhash"]
        assert_equal(deployment["bip9"]["status"], status)
        assert_equal(deployment["bip9"]["status_next"], status_next)
        assert_equal(deployment["active"], active)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.txhash_taproot = taproot_construct((1).to_bytes(32, "big"), [("txhash", CScript([OP_TXHASH, OP_DROP, OP_TRUE]))])
        self.txhash_leaf = self.txhash_taproot.leaves["txhash"]
        self.txhash_control_block = bytes([self.txhash_leaf.version | self.txhash_taproot.negflag]) + self.txhash_taproot.internal_pubkey + self.txhash_leaf.merklebranch

        self.log.info("Mine to the last tip where txhash is not yet active")
        self.generate(self.wallet, 430)
        assert_equal(self.nodes[0].getblockcount(), 430)
        self.assert_txhash_deployment(status="locked_in", status_next="locked_in", active=False)

        self.log.info("Pre-activation: OP_TXHASH behaves as OP_SUCCESS and missing selector is accepted")
        pre_funding = self.create_txhash_funding_tx()
        pre_spend = self.create_txhash_spend(pre_funding, selector=None)
        pre_block, pre_result = self.submit_test_block([pre_funding, pre_spend])
        assert_equal(pre_result, None)
        assert_equal(self.nodes[0].getbestblockhash(), pre_block.hash_hex)
        self.assert_txhash_deployment(status="locked_in", status_next="active", active=True)

        self.log.info("Post-activation: OP_TXHASH requires selector and missing-selector spend fails")
        self.wallet.rescan_utxos()
        post_funding_fail = self.create_txhash_funding_tx()
        post_spend_fail = self.create_txhash_spend(post_funding_fail, selector=None)
        tip_before = self.nodes[0].getbestblockhash()
        _, fail_result = self.submit_test_block([post_funding_fail, post_spend_fail])
        assert_not_equal(fail_result, None)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)

        self.log.info("Post-activation: valid selector makes OP_TXHASH spend succeed")
        self.wallet.rescan_utxos()
        post_funding_ok = self.create_txhash_funding_tx()
        post_spend_ok = self.create_txhash_spend(post_funding_ok, selector=b"")
        post_block, post_result = self.submit_test_block([post_funding_ok, post_spend_ok])
        assert_equal(post_result, None)
        assert_equal(self.nodes[0].getbestblockhash(), post_block.hash_hex)
        self.assert_txhash_deployment(status="active", status_next="active", active=True)


if __name__ == '__main__':
    TxHashActivationTest(__file__).main()

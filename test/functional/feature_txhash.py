#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP346 OP_TXHASH covenant enforcement on regtest.

Exercises real covenant behavior: vaults, congestion control, crowdfunding,
LN-style channel closes, and invalid selector rejection.
"""

import hashlib
import struct

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
    OP_EQUALVERIFY,
    OP_TRUE,
    OP_TXHASH,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


# ===== TXFS constants (BIP 346, mirrors src/script/txhash.h) =====

# Byte 0: Global field flags
TXFS_VERSION                              = 0x01
TXFS_LOCKTIME                             = 0x02
TXFS_CURRENT_INPUT_IDX                    = 0x04
TXFS_CURRENT_INPUT_CONTROL_BLOCK          = 0x08
TXFS_CURRENT_INPUT_SPENTSCRIPT            = 0x10
TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS = 0x20
TXFS_CURRENT_INPUT_TAPROOT_ANNEX          = 0x40
TXFS_CONTROL                              = 0x80

# Byte 1: Input/output field flags
TXFS_INPUTS_PREVOUTS          = 0x01
TXFS_INPUTS_SEQUENCES         = 0x02
TXFS_INPUTS_SCRIPTSIGS        = 0x04
TXFS_INPUTS_PREV_SCRIPTPUBKEYS = 0x08
TXFS_INPUTS_PREV_VALUES       = 0x10
TXFS_INPUTS_TAPROOT_ANNEXES   = 0x20
TXFS_OUTPUTS_SCRIPTPUBKEYS    = 0x40
TXFS_OUTPUTS_VALUES           = 0x80

# In/out selector byte flags
TXFS_INOUT_NUMBER         = 0x80
TXFS_INOUT_SELECTION_NONE = 0x00
TXFS_INOUT_SELECTION_ALL  = 0x3F
TXFS_INOUT_SELECTION_CURRENT = 0x40

# Empty selector resolves to this 4-byte template (CTV-equivalent)
TXFS_SPECIAL_TEMPLATE = bytes([0x07, 0xC6, 0xBF, 0xBF])

SHA256_EMPTY = hashlib.sha256(b"").digest()

# Expected submitblock error strings
EQUALVERIFY_ERROR = "block-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
INVALID_SELECTOR_ERROR = "block-script-verify-flag-failed (Invalid TxFieldSelector for OP_TXHASH)"


# ===== Serialization helpers =====

def sha256(data):
    """Single SHA256 hash."""
    return hashlib.sha256(data).digest()


def ser_int32(n):
    return struct.pack("<i", n)


def ser_uint32(n):
    return struct.pack("<I", n)


def ser_int64(n):
    return struct.pack("<q", n)


# ===== TxFieldSelector parser =====

def parse_inout_selector(resolved, pos, nb_items, in_pos):
    """Parse one input/output selector byte from the resolved TxFieldSelector.

    Returns (commit_count, selected_indices, new_pos).
    Returns (None, None, pos) on parse error.
    """
    if pos >= len(resolved):
        return False, [], pos

    first = resolved[pos]
    pos += 1

    commit_count = (first & TXFS_INOUT_NUMBER) != 0
    selection = first & ~TXFS_INOUT_NUMBER  # mask out bit 7

    if selection == TXFS_INOUT_SELECTION_NONE:
        return commit_count, [], pos
    elif selection == TXFS_INOUT_SELECTION_ALL:
        return commit_count, list(range(nb_items)), pos
    elif selection == TXFS_INOUT_SELECTION_CURRENT:
        if in_pos >= nb_items:
            return None, None, pos
        return commit_count, [in_pos], pos
    else:
        # Leading/individual modes — not needed for these tests
        return None, None, pos


# ===== Python port of calculate_txhash (src/script/txhash.cpp:442-743) =====

def calculate_txhash(tx, prevout_outputs, selector, in_pos,
                     codeseparator_pos=0xFFFFFFFF):
    """Compute the BIP 346 TransactionHash.

    Simplified Python port supporting empty selector (TXFS_SPECIAL_TEMPLATE)
    and multi-byte selectors with NONE/ALL/CURRENT selection modes.

    control_block, spent_script, and annex bits emit SHA256_EMPTY
    (none of the functional tests exercise those fields).
    """
    # 0. Resolve selector
    if len(selector) == 0:
        resolved = TXFS_SPECIAL_TEMPLATE
    else:
        resolved = bytes(selector)

    outer = hashlib.sha256()
    global_flags = resolved[0]

    # 1. CONTROL — include the raw TxFieldSelector bytes
    if global_flags & TXFS_CONTROL:
        outer.update(resolved)

    # 2. VERSION (int32 LE)
    if global_flags & TXFS_VERSION:
        outer.update(ser_int32(tx.version))

    # 3. LOCKTIME (uint32 LE)
    if global_flags & TXFS_LOCKTIME:
        outer.update(ser_uint32(tx.nLockTime))

    # 4. CURRENT_INPUT_IDX (uint32 LE)
    if global_flags & TXFS_CURRENT_INPUT_IDX:
        outer.update(ser_uint32(in_pos))

    # 5. CURRENT_INPUT_CONTROL_BLOCK (simplified → SHA256_EMPTY)
    if global_flags & TXFS_CURRENT_INPUT_CONTROL_BLOCK:
        outer.update(SHA256_EMPTY)

    # 6. CURRENT_INPUT_SPENTSCRIPT (simplified → SHA256_EMPTY)
    if global_flags & TXFS_CURRENT_INPUT_SPENTSCRIPT:
        outer.update(SHA256_EMPTY)

    # 7. CODESEPARATOR_POS (uint32 LE)
    if global_flags & TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS:
        outer.update(ser_uint32(codeseparator_pos))

    # 8. CURRENT_INPUT_TAPROOT_ANNEX (simplified → SHA256_EMPTY)
    if global_flags & TXFS_CURRENT_INPUT_TAPROOT_ANNEX:
        outer.update(SHA256_EMPTY)

    # ── Parse remaining bytes ──
    pos = 1
    inout_fields = 0
    if pos < len(resolved):
        inout_fields = resolved[pos]
        pos += 1

    # === INPUTS ===
    num_inputs = len(tx.vin)
    commit_num_inputs = False
    input_selected = []
    if pos < len(resolved):
        commit_num_inputs, input_selected, pos = parse_inout_selector(
            resolved, pos, num_inputs, in_pos)
        if commit_num_inputs is None:
            return None  # parse error

    if commit_num_inputs:
        outer.update(ser_uint32(num_inputs))

    if input_selected:
        if inout_fields & TXFS_INPUTS_PREVOUTS:
            inner = hashlib.sha256()
            for idx in input_selected:
                inner.update(tx.vin[idx].prevout.serialize())
            outer.update(inner.digest())

        if inout_fields & TXFS_INPUTS_SEQUENCES:
            inner = hashlib.sha256()
            for idx in input_selected:
                inner.update(ser_uint32(tx.vin[idx].nSequence))
            outer.update(inner.digest())

        if inout_fields & TXFS_INPUTS_SCRIPTSIGS:
            inner = hashlib.sha256()
            for idx in input_selected:
                inner.update(sha256(bytes(tx.vin[idx].scriptSig)))
            outer.update(inner.digest())

        if inout_fields & TXFS_INPUTS_PREV_SCRIPTPUBKEYS:
            inner = hashlib.sha256()
            for idx in input_selected:
                inner.update(sha256(bytes(prevout_outputs[idx].scriptPubKey)))
            outer.update(inner.digest())

        if inout_fields & TXFS_INPUTS_PREV_VALUES:
            inner = hashlib.sha256()
            for idx in input_selected:
                inner.update(ser_int64(prevout_outputs[idx].nValue))
            outer.update(inner.digest())

        if inout_fields & TXFS_INPUTS_TAPROOT_ANNEXES:
            inner = hashlib.sha256()
            for idx in input_selected:
                inner.update(SHA256_EMPTY)  # simplified
            outer.update(inner.digest())

    # === OUTPUTS ===
    num_outputs = len(tx.vout)
    commit_num_outputs = False
    output_selected = []
    if pos < len(resolved):
        commit_num_outputs, output_selected, pos = parse_inout_selector(
            resolved, pos, num_outputs, in_pos)
        if commit_num_outputs is None:
            return None  # parse error

    if commit_num_outputs:
        outer.update(ser_uint32(num_outputs))

    if output_selected:
        if inout_fields & TXFS_OUTPUTS_SCRIPTPUBKEYS:
            inner = hashlib.sha256()
            for idx in output_selected:
                inner.update(sha256(bytes(tx.vout[idx].scriptPubKey)))
            outer.update(inner.digest())

        if inout_fields & TXFS_OUTPUTS_VALUES:
            inner = hashlib.sha256()
            for idx in output_selected:
                inner.update(ser_int64(tx.vout[idx].nValue))
            outer.update(inner.digest())

    # Trailing bytes → invalid selector
    if pos < len(resolved):
        return None

    return outer.digest()


# ===== Test class =====

class TxHashFunctionalTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # regtest has txhash ALWAYS_ACTIVE — no special vbparams needed

    # ── Helpers ──

    def create_funding_tx(self, taproot_spk, amount=50_000):
        """Fund a taproot UTXO via MiniWallet."""
        utxo = self.wallet.get_utxo(confirmed_only=True)
        input_value = int(utxo["value"] * COIN)
        fee = 1_000
        change_value = input_value - amount - fee
        assert change_value > 0

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [
            CTxOut(change_value, self.wallet.get_output_script()),
            CTxOut(amount, taproot_spk),
        ]
        self.wallet.sign_tx(tx)
        return tx

    def create_spend_tx(self, funding_tx, leaf, control_block, outputs,
                        selector):
        """Build a script-path spend of a covenant UTXO (funding vout[1])."""
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, 1))]
        tx.vout = outputs
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            selector, leaf.script, control_block,
        ]
        return tx

    def submit_block(self, txs):
        """Mine a block containing the given transactions.

        Returns (block, submitblock_result).  result is None on success.
        """
        block = create_block(
            tmpl=self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS),
            txlist=txs,
        )
        add_witness_commitment(block)
        block.solve()
        return block, self.nodes[0].submitblock(block.serialize().hex())

    def make_taproot(self, leaves):
        """Construct a taproot output.  *leaves*: list of (name, CScript)."""
        return taproot_construct((1).to_bytes(32, "big"), leaves)

    def get_leaf_and_cb(self, taproot, name):
        """Return (leaf, control_block) for the named leaf."""
        leaf = taproot.leaves[name]
        cb = (bytes([leaf.version | taproot.negflag])
              + taproot.internal_pubkey + leaf.merklebranch)
        return leaf, cb

    # ── Test methods ──

    def test_empty_selector_covenant(self):
        """CTV-equivalent template enforcement using empty selector."""
        self.log.info("Test 1: Empty selector covenant (CTV-equivalent)")
        self.wallet.rescan_utxos()

        output_spk = self.wallet.get_output_script()
        funding_amount = 50_000
        spend_fee = 500
        output_value = funding_amount - spend_fee

        # Build a template tx to compute the expected hash
        template_tx = CTransaction()
        template_tx.vin = [CTxIn()]  # nSequence=0, scriptSig=b""
        template_tx.vout = [CTxOut(output_value, output_spk)]
        expected_hash = calculate_txhash(template_tx, [], b"", in_pos=0)

        # Build covenant taproot
        script = CScript([OP_TXHASH, expected_hash, OP_EQUALVERIFY, OP_TRUE])
        taproot = self.make_taproot([("cov", script)])
        leaf, cb = self.get_leaf_and_cb(taproot, "cov")

        # SUCCESS: exact template match
        funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(funding.txid_int, 1))]
        spend.vout = [CTxOut(output_value, output_spk)]
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [b"", leaf.script, cb]

        block, result = self.submit_block([funding, spend])
        assert_equal(result, None)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
        self.log.info("  Success: template-matching spend accepted")

        # FAILURE: different output value
        self.wallet.rescan_utxos()
        bad_funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        bad_spend = CTransaction()
        bad_spend.vin = [CTxIn(COutPoint(bad_funding.txid_int, 1))]
        bad_spend.vout = [CTxOut(output_value - 100, output_spk)]  # wrong
        bad_spend.wit.vtxinwit = [CTxInWitness()]
        bad_spend.wit.vtxinwit[0].scriptWitness.stack = [b"", leaf.script, cb]

        tip_before = self.nodes[0].getbestblockhash()
        _, fail_result = self.submit_block([bad_funding, bad_spend])
        assert_equal(fail_result, EQUALVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)
        self.log.info("  Rejected (%s)", fail_result)

    def test_output_only_covenant(self):
        """Enforce outputs only — inputs are free to vary."""
        self.log.info("Test 2: Output-only covenant")
        self.wallet.rescan_utxos()

        output_spk = self.wallet.get_output_script()
        funding_amount = 50_000
        output_value = funding_amount - 500

        # Selector: no globals, output spks+values, input=NONE, output=ALL
        selector = bytes([
            0x00,
            TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES,
            TXFS_INOUT_SELECTION_NONE,
            TXFS_INOUT_SELECTION_ALL,
        ])

        template_tx = CTransaction()
        template_tx.vin = [CTxIn()]
        template_tx.vout = [CTxOut(output_value, output_spk)]
        expected_hash = calculate_txhash(template_tx, [], selector, in_pos=0)

        script = CScript([OP_TXHASH, expected_hash, OP_EQUALVERIFY, OP_TRUE])
        taproot = self.make_taproot([("cov", script)])
        leaf, cb = self.get_leaf_and_cb(taproot, "cov")

        # SUCCESS
        funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        spend = self.create_spend_tx(
            funding, leaf, cb, [CTxOut(output_value, output_spk)], selector)
        block, result = self.submit_block([funding, spend])
        assert_equal(result, None)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
        self.log.info("  Success: correct outputs accepted")

        # FAILURE: different scriptPubKey
        self.wallet.rescan_utxos()
        bad_funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        bad_spend = self.create_spend_tx(
            bad_funding, leaf, cb,
            [CTxOut(output_value, CScript([OP_TRUE]))], selector)  # wrong spk
        tip_before = self.nodes[0].getbestblockhash()
        _, fail_result = self.submit_block([bad_funding, bad_spend])
        assert_equal(fail_result, EQUALVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)
        self.log.info("  Rejected (%s)", fail_result)

    def test_invalid_selector_rejection(self):
        """Invalid TxFieldSelector with trailing bytes is rejected."""
        self.log.info("Test 3: Invalid selector rejection")
        self.wallet.rescan_utxos()

        # Script that accepts any hash — only the selector validity matters
        script = CScript([OP_TXHASH, OP_DROP, OP_TRUE])
        taproot = self.make_taproot([("test", script)])
        leaf, cb = self.get_leaf_and_cb(taproot, "test")

        funding = self.create_funding_tx(taproot.scriptPubKey)
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(funding.txid_int, 1))]
        spend.vout = [CTxOut(funding.vout[1].nValue - 500,
                             self.wallet.get_output_script())]
        spend.wit.vtxinwit = [CTxInWitness()]
        # 5 bytes: valid 4-byte selector + 1 trailing garbage byte
        invalid_selector = bytes([0xFF, 0xFF, 0x3F, 0x3F, 0x00])
        spend.wit.vtxinwit[0].scriptWitness.stack = [
            invalid_selector, leaf.script, cb,
        ]

        tip_before = self.nodes[0].getbestblockhash()
        _, result = self.submit_block([funding, spend])
        assert_equal(result, INVALID_SELECTOR_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)
        self.log.info("  Rejected (%s)", result)

    def test_vault(self):
        """Vault: enforced withdrawal to a predetermined address."""
        self.log.info("Test 4: Vault covenant")
        self.wallet.rescan_utxos()

        vault_dest = self.wallet.get_output_script()
        funding_amount = 50_000
        output_value = funding_amount - 500

        # Selector: outputs ALL + commit count, nothing else
        selector = bytes([
            0x00,
            TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES,
            TXFS_INOUT_SELECTION_NONE,
            TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
        ])

        template_tx = CTransaction()
        template_tx.vin = [CTxIn()]
        template_tx.vout = [CTxOut(output_value, vault_dest)]
        expected_hash = calculate_txhash(template_tx, [], selector, in_pos=0)

        script = CScript([OP_TXHASH, expected_hash, OP_EQUALVERIFY, OP_TRUE])
        taproot = self.make_taproot([("vault", script)])
        leaf, cb = self.get_leaf_and_cb(taproot, "vault")

        # SUCCESS: withdraw to vault destination
        funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        spend = self.create_spend_tx(
            funding, leaf, cb, [CTxOut(output_value, vault_dest)], selector)
        block, result = self.submit_block([funding, spend])
        assert_equal(result, None)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
        self.log.info("  Success: withdrawal to vault destination accepted")

        # FAILURE: divert to attacker address
        self.wallet.rescan_utxos()
        bad_funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        bad_spend = self.create_spend_tx(
            bad_funding, leaf, cb,
            [CTxOut(output_value, CScript([OP_TRUE]))], selector)
        tip_before = self.nodes[0].getbestblockhash()
        _, fail_result = self.submit_block([bad_funding, bad_spend])
        assert_equal(fail_result, EQUALVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)
        self.log.info("  Rejected (%s)", fail_result)

    def test_congestion_control(self):
        """Batched payout: one UTXO expands into exactly 3 outputs."""
        self.log.info("Test 5: Congestion control (3-output expansion)")
        self.wallet.rescan_utxos()

        output_spk = self.wallet.get_output_script()
        funding_amount = 50_000
        per_output = (funding_amount - 500) // 3
        outputs = [
            CTxOut(per_output, output_spk),
            CTxOut(per_output, output_spk),
            CTxOut(per_output, output_spk),
        ]

        # Empty selector → CTV-like template (commits to output count)
        template_tx = CTransaction()
        template_tx.vin = [CTxIn()]
        template_tx.vout = outputs
        expected_hash = calculate_txhash(template_tx, [], b"", in_pos=0)

        script = CScript([OP_TXHASH, expected_hash, OP_EQUALVERIFY, OP_TRUE])
        taproot = self.make_taproot([("expand", script)])
        leaf, cb = self.get_leaf_and_cb(taproot, "expand")

        # SUCCESS: 3 correct outputs
        funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(funding.txid_int, 1))]
        spend.vout = outputs
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [b"", leaf.script, cb]

        block, result = self.submit_block([funding, spend])
        assert_equal(result, None)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
        self.log.info("  Success: 3-output expansion accepted")

        # FAILURE: only 2 outputs (template mismatch)
        self.wallet.rescan_utxos()
        bad_funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        bad_spend = CTransaction()
        bad_spend.vin = [CTxIn(COutPoint(bad_funding.txid_int, 1))]
        bad_spend.vout = outputs[:2]
        bad_spend.wit.vtxinwit = [CTxInWitness()]
        bad_spend.wit.vtxinwit[0].scriptWitness.stack = [b"", leaf.script, cb]

        tip_before = self.nodes[0].getbestblockhash()
        _, fail_result = self.submit_block([bad_funding, bad_spend])
        assert_equal(fail_result, EQUALVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)
        self.log.info("  Rejected (%s)", fail_result)

    def test_crowdfunding(self):
        """ANYONECANPAY-like: multiple inputs, enforced outputs."""
        self.log.info("Test 6: Crowdfunding (multi-input, output-enforced)")
        self.wallet.rescan_utxos()

        output_spk = self.wallet.get_output_script()
        funding_amount = 30_000

        # Output-only selector (no globals, no inputs, all outputs)
        selector = bytes([
            0x00,
            TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES,
            TXFS_INOUT_SELECTION_NONE,
            TXFS_INOUT_SELECTION_ALL,
        ])

        enforced_value = (funding_amount * 2) - 1_000
        enforced_outputs = [CTxOut(enforced_value, output_spk)]

        # Hash only depends on outputs — input count doesn't matter
        template_tx = CTransaction()
        template_tx.vin = [CTxIn()]
        template_tx.vout = enforced_outputs
        expected_hash = calculate_txhash(template_tx, [], selector, in_pos=0)

        script = CScript([OP_TXHASH, expected_hash, OP_EQUALVERIFY, OP_TRUE])
        taproot = self.make_taproot([("fund", script)])
        leaf, cb = self.get_leaf_and_cb(taproot, "fund")

        # Mine 2 funding UTXOs in separate blocks
        funding1 = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        block1, r1 = self.submit_block([funding1])
        assert_equal(r1, None)

        self.wallet.rescan_utxos()
        funding2 = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        block2, r2 = self.submit_block([funding2])
        assert_equal(r2, None)

        # SUCCESS: 2-input spend with enforced output
        spend = CTransaction()
        spend.vin = [
            CTxIn(COutPoint(funding1.txid_int, 1)),
            CTxIn(COutPoint(funding2.txid_int, 1)),
        ]
        spend.vout = enforced_outputs
        spend.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [selector, leaf.script, cb]
        spend.wit.vtxinwit[1].scriptWitness.stack = [selector, leaf.script, cb]

        block, result = self.submit_block([spend])
        assert_equal(result, None)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
        self.log.info("  Success: 2-input crowdfunding spend accepted")

        # FAILURE: wrong output value
        self.wallet.rescan_utxos()
        bad_funding1 = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        b1, _ = self.submit_block([bad_funding1])
        self.wallet.rescan_utxos()
        bad_funding2 = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        b2, _ = self.submit_block([bad_funding2])

        bad_spend = CTransaction()
        bad_spend.vin = [
            CTxIn(COutPoint(bad_funding1.txid_int, 1)),
            CTxIn(COutPoint(bad_funding2.txid_int, 1)),
        ]
        bad_spend.vout = [CTxOut(enforced_value - 100, output_spk)]  # wrong
        bad_spend.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        bad_spend.wit.vtxinwit[0].scriptWitness.stack = [
            selector, leaf.script, cb]
        bad_spend.wit.vtxinwit[1].scriptWitness.stack = [
            selector, leaf.script, cb]

        tip_before = self.nodes[0].getbestblockhash()
        _, fail_result = self.submit_block([bad_spend])
        assert_equal(fail_result, EQUALVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)
        self.log.info("  Rejected (%s)", fail_result)

    def test_ln_channel_close(self):
        """Two-leaf tapscript tree: either party can close with their split."""
        self.log.info("Test 7: LN-style channel close (two-leaf tapscript)")
        self.wallet.rescan_utxos()

        output_spk = self.wallet.get_output_script()
        funding_amount = 50_000
        alice_gets = 30_000
        bob_gets = 19_000  # funding_amount - alice_gets - 1_000 fee

        # Output-only selector
        selector = bytes([
            0x00,
            TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES,
            TXFS_INOUT_SELECTION_NONE,
            TXFS_INOUT_SELECTION_ALL,
        ])

        # Alice's close: Alice gets more
        alice_outputs = [
            CTxOut(alice_gets, output_spk),
            CTxOut(bob_gets, output_spk),
        ]
        tmpl_a = CTransaction()
        tmpl_a.vin = [CTxIn()]
        tmpl_a.vout = alice_outputs
        hash_a = calculate_txhash(tmpl_a, [], selector, in_pos=0)

        # Bob's close: Bob gets more
        bob_outputs = [
            CTxOut(bob_gets, output_spk),
            CTxOut(alice_gets, output_spk),
        ]
        tmpl_b = CTransaction()
        tmpl_b.vin = [CTxIn()]
        tmpl_b.vout = bob_outputs
        hash_b = calculate_txhash(tmpl_b, [], selector, in_pos=0)

        alice_script = CScript([OP_TXHASH, hash_a, OP_EQUALVERIFY, OP_TRUE])
        bob_script = CScript([OP_TXHASH, hash_b, OP_EQUALVERIFY, OP_TRUE])
        taproot = self.make_taproot([
            ("alice", alice_script), ("bob", bob_script),
        ])
        alice_leaf, alice_cb = self.get_leaf_and_cb(taproot, "alice")

        # SUCCESS: Alice closes with her leaf + correct outputs
        funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        spend = self.create_spend_tx(
            funding, alice_leaf, alice_cb, alice_outputs, selector)
        block, result = self.submit_block([funding, spend])
        assert_equal(result, None)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
        self.log.info("  Success: Alice's close accepted")

        # FAILURE: Alice's leaf + Bob's outputs
        self.wallet.rescan_utxos()
        bad_funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)
        bad_spend = self.create_spend_tx(
            bad_funding, alice_leaf, alice_cb, bob_outputs, selector)
        tip_before = self.nodes[0].getbestblockhash()
        _, fail_result = self.submit_block([bad_funding, bad_spend])
        assert_equal(fail_result, EQUALVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)
        self.log.info("  Rejected (%s)", fail_result)

    def test_prevout_circular_dependency(self):
        """Hashing own prevout creates an unspendable covenant.

        Demonstrates the circular dependency: to compute expected_hash we
        need the funding txid, but the funding txid depends on the taproot
        address, which depends on expected_hash.  Any dummy prevout used at
        creation time will mismatch the real prevout at spend time.
        """
        self.log.info("Test 8: Prevout circular dependency (unspendable)")
        self.wallet.rescan_utxos()

        output_spk = self.wallet.get_output_script()
        funding_amount = 50_000
        output_value = funding_amount - 500

        # Selector identical to the output-only one (Test 2) but with
        # PREVOUTS bit turned ON — this single bit is what breaks it.
        selector = bytes([
            0x00,
            TXFS_INPUTS_PREVOUTS | TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES,
            TXFS_INOUT_SELECTION_ALL,   # ALL inputs (hashes prevouts)
            TXFS_INOUT_SELECTION_ALL,   # ALL outputs
        ])

        # We don't know the funding txid yet (it depends on the taproot
        # address, which depends on the hash we're computing now).
        # Use a dummy prevout — any value here will be wrong.
        dummy_tx = CTransaction()
        dummy_tx.vin = [CTxIn(COutPoint(0, 0))]   # dummy prevout
        dummy_tx.vout = [CTxOut(output_value, output_spk)]
        expected_hash = calculate_txhash(dummy_tx, [], selector, in_pos=0)

        # Build the covenant with the hash derived from the dummy prevout
        script = CScript([OP_TXHASH, expected_hash, OP_EQUALVERIFY, OP_TRUE])
        taproot = self.make_taproot([("cov", script)])
        leaf, cb = self.get_leaf_and_cb(taproot, "cov")

        # Fund the covenant — the REAL prevout is now (funding.txid, vout=1),
        # which is definitely not (0x00..00, 0).
        funding = self.create_funding_tx(taproot.scriptPubKey, funding_amount)

        # Attempt to spend: OP_TXHASH hashes the REAL prevout, producing a
        # different hash than expected_hash → OP_EQUALVERIFY fails.
        spend = self.create_spend_tx(
            funding, leaf, cb, [CTxOut(output_value, output_spk)], selector)

        tip_before = self.nodes[0].getbestblockhash()
        _, result = self.submit_block([funding, spend])
        assert_equal(result, EQUALVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip_before)
        self.log.info("  Rejected (%s)", result)
        self.log.info("  (circular dependency: real prevout differs from dummy)")

    # ── Main ──

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 200)

        self.test_empty_selector_covenant()
        self.test_output_only_covenant()
        self.test_invalid_selector_rejection()
        self.test_vault()
        self.test_congestion_control()
        self.test_crowdfunding()
        self.test_ln_channel_close()
        self.test_prevout_circular_dependency()


if __name__ == "__main__":
    TxHashFunctionalTest(__file__).main()

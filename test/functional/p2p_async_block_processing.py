#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test asynchronous P2P block completion, FIFO resumption and full-block fallback.

The source peer's PING is a completion barrier. A different peer's PONG is not:
unit tests use explicit lock gates to check progress while validation is paused.
"""

from copy import deepcopy

from test_framework.blocktools import create_empty_fork
from test_framework.messages import (
    CBlockHeader,
    HeaderAndShortIDs,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    msg_block,
    msg_cmpctblock,
    msg_headers,
    msg_sendcmpct,
    msg_tx,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_not_equal
from test_framework.wallet import MiniWallet


class AsyncBlockProcessingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 101)
        source = node.add_p2p_connection(P2PInterface())

        self.log.info("Resume queued duplicate blocks, transactions and headers")
        blocks = create_empty_fork(node, fork_length=4)
        tx = wallet.create_self_transfer()
        for block in [blocks[0], blocks[0], blocks[1], blocks[2]]:
            source.send_without_ping(msg_block(block))
        source.send_without_ping(msg_tx(tx["tx"]))
        source.send_without_ping(msg_headers([CBlockHeader(blocks[3])]))
        source.sync_with_ping()
        assert_equal(node.getbestblockhash(), blocks[2].hash_hex)
        assert tx["txid"] in node.getrawmempool()
        assert_equal(node.getblockheader(blocks[3].hash_hex)["confirmations"], -1)
        for block in blocks[:3]:
            assert_equal(node.getblock(block.hash_hex, 0), block.serialize().hex())

        self.log.info("Accept valid blocks after worker-invalid and mutated bodies")
        for mutated in [False, True]:
            good = create_empty_fork(node, fork_length=1)[0]
            bad = deepcopy(good)
            if mutated:
                # Keep the valid header while changing the transaction merkle root.
                bad.vtx[0].vout[0].nValue -= 1
                assert_equal(bad.hash_hex, good.hash_hex)
                reason = "Received mutated block"
            else:
                bad.vtx[0].vout[0].nValue = -1
                bad.hashMerkleRoot = bad.calc_merkle_root()
                bad.solve()
                assert_not_equal(bad.hash_hex, good.hash_hex)
                reason = "bad-txns-vout-negative"
            invalid_source = node.add_p2p_connection(P2PInterface())
            tip = node.getbestblockhash()
            with node.assert_debug_log([reason]):
                invalid_source.send_without_ping(msg_block(bad))
                # Loopback sources disconnect without discouraging other local peers.
                invalid_source.wait_for_disconnect()
            assert_equal(node.getbestblockhash(), tip)
            source.send_and_ping(msg_block(good))
            assert_equal(node.getbestblockhash(), good.hash_hex)
            assert_equal(node.getblock(good.hash_hex, 0), good.serialize().hex())

        self.log.info("Accept a requested block using only compact reconstruction")
        good = create_empty_fork(node, fork_length=1)[0]
        source.send_and_ping(msg_sendcmpct())
        source.send_without_ping(msg_headers([CBlockHeader(good)]))
        source.wait_for_getdata([good.hash_int])
        compact = HeaderAndShortIDs()
        compact.initialize_from_block(good, use_witness=True)
        source.send_and_ping(msg_cmpctblock(compact.to_p2p()))
        assert_equal(node.getbestblockhash(), good.hash_hex)
        assert_equal(node.getblock(good.hash_hex, 0), good.serialize().hex())

        self.log.info("Reject a worker-invalid compact block without punishing its source")
        good = create_empty_fork(node, fork_length=1)[0]
        bad = deepcopy(good)
        bad.vtx[0].vout[0].nValue = -1
        bad.hashMerkleRoot = bad.calc_merkle_root()
        bad.solve()
        assert_not_equal(bad.hash_hex, good.hash_hex)
        source.send_without_ping(msg_headers([CBlockHeader(bad)]))
        source.wait_for_getdata([bad.hash_int])
        compact = HeaderAndShortIDs()
        compact.initialize_from_block(bad, use_witness=True)
        tip = node.getbestblockhash()
        with node.assert_debug_log(["bad-txns-vout-negative"]):
            source.send_and_ping(msg_cmpctblock(compact.to_p2p()))
        assert_equal(node.getbestblockhash(), tip)
        with p2p_lock:
            assert source.is_connected
        source.send_and_ping(msg_block(good))
        assert_equal(node.getbestblockhash(), good.hash_hex)
        assert_equal(node.getblock(good.hash_hex, 0), good.serialize().hex())

        self.log.info("Fall back from a mutated compact reconstruction to a full block")
        good = create_empty_fork(node, fork_length=1)[0]
        source.send_and_ping(msg_sendcmpct())
        source.send_without_ping(msg_headers([CBlockHeader(good)]))
        source.wait_for_getdata([good.hash_int])
        with p2p_lock:
            source.last_message.pop("getdata")
        compact = HeaderAndShortIDs()
        compact.initialize_from_block(good, use_witness=True)
        compact.prefilled_txn[0].tx = deepcopy(good.vtx[0])
        compact.prefilled_txn[0].tx.vout[0].nValue -= 1
        source.send_without_ping(msg_cmpctblock(compact.to_p2p()))
        source.wait_for_getdata([good.hash_int])
        with p2p_lock:
            assert_equal(source.last_message["getdata"].inv[0].type, MSG_BLOCK | MSG_WITNESS_FLAG)
        assert_not_equal(node.getbestblockhash(), good.hash_hex)
        source.send_and_ping(msg_block(good))
        assert_equal(node.getbestblockhash(), good.hash_hex)

        self.log.info("Preserve accepted data across an orderly shutdown and restart")
        # Pending-job drain and source destruction have deterministic unit coverage.
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), good.hash_hex)
        assert_equal(node.getblock(good.hash_hex, 0), good.serialize().hex())


if __name__ == "__main__":
    AsyncBlockProcessingTest(__file__).main()

#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test P2P block processing across source disconnect and subsequent reuse."""

from test_framework.blocktools import create_block
from test_framework.messages import (
    CBlockHeader,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PAsyncBlockProcessingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def _create_next_block(self, node):
        tip = node.getblock(node.getbestblockhash())
        block = create_block(
            int(tip["hash"], 16),
            height=tip["height"] + 1,
            ntime=tip["time"] + 1,
        )
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        tip = node.getblock(node.getbestblockhash())
        expected_height = tip["height"] + 1

        source = node.add_p2p_connection(P2PInterface())
        probe = node.add_p2p_connection(P2PInterface())

        block = self._create_next_block(node)
        source.send_without_ping(msg_headers([CBlockHeader(block)]))
        source.wait_for_getdata([block.hash_int])
        # Ensure the block reached ProcessMessage without waiting for validation.
        with node.busy_wait_for_debug_log(
            expected_msgs=[f"received block {block.hash_hex} peer=".encode()],
        ):
            source.send_without_ping(msg_block(block))
        source.peer_disconnect()
        source.wait_for_disconnect()

        node.wait_until(lambda: node.getbestblockhash() == block.hash_hex)
        assert_equal(node.getblockcount(), expected_height)
        probe.sync_with_ping()
        assert probe.is_connected

        replacement_source = node.add_p2p_connection(P2PInterface())
        next_block = self._create_next_block(node)
        expected_height += 1
        replacement_source.send_without_ping(msg_headers([CBlockHeader(next_block)]))
        replacement_source.wait_for_getdata([next_block.hash_int])
        replacement_source.send_without_ping(msg_block(next_block))

        node.wait_until(lambda: node.getbestblockhash() == next_block.hash_hex)
        assert_equal(node.getblockcount(), expected_height)


if __name__ == '__main__':
    P2PAsyncBlockProcessingTest(__file__).main()

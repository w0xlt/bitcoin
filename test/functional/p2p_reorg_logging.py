#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logging for a near-tip competing branch with withheld blocks.

The scenario reproduced here is:

- the node is on a public two-block branch
- a competing same-work two-block branch is announced by one peer
- that peer withholds the announced blocks after they are requested
- another peer later announces the next header on the competing branch
- the node cannot re-request the earlier blocks immediately because they are
  already in flight from the first peer
- after the long block download timeout, the node disconnects the stalling peer,
  requests the missing blocks from another peer, and reorgs

The behavior itself is not changed by the accompanying net_processing patch.
This test primarily locks in the new log detail for investigation:
request reason, direct-fetch skips due to in-flight blocks, and improved timeout
messages.
"""

import re
import time

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CBlockHeader,
    MSG_BLOCK,
    MSG_TYPE_MASK,
    msg_block,
    msg_headers,
)
from test_framework.p2p import (
    P2PDataStore,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework


DIRECT_FETCH_TIMEOUT = 5


class HeadersPeer(P2PDataStore):
    def send_headers_for_blocks(self, blocks):
        self.send_without_ping(msg_headers([CBlockHeader(block) for block in blocks]))


class WithholdingPeer(HeadersPeer):
    def __init__(self, withheld_blocks):
        self.withheld_blocks = set(withheld_blocks)
        super().__init__()

    def on_getdata(self, message):
        for inv in message.inv:
            self.getdata_requests.append(inv.hash)
            invtype = inv.type & MSG_TYPE_MASK
            if invtype == MSG_BLOCK and inv.hash in self.block_store and inv.hash not in self.withheld_blocks:
                self.send_without_ping(msg_block(self.block_store[inv.hash]))


class ReorgLoggingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def assert_log_matches(self, node, regexes):
        with open(node.debug_log_path, encoding="utf-8", errors="replace") as debug_log:
            log = debug_log.read()
        for regex in regexes:
            assert re.search(regex, log), f"Expected regex not found in debug log: {regex}\n\n{log}"

    def build_branch(self, parent_hash, start_height, start_time, num_blocks):
        blocks = []
        tip = parent_hash
        height = start_height
        block_time = start_time
        for _ in range(num_blocks):
            block = create_block(tip, create_coinbase(height), block_time)
            block.solve()
            blocks.append(block)
            tip = block.hash_int
            height += 1
            block_time += 1
        return blocks

    def store_blocks(self, peer, blocks):
        with p2p_lock:
            for block in blocks:
                peer.block_store[block.hash_int] = block
                peer.last_block_hash = block.hash_int

    def run_test(self):
        node = self.nodes[0]

        self.generate(node, 2)

        public_peer = node.add_p2p_connection(HeadersPeer())
        staller = node.add_p2p_connection(WithholdingPeer(withheld_blocks=[]))
        relay = node.add_p2p_connection(HeadersPeer())

        base_hash = int(node.getbestblockhash(), 16)
        base_height = node.getblockcount()
        base_time = node.getblock(node.getbestblockhash())["time"]

        public_branch = self.build_branch(base_hash, base_height + 1, base_time + 1, 2)
        self.store_blocks(public_peer, public_branch)
        public_peer.send_blocks_and_test(public_branch, node)

        competing_branch = self.build_branch(base_hash, base_height + 1, base_time + 10, 3)
        b1, b2, b3 = competing_branch
        staller.withheld_blocks = {b1.hash_int, b2.hash_int}
        self.store_blocks(staller, [b1, b2])
        self.store_blocks(relay, competing_branch)

        self.mocktime = int(time.time())
        node.setmocktime(self.mocktime)

        self.log.info("Announce a competing branch, then withhold its first two blocks")
        with node.assert_debug_log(expected_msgs=[
            f"Requesting block {b1.hash_hex} ({base_height + 1}) peer=",
            f"Requesting block {b2.hash_hex} ({base_height + 2}) peer=",
            f"Skipping direct fetch for block {b2.hash_hex} ({base_height + 2}) from peer=",
            f"Skipping direct fetch for block {b1.hash_hex} ({base_height + 1}) from peer=",
            f"Timeout downloading block {b1.hash_hex} ({base_height + 1}) after ",
        ], timeout=10):
            staller.send_headers_for_blocks([b1, b2])
            staller.wait_for_getdata([b1.hash_int, b2.hash_int], timeout=DIRECT_FETCH_TIMEOUT)

            relay.send_headers_for_blocks([b3])
            relay.wait_for_getdata([b3.hash_int], timeout=DIRECT_FETCH_TIMEOUT)
            relay.sync_with_ping()

            node.setmocktime(self.mocktime + (11 * 60))
            staller.wait_for_disconnect(timeout=10)

        self.log.info("After the timeout, the node should fetch the missing branch from another peer")
        relay.sync_with_ping()
        self.wait_until(lambda: b1.hash_int in relay.getdata_requests and b2.hash_int in relay.getdata_requests, timeout=10)
        self.wait_until(lambda: node.getbestblockhash() == b3.hash_hex, timeout=10)
        self.assert_log_matches(node, [
            rf"Requesting block {b1.hash_hex} \({base_height + 1}\) peer=\d+ reason=headers-direct-fetch",
            rf"Requesting block {b2.hash_hex} \({base_height + 2}\) peer=\d+ reason=headers-direct-fetch",
            rf"Timeout downloading block {b1.hash_hex} \({base_height + 1}\) after \d+ms reason=headers-direct-fetch",
            rf"Requesting block {b1.hash_hex} \({base_height + 1}\) peer=\d+ reason=download-window",
            rf"Requesting block {b2.hash_hex} \({base_height + 2}\) peer=\d+ reason=download-window",
        ])

        node.setmocktime(0)


if __name__ == '__main__':
    ReorgLoggingTest(__file__).main()

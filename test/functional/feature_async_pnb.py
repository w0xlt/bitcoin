#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test asynchronous ProcessNewBlock during initial block download."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AsyncPnbTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0)

    @staticmethod
    def read_log_from(node, offset):
        with open(node.debug_log_path, encoding="utf-8", errors="replace") as debug_log:
            debug_log.seek(offset)
            return debug_log.read()

    def run_test(self):
        source = self.nodes[0]
        async_target = self.nodes[1]
        control_target = self.nodes[2]

        self.log.info("Build a source chain ahead of two fresh targets")
        blocks = self.generate(source, 32, sync_fun=self.no_op)
        source_tip = blocks[-1]
        source_height = source.getblockcount()
        minimum_chain_work = source.getblockheader(source_tip)["chainwork"]
        sync_args = [f"-minimumchainwork=0x{minimum_chain_work}"]

        self.log.info("Catch up in IBD with asynchronous block processing enabled")
        self.start_node(1, extra_args=["-asyncpnb=1", *sync_args])
        assert_equal(async_target.getblockchaininfo()["initialblockdownload"], True)
        async_log_start = async_target.debug_log_size(encoding="utf-8")
        self.connect_nodes(1, 0)
        self.sync_blocks([source, async_target], timeout=120)
        assert_equal(async_target.getblockcount(), source_height)
        assert_equal(async_target.getbestblockhash(), source_tip)
        assert_equal(async_target.getblockchaininfo()["initialblockdownload"], False)

        async_log = self.read_log_from(async_target, async_log_start)
        pnb_updates = [
            line for line in async_log.splitlines()
            if "[pnb]" in line and "UpdateTip: new best=" in line
        ]
        assert pnb_updates, "No standard UpdateTip log was emitted by the pnb thread"

        self.log.info("Restart the asynchronously synced datadir and retain its exact tip")
        self.restart_node(1, extra_args=["-asyncpnb=1", *sync_args])
        assert_equal(async_target.getblockcount(), source_height)
        assert_equal(async_target.getbestblockhash(), source_tip)

        self.log.info("Catch up with the default-off control")
        self.start_node(2, extra_args=sync_args)
        assert_equal(control_target.getblockchaininfo()["initialblockdownload"], True)
        self.connect_nodes(2, 0)
        self.sync_blocks([source, control_target], timeout=120)
        assert_equal(control_target.getblockcount(), source_height)
        assert_equal(control_target.getbestblockhash(), source_tip)
        assert_equal(control_target.getblockchaininfo()["initialblockdownload"], False)

        control_log = self.read_log_from(control_target, 0)
        control_updates = [
            line for line in control_log.splitlines()
            if "UpdateTip: new best=" in line
        ]
        assert control_updates, "The default-off control did not log normal block connection"
        assert "[pnb]" not in control_log


if __name__ == "__main__":
    AsyncPnbTest(__file__).main()

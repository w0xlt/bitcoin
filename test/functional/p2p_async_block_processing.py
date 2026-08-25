#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise bounded asynchronous P2P block processing through public behavior."""

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port
from test_framework.wallet import MiniWallet


class P2PAsyncBlockProcessingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0)

    @staticmethod
    def read_log(node, offset=0):
        with open(node.debug_log_path, encoding="utf-8", errors="replace") as debug_log:
            debug_log.seek(offset)
            return debug_log.read()

    @staticmethod
    def has_pnb_update(log):
        return any(
            "[pnb]" in line and "UpdateTip: new best=" in line
            for line in log.splitlines()
        )

    def run_test(self):
        source, async_target, control = self.nodes

        self.log.info("Build a source chain ahead of two fresh IBD targets")
        wallet = MiniWallet(source)
        blocks = self.generate(wallet, 110, sync_fun=self.no_op)
        # Make the stop-height block slow enough that the message handler can
        # deterministically admit later responses into the bounded queue.
        for _ in range(10):
            wallet.send_self_transfer(
                from_node=source,
                target_vsize=90_000,
                confirmed_only=True,
            )
        blocks += self.generate(wallet, 1, sync_fun=self.no_op)
        blocks += self.generate(wallet, 17, sync_fun=self.no_op)
        expected_tip = blocks[-1]
        expected_height = source.getblockcount()
        stop_height = 111
        stop_hash = blocks[stop_height - 1]
        queued_hash = blocks[stop_height]
        assert_equal(source.getblockheader(stop_hash)["height"], stop_height)
        assert_equal(source.getblockheader(queued_hash)["height"], stop_height + 1)
        minimum_chain_work = source.getblockheader(expected_tip)["chainwork"]
        ibd_args = [f"-minimumchainwork=0x{minimum_chain_work}"]

        self.log.info("Stop exactly at height with asynchronous receipts queued")
        self.start_node(1, extra_args=[
            "-asyncpnb=1",
            f"-stopatheight={stop_height}",
            *ibd_args,
        ])
        stop_log_start = async_target.debug_log_size(encoding="utf-8")
        assert_equal(async_target.getblockchaininfo()["initialblockdownload"], True)
        # Do not wait on target RPC during its intentional shutdown.
        async_target.addnode(f"127.0.0.1:{p2p_port(0)}", "onetry")
        async_target.wait_until_stopped(timeout=120)
        stopped_log = self.read_log(async_target, stop_log_start)
        # Height 112 was decoded on the async admission path while height 111
        # was active, providing public evidence that later work was queued.
        queued_position = stopped_log.index(f"received block {queued_hash}")
        tip_line = next(
            line for line in stopped_log.splitlines()
            if "[pnb]" in line
            and f"UpdateTip: new best={stop_hash} height={stop_height} " in line
        )
        assert queued_position < stopped_log.index(tip_line)

        # The component latch test proves queued jobs are present at the
        # boundary. This public integration assertion proves the synchronous
        # stop-at-height signal cannot promote them or a compact/full block on
        # the message-handler path before shutdown propagation.
        self.start_node(1, extra_args=["-asyncpnb=1", *ibd_args])
        assert_equal(async_target.getblockcount(), stop_height)

        self.log.info("Start async IBD, disconnect after worker progress, and keep another peer responsive")
        assert_equal(async_target.getblockchaininfo()["initialblockdownload"], True)
        responsive = async_target.add_p2p_connection(P2PInterface())
        async_log_start = async_target.debug_log_size(encoding="utf-8")
        self.connect_nodes(1, 0)
        self.wait_until(
            lambda: self.has_pnb_update(self.read_log(async_target, async_log_start)),
            timeout=120,
        )
        self.disconnect_nodes(1, 0)
        responsive.sync_with_ping()

        # Public shutdown/restart smoke after recent async IBD traffic. The C++
        # latch tests deterministically cover active completion and queue cancellation.
        self.stop_node(1)
        self.start_node(1, extra_args=["-asyncpnb=1", *ibd_args])
        self.connect_nodes(1, 0)
        self.sync_blocks([source, async_target], timeout=120)
        assert_equal(async_target.getblockcount(), expected_height)
        assert_equal(async_target.getbestblockhash(), expected_tip)
        assert_equal(async_target.getblockchaininfo()["initialblockdownload"], False)

        async_log = self.read_log(async_target)
        assert self.has_pnb_update(async_log)

        self.log.info("Restart the async datadir and retain the exact tip")
        self.restart_node(1, extra_args=["-asyncpnb=1", *ibd_args])
        assert_equal(async_target.getblockcount(), expected_height)
        assert_equal(async_target.getbestblockhash(), expected_tip)

        self.log.info("Sync the default-off control without creating a PNB worker")
        self.start_node(2, extra_args=ibd_args)
        assert_equal(control.getblockchaininfo()["initialblockdownload"], True)
        self.connect_nodes(2, 0)
        self.sync_blocks([source, control], timeout=120)
        assert_equal(control.getblockcount(), expected_height)
        assert_equal(control.getbestblockhash(), expected_tip)
        assert_equal(control.getblockchaininfo()["initialblockdownload"], False)
        control_log = self.read_log(control)
        assert "UpdateTip: new best=" in control_log
        assert "[pnb]" not in control_log


if __name__ == "__main__":
    P2PAsyncBlockProcessingTest(__file__).main()

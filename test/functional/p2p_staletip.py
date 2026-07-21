#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test stale-tip tracking."""

import time

from test_framework.blocktools import create_block
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PStaleTipTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-debug=net", "-peertimeout=999", "-staletips=headers"]]

    def run_test(self):
        self.test_staletip_option_validation()

        self.generate(self.nodes[0], 101)
        self.block_time_offset = 1

        self.test_reorged_out_active_tip_tracked()
        self.test_stale_header_tracked_after_catching_up()
        self.test_fresh_node_tracks_stale_header_after_ibd()
        self.test_startup_seeding_only_when_enabled()

    def assert_staletip_hash_tracked(self, block_hash):
        self.wait_until(lambda: any(tip["hash"] == block_hash for tip in self.nodes[0].getnetworkinfo()["staletips"]))

    def test_staletip_option_validation(self):
        self.log.info("Test staletip option validation")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-staletips=bogus"],
            expected_msg="Error: Invalid value for -staletips=<mode>: 'bogus'. Expected one of none, headers, or blocks.",
        )
        self.start_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def reorg_out_active_tip(self):
        """Reorg onto a longer branch forking off below the active tip, and
        return the hash of the reorged-out tip."""
        node = self.nodes[0]
        active_tip_hash = node.getbestblockhash()
        active_tip = node.getblock(active_tip_hash)

        fork_block = create_block(
            hashprev=int(active_tip["previousblockhash"], 16),
            height=active_tip["height"],
            ntime=active_tip["time"] + self.block_time_offset,
        )
        self.block_time_offset += 1
        fork_block.solve()
        assert node.submitblock(fork_block.serialize().hex()) in (None, "inconclusive")

        reorg_block = create_block(
            hashprev=fork_block.hash_int,
            height=active_tip["height"] + 1,
            ntime=active_tip["time"] + self.block_time_offset,
        )
        self.block_time_offset += 1
        reorg_block.solve()
        assert_equal(node.submitblock(reorg_block.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), reorg_block.hash_hex)
        return active_tip_hash

    def test_reorged_out_active_tip_tracked(self):
        self.log.info("Test reorged-out active tip is tracked as stale")
        self.assert_staletip_hash_tracked(self.reorg_out_active_tip())

    def test_stale_header_tracked_after_catching_up(self):
        self.log.info("Test a stale header with more work than the active tip at startup is tracked once caught up")
        node = self.nodes[0]
        tip = node.getblock(node.getbestblockhash())

        def branch(length):
            blocks = []
            prev_hash = int(tip["hash"], 16)
            for height in range(tip["height"] + 1, tip["height"] + 1 + length):
                block = create_block(hashprev=prev_hash, height=height, ntime=tip["time"] + self.block_time_offset)
                self.block_time_offset += 1
                block.solve()
                blocks.append(block)
                prev_hash = block.hash_int
            return blocks

        # Headers with more work than the active tip are not stale, and the
        # node restarts behind them.
        stale = branch(2)
        for block in stale:
            assert_equal(node.submitheader(block.serialize()[:80].hex()), None)
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])
        assert all(stale_tip["hash"] != stale[-1].hash_hex for stale_tip in node.getnetworkinfo()["staletips"])

        # Once the active chain catches up, the branch is stale and tracked.
        for block in branch(3):
            assert_equal(node.submitblock(block.serialize().hex()), None)
        self.assert_staletip_hash_tracked(stale[-1].hash_hex)

    def test_fresh_node_tracks_stale_header_after_ibd(self):
        self.log.info("Test a stale header learned during initial block download is tracked once caught up")
        node = self.nodes[0]
        self.stop_node(0)
        chain_backup = node.chain_path.parent / (node.chain_path.name + ".bak")
        node.chain_path.rename(chain_backup)
        self.start_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])
        assert node.getblockchaininfo()["initialblockdownload"]

        # A header with more work than the active tip, which the active chain
        # then catches up with.
        genesis_hash = int(node.getbestblockhash(), 16)
        stale, active = [create_block(hashprev=genesis_hash, height=1, ntime=int(time.time()) + i) for i in range(2)]
        for block in (stale, active):
            block.solve()
        assert_equal(node.submitheader(stale.serialize()[:80].hex()), None)
        assert_equal(node.submitblock(active.serialize().hex()), None)
        assert not node.getblockchaininfo()["initialblockdownload"]
        self.assert_staletip_hash_tracked(stale.hash_hex)

        self.stop_node(0)
        self.cleanup_folder(node.chain_path)
        chain_backup.rename(node.chain_path)
        self.start_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def test_startup_seeding_only_when_enabled(self):
        self.log.info("Test stale-tip cache is seeded at startup only when enabled")
        node = self.nodes[0]
        assert len(node.getnetworkinfo()["staletips"]) > 0

        # With stale-tip relay disabled, no stale tips are tracked: neither
        # those in the block index at startup nor reorged-out tips.
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=none"])
        assert_equal(node.getnetworkinfo()["staletips"], [])
        self.reorg_out_active_tip()
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getnetworkinfo()["staletips"], [])
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-nostaletips"])
        assert_equal(node.getnetworkinfo()["staletips"], [])

        # With stale-tip relay enabled, eligible stale tips already in the
        # block index are seeded at startup.
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])
        assert len(node.getnetworkinfo()["staletips"]) > 0


if __name__ == "__main__":
    P2PStaleTipTest(__file__).main()

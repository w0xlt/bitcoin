#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test stale-tip P2P relay."""

from test_framework.blocktools import create_block
from test_framework.messages import (
    CBlockHeader,
    MSG_BLOCK,
    MSG_TYPE_MASK,
    StaleTipCompressedHeader,
    msg_feature,
    msg_staletip,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

STALETIP_FEATURE = "https://github.com/ajtowns/bitcoin/tree/202601-staletips"
FEATURE_VERSION = 70017


class StaleTipPeer(P2PInterface):
    def __init__(self, *, send_feature=True, feature_data=b"\x00"):
        super().__init__()
        self.send_feature = send_feature
        self.feature_data = feature_data
        self.features = []
        self.getdata = []

    def on_version(self, message):
        if self.send_feature and message.nVersion >= FEATURE_VERSION:
            self.send_without_ping(msg_feature(STALETIP_FEATURE, self.feature_data))
        super().on_version(message)

    def on_feature(self, message):
        self.features.append(message)

    def on_getdata(self, message):
        self.getdata.extend(message.inv)

    def wait_for_getdata_hash(self, block_hash):
        self.wait_until(lambda: any(
            inv.hash == block_hash and inv.type & MSG_TYPE_MASK == MSG_BLOCK
            for inv in self.getdata
        ))


class P2PStaleTipTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-debug=net", "-peertimeout=999", "-staletips=headers"]]

    def run_test(self):
        self.test_staletip_option_validation()

        self.generate(self.nodes[0], 101)
        self.block_time_offset = 1

        self.test_feature_advertisement()

        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])
        self.test_unnegotiated_ignored()
        self.test_invalid_feature_data_ignored()
        self.test_oversized_staletip_ignored()
        self.test_reorged_out_active_tip_tracked()
        self.test_inbound_staletip_tracked()
        self.test_higher_work_staletip_requests_block()
        self.test_startup_seeding_only_when_enabled()

    def connect_peer(self, *, send_feature=True, feature_data=b"\x00", **kwargs):
        return self.nodes[0].add_p2p_connection(StaleTipPeer(send_feature=send_feature, feature_data=feature_data), **kwargs)

    def assert_staletip_hash_tracked(self, block_hash):
        self.wait_until(lambda: any(tip["hash"] == block_hash for tip in self.nodes[0].getnetworkinfo()["staletips"]))

    def stale_block(self, *, fork_depth=1):
        blocks, fork_point_hash = self.stale_branch(length=1, fork_depth=fork_depth)
        return blocks[0], fork_point_hash

    def stale_branch(self, *, length, fork_depth):
        node = self.nodes[0]
        active_tip = node.getblock(node.getbestblockhash())
        fork_point = active_tip
        for _ in range(fork_depth):
            fork_point = node.getblock(fork_point["previousblockhash"])
        fork_point_hash = int(fork_point["hash"], 16)
        prev_hash = fork_point_hash
        height = fork_point["height"]
        blocks = []
        for _ in range(length):
            block = create_block(
                hashprev=prev_hash,
                height=height + 1,
                ntime=active_tip["time"] + self.block_time_offset,
            )
            self.block_time_offset += 1
            block.solve()
            blocks.append(block)
            prev_hash = block.hash_int
            height += 1
        return blocks, fork_point_hash

    def active_block(self):
        node = self.nodes[0]
        active_tip_hash = node.getbestblockhash()
        active_tip = node.getblock(active_tip_hash)
        block = create_block(
            hashprev=int(active_tip_hash, 16),
            height=active_tip["height"] + 1,
            ntime=active_tip["time"] + self.block_time_offset,
        )
        self.block_time_offset += 1
        block.solve()
        return block, int(active_tip_hash, 16)

    def staletip_msg(self, blocks, fork_point_hash, *, have_block=False):
        if not isinstance(blocks, list):
            blocks = [blocks]
        return msg_staletip(
            hash_fork_point=fork_point_hash,
            headers=[StaleTipCompressedHeader(CBlockHeader(block)) for block in blocks],
            have_block=have_block,
        )

    def assert_staletip_tracked(self, block):
        self.assert_staletip_hash_tracked(block.hash_hex)

    def assert_staletip_not_tracked(self, block):
        assert block.hash_hex not in [tip["hash"] for tip in self.nodes[0].getnetworkinfo()["staletips"]]

    def test_staletip_option_validation(self):
        self.log.info("Test staletip option validation")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-staletips=bogus"],
            expected_msg="Error: Invalid value for -staletips=<mode>: 'bogus'. Expected one of none, headers, or blocks.",
        )
        self.start_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def test_reorged_out_active_tip_tracked(self):
        self.log.info("Test reorged-out active tip is tracked as stale")
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
        self.assert_staletip_hash_tracked(active_tip_hash)

    def test_feature_advertisement(self):
        self.log.info("Test staletip feature advertisement modes")
        for mode, expected_data in [("headers", b"\x00"), ("blocks", b"\x01"), ("none", None)]:
            self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", f"-staletips={mode}"])
            peer = self.connect_peer()
            stale_features = [feature for feature in peer.features if feature.feature_id == STALETIP_FEATURE]
            if expected_data is None:
                assert_equal(stale_features, [])
            else:
                assert_equal(len(stale_features), 1)
                assert_equal(stale_features[0].feature_data, expected_data)
            self.nodes[0].disconnect_p2ps()

    def test_invalid_feature_data_ignored(self):
        self.log.info("Test invalid staletip feature data is ignored")
        block, fork_point_hash = self.stale_block()
        invalid_features = [
            (b"", "ignoring staletip feature with malformed data"),
            (b"\x02", "ignoring staletip feature with invalid prefers_blocks=2"),
            (b"\x00\x01", "ignoring staletip feature with malformed data"),
        ]
        for feature_data, log_message in invalid_features:
            with self.nodes[0].assert_debug_log([log_message], timeout=2):
                peer = self.connect_peer(feature_data=feature_data)
            with self.nodes[0].assert_debug_log(["ignoring unnegotiated staletip"], timeout=2):
                peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
            assert peer.is_connected
            self.assert_staletip_not_tracked(block)
            self.nodes[0].disconnect_p2ps()

    def test_unnegotiated_ignored(self):
        self.log.info("Test unnegotiated staletip is ignored")
        peer = self.connect_peer(send_feature=False)
        block, fork_point_hash = self.stale_block()
        with self.nodes[0].assert_debug_log(["ignoring unnegotiated staletip"], timeout=2):
            peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_not_tracked(block)
        self.nodes[0].disconnect_p2ps()

    def test_oversized_staletip_ignored(self):
        self.log.info("Test oversized staletip is ignored without disconnect")
        peer = self.connect_peer(feature_data=b"\x00")
        block, fork_point_hash = self.stale_block()
        staletip = self.staletip_msg(block, fork_point_hash)
        staletip.headers *= 21
        with self.nodes[0].assert_debug_log(["ignoring staletip", "headers limit exceeded"], timeout=2):
            peer.send_and_ping(staletip)
        assert peer.is_connected
        self.assert_staletip_not_tracked(block)
        self.nodes[0].disconnect_p2ps()

    def test_inbound_staletip_tracked(self):
        self.log.info("Test negotiated inbound staletip is tracked")
        source_peer = self.connect_peer(feature_data=b"\x00")

        block, fork_point_hash = self.stale_block()
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_tracked(block)
        self.nodes[0].disconnect_p2ps()

    def test_higher_work_staletip_requests_block(self):
        self.log.info("Test block data is requested for a higher-work staletip")
        headers_peer = self.connect_peer(feature_data=b"\x00")
        block, fork_point_hash = self.active_block()
        headers_peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=False))
        assert_equal([
            inv.hash for inv in headers_peer.getdata
            if inv.type & MSG_TYPE_MASK == MSG_BLOCK
        ], [])
        self.nodes[0].disconnect_p2ps()

        block_peer = self.connect_peer(feature_data=b"\x00")
        block_peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=True))
        block_peer.wait_for_getdata_hash(block.hash_int)
        self.nodes[0].disconnect_p2ps()

    def test_startup_seeding_only_when_enabled(self):
        self.log.info("Test stale-tip cache is seeded at startup only when enabled")
        node = self.nodes[0]
        assert len(node.getnetworkinfo()["staletips"]) > 0

        # With stale-tip relay disabled, the block index is not scanned at
        # startup; only reorgs observed while running are reported.
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=none"])
        assert_equal(node.getnetworkinfo()["staletips"], [])
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-nostaletips"])
        assert_equal(node.getnetworkinfo()["staletips"], [])

        # With stale-tip relay enabled, eligible stale tips already in the
        # block index are seeded at startup.
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])
        assert len(node.getnetworkinfo()["staletips"]) > 0


if __name__ == "__main__":
    P2PStaleTipTest(__file__).main()

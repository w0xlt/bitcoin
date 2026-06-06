#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test stale-tip P2P relay."""

from test_framework.blocktools import create_block
from test_framework.messages import (
    CBlockHeader,
    CInv,
    MSG_BLOCK,
    MSG_TYPE_MASK,
    StaleTipCompressedHeader,
    msg_feature,
    msg_inv,
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
        self.staletips = []

    def on_version(self, message):
        if self.send_feature and message.nVersion >= FEATURE_VERSION:
            self.send_without_ping(msg_feature(STALETIP_FEATURE, self.feature_data))
        super().on_version(message)

    def on_feature(self, message):
        self.features.append(message)

    def on_getdata(self, message):
        self.getdata.extend(message.inv)

    def on_staletip(self, message):
        self.staletips.append(message)

    def wait_for_staletip(self):
        self.wait_until(lambda: len(self.staletips) > 0)

    def wait_for_getdata_hash(self, block_hash):
        self.wait_until(lambda: any(inv.hash == block_hash for inv in self.getdata))


class P2PStaleTipTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-debug=net", "-peertimeout=999", "-staletips=headers"]]

    def run_test(self):
        self.generate(self.nodes[0], 101)
        self.block_time_offset = 1

        self.test_feature_advertisement()

        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])
        self.test_unnegotiated_ignored()
        self.test_invalid_feature_data_ignored()
        self.test_inbound_and_outbound_relay()

        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=blocks"])
        self.test_blocks_mode_requests_tip_block()

    def connect_peer(self, *, send_feature=True, feature_data=b"\x00"):
        return self.nodes[0].add_p2p_connection(StaleTipPeer(send_feature=send_feature, feature_data=feature_data))

    def stale_block(self):
        node = self.nodes[0]
        active_tip = node.getblock(node.getbestblockhash())
        fork_point_hash = int(active_tip["previousblockhash"], 16)
        block = create_block(
            hashprev=fork_point_hash,
            height=active_tip["height"],
            ntime=active_tip["time"] + self.block_time_offset,
        )
        self.block_time_offset += 1
        block.solve()
        return block, fork_point_hash

    def staletip_msg(self, block, fork_point_hash, *, have_block=False):
        return msg_staletip(
            hash_fork_point=fork_point_hash,
            headers=[StaleTipCompressedHeader(CBlockHeader(block))],
            have_block=have_block,
        )

    def assert_staletip_tracked(self, block):
        self.wait_until(lambda: any(tip["hash"] == block.hash_hex for tip in self.nodes[0].getnetworkinfo()["staletips"]))

    def assert_staletip_not_tracked(self, block):
        assert block.hash_hex not in [tip["hash"] for tip in self.nodes[0].getnetworkinfo()["staletips"]]

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

    def test_unnegotiated_ignored(self):
        self.log.info("Test unnegotiated staletip is ignored")
        peer = self.connect_peer(send_feature=False)
        block, fork_point_hash = self.stale_block()
        with self.nodes[0].assert_debug_log(["ignoring unnegotiated staletip"], timeout=2):
            peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_not_tracked(block)
        self.nodes[0].disconnect_p2ps()

    def test_invalid_feature_data_ignored(self):
        self.log.info("Test invalid staletip feature data is ignored")
        peer = self.connect_peer(feature_data=b"\x02")
        block, fork_point_hash = self.stale_block()
        with self.nodes[0].assert_debug_log(["ignoring unnegotiated staletip"], timeout=2):
            peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        assert peer.is_connected
        self.assert_staletip_not_tracked(block)
        self.nodes[0].disconnect_p2ps()

    def test_inbound_and_outbound_relay(self):
        self.log.info("Test negotiated inbound staletip is tracked and relayed")
        source_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer = self.connect_peer(feature_data=b"\x00")

        relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(self.nodes[0].getbestblockhash(), 16))]))

        block, fork_point_hash = self.stale_block()
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_tracked(block)

        relay_peer.wait_for_staletip()
        assert_equal(relay_peer.staletips[-1].hash_fork_point, fork_point_hash)
        assert_equal(len(relay_peer.staletips[-1].headers), 1)
        assert_equal(relay_peer.staletips[-1].have_block, False)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_requests_tip_block(self):
        self.log.info("Test blocks mode requests only the announced stale tip block")
        peer = self.connect_peer(feature_data=b"\x01")
        block, fork_point_hash = self.stale_block()
        peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=True))
        self.assert_staletip_tracked(block)
        peer.wait_for_getdata_hash(block.hash_int)
        assert_equal([inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK], [block.hash_int])
        self.nodes[0].disconnect_p2ps()


if __name__ == "__main__":
    P2PStaleTipTest(__file__).main()

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
    NODE_NETWORK,
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
        self.invs = []
        self.staletips = []

    def on_version(self, message):
        if self.send_feature and message.nVersion >= FEATURE_VERSION:
            self.send_without_ping(msg_feature(STALETIP_FEATURE, self.feature_data))
        super().on_version(message)

    def on_feature(self, message):
        self.features.append(message)

    def on_getdata(self, message):
        self.getdata.extend(message.inv)

    def on_inv(self, message):
        self.invs.extend(message.inv)
        super().on_inv(message)

    def on_staletip(self, message):
        self.staletips.append(message)

    def wait_for_staletip(self, match=None):
        if match is None:
            match = lambda _: True
        self.wait_until(lambda: any(match(staletip) for staletip in self.staletips))
        return next(staletip for staletip in self.staletips if match(staletip))

    def wait_for_getdata_hash(self, block_hash):
        self.wait_until(lambda: any(inv.hash == block_hash for inv in self.getdata))

    def wait_for_block_inv(self, block_hash):
        self.wait_until(lambda: any(inv.type == MSG_BLOCK and inv.hash == block_hash for inv in self.invs))


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
        self.test_oversized_staletip_ignored()
        self.test_reorged_out_active_tip_tracked()
        self.test_skipped_staletip_does_not_block_later_eligible_announcement()
        self.test_active_tip_announced_to_source_peer()
        self.test_inbound_and_outbound_relay()

        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=blocks"])
        self.test_blocks_mode_does_not_overstate_unservable_stale_block()
        self.test_blocks_mode_ignores_non_witness_block_peer()
        self.test_blocks_mode_requests_better_work_tip_block()
        self.test_blocks_mode_requests_tip_block()

    def connect_peer(self, *, send_feature=True, feature_data=b"\x00", **kwargs):
        return self.nodes[0].add_p2p_connection(StaleTipPeer(send_feature=send_feature, feature_data=feature_data), **kwargs)

    def stale_block(self, *, fork_depth=1):
        node = self.nodes[0]
        active_tip = node.getblock(node.getbestblockhash())
        fork_point = active_tip
        for _ in range(fork_depth):
            fork_point = node.getblock(fork_point["previousblockhash"])
        fork_point_hash = int(fork_point["hash"], 16)
        block = create_block(
            hashprev=fork_point_hash,
            height=fork_point["height"] + 1,
            ntime=active_tip["time"] + self.block_time_offset,
        )
        self.block_time_offset += 1
        block.solve()
        return block, fork_point_hash

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

    def staletip_msg(self, block, fork_point_hash, *, have_block=False):
        return msg_staletip(
            hash_fork_point=fork_point_hash,
            headers=[StaleTipCompressedHeader(CBlockHeader(block))],
            have_block=have_block,
        )

    def assert_staletip_tracked(self, block):
        self.assert_staletip_hash_tracked(block.hash_hex)

    def assert_staletip_hash_tracked(self, block_hash):
        self.wait_until(lambda: any(tip["hash"] == block_hash for tip in self.nodes[0].getnetworkinfo()["staletips"]))

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

    def test_active_tip_announced_to_source_peer(self):
        self.log.info("Test active tip is announced even to peers that announced it first")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")

        block, _ = self.active_block()
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, block.hash_int)]))
        assert_equal(node.submitblock(block.serialize().hex()), None)
        peer.wait_for_block_inv(block.hash_int)
        self.nodes[0].disconnect_p2ps()

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

    def test_skipped_staletip_does_not_block_later_eligible_announcement(self):
        self.log.info("Test skipped stale-tip announcements do not block later eligible tips")
        node = self.nodes[0]
        source_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer = self.connect_peer(feature_data=b"\x00")

        active_tip = node.getblock(node.getbestblockhash())
        common_hash = node.getblock(active_tip["previousblockhash"])["previousblockhash"]
        relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(common_hash, 16))]))

        ineligible_block, ineligible_fork_point_hash = self.stale_block(fork_depth=1)
        source_peer.send_and_ping(self.staletip_msg(ineligible_block, ineligible_fork_point_hash))
        self.assert_staletip_tracked(ineligible_block)

        eligible_block, eligible_fork_point_hash = self.stale_block(fork_depth=2)
        source_peer.send_and_ping(self.staletip_msg(eligible_block, eligible_fork_point_hash))
        self.assert_staletip_tracked(eligible_block)

        staletip = relay_peer.wait_for_staletip(
            lambda msg: msg.hash_fork_point == eligible_fork_point_hash
            and len(msg.headers) == 1
            and msg.headers[0].hashMerkleRoot == eligible_block.hashMerkleRoot
        )
        assert_equal(staletip.have_block, False)
        self.nodes[0].disconnect_p2ps()

    def test_inbound_and_outbound_relay(self):
        self.log.info("Test negotiated inbound staletip is tracked and relayed")
        source_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer = self.connect_peer(feature_data=b"\x00")

        relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(self.nodes[0].getbestblockhash(), 16))]))

        block, fork_point_hash = self.stale_block()
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_tracked(block)

        staletip = relay_peer.wait_for_staletip(
            lambda msg: msg.hash_fork_point == fork_point_hash
            and len(msg.headers) == 1
            and msg.headers[0].hashMerkleRoot == block.hashMerkleRoot
        )
        assert_equal(staletip.have_block, False)
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

    def test_blocks_mode_does_not_overstate_unservable_stale_block(self):
        self.log.info("Test blocks mode does not announce unservable stale block data")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x01")

        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))

        block, fork_point_hash = self.stale_block()
        assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
        self.assert_staletip_tracked(block)

        staletip = peer.wait_for_staletip(
            lambda msg: msg.hash_fork_point == fork_point_hash
            and len(msg.headers) == 1
            and msg.headers[0].hashMerkleRoot == block.hashMerkleRoot
        )
        assert_equal(staletip.have_block, False)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_ignores_non_witness_block_peer(self):
        self.log.info("Test blocks mode does not request stale tip blocks from non-witness peers")
        peer = self.connect_peer(feature_data=b"\x01", services=NODE_NETWORK)
        block, fork_point_hash = self.stale_block()
        peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=True))
        self.assert_staletip_tracked(block)
        assert_equal([inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK], [])
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_requests_better_work_tip_block(self):
        self.log.info("Test blocks mode requests block data for known better-work staletip headers")
        header_peer = self.connect_peer(feature_data=b"\x01")
        block, fork_point_hash = self.active_block()
        header_peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=False))
        assert_equal([inv.hash for inv in header_peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK], [])
        self.nodes[0].disconnect_p2ps()

        peer = self.connect_peer(feature_data=b"\x01")
        peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=True))
        peer.wait_for_getdata_hash(block.hash_int)
        self.nodes[0].disconnect_p2ps()


if __name__ == "__main__":
    P2PStaleTipTest(__file__).main()

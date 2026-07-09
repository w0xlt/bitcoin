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
    msg_getdata,
    msg_inv,
    msg_staletip,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

STALETIP_FEATURE = "https://github.com/ajtowns/bitcoin/tree/202601-staletips"
FEATURE_VERSION = 70017
MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16


class StaleTipPeer(P2PInterface):
    def __init__(self, *, send_feature=True, feature_data=b"\x00"):
        super().__init__()
        self.send_feature = send_feature
        self.feature_data = feature_data
        self.features = []
        self.getdata = []
        self.invs = []
        self.blocks = []
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

    def on_block(self, message):
        self.blocks.append(message.block)

    def on_staletip(self, message):
        self.staletips.append(message)

    def wait_for_staletip(self, match=None):
        if match is None:
            match = lambda _: True
        self.wait_until(lambda: any(match(staletip) for staletip in self.staletips))
        return next(staletip for staletip in self.staletips if match(staletip))

    def wait_for_getdata_hash(self, block_hash):
        self.wait_until(lambda: any(inv.hash == block_hash for inv in self.getdata))

    def wait_for_getdata_hashes(self, block_hashes):
        expected = set(block_hashes)
        self.wait_until(lambda: expected.issubset({
            inv.hash for inv in self.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK
        }))

    def wait_for_block_inv(self, block_hash):
        self.wait_until(lambda: any(inv.type == MSG_BLOCK and inv.hash == block_hash for inv in self.invs))

    def wait_for_block_hash(self, block_hash):
        self.wait_until(lambda: any(block.hash_int == block_hash for block in self.blocks))


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
        self.test_skipped_staletip_does_not_block_later_eligible_announcement()
        self.test_active_tip_announced_to_source_peer()
        self.test_inbound_and_outbound_relay()
        self.test_peer_must_know_fork_point()
        self.test_no_reannouncement_after_transient_ineligibility()
        self.test_startup_seeding_only_when_enabled()

        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=blocks"])
        self.test_blocks_mode_serves_tracked_stale_branch()
        self.test_blocks_mode_ignores_non_witness_block_peer()
        self.test_blocks_mode_requests_better_work_tip_block()
        self.test_blocks_mode_requests_stale_branch_blocks()
        self.test_blocks_mode_caps_stale_branch_requests_and_clears_timeout()

    def connect_peer(self, *, send_feature=True, feature_data=b"\x00", **kwargs):
        return self.nodes[0].add_p2p_connection(StaleTipPeer(send_feature=send_feature, feature_data=feature_data), **kwargs)

    def test_staletip_option_validation(self):
        self.log.info("Test staletip option validation")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-staletips=bogus"],
            expected_msg="Error: Invalid value for -staletips=<mode>: 'bogus'. Expected one of none, headers, or blocks.",
        )
        self.start_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

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

    def test_peer_must_know_fork_point(self):
        self.log.info("Test staletip is not announced unless peer knows fork point")
        node = self.nodes[0]
        source_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer = self.connect_peer(feature_data=b"\x00")

        active_tip_hash = node.getbestblockhash()
        competing_blocks, _ = self.stale_branch(length=2, fork_depth=2)
        for block in competing_blocks:
            assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
        assert_equal(node.getbestblockhash(), active_tip_hash)

        # Advance the relay peer's best-known chain along a competing branch
        # whose height passes the old check, but which does not contain the
        # active-chain fork point below.
        relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, competing_blocks[-1].hash_int)]))
        relay_peer.sync_with_ping()

        block, fork_point_hash = self.stale_block(fork_depth=1)
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_tracked(block)

        relay_peer.sync_with_ping()
        assert_equal([
            msg for msg in relay_peer.staletips
            if msg.hash_fork_point == fork_point_hash
            and len(msg.headers) == 1
            and msg.headers[0].nTime == block.nTime
            and msg.headers[0].nNonce == block.nNonce
        ], [])
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_requests_stale_branch_blocks(self):
        self.log.info("Test blocks mode requests missing stale branch blocks")
        peer = self.connect_peer(feature_data=b"\x01")
        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash, have_block=True))
        self.assert_staletip_tracked(blocks[-1])
        expected_hashes = [block.hash_int for block in blocks]
        peer.wait_for_getdata_hashes(expected_hashes)
        assert_equal([inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK], expected_hashes)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_caps_stale_branch_requests_and_clears_timeout(self):
        self.log.info("Test stale branch requests are capped and time out without disconnect")
        node = self.nodes[0]
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        peer = self.connect_peer(feature_data=b"\x01")

        blocks, fork_point_hash = self.stale_branch(length=20, fork_depth=20)
        peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash, have_block=True))
        self.assert_staletip_tracked(blocks[-1])

        expected_hashes = [block.hash_int for block in blocks[:MAX_BLOCKS_IN_TRANSIT_PER_PEER]]
        getdata_hashes = lambda: [inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK]
        self.wait_until(lambda: getdata_hashes() == expected_hashes)
        assert_equal(len(node.getpeerinfo()[0]["inflight"]), MAX_BLOCKS_IN_TRANSIT_PER_PEER)

        with node.assert_debug_log(["Timeout downloading stale-tip branch block"]):
            node.bumpmocktime(601)
            peer.sync_with_ping()
        self.wait_until(lambda: peer.is_connected and node.getpeerinfo()[0]["inflight"] == [])

        node.setmocktime(0)
        self.nodes[0].disconnect_p2ps()

    def test_no_reannouncement_after_transient_ineligibility(self):
        self.log.info("Test stale tip is not re-announced after transient ineligibility")
        node = self.nodes[0]

        # Prior subtests may have left same-work competing branches in the
        # block index. Move the active tip forward so the branch created below
        # is the best candidate when the current tip is invalidated.
        self.generate(node, 1)

        peer = self.connect_peer(feature_data=b"\x00")
        active_tip_hash = node.getbestblockhash()
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(active_tip_hash, 16))]))

        block, fork_point_hash = self.stale_block()

        # Coinbase-only test blocks at the same height share a merkle root,
        # so identify the announcement by the unique (time, nonce) instead.
        def matches_block(msg):
            return (msg.hash_fork_point == fork_point_hash
                    and len(msg.headers) == 1
                    and msg.headers[0].nTime == block.nTime
                    and msg.headers[0].nNonce == block.nNonce)

        assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
        self.assert_staletip_tracked(block)
        peer.wait_for_staletip(matches_block)

        # Reorg onto the stale branch and back. While its branch is active the
        # tip is temporarily not stale, but it stays in the cache throughout.
        node.invalidateblock(active_tip_hash)
        assert_equal(node.getbestblockhash(), block.hash_hex)
        peer.wait_for_block_inv(block.hash_int)
        node.reconsiderblock(active_tip_hash)
        assert_equal(node.getbestblockhash(), active_tip_hash)
        self.assert_staletip_tracked(block)

        # The node announces its restored active tip, but must not announce
        # the stale tip to the same peer a second time.
        peer.wait_for_block_inv(int(active_tip_hash, 16))
        peer.sync_with_ping()
        assert_equal(len([msg for msg in peer.staletips if matches_block(msg)]), 1)
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

    def test_blocks_mode_serves_tracked_stale_branch(self):
        self.log.info("Test blocks mode announces and serves tracked stale branch data")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x01")

        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))

        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        for block in blocks:
            assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
        self.assert_staletip_tracked(blocks[-1])

        # The stale branch was never connected, but its data is available and
        # the tip is tracked, so the announcement offers the branch data and
        # requests for missing branch blocks succeed.
        staletip = peer.wait_for_staletip(
            lambda msg: msg.hash_fork_point == fork_point_hash
            and len(msg.headers) == 2
            and msg.headers[-1].hashMerkleRoot == blocks[-1].hashMerkleRoot
        )
        assert_equal(staletip.have_block, True)

        peer.send_without_ping(msg_getdata([CInv(MSG_BLOCK, block.hash_int) for block in blocks]))
        for block in blocks:
            peer.wait_for_block_hash(block.hash_int)

        unnegotiated_peer = self.connect_peer(send_feature=False)
        unnegotiated_peer.send_and_ping(msg_getdata([CInv(MSG_BLOCK, block.hash_int) for block in blocks]))
        assert_equal(unnegotiated_peer.blocks, [])
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

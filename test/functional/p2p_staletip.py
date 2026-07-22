#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test stale-tip P2P relay."""

from copy import deepcopy
import time

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CBlockHeader,
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    HeaderAndShortIDs,
    MSG_BLOCK,
    MSG_TYPE_MASK,
    NODE_NETWORK,
    NODE_NETWORK_LIMITED,
    NODE_WITNESS,
    StaleTipCompressedHeader,
    from_hex,
    msg_block,
    msg_cmpctblock,
    msg_feature,
    msg_getdata,
    msg_getheaders,
    msg_headers,
    msg_inv,
    msg_sendcmpct,
    msg_sendheaders,
    msg_staletip,
)
from test_framework.p2p import P2PInterface
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

STALETIP_FEATURE = "BIP332"
FEATURE_VERSION = 70017
MAX_STALE_BLOCK_REQUESTS_PER_PEER = 20
MAX_ADVERTISED_STALETIPS = 10
MAX_RETAINED_STALETIPS = 20
STALETIP_BLOCK_WAIT = 60
STALETIP_RECENT_WINDOW = 1000
NODE_NETWORK_LIMITED_MIN_BLOCKS = 288


class StaleTipPeer(P2PInterface):
    def __init__(self, *, send_feature=True, feature_data=b"\x00"):
        super().__init__()
        self.send_feature = send_feature
        self.feature_data = feature_data
        self.blocks = []
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

    def on_block(self, message):
        self.blocks.append(message.block)

    def on_inv(self, message):
        self.invs.extend(message.inv)
        super().on_inv(message)

    def on_staletip(self, message):
        self.staletips.append(message)

    def wait_for_staletip(self, match=None):
        def matches(staletip):
            return match is None or match(staletip)

        self.wait_until(lambda: any(matches(staletip) for staletip in self.staletips))
        return next(staletip for staletip in self.staletips if matches(staletip))

    def wait_for_getdata_hash(self, block_hash):
        self.wait_until(lambda: any(
            inv.hash == block_hash and inv.type & MSG_TYPE_MASK == MSG_BLOCK
            for inv in self.getdata
        ))

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
        self.test_stale_header_tracked_after_catching_up()
        self.test_fresh_node_tracks_stale_header_after_ibd()
        self.test_skipped_staletip_does_not_block_later_eligible_announcement()
        self.test_active_tip_announced_to_source_peer()
        self.test_active_tip_not_reannounced_to_unnegotiated_peer()
        self.test_active_tip_not_announced_after_compact_block()
        self.test_active_tip_announced_when_reactivated()
        self.test_inbound_and_outbound_relay()
        self.test_staletip_not_announced_back_to_announcer()
        self.test_partially_accepted_staletip_not_announced_back()
        self.test_staletip_not_reannounced_after_eviction()
        self.test_fork_point_known_to_peer()
        self.test_staletip_relayed_to_peer_known_through_sent_headers()
        self.test_peer_must_know_fork_point()
        self.test_no_reannouncement_after_transient_ineligibility()
        self.test_higher_work_staletip_requests_block()
        self.test_higher_work_staletip_only_promises_tip()
        self.test_higher_work_staletip_tip_ignores_stale_request_cap()
        self.test_known_invalid_staletip_ignored()
        self.test_startup_seeding_only_when_enabled()
        self.test_serves_tracked_stale_branch()
        self.test_have_block_requires_branch_data()
        self.test_have_block_requires_data_below_known_fork_point()
        self.test_invalid_announced_branch_block_not_punished()
        self.test_initial_advertisement_limited()
        self.test_recency_window_and_minimum_work()
        self.test_more_work_staletip_tracked_after_catching_up()
        self.test_more_work_headers_tracked_after_catching_up()
        self.test_more_work_rpc_headers_tracked_after_catching_up()
        self.test_more_work_full_block_tracked_after_catching_up()
        self.test_more_work_compact_block_tracked_after_catching_up()
        self.test_pruned_node_have_block()

        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=blocks"])
        self.test_blocks_mode_ignores_non_witness_block_peer()
        self.test_blocks_mode_respects_pruned_peer_depth()
        self.test_blocks_mode_requests_stale_branch_blocks()
        self.test_blocks_mode_staletip_not_announced_back_after_download()
        self.test_blocks_mode_stops_waiting_for_block_data()
        self.test_blocks_mode_initial_advertisement_limited()
        self.test_blocks_mode_withheld_stale_block_does_not_delay_reorg()
        self.test_blocks_mode_mutated_block_keeps_request_to_other_peer()
        self.test_blocks_mode_stale_block_not_counted_for_eviction()
        self.test_blocks_mode_waits_for_branch_block_data()
        self.test_blocks_mode_invalid_child_does_not_hide_parent()
        self.test_blocks_mode_caps_stale_branch_requests_and_clears_timeout()
        self.test_blocks_mode_resumes_stale_branch_downloads()

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

    def staletip_matcher(self, block, fork_point_hash):
        # Coinbase-only test blocks at the same height share a merkle root,
        # so identify the announcement by the unique (time, nonce) instead.
        return lambda msg: (msg.hash_fork_point == fork_point_hash
                            and len(msg.headers) == 1
                            and msg.headers[0].nTime == block.nTime
                            and msg.headers[0].nNonce == block.nNonce)

    def staletip_tip_hash(self, msg):
        prev_hash = msg.hash_fork_point
        for compressed in msg.headers:
            header = CBlockHeader()
            header.nVersion = compressed.nVersion
            header.hashPrevBlock = prev_hash
            header.hashMerkleRoot = compressed.hashMerkleRoot
            header.nTime = compressed.nTime
            header.nBits = compressed.nBits
            header.nNonce = compressed.nNonce
            prev_hash = header.hash_int
        return prev_hash

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

    def test_known_invalid_staletip_ignored(self):
        self.log.info("Test a staletip naming a header known to be invalid is ignored")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")
        fork_point_hash = node.getbestblockhash()
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(fork_point_hash, 16))]))
        fork_point_height = node.getblockcount()

        # A known invalid block with more work than the tip, claimed available.
        invalid_hash = self.generate(node, 1)[0]
        node.invalidateblock(invalid_hash)
        assert_equal(node.getbestblockhash(), fork_point_hash)
        invalid_header = from_hex(CBlockHeader(), node.getblockheader(invalid_hash, False))
        with node.assert_debug_log([f"ignoring staletip with known invalid tip {invalid_hash}"]):
            peer.send_and_ping(self.staletip_msg(invalid_header, int(fork_point_hash, 16), have_block=True))
        # It is not taken as the peer's best known block.
        assert_equal(node.getpeerinfo()[0]["synced_headers"], fork_point_height)

        node.reconsiderblock(invalid_hash)
        assert_equal(node.getbestblockhash(), invalid_hash)
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

    def test_higher_work_staletip_only_promises_tip(self):
        self.log.info("Test a higher-work tip-only announcer is not disconnected for missing stale ancestors")
        self.block_time_offset = getattr(self, "block_time_offset", 1)
        node = self.nodes[0]
        for mode in ("headers", "blocks"):
            self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", f"-staletips={mode}"])
            node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
            peer = self.connect_peer(feature_data=b"\x00")
            blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=1)
            parent, tip = blocks
            peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash, have_block=True))
            peer.wait_for_getdata_hashes([parent.hash_int, tip.hash_int])
            assert_equal(node.getpeerinfo()[0]["inflight"], [node.getblockheader(tip.hash_hex)["height"]])
            peer.send_and_ping(msg_block(tip))
            assert_equal(node.getblock(tip.hash_hex)["confirmations"], -1)

            # have_block promises only the tip. A missing ancestor must time
            # out without disconnecting this compliant peer or being retried.
            with node.assert_debug_log([f"Timeout downloading stale-tip branch block {parent.hash_hex}"], unexpected_msgs=["Timeout downloading block"]):
                node.bumpmocktime(601)
                peer.sync_with_ping()
            assert peer.is_connected
            assert_equal(node.getpeerinfo()[0]["inflight"], [])
            requested_hashes = [inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK]
            assert_equal(requested_hashes.count(parent.hash_int), 1)
            assert_equal(requested_hashes.count(tip.hash_int), 1)

            # A separate ordinary headers announcement establishes the branch
            # for normal download. Its ancestor can then be requested normally.
            peer.send_and_ping(msg_headers([CBlockHeader(tip)]))
            peer.wait_until(lambda: sum(inv.hash == parent.hash_int and inv.type & MSG_TYPE_MASK == MSG_BLOCK for inv in peer.getdata) == 2)
            assert_equal(node.getpeerinfo()[0]["inflight"], [node.getblockheader(parent.hash_hex)["height"]])
            peer.send_and_ping(msg_block(parent))
            assert_equal(node.getbestblockhash(), tip.hash_hex)
            node.setmocktime(0)
            node.disconnect_p2ps()
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def test_higher_work_staletip_tip_ignores_stale_request_cap(self):
        self.log.info("Test optional stale requests do not delay a promised higher-work tip")
        self.block_time_offset = getattr(self, "block_time_offset", 1)
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=blocks"])
        node = self.nodes[0]
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        peer = self.connect_peer(feature_data=b"\x00")

        stale, fork_point_hash = self.stale_branch(length=20, fork_depth=20)
        peer.send_and_ping(self.staletip_msg(stale, fork_point_hash, have_block=True))
        peer.wait_for_getdata_hashes([block.hash_int for block in stale])
        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=1)
        parent, tip = blocks
        peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash, have_block=True))
        peer.wait_for_getdata_hash(tip.hash_int)
        assert_equal(node.getpeerinfo()[0]["inflight"], [node.getblockheader(tip.hash_hex)["height"]])
        assert not any(inv.hash == parent.hash_int for inv in peer.getdata)
        peer.send_and_ping(msg_block(tip))

        # When optional slots are freed, collect the missing ancestor without
        # another announcement or retrying the expired requests or tip.
        with node.assert_debug_log(["Timeout downloading stale-tip branch block"], unexpected_msgs=["Timeout downloading block"]):
            node.bumpmocktime(601)
            peer.sync_with_ping()
        peer.wait_for_getdata_hash(parent.hash_int)
        requested_hashes = [inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK]
        assert_equal(requested_hashes, [block.hash_int for block in stale] + [tip.hash_int, parent.hash_int])
        assert_equal(node.getpeerinfo()[0]["inflight"], [])
        peer.send_and_ping(msg_block(parent))
        assert_equal(node.getbestblockhash(), tip.hash_hex)
        node.setmocktime(0)
        node.disconnect_p2ps()
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def test_active_tip_announced_to_source_peer(self):
        self.log.info("Test active tip is announced even to peers that announced it first")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")

        block, _ = self.active_block()
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, block.hash_int)]))
        assert_equal(node.submitblock(block.serialize().hex()), None)
        peer.wait_for_block_inv(block.hash_int)
        self.nodes[0].disconnect_p2ps()

    def test_active_tip_not_reannounced_to_unnegotiated_peer(self):
        self.log.info("Test the active tip is not announced to a peer that announced it first and did not negotiate staletip")
        node = self.nodes[0]
        peer = self.connect_peer(send_feature=False)

        block, _ = self.active_block()
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, block.hash_int)]))
        assert_equal(node.submitblock(block.serialize().hex()), None)
        node.syncwithvalidationinterfacequeue()
        peer.sync_with_ping()
        peer.sync_with_ping()
        assert all(inv.hash != block.hash_int for inv in peer.invs)
        self.nodes[0].disconnect_p2ps()

    def test_active_tip_not_announced_after_compact_block(self):
        self.log.info("Test the active tip is not also announced by inv to a peer sent its compact block")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")
        peer.send_and_ping(msg_sendcmpct(announce=True, version=2))
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))

        block_hash = int(self.generate(node, 1)[0], 16)
        peer.wait_until(lambda: "cmpctblock" in peer.last_message and
                        peer.last_message["cmpctblock"].header_and_shortids.header.hash_int == block_hash)
        node.syncwithvalidationinterfacequeue()
        peer.sync_with_ping()
        peer.sync_with_ping()
        assert all(inv.hash != block_hash for inv in peer.invs)
        self.nodes[0].disconnect_p2ps()

    def test_active_tip_announced_when_reactivated(self):
        self.log.info("Test the active tip is announced again when reactivated, although its header was sent before")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")
        peer.send_and_ping(msg_sendheaders())
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))

        # Block A is announced to the peer by its header.
        competing, _ = self.active_block()
        a_hash = self.generate(node, 1)[0]
        peer.wait_for_header(a_hash)

        # The peer announces competing block B, which the node switches to.
        peer.send_and_ping(msg_headers([CBlockHeader(competing)]))
        assert node.submitblock(competing.serialize().hex()) in (None, "inconclusive")
        node.preciousblock(competing.hash_hex)
        assert_equal(node.getbestblockhash(), competing.hash_hex)
        peer.wait_for_block_inv(competing.hash_int)

        # Switching back to A is announced too.
        node.preciousblock(a_hash)
        assert_equal(node.getbestblockhash(), a_hash)
        peer.wait_for_block_inv(int(a_hash, 16))
        self.nodes[0].disconnect_p2ps()

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

        staletip = relay_peer.wait_for_staletip(self.staletip_matcher(eligible_block, eligible_fork_point_hash))
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

        staletip = relay_peer.wait_for_staletip(self.staletip_matcher(block, fork_point_hash))
        assert_equal(staletip.have_block, False)
        self.nodes[0].disconnect_p2ps()

    def test_staletip_not_announced_back_to_announcer(self):
        self.log.info("Test staletip is not announced back to peers that announced it")
        node = self.nodes[0]
        active_tip_inv = msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))])
        source_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer = self.connect_peer(feature_data=b"\x00")
        # This peer does not know the fork point yet, so the tip cannot be
        # announced to it before it announces the tip itself.
        late_peer = self.connect_peer(feature_data=b"\x00")
        source_peer.send_and_ping(active_tip_inv)
        relay_peer.send_and_ping(active_tip_inv)

        block, fork_point_hash = self.stale_block()
        matches_block = self.staletip_matcher(block, fork_point_hash)
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_tracked(block)
        relay_peer.wait_for_staletip(matches_block)

        # Announcing an already-known tip also counts, even if the peer only
        # learns the fork point afterwards.
        late_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        late_peer.send_and_ping(active_tip_inv)

        source_peer.sync_with_ping()
        assert_equal([msg for msg in source_peer.staletips if matches_block(msg)], [])
        assert_equal([msg for msg in late_peer.staletips if matches_block(msg)], [])
        self.nodes[0].disconnect_p2ps()

    def test_partially_accepted_staletip_not_announced_back(self):
        self.log.info("Test the accepted prefix of a partially invalid staletip is not announced back to its announcer")
        node = self.nodes[0]
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        active_tip_inv = msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))])
        source_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer = self.connect_peer(feature_data=b"\x00")
        source_peer.send_and_ping(active_tip_inv)
        relay_peer.send_and_ping(active_tip_inv)

        # The second header is too far in the future to be accepted.
        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        blocks[1].nTime = node.getblockheader(node.getbestblockhash())["time"] + 3 * 60 * 60
        blocks[1].solve()
        matches_prefix = self.staletip_matcher(blocks[0], fork_point_hash)
        with node.assert_debug_log(["ignoring staletip headers", "time-too-new"]):
            source_peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash))
        self.assert_staletip_tracked(blocks[0])
        relay_peer.wait_for_staletip(matches_prefix)

        # The tip becomes announceable asynchronously, so wait for a
        # message-handler pass that has seen it.
        source_peer.sync_with_ping()
        source_peer.sync_with_ping()
        assert_equal([msg for msg in source_peer.staletips if matches_prefix(msg)], [])
        node.setmocktime(0)
        self.nodes[0].disconnect_p2ps()

    def test_staletip_not_reannounced_after_eviction(self):
        self.log.info("Test a stale tip dropped from the cache and tracked again is not announced again to the same peer")
        node = self.nodes[0]
        active_tip_inv = msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))])
        source_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer = self.connect_peer(feature_data=b"\x00")
        source_peer.send_and_ping(active_tip_inv)
        relay_peer.send_and_ping(active_tip_inv)

        block, fork_point_hash = self.stale_block()
        matches_block = self.staletip_matcher(block, fork_point_hash)
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        relay_peer.wait_for_staletip(matches_block)

        # Newer stale tips with equal work evict it from the full cache.
        for _ in range(MAX_RETAINED_STALETIPS):
            other, other_fork_point_hash = self.stale_block()
            source_peer.send_and_ping(self.staletip_msg(other, other_fork_point_hash))
        assert all(tip["hash"] != block.hash_hex for tip in node.getnetworkinfo()["staletips"])

        # It is tracked again when announced again.
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_tracked(block)
        relay_peer.sync_with_ping()
        relay_peer.sync_with_ping()
        assert_equal(len([msg for msg in relay_peer.staletips if matches_block(msg)]), 1)
        self.nodes[0].disconnect_p2ps()

    def test_fork_point_known_to_peer(self):
        self.log.info("Test staletip fork points are the highest branch blocks the peer certainly has")
        node = self.nodes[0]
        # Move above the stale tips left by earlier subtests.
        self.generate(node, 2)
        active_tip_inv = msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))])
        peer = self.connect_peer(feature_data=b"\x00")
        other_peer = self.connect_peer(feature_data=b"\x00")
        peer.send_and_ping(active_tip_inv)
        other_peer.send_and_ping(active_tip_inv)

        # A tip the peer announced is the fork point for its extension. A tip
        # only announced to a peer is not, as the peer may have ignored it.
        (tip1, tip2), fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        peer.send_and_ping(self.staletip_msg(tip1, fork_point_hash))
        other_peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == tip1.hash_int)
        assert node.submitblock(tip2.serialize().hex()) in (None, "inconclusive")
        peer.wait_for_staletip(lambda msg: msg.hash_fork_point == tip1.hash_int and len(msg.headers) == 1
                               and self.staletip_tip_hash(msg) == tip2.hash_int)
        other_peer.wait_for_staletip(lambda msg: msg.hash_fork_point == fork_point_hash and len(msg.headers) == 2
                                     and self.staletip_tip_hash(msg) == tip2.hash_int)

        # For a branch diverging from one the peer announced, the fork point is
        # where the branches diverge.
        (branch1, branch2), fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        peer.send_and_ping(self.staletip_msg([branch1, branch2], fork_point_hash))
        sibling = create_block(hashprev=branch1.hash_int, height=node.getblockheader(f"{fork_point_hash:064x}")["height"] + 2,
                               ntime=branch2.nTime + 1)
        sibling.solve()
        assert node.submitblock(sibling.serialize().hex()) in (None, "inconclusive")
        peer.wait_for_staletip(lambda msg: msg.hash_fork_point == branch1.hash_int and len(msg.headers) == 1
                               and self.staletip_tip_hash(msg) == sibling.hash_int)

        # The chain of the peer's best known block counts too: a peer that
        # announced a tip's parent is sent only the tip, and a peer that
        # announced the tip itself is not sent it.
        parent_peer = self.connect_peer(feature_data=b"\x00")
        parent_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, tip1.hash_int)]))
        parent_peer.wait_for_staletip(lambda msg: msg.hash_fork_point == tip1.hash_int and len(msg.headers) == 1
                                      and self.staletip_tip_hash(msg) == tip2.hash_int)
        tip_peer = self.connect_peer(feature_data=b"\x00")
        tip_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, tip2.hash_int)]))
        assert_equal([msg for msg in tip_peer.staletips if self.staletip_tip_hash(msg) == tip2.hash_int], [])
        self.nodes[0].disconnect_p2ps()

    def test_staletip_relayed_to_peer_known_through_sent_headers(self):
        self.log.info("Test stale tips are relayed to a peer that learned our chain only from headers we sent")
        node = self.nodes[0]
        # The peer doesn't serve blocks, so the node doesn't sync headers from
        # it, and it never announces a block.
        peer = self.connect_peer(feature_data=b"\x00", services=NODE_WITNESS)
        getheaders = msg_getheaders()
        getheaders.locator.vHave = [int(node.getbestblockhash(), 16)]
        peer.send_and_ping(getheaders)

        block, fork_point_hash = self.stale_block()
        assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
        peer.wait_for_staletip(self.staletip_matcher(block, fork_point_hash))
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

    def test_serves_tracked_stale_branch(self):
        self.log.info("Test headers mode announces and serves tracked stale branch data")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))

        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        for block in blocks:
            assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
        self.assert_staletip_tracked(blocks[-1])

        staletip = peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == blocks[-1].hash_int)
        assert_equal(staletip.hash_fork_point, fork_point_hash)
        assert_equal(len(staletip.headers), 2)
        assert_equal(staletip.have_block, True)

        peer.send_without_ping(msg_getdata([CInv(MSG_BLOCK, block.hash_int) for block in blocks]))
        for block in blocks:
            peer.wait_for_block_hash(block.hash_int)

        unnegotiated_peer = self.connect_peer(send_feature=False)
        unnegotiated_peer.send_and_ping(msg_getdata([CInv(MSG_BLOCK, block.hash_int) for block in blocks]))
        assert_equal(unnegotiated_peer.blocks, [])
        self.nodes[0].disconnect_p2ps()

    def test_have_block_requires_branch_data(self):
        self.log.info("Test block data is only claimed when it is available for the whole announced branch")
        node = self.nodes[0]
        source_peer = self.connect_peer(feature_data=b"\x00")
        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        source_peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash))
        self.assert_staletip_tracked(blocks[-1])

        # Only the tip's block data is stored.
        assert node.submitblock(blocks[-1].serialize().hex()) in (None, "inconclusive")
        relay_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))
        staletip = relay_peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == blocks[-1].hash_int)
        assert_equal(len(staletip.headers), 2)
        assert_equal(staletip.have_block, False)
        self.nodes[0].disconnect_p2ps()

    def test_have_block_requires_data_below_known_fork_point(self):
        self.log.info("Test block data is only claimed if available down to the active chain, below the peer's known fork point")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))
        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        # The peer announces the first block, without its data.
        peer.send_and_ping(self.staletip_msg(blocks[0], fork_point_hash))
        self.assert_staletip_tracked(blocks[0])

        # The branch is extended by a block whose data is stored.
        assert node.submitblock(blocks[1].serialize().hex()) in (None, "inconclusive")
        staletip = peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == blocks[1].hash_int)
        assert_equal(staletip.hash_fork_point, blocks[0].hash_int)
        assert_equal(staletip.have_block, False)
        self.nodes[0].disconnect_p2ps()

    def test_invalid_announced_branch_block_not_punished(self):
        self.log.info("Test a peer is not punished for an invalid block on a stale branch it announced")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")
        tip = node.getblock(node.getbestblockhash())
        fork_point_hash = int(tip["previousblockhash"], 16)

        # A branch with more work than the active tip, ending in a block whose
        # coinbase claims too much, so it is only found invalid when connected.
        valid = create_block(hashprev=fork_point_hash, height=tip["height"], ntime=tip["time"] + self.block_time_offset)
        self.block_time_offset += 1
        valid.solve()
        invalid = create_block(hashprev=valid.hash_int, coinbase=create_coinbase(tip["height"] + 1, nValue=100), ntime=tip["time"] + self.block_time_offset)
        self.block_time_offset += 1
        invalid.solve()
        peer.send_and_ping(self.staletip_msg([valid, invalid], fork_point_hash, have_block=True))
        peer.wait_for_getdata_hash(valid.hash_int)
        peer.wait_for_getdata_hash(invalid.hash_int)

        with node.assert_debug_log(expected_msgs=["bad-cb-amount"], unexpected_msgs=["Misbehaving"]):
            peer.send_and_ping(msg_block(valid))
            peer.send_and_ping(msg_block(invalid))
        assert peer.is_connected
        self.nodes[0].disconnect_p2ps()

    def test_initial_advertisement_limited(self):
        self.log.info("Test only the greatest-chainwork known stale tips are advertised when relay begins")
        node = self.nodes[0]
        # Move the active tip above the stale tips left by earlier subtests, so
        # the tips created below have the greatest chainwork.
        self.generate(node, MAX_ADVERTISED_STALETIPS + 2)

        # Tips forking off deeper have less chainwork.
        known_tips = []
        for fork_depth in range(1, MAX_ADVERTISED_STALETIPS + 2):
            block, _ = self.stale_block(fork_depth=fork_depth)
            assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
            known_tips.append(block)
        for block in known_tips:
            self.assert_staletip_tracked(block)

        peer = self.connect_peer(feature_data=b"\x00")
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))
        advertised = {block.hash_int for block in known_tips[:MAX_ADVERTISED_STALETIPS]}
        peer.wait_until(lambda: {self.staletip_tip_hash(msg) for msg in peer.staletips} == advertised)
        peer.sync_with_ping()
        assert_equal(len(peer.staletips), MAX_ADVERTISED_STALETIPS)

        # The limit does not apply to tips learned after relay began, even
        # with less chainwork than the tip that was not advertised.
        new_tip, _ = self.stale_block(fork_depth=MAX_ADVERTISED_STALETIPS + 2)
        assert node.submitblock(new_tip.serialize().hex()) in (None, "inconclusive")
        peer.wait_until(lambda: new_tip.hash_int in {self.staletip_tip_hash(msg) for msg in peer.staletips})
        peer.sync_with_ping()
        assert_equal(len(peer.staletips), MAX_ADVERTISED_STALETIPS + 1)
        self.nodes[0].disconnect_p2ps()

    def test_recency_window_and_minimum_work(self):
        self.log.info("Test staletips are accepted across the recency window, but not below the minimum chain work")
        node = self.nodes[0]
        self.generate(node, max(0, STALETIP_RECENT_WINDOW + 2 - node.getblockcount()))
        source_peer = self.connect_peer(feature_data=b"\x00")

        # The oldest stale tip within the recency window is accepted, well
        # beyond the usual anti-DoS work threshold of about 144 blocks.
        oldest, fork_point_hash = self.stale_block(fork_depth=STALETIP_RECENT_WINDOW + 1)
        source_peer.send_and_ping(self.staletip_msg(oldest, fork_point_hash))
        assert_equal(node.getblockheader(oldest.hash_hex)["hash"], oldest.hash_hex)

        too_old, fork_point_hash = self.stale_block(fork_depth=STALETIP_RECENT_WINDOW + 2)
        with node.assert_debug_log(["ignoring staletip outside recency window"]):
            source_peer.send_and_ping(self.staletip_msg(too_old, fork_point_hash))
        assert_raises_rpc_error(-5, "Block not found", node.getblockheader, too_old.hash_hex)
        self.nodes[0].disconnect_p2ps()

        # Below the minimum chain work, for example during initial sync, stale
        # headers are not necessarily costly to produce.
        tip_work = int(node.getblockchaininfo()["chainwork"], 16)
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers", f"-minimumchainwork={tip_work + 1:x}"])
        source_peer = self.connect_peer(feature_data=b"\x00")
        block, fork_point_hash = self.stale_block()
        with node.assert_debug_log(["ignoring low-work staletip fork point"]):
            source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        assert_raises_rpc_error(-5, "Block not found", node.getblockheader, block.hash_hex)
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def test_more_work_staletip_tracked_after_catching_up(self):
        self.log.info("Test a staletip with more work than the active tip is tracked once the active chain catches up")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x00")
        tip = node.getblock(node.getbestblockhash())
        tip_hash = int(tip["hash"], 16)
        stale = create_block(hashprev=tip_hash, height=tip["height"] + 1, ntime=tip["time"] + self.block_time_offset)
        self.block_time_offset += 1
        stale.solve()
        peer.send_and_ping(self.staletip_msg(stale, tip_hash))
        assert_equal(node.getblockheader(stale.hash_hex)["hash"], stale.hash_hex)
        node.syncwithvalidationinterfacequeue()
        self.assert_staletip_not_tracked(stale)

        # Once the active chain has as much work, the announced tip is stale.
        active = create_block(hashprev=tip_hash, height=tip["height"] + 1, ntime=tip["time"] + self.block_time_offset)
        self.block_time_offset += 1
        active.solve()
        assert_equal(node.submitblock(active.serialize().hex()), None)
        self.assert_staletip_hash_tracked(stale.hash_hex)
        self.nodes[0].disconnect_p2ps()

    def test_more_work_headers_tracked_after_catching_up(self):
        self.log.info("Test an ordinary header with more work than the active tip is tracked and relayed once caught up")
        node = self.nodes[0]
        assert not node.getblockchaininfo()["initialblockdownload"]
        source_peer = self.connect_peer(send_feature=False)
        relay_peer = self.connect_peer()
        stale, fork_point_hash = self.active_block()
        relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, fork_point_hash)]))
        source_peer.send_and_ping(msg_headers([CBlockHeader(stale)]))
        assert_equal(node.getblockheader(stale.hash_hex)["hash"], stale.hash_hex)
        node.syncwithvalidationinterfacequeue()
        self.assert_staletip_not_tracked(stale)

        # Activate a competing block before the announced block's data arrives.
        active, _ = self.active_block()
        assert_equal(node.submitblock(active.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), active.hash_hex)
        self.assert_staletip_tracked(stale)
        assert_equal(relay_peer.wait_for_staletip(self.staletip_matcher(stale, fork_point_hash)).have_block, False)
        node.disconnect_p2ps()

    def test_more_work_rpc_headers_tracked_after_catching_up(self):
        self.log.info("Test higher-work RPC headers are tracked and relayed once caught up, without restarting")
        self.block_time_offset = getattr(self, "block_time_offset", 1)
        node = self.nodes[0]
        for mode in ("headers", "blocks"):
            self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", f"-staletips={mode}"])
            assert not node.getblockchaininfo()["initialblockdownload"]
            relay_peer = self.connect_peer(feature_data=b"\x00")
            relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))

            stale, _ = self.stale_branch(length=2, fork_depth=1)
            for block in stale:
                assert_equal(node.submitheader(CBlockHeader(block).serialize().hex()), None)
            assert_equal(node.getblockheader(stale[-1].hash_hex)["height"], node.getblockcount() + 1)
            node.syncwithvalidationinterfacequeue()
            self.assert_staletip_not_tracked(stale[-1])
            relay_peer.sync_with_ping()
            assert not any(self.staletip_tip_hash(msg) == stale[-1].hash_int for msg in relay_peer.staletips)

            # The active chain wins the race with a single new block. There
            # is no restart or P2P announcement to rediscover the RPC headers.
            active, _ = self.active_block()
            assert_equal(node.submitblock(active.serialize().hex()), None)
            assert_equal(node.getbestblockhash(), active.hash_hex)
            node.syncwithvalidationinterfacequeue()
            self.assert_staletip_tracked(stale[-1])
            self.assert_staletip_not_tracked(stale[0])
            announcement = relay_peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == stale[-1].hash_int)
            assert_equal(announcement.have_block, False)
            node.disconnect_p2ps()
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def test_more_work_full_block_tracked_after_catching_up(self):
        self.log.info("Test an out-of-order full block with more work is tracked, relayed, and served once caught up")
        node = self.nodes[0]
        self.block_time_offset = 1
        for mode in ("headers", "blocks"):
            self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", f"-staletips={mode}"])
            source_peer = self.connect_peer(send_feature=False)
            relay_peer = self.connect_peer(feature_data=b"\x00")
            parent, fork_point_hash = self.active_block()
            child = create_block(hashprev=parent.hash_int, height=node.getblockcount() + 2, ntime=parent.nTime + 1)
            child.solve()
            self.block_time_offset += 1
            relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, fork_point_hash)]))

            # Learn only the parent's header, then store its child from a full
            # block message. The child cannot connect without the parent's data.
            source_peer.send_and_ping(msg_headers([CBlockHeader(parent)]))
            source_peer.send_and_ping(msg_block(child))
            assert_equal(node.getblock(child.hash_hex)["confirmations"], -1)
            assert_raises_rpc_error(-1, "Block not available (not fully downloaded)", node.getblock, parent.hash_hex)
            node.syncwithvalidationinterfacequeue()
            self.assert_staletip_not_tracked(parent)
            self.assert_staletip_not_tracked(child)

            # A competing branch catches up before the missing parent arrives.
            for _ in range(2):
                active, _ = self.active_block()
                assert_equal(node.submitblock(active.serialize().hex()), None)
            assert_equal(node.getbestblockhash(), active.hash_hex)
            node.syncwithvalidationinterfacequeue()
            tips = node.getnetworkinfo()["staletips"]
            assert_equal([tip["have_block"] for tip in tips if tip["hash"] == child.hash_hex], [True])
            self.assert_staletip_not_tracked(parent)
            announcement = relay_peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == child.hash_int)
            assert_equal(announcement.hash_fork_point, fork_point_hash)
            assert_equal(len(announcement.headers), 2)
            assert_equal(announcement.have_block, False)

            # The tracked child's data can be served even though its missing
            # parent prevents the branch from being fully validated.
            relay_peer.send_without_ping(msg_getdata([CInv(MSG_BLOCK, child.hash_int)]))
            relay_peer.wait_for_block_hash(child.hash_int)

            source_peer.send_and_ping(msg_block(parent))
            assert_equal(node.getbestblockhash(), active.hash_hex)
            blocks_peer = self.connect_peer(feature_data=b"\x01")
            blocks_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, fork_point_hash)]))
            assert_equal(blocks_peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == child.hash_int).have_block, True)
            node.disconnect_p2ps()
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def test_more_work_compact_block_tracked_after_catching_up(self):
        self.log.info("Test a compact block header with more work than the active tip is tracked once caught up")
        node = self.nodes[0]
        source_peer = self.connect_peer(send_feature=False)
        source_peer.send_and_ping(msg_sendcmpct(announce=False, version=2))

        # The block's data never arrives: the peer doesn't serve it, and the
        # compact block isn't reconstructed, as it is unsolicited and has a
        # transaction the node doesn't have.
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0x1234, 0)))
        tx.vout.append(CTxOut(1000, CScript([OP_TRUE])))
        tip = node.getblock(node.getbestblockhash())
        stale = create_block(hashprev=int(tip["hash"], 16), height=tip["height"] + 1, ntime=tip["time"] + self.block_time_offset, txlist=[tx])
        self.block_time_offset += 1
        stale.solve()
        compact_block = HeaderAndShortIDs()
        compact_block.initialize_from_block(stale, prefill_list=[0], use_witness=True)
        source_peer.send_and_ping(msg_cmpctblock(compact_block.to_p2p()))
        assert_equal(node.getblockheader(stale.hash_hex)["hash"], stale.hash_hex)
        node.syncwithvalidationinterfacequeue()
        self.assert_staletip_not_tracked(stale)

        # Activate a competing block while the announced block is missing.
        active, _ = self.active_block()
        assert_equal(node.submitblock(active.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), active.hash_hex)
        self.assert_staletip_tracked(stale)
        self.nodes[0].disconnect_p2ps()

    def test_pruned_node_have_block(self):
        self.log.info("Test a pruned node only claims block data it would serve")
        node = self.nodes[0]
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers", "-prune=1"])
        peer = self.connect_peer(feature_data=b"\x00")
        peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))

        # A pruned node does not serve blocks this far below its tip.
        deep, _ = self.stale_block(fork_depth=NODE_NETWORK_LIMITED_MIN_BLOCKS + 10)
        shallow, _ = self.stale_block(fork_depth=2)
        for block in (deep, shallow):
            assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
        assert_equal(peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == deep.hash_int).have_block, False)
        assert_equal(peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == shallow.hash_int).have_block, True)
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=headers"])

    def test_blocks_mode_respects_pruned_peer_depth(self):
        self.log.info("Test blocks mode does not request blocks a pruned peer would not serve")
        peer = self.connect_peer(feature_data=b"\x01", services=NODE_NETWORK_LIMITED | NODE_WITNESS)
        deep, fork_point_hash = self.stale_block(fork_depth=NODE_NETWORK_LIMITED_MIN_BLOCKS + 10)
        peer.send_and_ping(self.staletip_msg(deep, fork_point_hash, have_block=True))
        shallow, fork_point_hash = self.stale_block(fork_depth=2)
        peer.send_and_ping(self.staletip_msg(shallow, fork_point_hash, have_block=True))
        peer.wait_for_getdata_hash(shallow.hash_int)
        assert deep.hash_int not in [inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK]
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_ignores_non_witness_block_peer(self):
        self.log.info("Test blocks mode does not request stale tip blocks from non-witness peers")
        peer = self.connect_peer(feature_data=b"\x01", services=NODE_NETWORK)
        block, fork_point_hash = self.stale_block()
        peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=True))
        self.assert_staletip_tracked(block)
        assert_equal([inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK], [])
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_requests_stale_branch_blocks(self):
        self.log.info("Test blocks mode requests missing stale branch blocks")
        peer = self.connect_peer(feature_data=b"\x01")
        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash, have_block=True))
        self.assert_staletip_tracked(blocks[-1])
        # Requested parents first.
        expected_hashes = [block.hash_int for block in blocks]
        peer.wait_for_getdata_hashes(expected_hashes)
        assert_equal([inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK], expected_hashes)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_staletip_not_announced_back_after_download(self):
        self.log.info("Test blocks mode does not announce a downloaded stale tip back to its announcer")
        node = self.nodes[0]
        active_tip_inv = msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))])
        source_peer = self.connect_peer(feature_data=b"\x01")
        relay_peer = self.connect_peer(feature_data=b"\x01")
        source_peer.send_and_ping(active_tip_inv)
        relay_peer.send_and_ping(active_tip_inv)

        block, fork_point_hash = self.stale_block()
        matches_block = self.staletip_matcher(block, fork_point_hash)
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=True))
        source_peer.wait_for_getdata_hash(block.hash_int)
        source_peer.send_and_ping(msg_block(block))

        # Peers preferring blocks are sent the tip once its block data is stored.
        staletip = relay_peer.wait_for_staletip(matches_block)
        assert_equal(staletip.have_block, True)
        # The tip becomes announceable asynchronously, so the source peer's
        # announcement may be queued behind the first pong. The second pong
        # comes after a message-handler pass that has seen the tip.
        source_peer.sync_with_ping()
        source_peer.sync_with_ping()
        assert_equal([msg for msg in source_peer.staletips if matches_block(msg)], [])
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_stops_waiting_for_block_data(self):
        self.log.info("Test blocks mode announces a tip without block data to block-preferring peers after a wait")
        node = self.nodes[0]
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        source_peer = self.connect_peer(feature_data=b"\x00")
        relay_peer = self.connect_peer(feature_data=b"\x01")
        relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))

        # Nobody announces having the block data, so it is not obtained.
        block, fork_point_hash = self.stale_block()
        matches_block = self.staletip_matcher(block, fork_point_hash)
        source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
        self.assert_staletip_tracked(block)
        relay_peer.sync_with_ping()
        assert_equal([msg for msg in relay_peer.staletips if matches_block(msg)], [])

        node.bumpmocktime(STALETIP_BLOCK_WAIT)
        staletip = relay_peer.wait_for_staletip(matches_block)
        assert_equal(staletip.have_block, False)

        # Block data obtained later does not cause a second announcement. The
        # second pong comes after a message-handler pass that has seen it.
        assert node.submitblock(block.serialize().hex()) in (None, "inconclusive")
        node.syncwithvalidationinterfacequeue()
        relay_peer.sync_with_ping()
        relay_peer.sync_with_ping()
        assert_equal(len([msg for msg in relay_peer.staletips if matches_block(msg)]), 1)

        node.setmocktime(0)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_initial_advertisement_limited(self):
        self.log.info("Test known tips still waiting for block data count toward the initial advertisement limit")
        node = self.nodes[0]
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        # Move above the stale tips left by earlier subtests.
        self.generate(node, MAX_ADVERTISED_STALETIPS + 2)

        # Nobody announces having the block data of these tips.
        source_peer = self.connect_peer(feature_data=b"\x00")
        known_tips = []
        for fork_depth in range(1, MAX_ADVERTISED_STALETIPS + 2):
            block, fork_point_hash = self.stale_block(fork_depth=fork_depth)
            source_peer.send_and_ping(self.staletip_msg(block, fork_point_hash))
            known_tips.append(block)

        relay_peer = self.connect_peer(feature_data=b"\x01")
        relay_peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))]))
        node.bumpmocktime(STALETIP_BLOCK_WAIT)
        advertised = {block.hash_int for block in known_tips[:MAX_ADVERTISED_STALETIPS]}
        relay_peer.wait_until(lambda: {self.staletip_tip_hash(msg) for msg in relay_peer.staletips} == advertised)
        relay_peer.sync_with_ping()
        assert_equal(len(relay_peer.staletips), MAX_ADVERTISED_STALETIPS)

        node.setmocktime(0)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_withheld_stale_block_does_not_delay_reorg(self):
        self.log.info("Test a withheld stale branch block is still downloaded from others once its branch is needed")
        node = self.nodes[0]
        announcer = self.connect_peer(feature_data=b"\x01")
        stale, fork_point_hash = self.stale_block()
        announcer.send_and_ping(self.staletip_msg(stale, fork_point_hash, have_block=True))
        announcer.wait_for_getdata_hash(stale.hash_int)

        # The announcer withholds the block. Another peer extends its branch,
        # making it the best chain, and is asked for both blocks right away.
        extension = create_block(hashprev=stale.hash_int, height=node.getblockcount() + 1, ntime=stale.nTime + 1)
        extension.solve()
        peer = self.connect_peer(send_feature=False)
        peer.send_and_ping(msg_headers([CBlockHeader(extension)]))
        peer.wait_for_getdata_hashes([stale.hash_int, extension.hash_int])
        peer.send_and_ping(msg_block(stale))
        peer.send_and_ping(msg_block(extension))
        assert_equal(node.getbestblockhash(), extension.hash_hex)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_mutated_block_keeps_request_to_other_peer(self):
        self.log.info("Test a mutated block from one peer does not cancel the stale branch block request to another")
        node = self.nodes[0]
        announcer = self.connect_peer(feature_data=b"\x01")
        # A stale block with less work than the tip is only stored if requested.
        stale, fork_point_hash = self.stale_block(fork_depth=2)
        announcer.send_and_ping(self.staletip_msg(stale, fork_point_hash, have_block=True))
        announcer.wait_for_getdata_hash(stale.hash_int)

        mutated = deepcopy(stale)
        mutated.vtx[0].nLockTime = 1
        assert_equal(mutated.hash_int, stale.hash_int)
        attacker = self.connect_peer(send_feature=False)
        with node.assert_debug_log(["Received mutated block"]):
            attacker.send_without_ping(msg_block(mutated))
            attacker.wait_for_disconnect()

        announcer.send_and_ping(msg_block(stale))
        assert_equal(node.getblock(stale.hash_hex)["hash"], stale.hash_hex)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_stale_block_not_counted_for_eviction(self):
        self.log.info("Test a stale branch block does not count as a new block from the peer for inbound eviction")
        node = self.nodes[0]
        peer = self.connect_peer(feature_data=b"\x01")
        block, fork_point_hash = self.stale_block(fork_depth=2)
        peer.send_and_ping(self.staletip_msg(block, fork_point_hash, have_block=True))
        peer.wait_for_getdata_hash(block.hash_int)
        peer.send_and_ping(msg_block(block))
        assert_equal(node.getblock(block.hash_hex)["hash"], block.hash_hex)
        assert_equal(node.getpeerinfo()[0]["last_block"], 0)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_waits_for_branch_block_data(self):
        self.log.info("Test peers preferring block data are sent a stale tip once the data of its whole branch is stored")
        node = self.nodes[0]
        # Freeze time, so the announcement isn't sent without block data
        # after STALETIP_BLOCK_WAIT.
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        active_tip_inv = msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))])
        source_peer = self.connect_peer(feature_data=b"\x01")
        relay_peer = self.connect_peer(feature_data=b"\x01")
        source_peer.send_and_ping(active_tip_inv)
        relay_peer.send_and_ping(active_tip_inv)

        blocks, fork_point_hash = self.stale_branch(length=2, fork_depth=2)
        source_peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash, have_block=True))
        source_peer.wait_for_getdata_hashes([block.hash_int for block in blocks])
        # The tip's block data arrives before its parent's. The tip becomes
        # announceable asynchronously, so wait for a message-handler pass for
        # the relay peer that has seen it: the second pong comes after one.
        source_peer.send_and_ping(msg_block(blocks[1]))
        node.syncwithvalidationinterfacequeue()
        relay_peer.sync_with_ping()
        relay_peer.sync_with_ping()
        source_peer.send_and_ping(msg_block(blocks[0]))
        staletip = relay_peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == blocks[1].hash_int)
        assert_equal(staletip.have_block, True)
        node.setmocktime(0)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_invalid_child_does_not_hide_parent(self):
        self.log.info("Test a stale block is tracked when its tracked child turns out invalid, in either arrival order")
        node = self.nodes[0]
        for child_first in (True, False):
            peer = self.connect_peer(feature_data=b"\x01")
            tip = node.getblock(node.getbestblockhash())
            peer.send_and_ping(msg_inv([CInv(MSG_BLOCK, int(tip["hash"], 16))]))
            fork_point = node.getblock(node.getblock(tip["previousblockhash"])["previousblockhash"])
            fork_point_hash = int(fork_point["hash"], 16)
            parent = create_block(hashprev=fork_point_hash, height=fork_point["height"] + 1, ntime=tip["time"] + self.block_time_offset)
            self.block_time_offset += 1
            parent.solve()
            # The child's coinbase is for another height, so it is invalid.
            child = create_block(hashprev=parent.hash_int, coinbase=create_coinbase(fork_point["height"] + 5), ntime=tip["time"] + self.block_time_offset)
            self.block_time_offset += 1
            child.solve()

            peer.send_and_ping(self.staletip_msg([parent, child], fork_point_hash, have_block=True))
            self.assert_staletip_tracked(child)
            peer.wait_for_getdata_hashes([parent.hash_int, child.hash_int])
            for block in ((child, parent) if child_first else (parent, child)):
                peer.send_and_ping(msg_block(block))
            self.assert_staletip_tracked(parent)
            self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_caps_stale_branch_requests_and_clears_timeout(self):
        self.log.info("Test stale branch requests are capped, leave block download alone, and time out without disconnect")
        node = self.nodes[0]
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        peer = self.connect_peer(feature_data=b"\x01")
        def getdata_hashes():
            return [inv.hash for inv in peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK]

        first, fork_point_hash = self.stale_block(fork_depth=2)
        peer.send_and_ping(self.staletip_msg(first, fork_point_hash, have_block=True))
        peer.wait_for_getdata_hash(first.hash_int)

        # Once the cap is reached, the earliest blocks of a branch are
        # deferred, while its tip is requested.
        blocks, fork_point_hash = self.stale_branch(length=20, fork_depth=20)
        peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash, have_block=True))
        self.assert_staletip_tracked(blocks[-1])
        expected_hashes = [first.hash_int] + [block.hash_int for block in blocks[-(MAX_STALE_BLOCK_REQUESTS_PER_PEER - 1):]]
        self.wait_until(lambda: getdata_hashes() == expected_hashes)
        another, fork_point_hash = self.stale_block(fork_depth=3)
        peer.send_and_ping(self.staletip_msg(another, fork_point_hash, have_block=True))
        self.assert_staletip_tracked(another)
        assert_equal(getdata_hashes(), expected_hashes)

        # The optional requests do not use the peer's block download slots, so
        # it is still asked for a new block on the active chain.
        assert_equal(node.getpeerinfo()[0]["inflight"], [])
        block, _ = self.active_block()
        peer.send_and_ping(msg_headers([CBlockHeader(block)]))
        peer.wait_for_getdata_hash(block.hash_int)
        peer.send_and_ping(msg_block(block))
        assert_equal(node.getbestblockhash(), block.hash_hex)

        with node.assert_debug_log(["Timeout downloading stale-tip branch block"]):
            node.bumpmocktime(601)
            peer.sync_with_ping()
        assert peer.is_connected
        # Expired requests free capacity for the unfinished branch and the
        # announcement received while every slot was occupied. Already
        # attempted blocks are not retried.
        resumed_hashes = [blocks[0].hash_int, another.hash_int]
        peer.wait_for_getdata_hashes(resumed_hashes)
        assert_equal(getdata_hashes(), expected_hashes + [block.hash_int] + resumed_hashes)

        node.setmocktime(0)
        self.nodes[0].disconnect_p2ps()

    def test_blocks_mode_resumes_stale_branch_downloads(self):
        self.log.info("Test stale branch downloads resume when earlier requests complete, without another announcement")
        self.block_time_offset = getattr(self, "block_time_offset", 1)
        self.restart_node(0, extra_args=["-debug=net", "-peertimeout=999", "-staletips=blocks"])
        node = self.nodes[0]
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        active_tip_inv = msg_inv([CInv(MSG_BLOCK, int(node.getbestblockhash(), 16))])
        source_peer = self.connect_peer(feature_data=b"\x01")
        relay_peer = self.connect_peer(feature_data=b"\x01")
        source_peer.send_and_ping(active_tip_inv)
        relay_peer.send_and_ping(active_tip_inv)

        first, fork_point_hash = self.stale_block(fork_depth=2)
        source_peer.send_and_ping(self.staletip_msg(first, fork_point_hash, have_block=True))
        source_peer.wait_for_getdata_hash(first.hash_int)
        blocks, fork_point_hash = self.stale_branch(length=20, fork_depth=20)
        source_peer.send_and_ping(self.staletip_msg(blocks, fork_point_hash, have_block=True))
        initial_hashes = [first.hash_int] + [block.hash_int for block in blocks[1:]]
        self.wait_until(lambda: [inv.hash for inv in source_peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK] == initial_hashes)

        # Fill every request slot, then answer all of those requests. The
        # oldest branch block must be requested without repeating staletip.
        source_peer.send_and_ping(msg_block(first))
        for block in blocks[1:]:
            source_peer.send_and_ping(msg_block(block))
        node.syncwithvalidationinterfacequeue()
        source_peer.sync_with_ping()
        source_peer.sync_with_ping()
        assert_equal([inv.hash for inv in source_peer.getdata if inv.type & MSG_TYPE_MASK == MSG_BLOCK], initial_hashes + [blocks[0].hash_int])
        relay_peer.sync_with_ping()
        relay_peer.sync_with_ping()
        assert not any(self.staletip_tip_hash(msg) == blocks[-1].hash_int for msg in relay_peer.staletips)

        source_peer.send_and_ping(msg_block(blocks[0]))
        staletip = relay_peer.wait_for_staletip(lambda msg: self.staletip_tip_hash(msg) == blocks[-1].hash_int)
        assert_equal(staletip.have_block, True)
        for block in blocks:
            assert_equal(node.getblock(block.hash_hex)["hash"], block.hash_hex)
        node.setmocktime(0)
        self.nodes[0].disconnect_p2ps()


if __name__ == "__main__":
    P2PStaleTipTest(__file__).main()

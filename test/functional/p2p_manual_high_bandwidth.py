#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test manual BIP152 high-bandwidth peer selection."""

from test_framework.messages import msg_sendcmpct
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class ManualHighBandwidthTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        self.sync_all()

    @staticmethod
    def peer_info(node, peer_id):
        return next(peer for peer in node.getpeerinfo() if peer["id"] == peer_id)

    def run_test(self):
        node, peer_node = self.nodes

        self.log.info("Manual selection requires negotiated compact block support")
        p2p_peer = node.add_p2p_connection(P2PInterface())
        peer_id = node.getpeerinfo()[0]["id"]
        info = self.peer_info(node, peer_id)
        assert_equal(info["bip152_hb_to"], False)
        assert_equal(info["bip152_hb_to_manual"], False)
        assert_raises_rpc_error(
            -1,
            "Peer has not negotiated version 2 compact block support",
            node.setpeerhighbandwidth,
            peer_id,
            True,
        )

        p2p_peer.send_and_ping(msg_sendcmpct(announce=False, version=2))
        assert_equal(p2p_peer.message_count["sendcmpct"], 1)

        self.log.info("The RPC enables, disables, and reports the manual source")
        assert_equal(
            node.setpeerhighbandwidth(peer_id, True),
            {
                "peer_id": peer_id,
                "bip152_hb_to_manual": True,
                "bip152_hb_to": True,
            },
        )
        p2p_peer.wait_until(lambda: p2p_peer.message_count["sendcmpct"] == 2)
        assert_equal(p2p_peer.last_message["sendcmpct"].announce, True)
        info = self.peer_info(node, peer_id)
        assert_equal(info["bip152_hb_to"], True)
        assert_equal(info["bip152_hb_to_manual"], True)

        # Repeating an effective state does not send a redundant SENDCMPCT.
        assert_equal(node.setpeerhighbandwidth(peer_id, True)["bip152_hb_to"], True)
        p2p_peer.sync_with_ping()
        assert_equal(p2p_peer.message_count["sendcmpct"], 2)

        assert_equal(
            node.setpeerhighbandwidth(peer_id, False),
            {
                "peer_id": peer_id,
                "bip152_hb_to_manual": False,
                "bip152_hb_to": False,
            },
        )
        p2p_peer.wait_until(lambda: p2p_peer.message_count["sendcmpct"] == 3)
        assert_equal(p2p_peer.last_message["sendcmpct"].announce, False)
        info = self.peer_info(node, peer_id)
        assert_equal(info["bip152_hb_to"], False)
        assert_equal(info["bip152_hb_to_manual"], False)
        assert_raises_rpc_error(-1, "Peer does not exist", node.setpeerhighbandwidth, 999999, False)

        node.disconnect_p2ps()

        self.log.info("Clearing the manual source preserves automatic selection")
        self.generate(node, 2, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks([node, peer_node])
        peer_id = next(peer["id"] for peer in node.getpeerinfo() if "(testnode1)" in peer["subver"])
        assert_equal(node.setpeerhighbandwidth(peer_id, True)["bip152_hb_to"], True)
        self.generate(peer_node, 1)
        self.sync_blocks([node, peer_node])
        node.syncwithvalidationinterfacequeue()
        result = node.setpeerhighbandwidth(peer_id, False)
        assert_equal(result["bip152_hb_to_manual"], False)
        assert_equal(result["bip152_hb_to"], True)
        info = self.peer_info(node, peer_id)
        assert_equal(info["bip152_hb_to_manual"], False)
        assert_equal(info["bip152_hb_to"], True)

        self.disconnect_nodes(0, 1)

        self.log.info("Short-lived address-fetch connections cannot be selected")
        addr_fetch_peer = node.add_outbound_p2p_connection(
            P2PInterface(),
            p2p_idx=0,
            connection_type="addr-fetch",
        )
        addr_fetch_peer.send_and_ping(msg_sendcmpct(announce=False, version=2))
        addr_fetch_id = next(peer["id"] for peer in node.getpeerinfo() if peer["connection_type"] == "addr-fetch")
        assert_raises_rpc_error(
            -1,
            "Connection type addr-fetch does not support manual high-bandwidth compact block announcements",
            node.setpeerhighbandwidth,
            addr_fetch_id,
            True,
        )
        addr_fetch_peer.peer_disconnect()
        node.wait_until(lambda: not node.getpeerinfo())

        self.log.info("Blocksonly mode rejects enabling but permits clearing")
        self.restart_node(0, ["-blocksonly"])
        p2p_peer = node.add_p2p_connection(P2PInterface())
        p2p_peer.send_and_ping(msg_sendcmpct(announce=False, version=2))
        peer_id = node.getpeerinfo()[0]["id"]
        assert_raises_rpc_error(
            -1,
            "Cannot enable high-bandwidth compact block announcements in blocksonly mode",
            node.setpeerhighbandwidth,
            peer_id,
            True,
        )
        assert_equal(node.setpeerhighbandwidth(peer_id, False)["bip152_hb_to"], False)


if __name__ == "__main__":
    ManualHighBandwidthTest(__file__).main()

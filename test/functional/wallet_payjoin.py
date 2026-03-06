#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 77 payjoin wallet RPCs.

Tests the payjoin RPC interface with a C++ OHTTP-aware mock directory:
- receivepayjoin: creates a session, returns a valid BIP 77 URI
- sendpayjoin: creates a funded PSBT, encrypts and posts to directory
- advancepayjoin: advances sessions through protocol steps
- payjoininfo: retrieves session information
- listpayjoin: lists sessions with filtering
- cancelpayjoin: cancels active sessions
- End-to-end payjoin: full protocol flow with real OHTTP
"""

import os
import subprocess
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.socks5 import Socks5Configuration, Socks5Server
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)


class PayjoinTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        # Launch C++ OHTTP-aware directory binary from the build bin directory
        build_dir = self.config["environment"]["BUILDDIR"]
        exe_ext = self.config["environment"]["EXEEXT"]
        directory_binary = os.path.join(build_dir, "bin", "test_payjoin_directory" + exe_ext)

        self.mock_http_port = p2p_port(self.num_nodes + 1)
        self.log.info(f"Starting C++ directory on port {self.mock_http_port}: {directory_binary}")

        self.directory_process = subprocess.Popen(
            [directory_binary, "--port", str(self.mock_http_port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for "READY <port>" from stdout
        line = self.directory_process.stdout.readline()
        assert line.startswith(b"READY"), f"Directory failed to start: {line}"
        self.log.info(f"C++ directory ready on port {self.mock_http_port}")

        # Start SOCKS5 proxy that redirects all external connections to the
        # C++ directory (both nodes use the same directory)
        socks_port = p2p_port(self.num_nodes)
        socks_conf = Socks5Configuration()
        socks_conf.addr = ("127.0.0.1", socks_port)
        socks_conf.unauth = True
        socks_conf.auth = False
        mock_port = self.mock_http_port
        socks_conf.destinations_factory = lambda addr, port: {
            "actual_to_addr": "127.0.0.1",
            "actual_to_port": mock_port,
        }

        self.socks_server = Socks5Server(socks_conf)
        self.socks_server.start()
        self.log.info(f"SOCKS5 proxy on port {socks_port}")

        # Configure nodes: -onion= routes payjoin HTTP traffic through proxy
        # while leaving P2P between test nodes unaffected
        self.extra_args = [
            [f"-onion=127.0.0.1:{socks_port}"],
            [f"-onion=127.0.0.1:{socks_port}"],
        ]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        self.import_deterministic_coinbase_privkeys()

    def shutdown(self):
        # Kill the C++ directory process
        if hasattr(self, 'directory_process') and self.directory_process:
            self.directory_process.terminate()
            self.directory_process.wait()
        super().shutdown()

    def run_test(self):
        self.log.info("Fund the wallets")
        self.generate(self.nodes[0], COINBASE_MATURITY + 10)
        self.sync_all()

        # Also fund the receiver node so it has UTXOs to contribute
        self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1.0)
        self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 0.5)
        self.generate(self.nodes[0], 1)
        self.sync_all()

        self.test_error_cases()
        self.test_receivepayjoin()
        self.test_sendpayjoin()
        self.test_end_to_end_payjoin()
        self.test_session_lifecycle()
        self.test_background_polling()

    # ------------------------------------------------------------------
    # Error case tests
    # ------------------------------------------------------------------

    def test_error_cases(self):
        self.log.info("Testing error cases...")

        # listpayjoin returns empty array when no sessions exist
        assert_equal(self.nodes[0].listpayjoin(), [])
        assert_equal(self.nodes[0].listpayjoin(True), [])

        # payjoininfo fails for non-existent session
        fake_id = "0" * 64
        assert_raises_rpc_error(-8, "Session not found",
                                self.nodes[0].payjoininfo, fake_id)

        # sendpayjoin fails with invalid URI (before network check)
        assert_raises_rpc_error(-4, "Failed to parse payjoin URI",
                                self.nodes[0].sendpayjoin, "not-a-valid-uri")

        # cancelpayjoin fails for non-existent session
        assert_raises_rpc_error(-8, "Session not found",
                                self.nodes[0].cancelpayjoin, fake_id)

        # advancepayjoin fails for non-existent session
        assert_raises_rpc_error(-8, "Session not found",
                                self.nodes[0].advancepayjoin, fake_id)

    # ------------------------------------------------------------------
    # receivepayjoin: valid session creation
    # ------------------------------------------------------------------

    def test_receivepayjoin(self):
        self.log.info("Testing receivepayjoin creates a valid session...")

        node = self.nodes[1]  # receiver is node 1
        result = node.receivepayjoin(0.001)

        # Check returned fields
        assert "session_id" in result
        assert "payjoin_uri" in result
        assert_equal(result["state"], "initialized")
        self.receiver_session_id = result["session_id"]
        self.payjoin_uri = result["payjoin_uri"]

        # Validate session ID is a 64-char hex string
        assert_equal(len(self.receiver_session_id), 64)
        int(self.receiver_session_id, 16)  # raises on invalid hex

        # Validate URI structure
        uri = self.payjoin_uri
        self.log.info(f"Payjoin URI: {uri}")
        assert uri.lower().startswith("bitcoin:"), "URI must start with bitcoin:"
        assert "pj=" in uri, "URI must contain pj= parameter"
        assert "amount=" in uri, "URI must contain amount"

        # payjoininfo should return the session
        info = node.payjoininfo(self.receiver_session_id)
        assert_equal(info["role"], "receiver")
        assert_equal(info["state"], "initialized")
        assert_equal(info["is_terminal"], False)
        assert "payjoin_uri" in info
        assert "created_at" in info
        assert "expires_at" in info
        assert info["expires_at"] > info["created_at"]

        # listpayjoin should show the session
        sessions = node.listpayjoin()
        assert_equal(len(sessions), 1)
        assert_equal(sessions[0]["session_id"], self.receiver_session_id)
        assert_equal(sessions[0]["role"], "receiver")
        assert_equal(sessions[0]["state"], "initialized")

    # ------------------------------------------------------------------
    # sendpayjoin: valid session creation with funded PSBT
    # ------------------------------------------------------------------

    def test_sendpayjoin(self):
        self.log.info("Testing sendpayjoin with valid URI from receiver...")

        node = self.nodes[0]  # sender is node 0

        # Use the URI generated by receivepayjoin
        result = node.sendpayjoin(self.payjoin_uri)

        # Check returned fields
        assert "session_id" in result
        assert_equal(result["state"], "posted_original")
        self.sender_session_id = result["session_id"]

        # Validate session ID
        assert_equal(len(self.sender_session_id), 64)
        int(self.sender_session_id, 16)

        # listpayjoin should show the session
        sessions = node.listpayjoin()
        self.log.info(f"Sender sessions: {sessions}")
        self.log.info(f"Looking for session_id: {self.sender_session_id}")
        assert_equal(len(sessions), 1)
        assert_equal(sessions[0]["session_id"], self.sender_session_id)
        assert_equal(sessions[0]["role"], "sender")

        # payjoininfo should show sender session
        info = node.payjoininfo(self.sender_session_id)
        assert_equal(info["role"], "sender")
        assert_equal(info["state"], "posted_original")
        assert_equal(info["is_terminal"], False)
        assert_equal(info["is_polling"], True)  # posted_original -> waiting for proposal

    # ------------------------------------------------------------------
    # End-to-end payjoin with advancepayjoin
    # ------------------------------------------------------------------

    def test_end_to_end_payjoin(self):
        self.log.info("Testing end-to-end payjoin protocol...")

        sender_node = self.nodes[0]
        receiver_node = self.nodes[1]

        # Use the sessions created by test_receivepayjoin and test_sendpayjoin
        recv_session_id = self.receiver_session_id
        send_session_id = self.sender_session_id

        # 1. Receiver polls for original -> receives it
        self.log.info("Step 1: Receiver polls for original PSBT...")
        info = receiver_node.advancepayjoin(recv_session_id)
        self.log.info(f"Receiver state after poll: {info['state']}")
        assert_equal(info["state"], "received_original")

        # 2. Receiver processes original and sends proposal
        self.log.info("Step 2: Receiver processes and sends proposal...")
        info = receiver_node.advancepayjoin(recv_session_id)
        self.log.info(f"Receiver state after process: {info['state']}")
        assert_equal(info["state"], "proposal_sent")

        # 3. Sender polls for proposal -> receives it and finalizes
        self.log.info("Step 3: Sender polls for proposal and finalizes...")
        info = sender_node.advancepayjoin(send_session_id)
        self.log.info(f"Sender state after advance: {info['state']}")
        assert_equal(info["state"], "completed")
        assert "txid" in info
        txid = info["txid"]
        self.log.info(f"Payjoin transaction broadcast: {txid}")

        # 4. Mine a block and sync
        self.log.info("Step 4: Mining a block...")
        self.generate(sender_node, 1)
        self.sync_all()

        # 5. Verify the payjoin tx has inputs from BOTH wallets
        self.log.info("Step 5: Verifying payjoin transaction...")
        wallet_tx = sender_node.gettransaction(txid)
        decoded = sender_node.decoderawtransaction(wallet_tx["hex"])
        self.log.info(f"Payjoin tx has {len(decoded['vin'])} inputs")
        assert len(decoded["vin"]) >= 2, "Payjoin tx should have inputs from both wallets"

        # 6. Receiver checks payment -> confirms
        self.log.info("Step 6: Receiver checks payment...")
        info = receiver_node.advancepayjoin(recv_session_id)
        self.log.info(f"Receiver state after check: {info['state']}")
        assert_equal(info["state"], "completed")
        assert "txid" in info

        self.log.info("End-to-end payjoin test PASSED!")

    # ------------------------------------------------------------------
    # Session lifecycle: cancel and verify terminal states
    # ------------------------------------------------------------------

    def test_session_lifecycle(self):
        self.log.info("Testing session lifecycle (cancel)...")

        # The end-to-end test completed both sessions. Verify terminal state.
        info = self.nodes[0].payjoininfo(self.sender_session_id)
        assert_equal(info["state"], "completed")
        assert_equal(info["is_terminal"], True)

        info = self.nodes[1].payjoininfo(self.receiver_session_id)
        assert_equal(info["state"], "completed")
        assert_equal(info["is_terminal"], True)

        # Cannot cancel a completed session
        assert_raises_rpc_error(-8, "terminal state",
                                self.nodes[0].cancelpayjoin,
                                self.sender_session_id)

        # Cannot advance a completed session
        assert_raises_rpc_error(-8, "terminal state",
                                self.nodes[0].advancepayjoin,
                                self.sender_session_id)

        # Create a new session and cancel it
        result = self.nodes[1].receivepayjoin(0.002)
        new_session_id = result["session_id"]
        cancel_result = self.nodes[1].cancelpayjoin(new_session_id)
        assert_equal(cancel_result["state"], "cancelled")

        info = self.nodes[1].payjoininfo(new_session_id)
        assert_equal(info["state"], "cancelled")
        assert_equal(info["is_terminal"], True)
        assert_equal(info["error"], "Cancelled by user")

        # Cannot cancel again
        assert_raises_rpc_error(-8, "terminal state",
                                self.nodes[1].cancelpayjoin,
                                new_session_id)


    # ------------------------------------------------------------------
    # Background polling: sessions auto-advance without advancepayjoin
    # ------------------------------------------------------------------

    def wait_for_payjoin_state(self, node, session_id, target_state, bump_nodes=None):
        """Wait for a payjoin session to reach target_state, using mockscheduler
        and setmocktime to fast-forward both the scheduler and NodeClock."""
        mock_time = int(time.time())
        for n in (bump_nodes or [node]):
            n.setmocktime(mock_time)
        for _ in range(20):
            # Advance mock time to satisfy per-session poll throttle
            mock_time += 31
            for n in (bump_nodes or [node]):
                n.setmocktime(mock_time)
                n.mockscheduler(31)
            time.sleep(0.5)  # Brief pause for scheduler thread to execute
            info = node.payjoininfo(session_id)
            self.log.info(f"  session {session_id[:8]}... state: {info['state']}")
            if info["state"] == target_state:
                # Reset mock time so subsequent operations use real time
                for n in (bump_nodes or [node]):
                    n.setmocktime(0)
                return info
            if info.get("is_terminal", False) and info["state"] != target_state:
                for n in (bump_nodes or [node]):
                    n.setmocktime(0)
                raise AssertionError(f"Session reached terminal state {info['state']} instead of {target_state}")
        for n in (bump_nodes or [node]):
            n.setmocktime(0)
        raise AssertionError(f"Session {session_id} did not reach {target_state} after 20 scheduler bumps")

    def test_background_polling(self):
        self.log.info("Testing background polling (sessions auto-advance)...")

        sender_node = self.nodes[0]
        receiver_node = self.nodes[1]

        # Fund receiver with fresh UTXOs for this test
        sender_node.sendtoaddress(receiver_node.getnewaddress(), 0.5)
        self.generate(sender_node, 1)
        self.sync_all()

        # Create receiver session
        recv_result = receiver_node.receivepayjoin(0.001)
        recv_id = recv_result["session_id"]
        uri = recv_result["payjoin_uri"]
        self.log.info(f"Receiver session: {recv_id}")

        # Create sender session (posts original to directory)
        send_result = sender_node.sendpayjoin(uri)
        send_id = send_result["session_id"]
        self.log.info(f"Sender session: {send_id}")

        # Do NOT call advancepayjoin — use mockscheduler to fast-forward
        both_nodes = [sender_node, receiver_node]

        self.log.info("Waiting for background polling to complete sender...")
        self.wait_for_payjoin_state(sender_node, send_id, "completed", both_nodes)
        self.log.info("Sender completed via background polling")

        # Mine a block so receiver can confirm payment
        self.generate(sender_node, 1)
        self.sync_all()

        self.log.info("Waiting for background polling to complete receiver...")
        self.wait_for_payjoin_state(receiver_node, recv_id, "completed", both_nodes)
        self.log.info("Receiver completed via background polling")

        # Verify the payjoin tx has inputs from both wallets
        txid = sender_node.payjoininfo(send_id)["txid"]
        wallet_tx = sender_node.gettransaction(txid)
        decoded = sender_node.decoderawtransaction(wallet_tx["hex"])
        assert len(decoded["vin"]) >= 2, "Payjoin tx should have inputs from both wallets"

        self.log.info("Background polling test PASSED!")


if __name__ == "__main__":
    PayjoinTest(__file__).main()

#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test wallet transaction broadcast when -privatebroadcast is enabled.

When -privatebroadcast is enabled, wallet transactions (sendtoaddress, sendmany,
send, etc.) should be broadcast privately through Tor/I2P networks instead of
being announced to all connected peers.

This test verifies:
1. Wallet RPCs (sendtoaddress) work correctly with private broadcast via SOCKS5 proxy
2. Transactions skip the local mempool and are broadcast via proxy to remote nodes
3. The private_broadcast flag is persisted to prevent privacy leaks on restart
4. MaybeResendWalletTxs uses private broadcast when -privatebroadcast is enabled
5. Error handling when Tor/I2P is not reachable

Test coverage matrix:

| Test | Scenario                                                           | Code Path Tested                                              |
|------|--------------------------------------------------------------------|---------------------------------------------------------------|
| 1    | New transaction with -privatebroadcast                             | CommitTransaction() -> SubmitTxMemoryPoolAndRelay()           |
| 2    | Resubmission SKIPPED when flag set but -privatebroadcast disabled  | MaybeResendWalletTxs() with MEMPOOL_AND_BROADCAST_TO_ALL      |
| 3    | Resubmission with -privatebroadcast enabled                        | MaybeResendWalletTxs() with NO_MEMPOOL_PRIVATE_BROADCAST      |
|      | - Verifies tx WITHOUT flag is SKIPPED (was sent publicly)          |                                                               |
|      | - Verifies tx WITH flag is resubmitted via private broadcast       |                                                               |
| 4    | Error when Tor/I2P not reachable                                   | Error handling in wallet send RPCs                            |

Note: The P2P-level private broadcast behavior (transaction returning from network,
rebroadcast, etc.) is tested in p2p_private_broadcast.py. This test focuses on
wallet-specific functionality.
"""

import threading
import time

from test_framework.blocktools import create_block, create_coinbase
from test_framework.p2p import P2PInterface
from test_framework.socks5 import (
    Socks5Configuration,
    Socks5Server,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
    tor_port,
)


# Fake .onion addresses for populating addrman. The mock SOCKS5 proxy will
# redirect connections to these addresses to the receiver node.
FAKE_ONION_ADDRESSES = [
    "testonlyad777777777777777777777777777777777777777775b6qd.onion",
    "testonlyah77777777777777777777777777777777777777777z7ayd.onion",
    "testonlyal77777777777777777777777777777777777777777vp6qd.onion",
    "testonlyap77777777777777777777777777777777777777777r5qad.onion",
    "testonlyat77777777777777777777777777777777777777777udsid.onion",
]


class WalletPrivateBroadcastTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.disable_autoconnect = False
        # Use v1 transport for simpler connection handling in this test
        self.extra_args = [[], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        # Start a SOCKS5 proxy server that redirects all connections to node 1.
        socks5_server_config = Socks5Configuration()
        # Use p2p_port(self.num_nodes) to avoid conflicts with node ports
        socks5_server_config.addr = ("127.0.0.1", p2p_port(self.num_nodes))
        socks5_server_config.unauth = True
        socks5_server_config.auth = True

        self.socks5_server = Socks5Server(socks5_server_config)
        self.socks5_server.start()
        self.socks5_port = self.socks5_server.conf.addr[1]

        self.destinations = []
        self.destinations_lock = threading.Lock()

        def destinations_factory(requested_to_addr, requested_to_port):
            """Redirect all SOCKS5 connections to the receiver node's onion port."""
            with self.destinations_lock:
                self.destinations.append({
                    "requested_to_addr": requested_to_addr,
                    "requested_to_port": requested_to_port,
                })
                self.log.debug(f"SOCKS5: Redirecting connection to {requested_to_addr}:{requested_to_port} "
                               f"-> 127.0.0.1:{tor_port(1)}")
                return {
                    "actual_to_addr": "127.0.0.1",
                    "actual_to_port": tor_port(1),
                }

        self.socks5_server.conf.destinations_factory = destinations_factory

        # Node 0: sender with -privatebroadcast enabled, using SOCKS5 proxy
        # Node 1: receiver, listening on an "onion" port
        self.extra_args = [
            [
                "-privatebroadcast=1",
                f"-proxy=127.0.0.1:{self.socks5_port}",
                # Needed to be able to add CJDNS addresses to addrman
                "-cjdnsreachable",
                "-v2transport=0",
                "-test=addrman",
            ],
            [
                "-connect=0",
                f"-bind=127.0.0.1:{tor_port(1)}=onion",
                "-v2transport=0",
            ],
        ]
        super().setup_nodes()

    def setup_network(self):
        self.setup_nodes()
        # Don't connect nodes - private broadcast goes through SOCKS5

    def add_onion_addresses_to_addrman(self):
        """Populate node 0's addrman with fake .onion addresses."""
        self.log.info("Adding fake .onion addresses to sender's addrman")
        for addr in FAKE_ONION_ADDRESSES:
            res = self.nodes[0].addpeeraddress(address=addr, port=8333, tried=False)
            if not res["success"]:
                self.log.debug(f"Could not add {addr} to addrman (collision?)")

    def wait_for_private_broadcast(self, num_broadcasts):
        """Wait until the specified number of private broadcast connections have been made."""
        self.wait_until(lambda: len(self.destinations) >= num_broadcasts)

    def run_test(self):
        sender = self.nodes[0]
        receiver = self.nodes[1]

        # Add a P2P connection to the receiver to observe transaction propagation
        observer = receiver.add_p2p_connection(P2PInterface())

        # Populate sender's addrman with fake .onion addresses
        self.add_onion_addresses_to_addrman()

        # Create and fund wallets
        self.log.info("Creating and funding wallets")
        sender.createwallet(wallet_name="sender_wallet")
        sender_wallet = sender.get_wallet_rpc("sender_wallet")

        receiver.createwallet(wallet_name="receiver_wallet")
        receiver_wallet = receiver.get_wallet_rpc("receiver_wallet")

        # Mine blocks to fund the sender wallet
        address = sender_wallet.getnewaddress()
        self.generatetoaddress(sender, 101, address, sync_fun=self.no_op)

        balance = sender_wallet.getbalance()
        assert balance > 0, f"Wallet should have balance, got {balance}"
        self.log.info(f"Sender wallet funded with {balance} BTC")

        # === Test 1: sendtoaddress with private broadcast ===
        self.log.info("Test 1: sendtoaddress with private broadcast")
        dest1 = receiver_wallet.getnewaddress()
        initial_destinations = len(self.destinations)

        txid1 = sender_wallet.sendtoaddress(dest1, 1.0)
        self.log.info(f"sendtoaddress txid={txid1}")

        # Transaction should NOT be in sender's mempool immediately (private broadcast)
        assert_equal(len(sender.getrawmempool()), 0)
        self.log.info("PASS: Transaction NOT in sender's mempool (expected for private broadcast)")

        # Wait for private broadcast connections to be established
        self.wait_for_private_broadcast(initial_destinations + 1)
        self.log.info("PASS: Private broadcast connection established via SOCKS5")

        # Transaction should reach the receiver's mempool
        self.wait_until(lambda: txid1 in receiver.getrawmempool(), timeout=30)
        self.log.info("PASS: Transaction received by receiver node")

        # Observer should see the transaction relayed
        observer.wait_for_tx(txid1)
        self.log.info("PASS: Transaction relayed to observer")

        # Note: The "transaction coming back" functionality is tested in p2p_private_broadcast.py
        # For this wallet test, we focus on verifying wallet-specific private broadcast behavior.
        # sendmany and send RPCs use the same code path as sendtoaddress, so we don't test them separately.

        # === Test 2: Verify private_broadcast flag persistence ===
        self.log.info("Test 2: Verify private_broadcast flag prevents rebroadcast on restart")

        # txid1 was created with -privatebroadcast=1, so it has mapValue["private_broadcast"] = "1"
        # stored in the wallet. Now restart WITHOUT -privatebroadcast and verify that
        # ResubmitWalletTransactions skips this transaction.

        # Stop the SOCKS5 server since we won't need it for this test
        self.socks5_server.stop()

        # Restart sender WITHOUT -privatebroadcast (normal mode)
        self.restart_node(0, extra_args=["-v2transport=0"])

        sender.loadwallet("sender_wallet")
        sender_wallet = sender.get_wallet_rpc("sender_wallet")

        # To trigger ResubmitWalletTransactions, we need:
        # 1. A block at least 5 minutes after the transaction was created
        # 2. Enough time passed for the resubmit timer (12-36 hours)
        #
        # Create a block with mocktime in the future to satisfy these conditions.
        block_time = int(time.time()) + 6 * 60  # 6 minutes in the future
        sender.setmocktime(block_time)
        best_block_hash = int(sender.getbestblockhash(), 16)
        block = create_block(best_block_hash, create_coinbase(sender.getblockcount() + 1), block_time)
        block.solve()
        sender.submitblock(block.serialize().hex())

        # Ensure m_best_block_time is updated
        sender.syncwithvalidationinterfacequeue()

        # Now advance time to trigger resubmission (36 hours is the upper limit)
        sender.setmocktime(block_time + 36 * 60 * 60)

        # Trigger MaybeResendWalletTxs and verify the private_broadcast tx is skipped
        skip_msg = f"skipping tx {txid1} originally sent via private broadcast"
        with sender.assert_debug_log(expected_msgs=[skip_msg]):
            sender.mockscheduler(60)  # Trigger the scheduler to call MaybeResendWalletTxs

        self.log.info("PASS: Transaction with private_broadcast flag was skipped during rebroadcast")

        # === Test 3: MaybeResendWalletTxs skips public txs when -privatebroadcast enabled ===
        self.log.info("Test 3: Verify MaybeResendWalletTxs skips public txs when -privatebroadcast enabled")

        # Reset mocktime to real time for transaction creation
        sender.setmocktime(0)

        # Create a new transaction WITHOUT -privatebroadcast flag
        # (node is currently running without -privatebroadcast after Test 2)
        dest3 = receiver_wallet.getnewaddress()
        txid_public = sender_wallet.sendtoaddress(dest3, 0.5)
        self.log.info(f"Created transaction without private_broadcast flag: {txid_public}")

        # Transaction should be in sender's mempool (normal broadcast mode)
        assert txid_public in sender.getrawmempool()
        self.log.info("Transaction is in sender's mempool (expected for normal mode)")

        # Restart SOCKS5 server for private broadcast (use a different port to avoid TIME_WAIT)
        socks5_server_config = Socks5Configuration()
        self.socks5_port = p2p_port(self.num_nodes + 1)
        socks5_server_config.addr = ("127.0.0.1", self.socks5_port)
        socks5_server_config.unauth = True
        socks5_server_config.auth = True
        self.socks5_server = Socks5Server(socks5_server_config)

        def destinations_factory_test3(requested_to_addr, requested_to_port):
            """Redirect all SOCKS5 connections to the receiver node's onion port."""
            with self.destinations_lock:
                self.destinations.append({
                    "requested_to_addr": requested_to_addr,
                    "requested_to_port": requested_to_port,
                })
                self.log.debug(f"SOCKS5: Redirecting connection to {requested_to_addr}:{requested_to_port} "
                               f"-> 127.0.0.1:{tor_port(1)}")
                return {
                    "actual_to_addr": "127.0.0.1",
                    "actual_to_port": tor_port(1),
                }

        self.socks5_server.conf.destinations_factory = destinations_factory_test3
        self.socks5_server.start()

        # Record current destinations count
        with self.destinations_lock:
            initial_destinations_test3 = len(self.destinations)

        # Restart sender WITH -privatebroadcast and proxy
        self.restart_node(0, extra_args=[
            "-privatebroadcast=1",
            f"-proxy=127.0.0.1:{self.socks5_port}",
            "-cjdnsreachable",
            "-v2transport=0",
            "-test=addrman",
        ])

        sender = self.nodes[0]
        sender.loadwallet("sender_wallet")
        sender_wallet = sender.get_wallet_rpc("sender_wallet")

        # Re-add onion addresses to addrman
        self.add_onion_addresses_to_addrman()

        # Set up mocktime for resubmission trigger
        # Transaction needs to be more than 5 minutes older than best block
        block_time = int(time.time()) + 6 * 60
        sender.setmocktime(block_time)
        best_block_hash = int(sender.getbestblockhash(), 16)
        block = create_block(best_block_hash, create_coinbase(sender.getblockcount() + 1), block_time)
        block.solve()
        sender.submitblock(block.serialize().hex())
        sender.syncwithvalidationinterfacequeue()

        # Advance time to trigger resubmission
        sender.setmocktime(block_time + 36 * 60 * 60)

        # Trigger MaybeResendWalletTxs and verify:
        # - txid1 (has private_broadcast flag): resubmitted via private broadcast
        # - txid_public (no flag, was sent publicly): SKIPPED to prevent privacy leak
        #   (rebroadcasting a public tx privately would reveal user has -privatebroadcast)
        skip_msg_txid1 = f"skipping tx {txid1} originally sent via private broadcast"
        skip_msg_public = f"skipping tx {txid_public} originally sent via public broadcast"
        with sender.assert_debug_log(expected_msgs=[skip_msg_public], unexpected_msgs=[skip_msg_txid1]):
            sender.mockscheduler(60)

        # Verify SOCKS5 connection was made only for txid1 (the private tx):
        # - txid1: has private_broadcast flag, resubmitted privately
        # - txid_public: no flag (was public), SKIPPED
        # We expect only 1 new connection (for txid1)
        self.wait_for_private_broadcast(initial_destinations_test3 + 1)
        self.log.info("PASS: MaybeResendWalletTxs skipped public tx and rebroadcast private tx")

        # Stop SOCKS5 server before Test 4
        self.socks5_server.stop()

        # === Test 4: Error when Tor/I2P not reachable ===
        self.log.info("Test 4: Error when Tor/I2P not reachable")

        # Restart sender with -privatebroadcast but no working Tor/I2P.
        # Use -listenonion so the node thinks Tor might become available (and starts),
        # but use an invalid torcontrol port so Tor connections actually fail.
        self.restart_node(0, extra_args=[
            "-privatebroadcast=1",
            "-v2transport=0",
            "-listenonion",  # Makes node think Tor may be available later
            "-torcontrol=127.0.0.1:1",  # Invalid port, so Tor won't actually work
        ])

        sender.loadwallet("sender_wallet")
        sender_wallet = sender.get_wallet_rpc("sender_wallet")

        dest2 = receiver_wallet.getnewaddress()

        # Wallet send RPCs should fail with network unavailable error
        # (The wallet uses the same code path for sendtoaddress, sendmany, and send)
        assert_raises_rpc_error(
            -1,
            "none of the Tor or I2P networks is reachable",
            sender_wallet.sendtoaddress, dest2, 0.1
        )
        self.log.info("PASS: sendtoaddress correctly rejected when Tor/I2P not reachable")

        self.log.info("All 4 wallet private broadcast tests passed!")


if __name__ == "__main__":
    WalletPrivateBroadcastTest(__file__).main()

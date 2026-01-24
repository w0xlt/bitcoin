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
1. Error when Tor/I2P not reachable but -privatebroadcast is enabled
2. Normal broadcast works when -privatebroadcast is disabled
3. All wallet send RPCs (sendtoaddress, sendmany, send) work correctly

Note: Positive private broadcast testing (tx reaching destination via Tor) is
covered by p2p_private_broadcast.py which has the full SOCKS5 proxy setup.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletPrivateBroadcastTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Disable autoconnect to prevent -connect being added to bitcoin.conf
        # (required because -privatebroadcast is incompatible with -connect)
        self.disable_autoconnect = False
        # Node 0: -privatebroadcast enabled but Tor/I2P unreachable (for negative test)
        # Node 1: normal node (for positive test as receiver)
        self.extra_args = [
            [
                "-privatebroadcast",
                # Point to non-existent Tor control to make Tor unreachable
                "-torcontrol=127.0.0.1:1",
                "-listenonion",
            ],
            ["-connect=0"],  # Node 1: isolated, won't connect to anyone
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        # Don't connect nodes initially - we'll connect them later for normal broadcast test

    def run_test(self):
        wallet_node = self.nodes[0]
        receiver_node = self.nodes[1]

        # === Test 1: Error when Tor/I2P not reachable ===
        self.log.info("Test 1: Error when -privatebroadcast enabled but Tor/I2P not reachable")

        # Create and fund wallet
        wallet_node.createwallet(wallet_name="test_wallet")
        wallet = wallet_node.get_wallet_rpc("test_wallet")

        # Mine blocks to fund the wallet (no sync - nodes not connected)
        address = wallet.getnewaddress()
        self.generatetoaddress(wallet_node, COINBASE_MATURITY + 5, address, sync_fun=self.no_op)

        balance = wallet.getbalance()
        assert balance > 0, f"Wallet should have balance, got {balance}"
        self.log.info(f"Wallet funded with {balance} BTC")

        # Test sendtoaddress - should fail with network unavailable
        dest = receiver_node.getnewaddress()
        assert_raises_rpc_error(
            -1,
            "none of the Tor or I2P networks is reachable",
            wallet.sendtoaddress, dest, 0.1
        )
        self.log.info("sendtoaddress correctly rejected when Tor/I2P not reachable")

        # Test sendmany - should also fail
        assert_raises_rpc_error(
            -1,
            "none of the Tor or I2P networks is reachable",
            wallet.sendmany, "", {dest: 0.1}
        )
        self.log.info("sendmany correctly rejected")

        # Test send RPC - should also fail
        assert_raises_rpc_error(
            -1,
            "none of the Tor or I2P networks is reachable",
            wallet.send, {dest: 0.1}
        )
        self.log.info("send RPC correctly rejected")

        # === Test 2: Normal broadcast when -privatebroadcast disabled ===
        self.log.info("Test 2: Normal broadcast when -privatebroadcast disabled")

        # Restart node 0 without -privatebroadcast
        self.stop_node(0)
        self.start_node(0, extra_args=[])

        # Connect nodes directly for normal relay
        self.connect_nodes(0, 1)
        self.sync_blocks()

        # Reload wallet
        wallet_node.loadwallet("test_wallet")
        wallet = wallet_node.get_wallet_rpc("test_wallet")

        # Send transaction - should succeed with normal broadcast
        dest_normal = receiver_node.getnewaddress()
        txid = wallet.sendtoaddress(dest_normal, 0.1)
        self.log.info(f"sendtoaddress txid={txid}")

        # Transaction should reach receiver through normal relay
        self.wait_until(lambda: txid in receiver_node.getrawmempool(), timeout=30)
        self.log.info("Transaction received via normal broadcast")

        # Verify transaction is in wallet
        tx_info = wallet.gettransaction(txid)
        assert_equal(tx_info["txid"], txid)
        self.log.info("Transaction recorded in wallet")

        # === Test 3: sendmany and send also work with normal broadcast ===
        self.log.info("Test 3: sendmany and send work with normal broadcast")

        dest2 = receiver_node.getnewaddress()
        txid2 = wallet.sendmany("", {dest2: 0.05})
        self.wait_until(lambda: txid2 in receiver_node.getrawmempool(), timeout=30)
        self.log.info(f"sendmany txid={txid2} - received")

        dest3 = receiver_node.getnewaddress()
        result = wallet.send({dest3: 0.05})
        txid3 = result["txid"]
        self.wait_until(lambda: txid3 in receiver_node.getrawmempool(), timeout=30)
        self.log.info(f"send txid={txid3} - received")

        self.log.info("All tests passed!")


if __name__ == "__main__":
    WalletPrivateBroadcastTest(__file__).main()

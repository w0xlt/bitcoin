#!/usr/bin/env python3
"""
Test HD split migration using an ancient wallet from Bitcoin Core v0.14.3.
"""
import os
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

class WalletSplitHDMigrationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()  # Skip if wallet is not compiled in
        self.skip_if_no_previous_releases()

    def setup_network(self):
        self.add_nodes(
            self.num_nodes,
            versions=[
                140300,  # Supporting non-HD wallet format (with `-usehd=0`)
                None,    # Current version for testing migration
            ],
        )

    def run_test(self):
        self.log.info("Testing migration of non-HD wallet from v0.14.3 to current version")
        
        # Start the old node with -usehd=0 to create a non-HD wallet
        self.log.info("Starting old node with non-HD wallet...")
        self.start_node(0, extra_args=["-usehd=0", "-keypool=10"])
        
        # Save the datadir paths while nodes are running
        node0_datadir = self.nodes[0].datadir_path
        node1_datadir = self.nodes[1].datadir_path
        
        # Generate some addresses and get wallet info from the old wallet
        self.log.info("Creating addresses and transactions in old wallet...")
        old_addresses = []
        for i in range(5):
            addr = self.nodes[0].getnewaddress()
            old_addresses.append(addr)
            self.log.info(f"  Generated address {i+1}: {addr}")
        
        # Get some wallet info before migration
        old_wallet_info = self.nodes[0].getwalletinfo()
        self.log.info(f"Old wallet info: HD enabled = {old_wallet_info.get('hdmasterkeyid', 'Not HD')}")
        # Assert wallet is non-HD as expected
        assert('hdmasterkeyid' not in old_wallet_info)
        
        # Generate some blocks to the first address to have balance
        # Use sync_fun=lambda:None to avoid syncing with non-started nodes
        # This is necessary because v0.14.3 does not support syncwithvalidationinterfacequeue RPC
        # which is used by `test_framework.py` to sync nodes
        self.log.info("Generating blocks to create balance...")
        self.generatetoaddress(self.nodes[0], 101, old_addresses[0], sync_fun=lambda: None)
        
        # Send some transactions to create history
        # Send with amounts that will likely create change
        self.log.info("Creating transaction history...")
        self.nodes[0].sendtoaddress(old_addresses[1], 0.1)
        self.nodes[0].sendtoaddress(old_addresses[2], 0.2)
        self.nodes[0].sendtoaddress(old_addresses[3], 0.3)
        
        # Mine the transactions
        self.generatetoaddress(self.nodes[0], 1, old_addresses[0], sync_fun=lambda: None)
        
        # Get the balance and transaction count
        old_balance = self.nodes[0].getbalance()
        old_txs = self.nodes[0].listtransactions("*", 1000)
        old_tx_count = len(old_txs)
        self.log.info(f"Old wallet balance: {old_balance} BTC")
        self.log.info(f"Old wallet transaction count: {old_tx_count}")
        # Assert we have expected balance and transactions
        assert(old_balance > 0)
        assert(old_tx_count > 0)
        
        # Get all addresses from transactions (including change addresses if any)
        all_old_addresses = set()
        for tx in old_txs:
            if 'address' in tx:
                all_old_addresses.add(tx['address'])
        
        self.log.info(f"Total addresses in wallet transactions: {len(all_old_addresses)}")
        self.log.info(f"Explicitly generated addresses: {len(old_addresses)}")
        
        # Identify which generated addresses appear in transactions
        addresses_in_txs = set(old_addresses) & all_old_addresses
        self.log.info(f"Generated addresses that appear in transactions: {len(addresses_in_txs)}")
        
        # Identify potential change addresses (addresses in transactions but not explicitly generated)
        change_addresses = all_old_addresses - set(old_addresses)
        if change_addresses:
            self.log.info(f"Found {len(change_addresses)} change addresses:")
            for change_addr in change_addresses:
                self.log.info(f"  Change address: {change_addr}")
        else:
            self.log.info("No change addresses detected (transactions may have spent exact UTXOs)")
        
        # Stop the old node
        self.log.info("Stopping old node...")
        self.stop_node(0)
        
        # Copy blockchain data from node0 to node1 BEFORE starting node1
        # Only copy blocks directory - chainstate will be rebuilt
        self.log.info("Copying blockchain data from old node to modern node...")
        old_blocks_dir = os.path.join(node0_datadir, self.chain, "blocks")
        new_blocks_dir = os.path.join(node1_datadir, self.chain, "blocks")
        
        # Copy only the blocks directory (not chainstate due to format incompatibility)
        if os.path.exists(old_blocks_dir):
            shutil.copytree(old_blocks_dir, new_blocks_dir)
            self.log.info(f"  Copied blocks directory")
        # Assert blocks directory was copied
        assert(os.path.exists(new_blocks_dir))
        
        # Start the modern node with -reindex-chainstate to rebuild chainstate from blocks
        self.log.info("Starting modern node with -reindex-chainstate to rebuild chainstate...")
        self.start_node(1, extra_args=["-reindex-chainstate"])
        
        # Wait for reindex to complete
        self.log.info("Waiting for chainstate reindex to complete...")
        self.wait_until(
            lambda: self.nodes[1].getblockcount() == 102,
            timeout=30
        )
        
        # Verify the blockchain was loaded correctly
        node1_info = self.nodes[1].getblockchaininfo()
        self.log.info(f"Modern node blockchain info: height={node1_info['blocks']}, bestblockhash={node1_info['bestblockhash'][:16]}...")
        # Assert correct blockchain height
        assert_equal(node1_info['blocks'], 102)
        
        # Copy the old wallet to the modern node's wallet directory
        self.log.info("Copying old wallet to modern node...")
        old_wallet_path = os.path.join(node0_datadir, self.chain, "wallet.dat")
        modern_wallets_dir = os.path.join(node1_datadir, self.chain, "wallets")
        os.makedirs(modern_wallets_dir, exist_ok=True)
        
        # Create a directory for the migrated wallet
        migrated_wallet_dir = os.path.join(modern_wallets_dir, "migrated_wallet")
        os.makedirs(migrated_wallet_dir, exist_ok=True)
        migrated_wallet_path = os.path.join(migrated_wallet_dir, "wallet.dat")
        shutil.copy2(old_wallet_path, migrated_wallet_path)
        # Assert wallet file was copied
        assert(os.path.exists(migrated_wallet_path))
        
        # Perform wallet migration to descriptor wallet
        self.log.info("Performing wallet migration to descriptor wallet...")
        migration_result = self.nodes[1].migratewallet("migrated_wallet")
        self.log.info(f"Migration result: {migration_result}")
        
        # Assert migration succeeded and created backup
        assert('wallet_name' in migration_result)
        assert('backup_path' in migration_result)
        wallet_name = migration_result['wallet_name']
        self.log.info(f"Backup created at: {migration_result['backup_path']}")
        # Assert backup file exists
        assert(os.path.exists(migration_result['backup_path']))
        
        # Rescan the blockchain to pick up all transactions
        self.log.info("Rescanning blockchain to ensure all transactions are detected...")
        self.nodes[1].rescanblockchain()
        
        # Verify the migration
        self.log.info("Verifying migration...")
        
        # Get the new wallet info
        new_wallet_info = self.nodes[1].getwalletinfo()
        self.log.info(f"New wallet info:")
        self.log.info(f"  Format: {new_wallet_info.get('format', 'unknown')}")
        self.log.info(f"  HD: {new_wallet_info.get('hdmasterkeyid', 'Not HD')}")
        self.log.info(f"  Descriptors: {new_wallet_info.get('descriptors', False)}")
        
        # Assert expected wallet format after migration
        assert_equal(new_wallet_info.get('format'), 'sqlite')
        assert_equal(new_wallet_info.get('descriptors'), True)
        # Assert wallet remains non-HD after migration (since original was non-HD)
        assert('hdmasterkeyid' not in new_wallet_info)
        
        # Verify balance is preserved
        new_balance = self.nodes[1].getbalance()
        self.log.info(f"New wallet balance: {new_balance} BTC")
        
        # NOW we can properly compare balances since both nodes have the same blockchain
        assert_equal(old_balance, new_balance) # Balance should be preserved after migration
        self.log.info(f"✓ Balance correctly preserved: {old_balance} BTC")
        
        # Verify transactions are preserved
        new_txs = self.nodes[1].listtransactions("*", 1000)
        new_tx_count = len(new_txs)
        self.log.info(f"New wallet transaction count: {new_tx_count}")
        assert_equal(old_tx_count, new_tx_count) # Transaction count should be preserved
        self.log.info(f"✓ Transaction count correctly preserved: {old_tx_count}")
        
        # Verify all explicitly generated addresses are still valid
        self.log.info("Verifying explicitly generated addresses are still valid...")
        for addr in old_addresses:
            addr_info = self.nodes[1].getaddressinfo(addr)
            assert(addr_info['ismine']) # The address must still belong to the wallet after migration
            self.log.info(f"  Address {addr}: OK (mine={addr_info['ismine']})")
        
        # Verify change addresses (if any) are still valid
        if change_addresses:
            self.log.info("Verifying change addresses are still valid...")
            for change_addr in change_addresses:
                addr_info = self.nodes[1].getaddressinfo(change_addr)
                assert(addr_info['ismine']) # The change address must still belong to the wallet after migration
                self.log.info(f"  Change address {change_addr}: OK (mine={addr_info['ismine']})")
        
        # Verify ALL addresses from transactions are still owned
        self.log.info("Verifying all addresses from transactions are still owned...")
        for addr in all_old_addresses:
            addr_info = self.nodes[1].getaddressinfo(addr)
            assert(addr_info['ismine']) # The address must still belong to the wallet after migration
        self.log.info(f"✓ All {len(all_old_addresses)} addresses from transactions verified as owned after migration")
        
        # Test that we can still receive and send with migrated wallet
        self.log.info("Testing wallet functionality after migration...")
        
        # Generate a new address
        new_addr = self.nodes[1].getnewaddress()
        self.log.info(f"New address after migration: {new_addr}")
        # Assert new address was created successfully
        assert(len(new_addr) > 0)
        
        # For descriptor wallets, check if it's using descriptors
        new_addr_info = self.nodes[1].getaddressinfo(new_addr)
        self.log.info(f"Address has descriptor: {new_addr_info['desc'][:50]}...")
        # Assert new address has descriptor (since wallet is now descriptor-based)
        assert('desc' in new_addr_info)
        
        # Create a test transaction (we should have balance now)
        test_addr = self.nodes[1].getnewaddress()
        txid = self.nodes[1].sendtoaddress(test_addr, 0.1)
        self.log.info(f"✓ Test transaction created successfully: {txid}")
        # Assert transaction was created
        assert(len(txid) == 64)  # Transaction ID should be 64 hex characters
        
        self.log.info("Migration test completed successfully!")

if __name__ == '__main__':
    WalletSplitHDMigrationTest(__file__).main()

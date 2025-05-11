#!/usr/bin/env python3

import argparse
from pathlib import Path
import sqlite3
import sys
import time
import os

from bitcoin_primitives import CBlock, from_binary, CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness, CTxInWitness, CScriptWitness
import pbk

def setup_database(db_path: Path):
    """
    Recreates the SQLite database and sets up the schema.
    Returns a (connection, cursor) tuple.
    """
    if db_path.exists():
        # Ensure the path is not a directory, then unlink
        if db_path.is_file():
            db_path.unlink()
        elif db_path.is_dir():
            print(f"Error: Expected a file path for the database, but got a directory: {db_path}")
            sys.exit(1)
        # If it doesn't exist or was unlinked, proceed.

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("PRAGMA foreign_keys = ON;")

    cursor.execute('''
    CREATE TABLE blocks (
        height INTEGER PRIMARY KEY,
        block_hash_hex TEXT UNIQUE NOT NULL,
        timestamp INTEGER NOT NULL
    )''')

    cursor.execute('''
    CREATE TABLE transactions (
        txid_hex TEXT PRIMARY KEY,
        block_height INTEGER NOT NULL,
        tx_index_in_block INTEGER NOT NULL,
        version INTEGER NOT NULL,
        lock_time INTEGER NOT NULL,
        has_witness BOOLEAN NOT NULL,
        FOREIGN KEY (block_height) REFERENCES blocks(height) ON DELETE CASCADE,
        UNIQUE (block_height, tx_index_in_block)
    )''')

    cursor.execute('''
    CREATE TABLE tx_inputs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        txid_hex TEXT NOT NULL,
        input_index INTEGER NOT NULL,
        prev_tx_hash_hex TEXT,
        prev_output_index INTEGER,
        script_sig_hex TEXT,
        sequence INTEGER NOT NULL,
        FOREIGN KEY (txid_hex) REFERENCES transactions(txid_hex) ON DELETE CASCADE,
        UNIQUE (txid_hex, input_index)
    )''')

    cursor.execute('''
    CREATE TABLE tx_outputs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        txid_hex TEXT NOT NULL,
        output_index INTEGER NOT NULL,
        value_satoshi INTEGER NOT NULL,
        script_pub_key_hex TEXT NOT NULL,
        FOREIGN KEY (txid_hex) REFERENCES transactions(txid_hex) ON DELETE CASCADE,
        UNIQUE (txid_hex, output_index)
    )''')

    cursor.execute('''
    CREATE TABLE witness_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        txid_hex TEXT NOT NULL,
        input_index INTEGER NOT NULL,
        item_index_in_stack INTEGER NOT NULL,
        witness_data_hex TEXT NOT NULL,
        FOREIGN KEY (txid_hex, input_index) REFERENCES tx_inputs (txid_hex, input_index) ON DELETE CASCADE,
        UNIQUE (txid_hex, input_index, item_index_in_stack)
    )''')

    conn.commit()
    return conn, cursor

# command:   uv run main.py -v <your_bitcoin_folder> <new_db_name> --chain=<chain>
# ex. macos: uv run main.py -v /Users/node/Library/Application\ Support/Bitcoin tx-db.sqlite --chain=signet
# ex. linux: uv run main.py -v /home/node/.bitcoin/ tx-db.sqlite --chain=signet

def main():
    parser = argparse.ArgumentParser(description="Dump Bitcoin transaction data from node's datadir into an SQLite database.",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('node_datadir', help='path to bitcoin data directory (must be from a non-pruned node)')
    parser.add_argument('sqlite_db_path', help='path to SQLite3 database to be created/overwritten')
    parser.add_argument('-v', '--verbose', action='store_true', help='show more detailed conversion stats periodically')
    parser.add_argument('--chain', default='mainnet', help='chain to use (mainnet by default; allowed values: mainnet, signet, testnet4, testnet, regtest)')
    parser.add_argument('--start_height', type=int, default=0, help='Block height to start processing from (default: 0)')

    args = parser.parse_args()

    node_datadir_path = Path(args.node_datadir)
    if not node_datadir_path.exists():
        print(f"Error: provided input directory '{args.node_datadir}' doesn't exist.")
        sys.exit(1)

    chaintype = {
        'mainnet':  pbk.ChainType.MAINNET,
        'signet':   pbk.ChainType.SIGNET,
        'testnet4': pbk.ChainType.TESTNET_4,
        'testnet':  pbk.ChainType.TESTNET,
        'regtest':  pbk.ChainType.REGTEST,
    }.get(args.chain)
    if chaintype is None:
        print(f"Error: provided invalid chain type '{args.chain}'.")
        sys.exit(1)

    db_path = Path(args.sqlite_db_path)

    print(f"Using node datadir: {node_datadir_path}")
    print(f"Output SQLite DB: {db_path}")

    conn, cursor = setup_database(db_path)
    
    total_blocks_processed_count = 0
    total_txs_processed_count = 0

    try:
        print("Loading chain manager... ", end='', flush=True)
        if args.chain == 'mainnet' and (node_datadir_path / 'blocks').exists():
            chain_path = node_datadir_path
        elif args.chain == 'testnet' and (node_datadir_path / 'testnet3' / 'blocks').exists():
             chain_path = node_datadir_path / 'testnet3'
        else:
            chain_path = node_datadir_path / args.chain
        
        if not chain_path.exists() or not (chain_path / 'blocks').exists():
            print(f"\nError: Chain path {chain_path} (or its 'blocks' subdirectory) does not seem to be a valid Bitcoin chain directory.")
            sys.exit(1)

        print(f"from {chain_path}... ", end='', flush=True)
        chainman = pbk.load_chainman(chain_path, chaintype)
        print("done.")

        start_height = args.start_height
        tip_index = chainman.get_block_index_from_tip()
        if tip_index is None:
            print(f"Error: Could not get tip block index from chain manager. Chain might be empty or corrupted.")
            sys.exit(1)
        tip_height = tip_index.height


        print(f"Processing blocks from height {start_height} to {tip_height}")
        overall_processing_start_time = time.time()

        for block_height in range(start_height, tip_height + 1):
            block_processing_start_time = time.time()
            transactions_to_batch_insert = []
            inputs_to_batch_insert = []
            outputs_to_batch_insert = []
            witness_items_to_batch_insert = []
            
            print(f"Processing block {block_height}/{tip_height}... ", end='', flush=True)

            block_index = chainman.get_block_index_from_height(block_height)
            if block_index is None:
                print(f"Warning: Could not retrieve block index for height {block_height}. Skipping.")
                continue
            block_data_result = chainman.read_block_from_disk(block_index)
            if block_data_result is None or block_data_result.data is None:
                print(f"Warning: Could not read block data for height {block_height}. Skipping.")
                continue
            block_data = block_data_result.data
            
            block = from_binary(CBlock, block_data)
            
            block.calc_sha256()
            
            cursor.execute("INSERT INTO blocks (height, block_hash_hex, timestamp) VALUES (?, ?, ?)",
                           (block_height, block.hash, block.nTime))

            for tx_idx, tx in enumerate(block.vtx):
                tx.calc_sha256()
                txid_hex = tx.sha256[::-1].hex()

                # Determine if the transaction has a SegWit structure (non-empty vtxinwit)
                # CTransaction.wit is CTxWitness. CTxWitness.vtxinwit is a list of CTxInWitness.
                # This list is empty for non-SegWit txs.
                transaction_has_witness_structure = bool(tx.wit and tx.wit.vtxinwit)

                transactions_to_batch_insert.append((
                    txid_hex,
                    block_height,
                    tx_idx,
                    tx.version,
                    tx.nLockTime,
                    transaction_has_witness_structure
                ))

                for input_idx, txin in enumerate(tx.vin):
                    prev_tx_hash_hex = txin.prevout.hash.to_bytes(32, 'little').hex()
                    inputs_to_batch_insert.append((
                        txid_hex,
                        input_idx,
                        prev_tx_hash_hex,
                        txin.prevout.n,
                        txin.scriptSig.hex(),
                        txin.nSequence
                    ))

                for output_idx, txout in enumerate(tx.vout):
                    outputs_to_batch_insert.append((
                        txid_hex,
                        output_idx,
                        txout.nValue,
                        txout.scriptPubKey.hex()
                    ))
                
                # Only attempt to process witness items if the transaction has a witness structure
                if transaction_has_witness_structure:
                    for witness_input_idx, tx_in_witness_obj in enumerate(tx.wit.vtxinwit):
                        # tx_in_witness_obj is CTxInWitness
                        # tx_in_witness_obj.scriptWitness is CScriptWitness
                        # tx_in_witness_obj.scriptWitness.stack is a list of bytes (witness items)
                        
                        # Only proceed if this specific input's witness stack is not empty
                        if tx_in_witness_obj.scriptWitness.stack:
                            for item_idx, witness_item_bytes in enumerate(tx_in_witness_obj.scriptWitness.stack):
                                witness_items_to_batch_insert.append((
                                    txid_hex,
                                    witness_input_idx, # This corresponds to the input_index in tx.vin
                                    item_idx,
                                    witness_item_bytes.hex()
                                ))
            
            if transactions_to_batch_insert:
                cursor.executemany("INSERT INTO transactions (txid_hex, block_height, tx_index_in_block, version, lock_time, has_witness) VALUES (?, ?, ?, ?, ?, ?)", transactions_to_batch_insert)
            if inputs_to_batch_insert:
                cursor.executemany("INSERT INTO tx_inputs (txid_hex, input_index, prev_tx_hash_hex, prev_output_index, script_sig_hex, sequence) VALUES (?, ?, ?, ?, ?, ?)", inputs_to_batch_insert)
            if outputs_to_batch_insert:
                cursor.executemany("INSERT INTO tx_outputs (txid_hex, output_index, value_satoshi, script_pub_key_hex) VALUES (?, ?, ?, ?)", outputs_to_batch_insert)
            if witness_items_to_batch_insert:
                cursor.executemany("INSERT INTO witness_items (txid_hex, input_index, item_index_in_stack, witness_data_hex) VALUES (?, ?, ?, ?)", witness_items_to_batch_insert)

            conn.commit()
            
            block_processing_time = time.time() - block_processing_start_time
            num_txs_in_block = len(block.vtx)
            total_blocks_processed_count += 1
            total_txs_processed_count += num_txs_in_block
            
            print(f"done ({num_txs_in_block} txs, {block_processing_time:.2f}s).")

            if args.verbose and total_blocks_processed_count > 0 and (total_blocks_processed_count % 100 == 0 or block_height == tip_height) :
                current_total_time = time.time() - overall_processing_start_time
                avg_time_per_block = current_total_time / total_blocks_processed_count if total_blocks_processed_count else 0
                print(f"  Stats @ block {block_height}: Avg time/block: {avg_time_per_block:.2f}s. Total txs: {total_txs_processed_count}")

        overall_processing_time = time.time() - overall_processing_start_time
        print(f"\nFinished processing {total_blocks_processed_count} blocks (from {start_height} to {tip_height}) in {overall_processing_time:.2f} seconds.")
        if total_blocks_processed_count > 0:
            print(f"Total transactions processed: {total_txs_processed_count}")
            print(f"Average time per block: {overall_processing_time / total_blocks_processed_count:.2f} seconds.")
            if total_txs_processed_count > 0:
                 print(f"Average time per transaction: {overall_processing_time / total_txs_processed_count:.4f} seconds.")


    except Exception as e:
        print(f"\nAn error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if 'conn' in locals() and conn:
            conn.close()
        print("Database connection closed.")

if __name__ == "__main__":
    main()
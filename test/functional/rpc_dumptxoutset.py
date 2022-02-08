#!/usr/bin/env python3
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the generation of UTXO snapshots using `dumptxoutset`.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

import hashlib
import os
from pathlib import Path


class DumptxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    @staticmethod
    def check_output_file(path, is_human_readable, expected_digest):
        with open(str(path), 'rb') as f:
            content = f.read()

            if is_human_readable:
                # Normalise platform EOL to \n, while making sure any stray \n becomes a literal backslash+n to avoid a false positive
                # This ensures the platform EOL and only the platform EOL produces the expected hash
                linesep = os.linesep.encode('utf8')
                content = b'\n'.join(line.replace(b'\n', b'\\n') for line in content.split(linesep))

            digest = hashlib.sha256(content).hexdigest()
            # UTXO snapshot hash should be deterministic based on mocked time.
            assert_equal(digest, expected_digest)

    def test_dump_file(self, filename, is_human_readable, expected_digest):

        node = self.nodes[0]

        out = node.dumptxoutset(filename, is_human_readable)
        expected_path = Path(node.datadir) / self.chain / filename

        assert expected_path.is_file()

        assert_equal(out['coins_written'], 100)
        assert_equal(out['base_height'], 100)
        assert_equal(out['path'], str(expected_path))
        # Blockhash should be deterministic based on mocked time.
        assert_equal(
            out['base_hash'],
            '6fd417acba2a8738b06fee43330c50d58e6a725046c3d843c8dd7e51d46d1ed6')

        self.check_output_file(expected_path, is_human_readable, expected_digest)

        assert_equal(
            out['txoutset_hash'], 'd4b614f476b99a6e569973bf1c0120d88b1a168076f8ce25691fb41dd1cef149')
        assert_equal(out['nchaintx'], 101)

        # Specifying a path to an existing file will fail.
        assert_raises_rpc_error(
            -8, '{} already exists'.format(filename),  node.dumptxoutset, filename)

        if (is_human_readable):
            with open(expected_path, 'r', encoding='utf-8') as f:
                content = f.readlines()
                assert_equal(content[0].rstrip(),
                    "#(blockhash 6fd417acba2a8738b06fee43330c50d58e6a725046c3d843c8dd7e51d46d1ed6),txid,vout,value,coinbase,height,scriptPubKey")
                assert_equal(content[1].rstrip(),
                    "213ecbdfe837a2c8ffc0812da62d4de94efce8894c67e22ff658517ecf104e03,0,5000000000,1,81,76a9142b4569203694fc997e13f2c0a1383b9e16c77a0d88ac")

    def run_test(self):
        """Test a trivial usage of the dumptxoutset RPC command."""
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)
        self.generate(node, COINBASE_MATURITY)

        self.test_dump_file('txoutset.dat', False, '7ae82c986fa5445678d2a21453bb1c86d39e47af13da137640c2b1cf8093691c')
        self.test_dump_file('txoutset.txt', True, '5bc8a9c14d1f6d89833342dcd6014bdf9ddb5f19e3741760da6d6d666971df41')

if __name__ == '__main__':
    DumptxoutsetTest().main()

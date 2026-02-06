#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that gettxoutsetinfo handles a block connecting between cs_main release and GetUTXOStats().

This is a regression test for the race condition described in the issue #34263.
The -test=gettxoutsetinfo_race_sleep option inserts a 100ms sleep after cs_main
is released in the gettxoutsetinfo handler, creating a deterministic window for
a block to connect. On the old (buggy) code this would trigger a CHECK_NONFATAL
failure; on the fixed code it succeeds because pindex is nullptr on the default
path and the check passes trivially.
"""

import threading
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy
from test_framework.wallet import MiniWallet


class GetTxOutSetInfoRaceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-test=gettxoutsetinfo_race_sleep"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("Mine initial blocks")
        self.generate(wallet, 10)

        self.log.info("Start gettxoutsetinfo in background thread")
        # Create a separate RPC proxy for the background thread — required
        # because the same connection cannot be used from two threads.
        rpc_proxy = get_rpc_proxy(node.url, 0, timeout=60, coveragedir=node.coverage_dir)

        result = [None]
        error = [None]

        def call_gettxoutsetinfo():
            try:
                result[0] = rpc_proxy.gettxoutsetinfo("none")
            except Exception as e:
                error[0] = e

        thr = threading.Thread(target=call_gettxoutsetinfo)
        thr.start()

        # Wait for the RPC to reach the sleep point (sleep is 100ms, so 50ms
        # should be enough for the RPC to enter the handler and hit the sleep).
        time.sleep(0.05)

        self.log.info("Generate a block while gettxoutsetinfo is sleeping")
        self.generate(wallet, 1, sync_fun=self.no_op)

        thr.join(timeout=30)
        assert not thr.is_alive(), "gettxoutsetinfo RPC did not return in time"

        self.log.info("Verify no error occurred")
        assert error[0] is None, f"gettxoutsetinfo failed: {error[0]}"
        assert result[0] is not None, "gettxoutsetinfo returned None"

        self.log.info("Verify result is self-consistent")
        height = result[0]["height"]
        bestblock = result[0]["bestblock"]
        assert_equal(bestblock, node.getblockhash(height))


if __name__ == '__main__':
    GetTxOutSetInfoRaceTest(__file__).main()

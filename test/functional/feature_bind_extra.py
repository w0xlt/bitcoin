#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test starting bitcoind with -bind and/or -bind=...=onion and confirm
that bind happens on the expected ports.
"""

from test_framework.netutil import (
    addr_to_hex,
    get_bind_addrs,
)
from test_framework.test_node import ErrorMatch
from test_framework.test_framework import (
    BitcoinTestFramework,
)
from test_framework.util import (
    assert_equal,
    p2p_port,
    rpc_port,
)


class BindExtraTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # Avoid any -bind= on the command line. Force the framework to avoid
        # adding -bind=127.0.0.1.
        self.bind_to_localhost_only = False
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        # Due to OS-specific network stats queries, we only run on Linux.
        self.skip_if_platform_not_linux()

    def setup_network(self):
        # Only setup the node initially, we'll restart it with different configs
        self.setup_nodes()

    def run_test(self):
        loopback_ipv4 = addr_to_hex("127.0.0.1")

        # Start custom ports by reusing unused p2p ports
        # We'll use different ports for each test to avoid conflicts
        port = p2p_port(self.num_nodes)

        # Array of tuples [command line arguments, expected bind addresses, test description].
        test_cases = []

        # Test case 1: no normal -bind=... with -bind=...=onion, thus only the tor target.
        test_cases.append(
            [
                [f"-bind=127.0.0.1:{port}=onion"],
                [(loopback_ipv4, port)],
                "no normal -bind with -bind=...=onion"
            ],
        )
        port += 1 # Increment port to avoid conflicts

        # Test case 2: both -bind=... and -bind=...=onion.
        test_cases.append(
            [
                [f"-bind=127.0.0.1:{port}", f"-bind=127.0.0.1:{port + 1}=onion"],
                [(loopback_ipv4, port), (loopback_ipv4, port + 1)],
                "both -bind and -bind=...=onion"
            ],
        )
        port += 2 # Increment port to avoid conflicts

        # Test case 3: no -bind=...=onion, thus no extra port for Tor target.
        test_cases.append(
            [
                [f"-bind=127.0.0.1:{port}"],
                [(loopback_ipv4, port)],
                "no -bind=...=onion"
            ],
        )
        port += 1 # Increment port to avoid conflicts

        # Test case 4: duplicated -bind=... and -bind=...
        test_cases.append(
            [
                [f"-bind=127.0.0.1:{port}", f"-bind=127.0.0.1:{port}", f"-bind=127.0.0.1:{port + 1}"],
                [(loopback_ipv4, port), (loopback_ipv4, port), (loopback_ipv4, port + 1)],
                "duplicated -bind=... and -bind=..."
            ],
        )
        port += 2

        # Test case 5: duplicated -bind=...=onion and -bind=...=onion
        test_cases.append(
            [
                [f"-bind=127.0.0.1:{port}=onion", f"-bind=127.0.0.1:{port}=onion", f"-bind=127.0.0.1:{port + 1}=onion"],
                [(loopback_ipv4, port), (loopback_ipv4, port), (loopback_ipv4, port + 1)],
                "duplicated -bind=...=onion and -bind=...=onion"
            ],
        )
        port += 2

        # Run each test case by restarting the node with different configurations
        for i, (args, expected_services, description) in enumerate(test_cases):
            self.log.info(f"Test case {i + 1}: {description}")
            self.log.info(f"Restarting node 0 with args: {args}")

            # Restart the node with the new configuration
            self.restart_node(0, extra_args=args)

            # Check the listening ports
            pid = self.nodes[0].process.pid
            binds = set(get_bind_addrs(pid))

            # Remove IPv6 addresses because on some CI environments "::1" is not configured
            # on the system (so our test_ipv6_local() would return False), but it is
            # possible to bind on "::". This makes it unpredictable whether to expect
            # that bitcoind has bound on "::1" (for RPC) and "::" (for P2P).
            ipv6_addr_len_bytes = 32
            binds = set(filter(lambda e: len(e[0]) != ipv6_addr_len_bytes, binds))

            # Remove RPC ports. They are not relevant for this test.
            binds = set(filter(lambda e: e[1] != rpc_port(0), binds))

            self.log.info(f"Expected binds: {expected_services}")
            self.log.info(f"Actual binds: {binds}")

            assert_equal(binds, set(expected_services))
            self.log.info(f"Test case {i + 1} passed!\n")

        self.stop_node(0)

        self.nodes[0].assert_start_raises_init_error(
            ["-bind=127.0.0.1:11012", "-bind=127.0.0.1:11012=onion"],
            "Different binding configurations assigned to the address 127.0.0.1:11012",
            match=ErrorMatch.PARTIAL_REGEX)

        self.nodes[0].assert_start_raises_init_error(
            ["-whitebind=noban@127.0.0.1:11012", "-whitebind=relay@127.0.0.1:11012"],
            "Different binding configurations assigned to the address 127.0.0.1:11012",
            match=ErrorMatch.PARTIAL_REGEX)


if __name__ == '__main__':
    BindExtraTest(__file__).main()

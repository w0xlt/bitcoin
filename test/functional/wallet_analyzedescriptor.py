#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the analyzedescriptor RPC."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AnalyzeDescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        owner = node.get_wallet_rpc(node.createwallet(wallet_name="owner")["name"])
        other = node.get_wallet_rpc(node.createwallet(wallet_name="other")["name"])

        owner_xpub = owner.gethdkeys()[0]["xpub"]
        other_xpub = other.gethdkeys()[0]["xpub"]
        desc = descsum_create(f"wsh(sortedmulti(1,{owner_xpub}/0/*,{other_xpub}/0/*))")

        result = owner.analyzedescriptor(desc, 0)
        assert_equal(result["input_has_private_keys"], False)
        assert_equal(result["wallet_has_any_private_key"], True)
        assert_equal(result["wallet_has_all_private_keys"], False)
        assert_equal(len(result["descriptors"]), 1)

        analysis = result["descriptors"][0]
        assert_equal(analysis["isrange"], True)
        assert_equal(analysis["issolvable"], True)
        assert_equal(analysis["wallet_has_any_private_key"], True)
        assert_equal(analysis["wallet_has_all_private_keys"], False)
        assert_equal(len(analysis["script"]["scriptPubKeys"]), 1)
        assert_equal(len(analysis["script"]["solving_scripts"]), 1)

        keys_by_xpub = {key["root_xpub"]: key for key in analysis["keys"]}
        assert_equal(keys_by_xpub[owner_xpub]["wallet_has_private_key"], True)
        assert_equal(keys_by_xpub[owner_xpub]["wallet_match_type"], "exact_xprv")
        assert_equal(keys_by_xpub[other_xpub]["wallet_has_private_key"], False)
        assert_equal(keys_by_xpub[other_xpub]["wallet_match_type"], "none")

        tree = analysis["tree"]
        assert_equal(tree["root"], 0)
        assert_equal(tree["nodes"][0]["type"], "wsh")
        multisig = tree["nodes"][tree["nodes"][0]["children"][0]]
        assert_equal(multisig["type"], "sortedmulti")
        assert_equal(multisig["threshold"], 1)
        assert_equal(multisig["key_indices"], [0, 1])


if __name__ == "__main__":
    AnalyzeDescriptorTest(__file__).main()

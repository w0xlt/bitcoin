#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the analyzedescriptor RPC."""

from test_framework.crypto import secp256k1
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import bytes_to_wif


class AnalyzeDescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_owned(self, result, match_type):
        assert_equal(result["wallet_has_any_private_key"], True)
        assert_equal(result["wallet_has_all_private_keys"], True)
        analysis = result["descriptors"][0]
        assert_equal(analysis["wallet_has_any_private_key"], True)
        assert_equal(analysis["wallet_has_all_private_keys"], True)
        key = analysis["keys"][0]
        assert_equal(key["wallet_has_private_key"], True)
        assert_equal(key["wallet_match_type"], match_type)


    def test_xonly_keys(self, owner, other, owner_xpub):
        self.log.info("Check both public-key parities for x-only ownership")
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(node.createwallet(wallet_name="xonly", blank=True)["name"])
        secret = next(i for i in range(1, 20) if (i * secp256k1.G).to_bytes_compressed()[0] == 3)
        pubkey = (secret * secp256k1.G).to_bytes_compressed().hex()
        private_desc = descsum_create(f"tr({bytes_to_wif(secret.to_bytes(32, 'big'))})")
        assert_equal(wallet.importdescriptors([{"desc": private_desc, "timestamp": "now"}])[0]["success"], True)
        public_desc = wallet.listdescriptors()["descriptors"][0]["desc"]
        address = node.deriveaddresses(public_desc)[0]
        assert_equal(wallet.getaddressinfo(address)["ismine"], True)
        self.assert_owned(wallet.analyzedescriptor(public_desc), "exact_private_key")
        input_key = other.analyzedescriptor(private_desc)["descriptors"][0]["keys"][0]
        assert_equal(input_key["input_has_private_key"], True)
        assert_equal(input_key["wallet_has_private_key"], False)

        opposite = "02" + pubkey[2:]
        for taproot_key in (pubkey, opposite, pubkey[2:]):
            result = wallet.analyzedescriptor(f"tr({taproot_key})")
            self.assert_owned(result, "exact_private_key")
            assert_equal(result["descriptors"][0]["script"]["scriptPubKeys"], [wallet.getaddressinfo(address)["scriptPubKey"]])
            self.assert_owned(wallet.analyzedescriptor(f"rawtr({taproot_key})"), "exact_private_key")
            for leaf in (f"pk({taproot_key})", f"multi_a(2,{taproot_key},{pubkey})", f"and_v(v:pk({taproot_key}),older(42))"):
                result = wallet.analyzedescriptor(f"tr({pubkey},{leaf})")
                assert_equal(result["wallet_has_all_private_keys"], True)
                assert all(key["wallet_has_private_key"] for key in result["descriptors"][0]["keys"])

        # ECDSA keys and MuSig participants still distinguish the two parities.
        assert_equal(wallet.analyzedescriptor(f"wpkh({opposite})")["wallet_has_any_private_key"], False)
        self.assert_owned(wallet.analyzedescriptor(f"wpkh({pubkey})"), "exact_private_key")

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

        self.test_xonly_keys(owner, other, owner_xpub)


if __name__ == "__main__":
    AnalyzeDescriptorTest(__file__).main()

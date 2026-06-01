#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the analyzedescriptor RPC."""

import hashlib
import hmac

from test_framework.address import b58chars
from test_framework.crypto import secp256k1
from test_framework.descriptors import descsum_create
from test_framework.key import ECPubKey
from test_framework.script import hash160
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def base58check_decode(s):
    value = 0
    for c in s:
        value *= 58
        assert c in b58chars
        value += b58chars.index(c)
    data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    data = b"\x00" * len(s[:len(s) - len(s.lstrip(b58chars[0]))]) + data
    assert_equal(hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4], data[-4:])
    return data[:-4]


def base58check_encode(data):
    data = data + hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    value = int.from_bytes(data, "big")
    result = ""
    while value:
        result = b58chars[value % 58] + result
        value //= 58
    for b in data:
        if b != 0:
            break
        result = b58chars[0] + result
    return result


def derive_xpub_nonhardened(xpub, index):
    assert index < 0x80000000
    raw = base58check_decode(xpub)
    version = raw[:4]
    depth = raw[4]
    chaincode = raw[13:45]
    pubkey = raw[45:78]

    tweak = hmac.new(chaincode, pubkey + index.to_bytes(4, "big"), "sha512").digest()
    tweak_int = int.from_bytes(tweak[:32], "big")
    assert 0 < tweak_int < secp256k1.GE.ORDER

    parent = ECPubKey()
    parent.set(pubkey)
    child_point = tweak_int * secp256k1.G + parent.p
    assert not child_point.infinity
    child_pubkey = child_point.to_bytes_compressed()
    child = version + bytes([depth + 1]) + hash160(pubkey)[:4] + index.to_bytes(4, "big") + tweak[32:] + child_pubkey
    return base58check_encode(child)


def xpub_pubkey(xpub):
    return base58check_decode(xpub)[45:78]


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

        child_index = 7
        child_xpub = derive_xpub_nonhardened(owner_xpub, child_index)
        origin_fingerprint = hash160(xpub_pubkey(owner_xpub))[:4].hex()
        derived_desc = descsum_create(f"wpkh([{origin_fingerprint}/{child_index}]{child_xpub}/0/*)")
        derived_result = owner.analyzedescriptor(derived_desc, 0)
        derived_key = derived_result["descriptors"][0]["keys"][0]
        assert_equal(derived_key["origin"], f"{origin_fingerprint}/{child_index}")
        assert_equal(derived_key["wallet_has_private_key"], True)
        assert_equal(derived_key["wallet_match_type"], "derived_xprv")


if __name__ == "__main__":
    AnalyzeDescriptorTest(__file__).main()

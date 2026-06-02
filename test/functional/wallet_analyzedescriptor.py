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
        assert_equal(result["unknown_due_to_locked_wallet"], False)
        assert_equal(len(result["descriptors"]), 1)

        analysis = result["descriptors"][0]
        assert_equal(analysis["isrange"], True)
        assert_equal(analysis["issolvable"], True)
        assert_equal(analysis["wallet_has_any_private_key"], True)
        assert_equal(analysis["wallet_has_all_private_keys"], False)
        assert_equal(analysis["unknown_due_to_locked_wallet"], False)
        assert_equal(analysis["script"]["used_wallet_private_keys"], False)
        assert_equal(analysis["script"]["unknown_due_to_locked_wallet"], False)
        assert_equal(len(analysis["script"]["scriptPubKeys"]), 1)
        assert_equal(len(analysis["script"]["solving_scripts"]), 1)

        keys_by_xpub = {key["root_xpub"]: key for key in analysis["keys"]}
        assert_equal(keys_by_xpub[owner_xpub]["type"], "bip32")
        assert_equal(keys_by_xpub[owner_xpub]["private_key_slot"], True)
        assert_equal(keys_by_xpub[owner_xpub]["children"], [])
        assert_equal(keys_by_xpub[owner_xpub]["wallet_has_private_key"], True)
        assert_equal(keys_by_xpub[owner_xpub]["unknown_due_to_locked_wallet"], False)
        assert_equal(keys_by_xpub[owner_xpub]["wallet_match_type"], "exact_xprv")
        assert_equal(keys_by_xpub[other_xpub]["type"], "bip32")
        assert_equal(keys_by_xpub[other_xpub]["private_key_slot"], True)
        assert_equal(keys_by_xpub[other_xpub]["children"], [])
        assert_equal(keys_by_xpub[other_xpub]["wallet_has_private_key"], False)
        assert_equal(keys_by_xpub[other_xpub]["unknown_due_to_locked_wallet"], False)
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
        assert_equal(derived_key["type"], "bip32")
        assert_equal(derived_key["private_key_slot"], True)
        assert_equal(derived_key["origin"], f"{origin_fingerprint}/{child_index}")
        assert_equal(derived_key["wallet_has_private_key"], True)
        assert_equal(derived_key["unknown_due_to_locked_wallet"], False)
        assert_equal(derived_key["wallet_match_type"], "derived_xprv")

        musig_desc = descsum_create(f"rawtr(musig({owner_xpub}/0/*,{other_xpub}/0/*))")
        musig_analysis = owner.analyzedescriptor(musig_desc, 0)["descriptors"][0]
        musig_key = [key for key in musig_analysis["keys"] if key["type"] == "musig"][0]
        assert_equal(musig_key["private_key_slot"], False)
        assert_equal(musig_key["children"], [0, 1])
        assert_equal(musig_key["wallet_has_private_key"], False)
        assert_equal(musig_key["unknown_due_to_locked_wallet"], False)
        assert_equal(musig_analysis["wallet_has_any_private_key"], True)
        assert_equal(musig_analysis["wallet_has_all_private_keys"], False)
        assert_equal(musig_analysis["tree"]["nodes"][0]["key_indices"], [2])

        hash256_hex = "ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588"
        miniscript_desc = descsum_create(f"wsh(and_v(and_v(v:hash256({hash256_hex}),v:pk({owner_xpub}/0/*)),older(42)))")
        miniscript_analysis = owner.analyzedescriptor(miniscript_desc, 0)["descriptors"][0]
        miniscript_nodes = miniscript_analysis["tree"]["nodes"]
        assert any(node["type"] == "hash256" and node["data"] == hash256_hex for node in miniscript_nodes)
        assert any(node["type"] == "older" and node["value"] == 42 for node in miniscript_nodes)
        assert any(node["type"] == "pk_k" and node["key_indices"] == [0] for node in miniscript_nodes)

        encrypted = node.get_wallet_rpc(node.createwallet(wallet_name="encrypted", passphrase="passphrase")["name"])
        encrypted_xpub = encrypted.gethdkeys()[0]["xpub"]
        encrypted_child_index = 11
        encrypted_child_xpub = derive_xpub_nonhardened(encrypted_xpub, encrypted_child_index)
        encrypted_origin_fingerprint = hash160(xpub_pubkey(encrypted_xpub))[:4].hex()
        hardened_desc = descsum_create(f"wpkh([{encrypted_origin_fingerprint}/{encrypted_child_index}]{encrypted_child_xpub}/0h/*)")

        locked_result = encrypted.analyzedescriptor(hardened_desc, 0)
        assert_equal(locked_result["unknown_due_to_locked_wallet"], True)
        locked_analysis = locked_result["descriptors"][0]
        assert_equal(locked_analysis["unknown_due_to_locked_wallet"], True)
        locked_key = locked_analysis["keys"][0]
        assert_equal(locked_key["wallet_has_private_key"], False)
        assert_equal(locked_key["unknown_due_to_locked_wallet"], True)
        assert_equal(locked_key["wallet_match_type"], "unknown_locked")
        assert_equal(locked_analysis["script"]["used_wallet_private_keys"], False)
        assert_equal(locked_analysis["script"]["unknown_due_to_locked_wallet"], True)
        assert "error" in locked_analysis["script"]

        encrypted.walletpassphrase("passphrase", 60)
        unlocked_result = encrypted.analyzedescriptor(hardened_desc, 0)
        assert_equal(unlocked_result["unknown_due_to_locked_wallet"], False)
        unlocked_analysis = unlocked_result["descriptors"][0]
        assert_equal(unlocked_analysis["unknown_due_to_locked_wallet"], False)
        unlocked_key = unlocked_analysis["keys"][0]
        assert_equal(unlocked_key["wallet_has_private_key"], True)
        assert_equal(unlocked_key["unknown_due_to_locked_wallet"], False)
        assert_equal(unlocked_key["wallet_match_type"], "derived_xprv")
        assert_equal(unlocked_analysis["script"]["used_wallet_private_keys"], True)
        assert_equal(unlocked_analysis["script"]["unknown_due_to_locked_wallet"], False)
        assert_equal(len(unlocked_analysis["script"]["scriptPubKeys"]), 1)
        encrypted.walletlock()


if __name__ == "__main__":
    AnalyzeDescriptorTest(__file__).main()

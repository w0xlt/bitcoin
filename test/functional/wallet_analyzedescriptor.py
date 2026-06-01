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
from test_framework.wallet_util import bytes_to_wif


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


def derive_xprv_nonhardened(xprv, index):
    assert index < 0x80000000
    raw = base58check_decode(xprv)
    secret = int.from_bytes(raw[46:78], "big")
    pubkey = (secret * secp256k1.G).to_bytes_compressed()
    tweak = hmac.new(raw[13:45], pubkey + index.to_bytes(4, "big"), "sha512").digest()
    tweak_int = int.from_bytes(tweak[:32], "big")
    assert tweak_int < secp256k1.GE.ORDER
    child_secret = (secret + tweak_int) % secp256k1.GE.ORDER
    assert child_secret != 0
    child = raw[:4] + bytes([raw[4] + 1]) + hash160(pubkey)[:4] + index.to_bytes(4, "big") + tweak[32:] + b"\x00" + child_secret.to_bytes(32, "big")
    return base58check_encode(child)


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
        other_pubkey = xpub_pubkey(other.gethdkeys()[0]["xpub"]).hex()
        for participant, owned in ((pubkey, True), (opposite, False)):
            result = wallet.analyzedescriptor(f"rawtr(musig({participant},{other_pubkey}))")
            assert_equal(result["wallet_has_any_private_key"], owned)

        fingerprint = hash160(xpub_pubkey(owner_xpub))[:4].hex()
        for index in range(256):
            child_pubkey = xpub_pubkey(derive_xpub_nonhardened(owner_xpub, index)).hex()
            if child_pubkey.startswith("03"):
                break
        else:
            raise AssertionError("No odd-Y child public key found")
        origin = f"{fingerprint}/{index}"
        self.assert_owned(owner.analyzedescriptor(f"rawtr([{origin}]{child_pubkey[2:]})"), "derived_private_key")
        for wrapper in ("tr", "rawtr"):
            self.assert_owned(owner.analyzedescriptor(f"{wrapper}([{origin}]02{child_pubkey[2:]})"), "derived_private_key")
        assert_equal(owner.analyzedescriptor(f"wpkh([{origin}]02{child_pubkey[2:]})")["wallet_has_any_private_key"], False)
        result = owner.analyzedescriptor(f"rawtr(musig([{origin}]02{child_pubkey[2:]},{other_pubkey}))")
        assert_equal(result["wallet_has_any_private_key"], False)

    def test_repeated_keys(self, owner, other, owner_xpub, other_xpub):
        self.log.info("Warn about repeated effective signing keys within each multisig leaf")
        repeated_descriptors = [
            f"wsh({kind}(2,{owner_xpub}/0/*,{owner_xpub}/0/*))" for kind in ("multi", "sortedmulti")
        ] + [
            f"tr({other_xpub}/0/*,{kind}(2,{owner_xpub}/0/*,{owner_xpub}/0/*))" for kind in ("multi_a", "sortedmulti_a")
        ]
        child_xpub = derive_xpub_nonhardened(owner_xpub, 0)
        repeated_descriptors += [
            f"wsh(sortedmulti(2,[12345678]{owner_xpub}/0/*,[87654321]{owner_xpub}/0/*))",
            f"wsh(sortedmulti(2,{owner_xpub}/0/*,{child_xpub}/*))",
        ]
        pubkey = xpub_pubkey(owner_xpub).hex()
        repeated_descriptors.append(f"tr({other_xpub}/0/*,multi_a(2,02{pubkey[2:]},03{pubkey[2:]}))")
        for descriptor in repeated_descriptors:
            analysis = owner.analyzedescriptor(descsum_create(descriptor), 3)["descriptors"][0]
            assert any("Repeated signing keys" in warning for warning in analysis["warnings"]), descriptor
            assert "error" not in analysis["script"]

        # Compare effective keys at the requested index, rather than just roots.
        pubkey7 = xpub_pubkey(derive_xpub_nonhardened(child_xpub, 7)).hex()
        descriptor = descsum_create(f"wsh(multi(2,{owner_xpub}/0/*,{pubkey7}))")
        assert_equal(owner.analyzedescriptor(descriptor, 0)["descriptors"][0]["warnings"], [])
        assert any("Repeated signing keys" in warning for warning in owner.analyzedescriptor(descriptor, 7)["descriptors"][0]["warnings"])

        for descriptor in (
            f"wsh(sortedmulti(2,{owner_xpub}/0/*,{owner_xpub}/1/*))",
            f"tr({other_xpub}/1/*,{{multi_a(1,{owner_xpub}/0/*,{other_xpub}/0/*),multi_a(1,{owner_xpub}/0/*,{owner_xpub}/1/*)}})",
        ):
            assert_equal(owner.analyzedescriptor(descsum_create(descriptor))["descriptors"][0]["warnings"], [])

        # Repeated hardened expressions can be recognized even without secrets.
        descriptor = descsum_create(f"wsh(multi(2,{owner_xpub}/0h/*,{owner_xpub}/0h/*))")
        analysis = other.analyzedescriptor(descriptor)["descriptors"][0]
        assert "error" in analysis["script"]
        assert any("Repeated signing keys" in warning for warning in analysis["warnings"])
        for first, second in (("/0h/*", "/0'/*"), ("/0/*h", "/0/*'"), ("/0h/1'/*", "/0'/1h/*")):
            descriptor = descsum_create(f"wsh(multi(2,{owner_xpub}{first},{owner_xpub}{second}))")
            analysis = other.analyzedescriptor(descriptor)["descriptors"][0]
            assert "error" in analysis["script"]
            assert any("Repeated signing keys" in warning for warning in analysis["warnings"]), descriptor
        descriptor = descsum_create(f"wsh(multi(2,{owner_xpub}/0h/*,{owner_xpub}/1'/*))")
        assert_equal(other.analyzedescriptor(descriptor)["descriptors"][0]["warnings"], [])

    def test_cached_keys(self, owner, other):
        self.log.info("Resolve known derived public keys without input origins")
        address = owner.getnewaddress(address_type="bech32")
        info = owner.getaddressinfo(address)
        descriptor = descsum_create(f"wpkh({info['pubkey']})")
        result = owner.analyzedescriptor(descriptor)
        self.assert_owned(result, "derived_private_key")
        assert_equal(result["descriptors"][0]["script"]["scriptPubKeys"], [info["scriptPubKey"]])
        self.assert_owned(owner.analyzedescriptor(f"rawtr({info['pubkey'][2:]})"), "derived_private_key")
        for prefix in ("02", "03"):
            self.assert_owned(owner.analyzedescriptor(f"rawtr({prefix}{info['pubkey'][2:]})"), "derived_private_key")
        assert_equal(other.analyzedescriptor(descriptor)["wallet_has_any_private_key"], False)

        node = self.nodes[0]
        watch = node.get_wallet_rpc(node.createwallet(wallet_name="watch", blank=True, disable_private_keys=True)["name"])
        public_desc = next(d["desc"] for d in owner.listdescriptors()["descriptors"] if d["desc"].startswith("wpkh(") and not d["internal"])
        assert_equal(watch.importdescriptors([{"desc": public_desc, "timestamp": "now", "range": [0, 10], "active": True}])[0]["success"], True)
        assert_equal(watch.getaddressinfo(address)["ismine"], True)
        result = watch.analyzedescriptor(descriptor)
        assert_equal(result["wallet_has_any_private_key"], False)

    def test_parent_origins_and_musig_inventory(self, owner, owner_xpub, other_xpub):
        node = self.nodes[0]
        owner_xprv = next(key["xprv"] for key in owner.gethdkeys({"private": True}) if key["xpub"] == owner_xpub)
        fingerprint = hash160(xpub_pubkey(owner_xpub))[:4].hex()
        account_xprv = derive_xprv_nonhardened(owner_xprv, 7)
        account_xpub = derive_xpub_nonhardened(owner_xpub, 7)
        child_xpub = derive_xpub_nonhardened(account_xpub, 8)
        descendant = f"[{fingerprint}/7/8]{child_xpub}"
        for name, private_desc in (
            ("account", f"wpkh([{fingerprint}/7]{account_xprv}/0/*)"),
            ("musig_account", f"tr(musig([{fingerprint}/7]{account_xprv}/0/*,{other_xpub}/0/*))"),
        ):
            self.log.info(f"Match descendants of an origin-qualified account key in {name}")
            wallet = node.get_wallet_rpc(node.createwallet(wallet_name=name, blank=True)["name"])
            assert_equal(wallet.importdescriptors([{"desc": descsum_create(private_desc), "timestamp": "now", "range": [0, 10]}])[0]["success"], True)
            self.assert_owned(wallet.analyzedescriptor(f"wpkh({descendant}/0/*)"), "derived_xprv")
            for origin in (f"{fingerprint}/9/8", f"{fingerprint}/7", f"{fingerprint}", "12345678/7/8"):
                result = wallet.analyzedescriptor(f"wpkh([{origin}]{child_xpub}/0/*)")
                assert_equal(result["wallet_has_any_private_key"], False)
                assert "error" in result["descriptors"][0]["script"]
            # A matching origin alone is insufficient; verify the derived key.
            assert_equal(wallet.analyzedescriptor(f"wpkh([{fingerprint}/7/8]{other_xpub}/0/*)")["wallet_has_any_private_key"], False)


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
        assert_equal(keys_by_xpub[owner_xpub]["type"], "bip32")
        assert_equal(keys_by_xpub[owner_xpub]["private_key_slot"], True)
        assert_equal(keys_by_xpub[owner_xpub]["children"], [])
        assert_equal(keys_by_xpub[owner_xpub]["wallet_has_private_key"], True)
        assert_equal(keys_by_xpub[owner_xpub]["wallet_match_type"], "exact_xprv")
        assert_equal(keys_by_xpub[other_xpub]["type"], "bip32")
        assert_equal(keys_by_xpub[other_xpub]["private_key_slot"], True)
        assert_equal(keys_by_xpub[other_xpub]["children"], [])
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
        assert_equal(derived_key["type"], "bip32")
        assert_equal(derived_key["private_key_slot"], True)
        assert_equal(derived_key["origin"], f"{origin_fingerprint}/{child_index}")
        assert_equal(derived_key["wallet_has_private_key"], True)
        assert_equal(derived_key["wallet_match_type"], "derived_xprv")

        musig_desc = descsum_create(f"rawtr(musig({owner_xpub}/0/*,{other_xpub}/0/*))")
        musig_analysis = owner.analyzedescriptor(musig_desc, 0)["descriptors"][0]
        musig_key = [key for key in musig_analysis["keys"] if key["type"] == "musig"][0]
        assert_equal(musig_key["private_key_slot"], False)
        assert_equal(musig_key["children"], [0, 1])
        assert_equal(musig_key["wallet_has_private_key"], False)
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

        self.test_xonly_keys(owner, other, owner_xpub)
        self.test_repeated_keys(owner, other, owner_xpub, other_xpub)
        self.test_cached_keys(owner, other)
        self.test_parent_origins_and_musig_inventory(owner, owner_xpub, other_xpub)


if __name__ == "__main__":
    AnalyzeDescriptorTest(__file__).main()

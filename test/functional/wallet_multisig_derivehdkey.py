#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test multisig signing using derivehdkey-exported xpubs at non-standard paths.

This test verifies that wallets can sign PSBTs for multisig outputs when the
xpubs were derived at paths not in the wallet's keypool (e.g., BIP 87 path
m/87'/1'/0' for multisig). The signing works because Bitcoin Core uses the
BIP 32 derivation path from the PSBT's hd_keypaths to derive keys on-the-fly.

This mirrors the workflow in doc/multisig-tutorial.md.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
)


class WalletMultisigDeriveHDKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.M = 2
        self.N = self.num_nodes
        self.log.info(f"Testing {self.M}-of-{self.N} multisig with derivehdkey at BIP 87 path...")

        # Create participant wallets (signers)
        self.log.info("Creating participant wallets...")
        signers = []
        for i in range(self.N):
            self.nodes[i].createwallet(wallet_name=f"participant_{i}")
            signers.append(self.nodes[i].get_wallet_rpc(f"participant_{i}"))

        # Use derivehdkey to get xpubs at BIP 87 path (m/87'/1'/0' for testnet multisig)
        # This path is NOT in the wallet's default keypool, which uses paths like m/84'/1'/0'
        self.log.info("Deriving xpubs at BIP 87 path m/87'/1'/0' using derivehdkey...")
        xpubs = []
        for signer in signers:
            derived = signer.derivehdkey("m/87'/1'/0'")
            # Format: [fingerprint/87'/1'/0']xpub/<0;1>/*
            xpub_with_origin = f"{derived['origin']}{derived['xpub']}/<0;1>/*"
            xpubs.append(xpub_with_origin)
            self.log.info(f"  {xpub_with_origin[:60]}...")

        # Create watch-only multisig wallets for each participant
        self.log.info("Creating watch-only multisig wallets...")
        multisigs = []
        multisig_desc = f"wsh(sortedmulti({self.M},{','.join(xpubs)}))"
        for i, node in enumerate(self.nodes):
            node.createwallet(wallet_name=f"multisig_{i}", blank=True, disable_private_keys=True)
            multisig = node.get_wallet_rpc(f"multisig_{i}")
            checksum = multisig.getdescriptorinfo(multisig_desc)["checksum"]
            result = multisig.importdescriptors([{
                "desc": f"{multisig_desc}#{checksum}",
                "active": True,
                "timestamp": "now",
                "range": [0, 100],
            }])
            assert all(r["success"] for r in result)
            multisigs.append(multisig)

        # Verify all multisigs generate the same addresses
        self.log.info("Verifying multisig address generation...")
        for _ in range(3):
            addresses = [m.getnewaddress() for m in multisigs]
            assert all(addr == addresses[0] for addr in addresses)

        # Fund the multisig
        self.log.info("Funding the multisig wallet...")
        self.generatetoaddress(self.nodes[0], 101, signers[0].getnewaddress())
        deposit_amount = 5.0
        multisig_addr = multisigs[0].getnewaddress()
        signers[0].sendtoaddress(multisig_addr, deposit_amount)
        self.generate(self.nodes[0], 1)
        assert_approx(multisigs[0].getbalance(), deposit_amount, vspan=0.001)

        # Create and sign a PSBT
        self.log.info("Creating PSBT to spend from multisig...")
        destination = signers[self.N - 1].getnewaddress()
        send_amount = 1.0
        psbt = multisigs[0].walletcreatefundedpsbt(
            inputs=[],
            outputs={destination: send_amount},
            feeRate=0.0001
        )

        # Have M signers sign the PSBT
        # This is the key test: signing should work even though the keys at
        # m/87'/1'/0'/0/X are NOT in the signers' keypools
        self.log.info(f"Signing PSBT with {self.M} participants...")
        psbts = []
        for i in range(self.M):
            self.log.info(f"  Participant {i} signing...")
            signed = signers[i].walletprocesspsbt(psbt["psbt"])
            psbts.append(signed["psbt"])
            # Individual signatures should not complete the multisig
            assert_equal(signed["complete"], False)

        # Combine, finalize, and broadcast
        self.log.info("Combining and finalizing PSBT...")
        combined = signers[0].combinepsbt(psbts)
        finalized = signers[0].finalizepsbt(combined)
        assert_equal(finalized["complete"], True)

        self.log.info("Broadcasting transaction...")
        signers[0].sendrawtransaction(finalized["hex"])
        self.generate(self.nodes[0], 1)

        # Verify balances
        self.log.info("Verifying final balances...")
        assert_approx(multisigs[0].getbalance(), deposit_amount - send_amount, vspan=0.001)
        assert_equal(signers[self.N - 1].getbalance(), send_amount)

        # Test daisy-chain signing (sequential)
        self.log.info("Testing sequential (daisy-chain) signing...")
        psbt2 = multisigs[0].walletcreatefundedpsbt(
            inputs=[],
            outputs={destination: send_amount},
            feeRate=0.0001
        )
        current_psbt = psbt2["psbt"]
        for i in range(self.M):
            self.log.info(f"  Participant {i} signing sequentially...")
            result = signers[i].walletprocesspsbt(current_psbt)
            current_psbt = result["psbt"]
            # Should be complete after M signatures
            assert_equal(result["complete"], i == self.M - 1)

        self.log.info("Broadcasting sequential-signed transaction...")
        signers[0].sendrawtransaction(result["hex"])
        self.generate(self.nodes[0], 1)

        assert_approx(multisigs[0].getbalance(), deposit_amount - (send_amount * 2), vspan=0.001)
        assert_equal(signers[self.N - 1].getbalance(), send_amount * 2)

        self.log.info("All tests passed!")


if __name__ == "__main__":
    WalletMultisigDeriveHDKeyTest(__file__).main()

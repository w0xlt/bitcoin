#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.util import (
    assert_equal,
)

import random
import string


class SilentPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-silentpaymentindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def init_wallet(self, *, node):
        pass

    def random_string(self, n):
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

    def test_psbt(self):
        self.nodes[0].createwallet(wallet_name=f'sender_wallet', descriptors=True)
        sender_wallet = self.nodes[0].get_wallet_rpc(f'sender_wallet')

        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 10, sender_wallet.getnewaddress())

        self.nodes[0].createwallet(wallet_name=f'silent_wallet_01', descriptors=True, silent_payment=True)
        silent_wallet_01 = self.nodes[0].get_wallet_rpc(f'silent_wallet_01')

        label01 = self.random_string(8)
        recv_addr_01 = silent_wallet_01.getsilentaddress()['address']
        recv_addr_02 = silent_wallet_01.getsilentaddress(label01)['address']

        psbt = sender_wallet.walletcreatefundedpsbt(inputs=[], outputs={recv_addr_01: 70, recv_addr_02: 90})['psbt']

        signed_tx = sender_wallet.walletprocesspsbt(psbt=psbt, finalize=False)['psbt']
        final_tx = self.nodes[0].finalizepsbt(signed_tx)['hex']
        self.nodes[0].sendrawtransaction(final_tx)

        self.generatetoaddress(self.nodes[0], 1, sender_wallet.getnewaddress())

        silent_wallet_01_utxos = silent_wallet_01.listunspent()
        assert_equal(len(silent_wallet_01_utxos), 2)

    def run_test(self):
        self.test_psbt()


if __name__ == '__main__':
    SilentPSBTTest().main()

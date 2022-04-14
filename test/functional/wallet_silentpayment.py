#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.util import (
    assert_raises_rpc_error,
)
from test_framework.descriptors import descsum_create

class SilentTransactioTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [[], ["-keypool=1", "-silentpaymentindex=1"], ["-keypool=1", "-silentpaymentindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def init_wallet(self, *, node):
        pass

    def invalid_create_wallet(self):
        self.log.info("Testing the creation of invalid wallets")

        if self.is_bdb_compiled():
            assert_raises_rpc_error(-4, "Only descriptor wallets support silent payments.",
                self.nodes[1].createwallet, wallet_name='invalid_wallet', descriptors=False, silent_payment=True)

        assert_raises_rpc_error(-4, "Silent payments require the ability to store private keys.",
            self.nodes[1].createwallet, wallet_name='invalid_wallet', descriptors=True, disable_private_keys=True, silent_payment=True)

        if self.is_external_signer_compiled():
            assert_raises_rpc_error(-4, "Silent payments require the ability to store private keys.",
                self.nodes[1].createwallet, wallet_name='invalid_wallet',  descriptors=True, disable_private_keys=True, external_signer=True, silent_payment=True)

        assert_raises_rpc_error(-4, "Silent payment verification requires access to private keys. Cannot be used with encrypted wallets.",
            self.nodes[1].createwallet, wallet_name='invalid_wallet', descriptors=True, passphrase="passphrase", silent_payment=True)

        # the first node does not have the silentpayment index enabled
        assert_raises_rpc_error(-4, "Silent payment index is required to verify silent transactions. It must be activated and synced before creating a wallet with this option.",
            self.nodes[0].createwallet, wallet_name='invalid_wallet', descriptors=True, silent_payment=True)

    def watch_only_wallet_send(self):
        self.nodes[0].createwallet(wallet_name='watch_only_wallet', descriptors=True, disable_private_keys=True, blank=True)
        watch_only_wallet = self.nodes[0].get_wallet_rpc('watch_only_wallet')

        desc_import = [{
            "desc": descsum_create("wpkh(tpubD6NzVbkrYhZ4YNXVQbNhMK1WqguFsUXceaVJKbmno2aZ3B6QfbMeraaYvnBSGpV3vxLyTTK9DYT1yoEck4XUScMzXoQ2U2oSmE2JyMedq3H/0/*)"),
            "timestamp": "now",
            "internal": False,
            "active": True,
            "keypool": True,
            "range": [0, 100],
            "watchonly": True,
        }]

        watch_only_wallet.importdescriptors(desc_import)

        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 10, watch_only_wallet.getnewaddress())

        self.log.info("Watch-only wallets cannot send coins using silent_payment option")
        outputs = [{"bcrt1pk0yzk76w2p55ykyjyfeq99td069c257se9nwugl7cl5geadq944spyc330": 15}]
        options= {"silent_payment": True }

        assert_raises_rpc_error(-4, "Silent payments require access to private keys to build transactions.",
            watch_only_wallet.send, outputs=outputs, options=options)

    def encrypted_wallet_send(self):
        self.nodes[0].createwallet(wallet_name='encrypted_wallet', descriptors=True, passphrase='passphrase')
        encrypted_wallet = self.nodes[0].get_wallet_rpc('encrypted_wallet')

        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 10, encrypted_wallet.getnewaddress())

        self.log.info("encrypted wallets must be able to send coins after decryption")
        outputs = [{"bcrt1pk0yzk76w2p55ykyjyfeq99td069c257se9nwugl7cl5geadq944spyc330": 15}]
        options= {"silent_payment": True }

        # send RPC can be run without decrypting the wallet and it must generate a incomplete PSBT
        tx = encrypted_wallet.send(outputs=outputs)
        assert(not tx['complete'])

        # but when silent_payment option is enabled, wallet must be decrypted
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first.",
            encrypted_wallet.send, outputs=outputs, options=options)

        encrypted_wallet.walletpassphrase('passphrase', 20)

        tx = encrypted_wallet.send(outputs=outputs, options=options)
        assert(tx['complete'])

    def test_transactions(self):
        self.nodes[0].createwallet(wallet_name='sender_wallet', descriptors=True)
        sender_wallet = self.nodes[0].get_wallet_rpc('sender_wallet')

        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 10, sender_wallet.getnewaddress())

        self.nodes[1].createwallet(wallet_name='recipient_wallet_01', descriptors=True, silent_payment=True)
        recipient_wallet_01 = self.nodes[1].get_wallet_rpc('recipient_wallet_01')

        self.nodes[2].createwallet(wallet_name='recipient_wallet_02', descriptors=True, silent_payment=True)
        recipient_wallet_02 = self.nodes[2].get_wallet_rpc('recipient_wallet_02')


        for input_type in ['bech32m', 'bech32', 'p2sh-segwit', 'legacy']:

            # sender wallet sends coins to itself using input_type address
            # The goal is to use the output of this tx as silent transaction inputs
            sen_addr_02 = sender_wallet.getnewaddress('', input_type)
            tx_id_01 = sender_wallet.send({sen_addr_02: 40})['txid']

            self.generate(self.nodes[0], 7)

            tx_01 = [x for x in sender_wallet.listunspent(0) if x['txid'] == tx_id_01]
            input_data = [x for x in tx_01 if x['address'] == sen_addr_02][0]

            # use two addresses so that one can be spent on a normal tx and the other on a normal transaction
            recv_addr_01 = recipient_wallet_01.getnewaddress('', 'bech32m')
            recv_addr_02 = recipient_wallet_01.getnewaddress('', 'bech32m')

            self.log.info("[%s] create silent transaction", input_type)
            inputs = [{"txid": input_data["txid"], "vout":input_data["vout"]}]
            outputs = [{recv_addr_01: 15}, {recv_addr_02: 15}]
            options= {"silent_payment": True, "inputs": inputs  }

            silent_tx_ret = sender_wallet.send(outputs=outputs, options=options)

            self.sync_mempools()

            silent_utxos = [x for x in recipient_wallet_01.listunspent(0) if x['txid'] == silent_tx_ret['txid']]

            self.log.info("[%s] confirm that transaction has a different address than the original", input_type)
            for utxo in silent_utxos:
                assert(utxo['address'] != recv_addr_01)
                assert(utxo['desc'].startswith('rawtr('))

            recv_addr_03 = recipient_wallet_02.getnewaddress('', 'bech32m')
            recv_addr_04 = recipient_wallet_02.getnewaddress('', 'bech32m')

            self.log.info("[%s] spend the silent output to a normal address", input_type)
            normal_inputs = [{"txid": silent_utxos[0]["txid"], "vout":silent_utxos[0]["vout"]}]
            normal_outputs = [{recv_addr_03: 10}]
            normal_options = {"inputs": normal_inputs}

            normal_tx_ret = recipient_wallet_01.send(outputs=normal_outputs, options=normal_options)

            self.log.info("[%s] spend the silent output to another", input_type)
            silent_inputs = [{"txid": silent_utxos[1]["txid"], "vout":silent_utxos[1]["vout"]}]
            silent_outputs = [{recv_addr_04: 10}]
            silent_options = {"silent_payment": True, "inputs": silent_inputs}

            silent_tx_ret = recipient_wallet_01.send(outputs=silent_outputs, options=silent_options)

            self.sync_mempools()

            normal_tx = [x for x in recipient_wallet_02.listunspent(0) if x['txid'] == normal_tx_ret['txid']][0]
            silent_tx = [x for x in recipient_wallet_02.listunspent(0) if x['txid'] == silent_tx_ret['txid']][0]

            self.log.info("[%s] confirm the silent output was spent correctly", input_type)
            assert(normal_tx['address'] == recv_addr_03)
            assert(not normal_tx['desc'].startswith('rawtr('))

            assert(silent_tx['address'] != recv_addr_04)
            assert(silent_tx['desc'].startswith('rawtr('))

    def test_scantxoutset(self):
        self.nodes[0].createwallet(wallet_name='sender_wallet_02', descriptors=True)
        sender_wallet_02 = self.nodes[0].get_wallet_rpc('sender_wallet_02')

        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 10, sender_wallet_02.getnewaddress())

        self.nodes[2].createwallet(wallet_name='recipient_wallet_03', descriptors=True, silent_payment=True, blank=True)
        recipient_wallet_03 = self.nodes[2].get_wallet_rpc('recipient_wallet_03')

        desc_import = [{
            "desc": descsum_create("tr(tprv8ZgxMBicQKsPe4mDP1295ti2BqcgFzPWkKnvsGyKVerGqf9tDif6yR4yLcK6Pf49tQ1HRQK2vjXrAVqxVUJCtXWn3AAiacXnXhUf6nxBJAp/86'/1'/0'/0/*)"),
            "timestamp": "now",
            "internal": False,
            "active": True,
            "range": [0, 3]
        },
        {
            "desc": descsum_create("tr(tprv8ZgxMBicQKsPe4mDP1295ti2BqcgFzPWkKnvsGyKVerGqf9tDif6yR4yLcK6Pf49tQ1HRQK2vjXrAVqxVUJCtXWn3AAiacXnXhUf6nxBJAp/86'/1'/0'/1/*)"),
            "timestamp": "now",
            "internal": True,
            "active": True,
            "range": [0, 3]
        }]

        self.log.info("send multiple silent transactions to test scantxoutset")
        for amount in [12.75, 11.98, 21.30]:

            recipient_wallet_03.importdescriptors(desc_import)

            recv_addr_03 = recipient_wallet_03.getnewaddress('', 'bech32m')

            outputs = [{recv_addr_03: amount}]
            options= {"silent_payment": True }

            silent_tx_ret = sender_wallet_02.send(outputs=outputs, options=options)

            self.sync_mempools()

            silent_utxo = [x for x in recipient_wallet_03.listunspent(0) if x['txid'] == silent_tx_ret['txid']][0]

            assert(silent_utxo['address'] != recv_addr_03)

            self.generate(self.nodes[0], 7)

            self.sync_all()

        self.wait_until(lambda: all(i["synced"] for i in self.nodes[0].getindexinfo().values()))

        utxos = recipient_wallet_03.listunspent()

        scan_result = self.nodes[1].scantxoutset("start", [{"desc": desc_import[0]["desc"], "range": [0, 3]}], True)

        self.log.info("check if silent scantxoutset and listunspent have the same result for the same descriptor")
        assert(len(scan_result["unspents"]) == len(utxos))

        for scan_tx in scan_result["unspents"]:
            assert(len([x for x in utxos if x['txid'] == scan_tx['txid']]) == 1)

    def test_load_silent_wallet(self):
        self.nodes[0].createwallet(wallet_name='sender_wallet_03', descriptors=True)
        sender_wallet_03 = self.nodes[0].get_wallet_rpc('sender_wallet_03')

        self.nodes[1].createwallet(wallet_name='recipient_wallet_04', descriptors=True, silent_payment=True)
        recipient_wallet_04 = self.nodes[1].get_wallet_rpc('recipient_wallet_04')

        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 10, sender_wallet_03.getnewaddress())

        recv_addr_list = []

        for _ in range(5):
            recv_addr_list.append(recipient_wallet_04.getnewaddress('', 'bech32m'))

        self.nodes[1].unloadwallet('recipient_wallet_04')

        silent_tx_ids = []

        for recv_addr in recv_addr_list:

            outputs = [{recv_addr: 13.12}]
            options= {"silent_payment": True  }

            silent_tx_ids.append(sender_wallet_03.send(outputs=outputs, options=options)['txid'])

            self.generate(self.nodes[0], 1)

        self.sync_all()

        self.nodes[1].loadwallet('recipient_wallet_04')

        listunspent = [u['txid'] for u in recipient_wallet_04.listunspent(0)]

        assert(len(listunspent) == len(silent_tx_ids))

        for txid in silent_tx_ids:
            assert(txid in listunspent)

    def run_test(self):
        self.invalid_create_wallet()
        self.watch_only_wallet_send()
        self.encrypted_wallet_send()
        self.test_transactions()
        self.test_scantxoutset()
        self.test_load_silent_wallet()

if __name__ == '__main__':
    SilentTransactioTest().main()

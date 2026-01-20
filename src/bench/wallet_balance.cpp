// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/merkle.h>
#include <interfaces/chain.h>
#include <kernel/chain.h>
#include <kernel/chainparams.h>
#include <kernel/types.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>
#include <versionbits.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <cassert>
#include <memory>
#include <optional>
#include <string>

namespace wallet {
static void WalletBalance(benchmark::Bench& bench, const bool set_dirty, const bool add_mine)
{
    const auto test_setup = MakeNoLogFileContext<const TestingSetup>();

    const auto& ADDRESS_WATCHONLY = ADDRESS_BCRT1_UNSPENDABLE;

    // Set clock to genesis block, so the descriptors/keys creation time don't interfere with the blocks scanning process.
    // The reason is 'generatetoaddress', which creates a chain with deterministic timestamps in the past.
    SetMockTime(test_setup->m_node.chainman->GetParams().GenesisBlock().nTime);
    CWallet wallet{test_setup->m_node.chain.get(), "", CreateMockableWalletDatabase()};
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }
    auto handler = test_setup->m_node.chain->handleNotifications({&wallet, [](CWallet*) {}});

    const std::optional<std::string> address_mine{add_mine ? std::optional<std::string>{getnewaddress(wallet)} : std::nullopt};

    for (int i = 0; i < 100; ++i) {
        generatetoaddress(test_setup->m_node, address_mine.value_or(ADDRESS_WATCHONLY));
        generatetoaddress(test_setup->m_node, ADDRESS_WATCHONLY);
    }
    // Calls SyncWithValidationInterfaceQueue
    wallet.chain().waitForNotificationsIfTipChanged(uint256::ZERO);

    auto bal = GetBalance(wallet); // Cache

    bench.run([&] {
        if (set_dirty) wallet.MarkDirty();
        bal = GetBalance(wallet);
        if (add_mine) assert(bal.m_mine_trusted > 0);
    });
}

static void WalletBalanceDirty(benchmark::Bench& bench) { WalletBalance(bench, /*set_dirty=*/true, /*add_mine=*/true); }
static void WalletBalanceClean(benchmark::Bench& bench) { WalletBalance(bench, /*set_dirty=*/false, /*add_mine=*/true); }
static void WalletBalanceMine(benchmark::Bench& bench) { WalletBalance(bench, /*set_dirty=*/false, /*add_mine=*/true); }
static void WalletBalanceWatch(benchmark::Bench& bench) { WalletBalance(bench, /*set_dirty=*/false, /*add_mine=*/false); }

BENCHMARK(WalletBalanceDirty);
BENCHMARK(WalletBalanceClean);
BENCHMARK(WalletBalanceMine);
BENCHMARK(WalletBalanceWatch);

struct TipBlock
{
    uint256 prev_block_hash;
    int64_t prev_block_time;
    int tip_height;
};

static TipBlock GetTip(const CChainParams& params, const node::NodeContext& context)
{
    auto tip = WITH_LOCK(::cs_main, return context.chainman->ActiveTip());
    return (tip) ? TipBlock{tip->GetBlockHash(), tip->GetBlockTime(), tip->nHeight} :
           TipBlock{params.GenesisBlock().GetHash(), params.GenesisBlock().GetBlockTime(), 0};
}

// Generate a fake block with a coinbase that has many outputs to the wallet,
// plus optionally include a spending transaction
static void GenerateFakeBlockWithTxos(const CChainParams& params,
                                       const node::NodeContext& context,
                                       CWallet& wallet,
                                       const CScript& wallet_script,
                                       int num_coinbase_outputs,
                                       const std::vector<CTransactionRef>& extra_txs = {})
{
    TipBlock tip{GetTip(params, context)};

    CBlock block;
    CMutableTransaction coinbase_tx;
    coinbase_tx.vin.resize(1);
    coinbase_tx.vin[0].prevout.SetNull();
    coinbase_tx.vin[0].scriptSig = CScript() << ++tip.tip_height << OP_0;

    // Create multiple outputs to the wallet
    CAmount per_output = 50 * COIN / num_coinbase_outputs;
    for (int i = 0; i < num_coinbase_outputs; ++i) {
        coinbase_tx.vout.emplace_back(per_output, wallet_script);
    }

    block.vtx = {MakeTransactionRef(std::move(coinbase_tx))};

    // Add any extra transactions (spending transactions)
    for (const auto& tx : extra_txs) {
        block.vtx.push_back(tx);
    }

    block.nVersion = VERSIONBITS_LAST_OLD_BLOCK_VERSION;
    block.hashPrevBlock = tip.prev_block_hash;
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.nTime = ++tip.prev_block_time;
    block.nBits = params.GenesisBlock().nBits;
    block.nNonce = 0;

    {
        LOCK(::cs_main);
        CBlockIndex* pindex{context.chainman->m_blockman.AddToBlockIndex(block, context.chainman->m_best_header)};
        context.chainman->ActiveChain().SetTip(*pindex);
    }

    const auto& pindex = WITH_LOCK(::cs_main, return context.chainman->ActiveChain().Tip());
    wallet.blockConnected(kernel::ChainstateRole{}, kernel::MakeBlockInfo(pindex, &block));
}

static void WalletBalanceManySpent(benchmark::Bench& bench)
{
    // Benchmark GetBalance with many spent TXOs and few unspent TXOs.
    // This scenario benefits from the m_unusable_txos optimization which
    // separates definitely-spent outputs from potentially-spendable ones.
    //
    // Target: ~50000 spent TXOs, ~50 unspent TXOs
    const auto test_setup = MakeNoLogFileContext<const TestingSetup>();
    const auto& params = test_setup->m_node.chainman->GetParams();

    SetMockTime(params.GenesisBlock().nTime);
    CWallet wallet{test_setup->m_node.chain.get(), "", CreateMockableWalletDatabase()};
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }
    auto handler = test_setup->m_node.chain->handleNotifications({&wallet, [](CWallet*) {}});

    const auto dest = getNewDestination(wallet, OutputType::BECH32);
    const CScript wallet_script = GetScriptForDestination(dest);

    // Phase 1: Create many UTXOs (100 outputs per block * 500 blocks = 50000 TXOs)
    // Need 100+ blocks for coinbase maturity
    constexpr int NUM_BLOCKS = 500;
    constexpr int OUTPUTS_PER_BLOCK = 100;

    for (int i = 0; i < NUM_BLOCKS; ++i) {
        GenerateFakeBlockWithTxos(params, test_setup->m_node, wallet, wallet_script, OUTPUTS_PER_BLOCK);
    }

    // Phase 2: Spend most UTXOs by creating spending transactions
    // Get all available coins and spend them in batches
    std::vector<COutPoint> outputs_to_spend;
    {
        LOCK(wallet.cs_wallet);
        auto available = AvailableCoins(wallet);
        for (const auto& coin : available.All()) {
            outputs_to_spend.push_back(coin.outpoint);
        }
    }

    // Keep last ~50 outputs unspent, spend the rest
    constexpr int KEEP_UNSPENT = 50;
    int num_to_spend = std::max(0, static_cast<int>(outputs_to_spend.size()) - KEEP_UNSPENT);

    // Create spending transactions in batches of 100 inputs each
    constexpr int BATCH_SIZE = 100;
    std::vector<CTransactionRef> spending_txs;

    for (int i = 0; i < num_to_spend; i += BATCH_SIZE) {
        CMutableTransaction spend_tx;
        spend_tx.nLockTime = i; // Unique locktime for unique txid

        int batch_end = std::min(i + BATCH_SIZE, num_to_spend);
        CAmount total_value = 0;

        for (int j = i; j < batch_end; ++j) {
            spend_tx.vin.emplace_back(outputs_to_spend[j]);
            // Each output has roughly 0.5 COIN value (50 COIN / 100 outputs)
            total_value += COIN / 2;
        }

        // Single output back to wallet (consolidation)
        spend_tx.vout.emplace_back(total_value - 1000, wallet_script); // subtract fee

        spending_txs.push_back(MakeTransactionRef(std::move(spend_tx)));
    }

    // Phase 3: Confirm all spending transactions in new blocks
    // Include multiple spending txs per block for efficiency
    constexpr int TXS_PER_BLOCK = 10;
    for (size_t i = 0; i < spending_txs.size(); i += TXS_PER_BLOCK) {
        std::vector<CTransactionRef> block_txs;
        for (size_t j = i; j < std::min(i + TXS_PER_BLOCK, spending_txs.size()); ++j) {
            block_txs.push_back(spending_txs[j]);
        }
        GenerateFakeBlockWithTxos(params, test_setup->m_node, wallet, wallet_script, 1, block_txs);
    }

    // Phase 4: Run the benchmark
    auto bal = GetBalance(wallet); // Cache

    bench.run([&] {
        wallet.MarkDirty();
        bal = GetBalance(wallet);
        assert(bal.m_mine_trusted > 0);
    });
}

BENCHMARK(WalletBalanceManySpent);
} // namespace wallet

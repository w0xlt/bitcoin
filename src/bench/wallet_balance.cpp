// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/consensus.h>
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
using kernel::ChainstateRole;

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

// Generate a fake block with a coinbase that has outputs to coinbase_script,
// plus optionally include additional transactions (e.g., spending transactions)
static void GenerateFakeBlockWithTxos(const CChainParams& params,
                                       const node::NodeContext& context,
                                       CWallet& wallet,
                                       const CScript& coinbase_script,
                                       int num_coinbase_outputs,
                                       const std::vector<CTransactionRef>& extra_txs = {})
{
    TipBlock tip{GetTip(params, context)};

    CBlock block;
    CMutableTransaction coinbase_tx;
    coinbase_tx.vin.resize(1);
    coinbase_tx.vin[0].prevout.SetNull();
    coinbase_tx.vin[0].scriptSig = CScript() << ++tip.tip_height << OP_0;

    // Create coinbase outputs
    CAmount per_output = 50 * COIN / num_coinbase_outputs;
    for (int i = 0; i < num_coinbase_outputs; ++i) {
        coinbase_tx.vout.emplace_back(per_output, coinbase_script);
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

    const auto* pindex = WITH_LOCK(::cs_main, return context.chainman->ActiveChain().Tip());
    wallet.blockConnected(ChainstateRole{}, kernel::MakeBlockInfo(pindex, &block));
}

static void WalletBalanceManySpent(benchmark::Bench& bench)
{
    // Benchmark GetBalance with many spent TXOs and few unspent TXOs.
    // This scenario benefits from optimizations that separate definitely-spent
    // outputs from potentially-spendable ones (such as m_unusable_txos).
    //
    // Target: ~50,000 spent TXOs, ~50 unspent TXOs
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
    // Burn script for outputs we don't want in the wallet
    const CScript burn_script{CScript() << OP_TRUE};

    // Phase 1: Create many UTXOs (100 outputs per block * 500 blocks = 50,000 TXOs)
    constexpr int NUM_BLOCKS = 500;
    constexpr int OUTPUTS_PER_BLOCK = 100;
    constexpr CAmount OUTPUT_VALUE = 50 * COIN / OUTPUTS_PER_BLOCK;

    for (int i = 0; i < NUM_BLOCKS; ++i) {
        GenerateFakeBlockWithTxos(params, test_setup->m_node, wallet, wallet_script, OUTPUTS_PER_BLOCK);
    }

    // Phase 2: Add COINBASE_MATURITY blocks to mature all coinbase outputs
    // This ensures all 50,000 TXOs are spendable
    for (int i = 0; i < COINBASE_MATURITY; ++i) {
        GenerateFakeBlockWithTxos(params, test_setup->m_node, wallet, burn_script, 1);
    }

    // Phase 3: Spend most UTXOs by creating spending transactions
    // Get all available coins and spend them in batches
    std::vector<COutPoint> outputs_to_spend;
    {
        LOCK(wallet.cs_wallet);
        auto available = AvailableCoins(wallet);
        for (const auto& coin : available.All()) {
            outputs_to_spend.push_back(coin.outpoint);
        }
    }

    // Keep ~50 outputs unspent, spend the rest
    constexpr int KEEP_UNSPENT = 50;
    int num_to_spend = std::max(0, static_cast<int>(outputs_to_spend.size()) - KEEP_UNSPENT);

    // Create spending transactions in batches of 100 inputs each
    constexpr int BATCH_SIZE = 100;
    constexpr CAmount BENCHMARK_FEE = 1000;
    std::vector<CTransactionRef> spending_txs;

    for (int i = 0; i < num_to_spend; i += BATCH_SIZE) {
        CMutableTransaction spend_tx;
        int batch_end = std::min(i + BATCH_SIZE, num_to_spend);

        for (int j = i; j < batch_end; ++j) {
            spend_tx.vin.emplace_back(outputs_to_spend[j]);
        }

        // Send to burn script so consolidation outputs don't add to wallet TXOs
        CAmount total_value = (batch_end - i) * OUTPUT_VALUE;
        spend_tx.vout.emplace_back(total_value - BENCHMARK_FEE, burn_script);

        spending_txs.push_back(MakeTransactionRef(std::move(spend_tx)));
    }

    // Phase 4: Confirm all spending transactions in new blocks
    // Include multiple spending txs per block for efficiency
    // Coinbase outputs go to burn script to avoid adding wallet TXOs
    constexpr int TXS_PER_BLOCK = 10;
    for (size_t i = 0; i < spending_txs.size(); i += TXS_PER_BLOCK) {
        std::vector<CTransactionRef> block_txs;
        for (size_t j = i; j < std::min(i + TXS_PER_BLOCK, spending_txs.size()); ++j) {
            block_txs.push_back(spending_txs[j]);
        }
        GenerateFakeBlockWithTxos(params, test_setup->m_node, wallet, burn_script, 1, block_txs);
    }

    // Phase 5: Run the benchmark
    auto bal = GetBalance(wallet); // Cache

    bench.run([&] {
        wallet.MarkDirty();
        bal = GetBalance(wallet);
        assert(bal.m_mine_trusted > 0);
    });
}

BENCHMARK(WalletBalanceManySpent);
} // namespace wallet

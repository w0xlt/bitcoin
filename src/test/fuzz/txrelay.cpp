// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>
#include <consensus/amount.h>
#include <merkleblock.h>
#include <node/txrelay.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/random.h>
#include <uint256.h>
#include <util/check.h>

#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <utility>
#include <vector>

using namespace std::chrono_literals;
using node::TxRelay;

namespace {

CBlock ConsumeBlock(FuzzedDataProvider& provider)
{
    CBlock block;
    const int num_txs{provider.ConsumeIntegralInRange<int>(1, 8)};
    for (int i = 0; i < num_txs; ++i) {
        CMutableTransaction tx_mut;
        tx_mut.nLockTime = provider.ConsumeIntegral<uint32_t>();
        tx_mut.vin.emplace_back(COutPoint{Txid::FromUint256(ConsumeUInt256(provider)), provider.ConsumeIntegral<uint32_t>()},
                                ConsumeScript(provider),
                                provider.ConsumeIntegral<uint32_t>());
        tx_mut.vout.emplace_back(ConsumeMoney(provider), ConsumeScript(provider));
        block.vtx.push_back(MakeTransactionRef(std::move(tx_mut)));
    }
    return block;
}

CBloomFilter ConsumeBloomFilter(FuzzedDataProvider& provider)
{
    return CBloomFilter{provider.ConsumeIntegralInRange<unsigned int>(1, 10000),
                        std::max(provider.ConsumeProbability<double>(), 0.000001),
                        /*nTweakIn=*/provider.ConsumeIntegral<unsigned int>(),
                        /*nFlagsIn=*/provider.ConsumeIntegralInRange<unsigned char>(0, 2)};
}

} // namespace

FUZZ_TARGET(txrelay)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    TxRelay tx_relay;

    // Shadow model of the externally observable state. The announcement queue
    // model stays exact by querying the (probabilistic) known-transactions
    // filter as an oracle before each PushInventory call.
    bool relay_txs{false};
    bool filter_set{false};
    bool send_mempool{false};
    std::chrono::microseconds next_inv_send_time{0};
    uint64_t last_inv_sequence{1};
    CAmount fee_filter{0};
    std::set<Wtxid> to_send;

    LIMITED_WHILE(provider.remaining_bytes() > 0, 1000)
    {
        CallOneOf(
            provider,
            [&] { // VERSION handshake decides the initial relay preference
                relay_txs = provider.ConsumeBool();
                tx_relay.SetRelayTxs(relay_txs);
            },
            [&] { // FILTERLOAD
                tx_relay.SetBloomFilter(ConsumeBloomFilter(provider));
                filter_set = true;
                relay_txs = true;
            },
            [&] { // FILTERADD: succeeds iff a filter is loaded
                const auto data{provider.ConsumeBytes<unsigned char>(provider.ConsumeIntegralInRange<size_t>(0, 64))};
                Assert(tx_relay.AddToBloomFilter(data) == filter_set);
            },
            [&] { // FILTERCLEAR removes the filter but keeps relaying
                tx_relay.ClearBloomFilter();
                filter_set = false;
                relay_txs = true;
            },
            [&] { // Serve a BIP37 merkle block
                const CBlock block{ConsumeBlock(provider)};
                const auto merkle_block{tx_relay.MakeMerkleBlock(block)};
                Assert(merkle_block.has_value() == filter_set);
                if (merkle_block) Assert(merkle_block->vMatchedTxn.size() <= block.vtx.size());
            },
            [&] { // Mark a transaction known; the rolling filter must remember
                  // it (capacity 50000 is far above the iteration limit)
                const uint256 hash{ConsumeUInt256(provider)};
                tx_relay.AddKnownTx(hash);
                LOCK(tx_relay.GetTxInventoryMutex());
                Assert(tx_relay.TxInventoryKnownContains(hash));
            },
            [&] { // Queue an announcement. Use the known-filter as an oracle
                  // so the model tolerates rolling-bloom false positives.
                const uint256 hash{ConsumeUInt256(provider)};
                const Wtxid wtxid{Wtxid::FromUint256(provider.ConsumeBool() ? hash : ConsumeUInt256(provider))};
                const bool known{WITH_LOCK(tx_relay.GetTxInventoryMutex(), return tx_relay.TxInventoryKnownContains(hash))};
                tx_relay.PushInventory(hash, wtxid);
                if (next_inv_send_time != 0s && !known) to_send.insert(wtxid);
            },
            [&] { // Trickle timing
                const std::chrono::microseconds now{provider.ConsumeIntegral<uint32_t>()};
                LOCK(tx_relay.GetTxInventoryMutex());
                Assert(tx_relay.IsInvSendTimeReached(now) == (next_inv_send_time < now));
                if (provider.ConsumeBool()) {
                    next_inv_send_time = std::chrono::microseconds{provider.ConsumeIntegralInRange<int64_t>(0, std::numeric_limits<int64_t>::max())};
                    tx_relay.SetNextInvSendTime(next_inv_send_time);
                }
            },
            [&] { // BIP35 mempool request flag is one-shot
                if (provider.ConsumeBool()) {
                    tx_relay.SetSendMempool();
                    send_mempool = true;
                }
                LOCK(tx_relay.GetTxInventoryMutex());
                Assert(tx_relay.ConsumeSendMempool() == send_mempool);
                send_mempool = false;
                Assert(!tx_relay.ConsumeSendMempool());
            },
            [&] { // BIP133 fee filter
                fee_filter = ConsumeMoney(provider);
                tx_relay.SetFeeFilterReceived(fee_filter);
            },
            [&] { // Mempool sequence bookkeeping
                last_inv_sequence = provider.ConsumeIntegral<uint64_t>();
                WITH_LOCK(tx_relay.GetTxInventoryMutex(), tx_relay.SetLastInvSequence(last_inv_sequence));
            },
            [&] { // Trickle-time queue clearing for non-relay peers
                LOCK(tx_relay.GetTxInventoryMutex());
                tx_relay.ClearTxInventoryToSendIfNoRelayTxs();
                if (!relay_txs) to_send.clear();
            },
            [&] { // Erase by wtxid, present or not
                const Wtxid wtxid{to_send.empty() || provider.ConsumeBool() ?
                                      Wtxid::FromUint256(ConsumeUInt256(provider)) :
                                      *to_send.begin()};
                LOCK(tx_relay.GetTxInventoryMutex());
                tx_relay.TxInventoryToSendErase(wtxid);
                to_send.erase(wtxid);
            },
            [&] { // Iterator-based drain, mirroring the SendMessages selection loop
                LOCK(tx_relay.GetTxInventoryMutex());
                auto iters{tx_relay.GetTxInventoryToSendIterators()};
                Assert(iters.size() == to_send.size());
                const size_t drain{provider.ConsumeIntegralInRange<size_t>(0, iters.size())};
                for (size_t i = 0; i < drain; ++i) {
                    const Wtxid wtxid{*iters.back()};
                    tx_relay.TxInventoryToSendErase(iters.back());
                    iters.pop_back();
                    Assert(to_send.erase(wtxid) == 1);
                }
                Assert(tx_relay.TxInventoryToSendSize() == to_send.size());
            });

        // Invariants that must hold after every operation.
        Assert(tx_relay.GetRelayTxs() == relay_txs);
        Assert(tx_relay.GetLastInvSequence() == last_inv_sequence);
        Assert(tx_relay.GetFeeFilterReceived() == fee_filter);
        const auto stats{tx_relay.GetInventoryStats()};
        Assert(stats.m_last_inv_seq == last_inv_sequence);
        Assert(stats.m_inv_to_send == to_send.size());
        Assert(tx_relay.IsInventoryPristine() == (to_send.empty() && next_inv_send_time == 0s));
    }
}

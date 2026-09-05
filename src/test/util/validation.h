// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_VALIDATION_H
#define BITCOIN_TEST_UTIL_VALIDATION_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <util/task_runner.h>
#include <validation.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

namespace node {
class BlockManager;
}
class CValidationInterface;
class FakeNodeClock;
struct TestingSetup;

/// Runs callbacks synchronously and deterministically, while avoiding DEBUG_LOCKORDER false positives.
class ImmediateBackgroundTaskRunner : public util::TaskRunnerInterface
{
public:
    void insert(std::function<void()> func) override { std::thread(std::move(func)).join(); }
    void flush() override {}
    size_t size() override { return 0; }
};

struct TestBlockManager : public node::BlockManager {
    /** Test-only method to clear internal state for fuzzing */
    void CleanupForFuzzing() EXCLUSIVE_LOCKS_REQUIRED(!m_blockfile_mutex);
    /** Return a snapshot of one block-file metadata entry. */
    kernel::CBlockFileInfo GetBlockFileInfo(size_t n) const EXCLUSIVE_LOCKS_REQUIRED(!m_blockfile_mutex);
    /** Set the recorded block-file size to force rollover in tests. */
    void SetBlockFileSize(size_t n, uint32_t size) EXCLUSIVE_LOCKS_REQUIRED(!m_blockfile_mutex);
};

struct TestChainstateManager : public ChainstateManager {
    /** Accept a block with both locks held. */
    bool AcceptBlock(const std::shared_ptr<const CBlock>& block, BlockValidationState& state, CBlockIndex** index,
                     const FlatFilePos* pos = nullptr, bool* new_block = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_accept_block_mutex) LOCKS_EXCLUDED(cs_main);
    /** Disable the next write of all chainstates */
    void DisableNextWrite();
    /** Reset the ibd cache to its initial state */
    void ResetIbd();
    /** Toggle IsInitialBlockDownload from true to false */
    void JumpOutOfIbd();
    /** Wrappers that avoid making chainstatemanager internals public for tests */
    void InvalidBlockFound(CBlockIndex* pindex, const BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void InvalidChainFound(CBlockIndex* pindexNew) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    CBlockIndex* FindMostWorkChain() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void ResetBestInvalid() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};

class ValidationInterfaceTest
{
public:
    static void BlockConnected(
        const kernel::ChainstateRole& role,
        CValidationInterface& obj,
        const std::shared_ptr<const CBlock>& block,
        const CBlockIndex* pindex);
};

std::vector<std::pair<COutPoint, CAmount>> ResetChainmanAndMempool(TestingSetup& setup, FakeNodeClock& node_clock);

#endif // BITCOIN_TEST_UTIL_VALIDATION_H

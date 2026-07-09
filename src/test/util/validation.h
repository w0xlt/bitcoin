// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_VALIDATION_H
#define BITCOIN_TEST_UTIL_VALIDATION_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <util/task_runner.h>
#include <validation.h>

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace node {
class BlockManager;
}
class CValidationInterface;
class FakeNodeClock;
struct TestingSetup;

/// Runs callbacks in order on a background thread, each in a fresh std::thread to avoid
/// DEBUG_LOCKORDER false positives. Callbacks may take locks held by the thread that
/// signals them, such as cs_main, so they must not run synchronously in that thread.
/// Use flush() (for example through SyncWithValidationInterfaceQueue()) for determinism.
class SerialBackgroundTaskRunner : public util::TaskRunnerInterface
{
public:
    SerialBackgroundTaskRunner() : m_worker{[this] { ProcessQueue(); }} {}
    ~SerialBackgroundTaskRunner() override
    {
        {
            std::lock_guard lock{m_mutex};
            m_stop = true;
        }
        m_cv.notify_one();
        m_worker.join();
    }

    void insert(std::function<void()> func) override
    {
        {
            std::lock_guard lock{m_mutex};
            m_tasks.emplace_back(std::move(func));
        }
        m_cv.notify_one();
    }

    void flush() override
    {
        std::promise<void> promise;
        auto future{promise.get_future()};
        insert([&promise] { promise.set_value(); });
        future.wait();
    }

    size_t size() override
    {
        std::lock_guard lock{m_mutex};
        return m_tasks.size();
    }

private:
    void ProcessQueue()
    {
        while (true) {
            std::function<void()> func;
            {
                std::unique_lock lock{m_mutex};
                m_cv.wait(lock, [this] { return m_stop || !m_tasks.empty(); });
                if (m_stop && m_tasks.empty()) return;
                func = std::move(m_tasks.front());
                m_tasks.pop_front();
            }
            std::thread(std::move(func)).join();
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::function<void()>> m_tasks;
    bool m_stop{false};
    std::thread m_worker;
};

struct TestBlockManager : public node::BlockManager {
    /** Test-only method to clear internal state for fuzzing */
    void CleanupForFuzzing();
};

struct TestChainstateManager : public ChainstateManager {
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

// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKPROCESSING_H
#define BITCOIN_NODE_BLOCKPROCESSING_H

#include <kernel/cs_main.h>
#include <net.h>
#include <sync.h>
#include <uint256.h>

#include <condition_variable>
#include <exception>
#include <memory>
#include <optional>
#include <thread>

class CBlock;
class ChainstateManager;

namespace node {
struct BlockProcessingJob {
    std::shared_ptr<const CBlock> block;
    NodeId source;
    bool force_processing;
    bool min_pow_checked;
    bool optimistic_reconstruction{false};
};

/** ProcessNewBlock outcomes; neither bool implies full consensus validity. */
struct BlockProcessingResult {
    NodeId source;
    uint256 hash;
    bool optimistic_reconstruction;
    bool processing_success{false};
    bool new_block{false};
    std::exception_ptr exception;
};

/** One P2P block job, including a completed result not yet consumed.
 *
 * The controller serializes Start/Submit/TakeResult/Stop. Wait releases the slot
 * mutex; validation and message-handler wakeups never hold it. Stop joins before
 * the referenced dependencies are destroyed. Construction starts no thread.
 */
class BlockProcessingWorker
{
public:
    BlockProcessingWorker(ChainstateManager& chainman, CConnman& connman)
        : m_chainman{chainman}, m_connman{connman} {}
    ~BlockProcessingWorker();

    /** Reopen after Stop; the next accepted job starts the thread lazily. */
    void Start() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool Submit(BlockProcessingJob job) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Wait for accepted work, returning whether a result awaits consumption. */
    bool Wait() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) LOCKS_EXCLUDED(cs_main);
    std::optional<BlockProcessingResult> TakeResult() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Close admissions, finish accepted work on the worker, join and settle it. */
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) LOCKS_EXCLUDED(cs_main);

private:
    void Run() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    ChainstateManager& m_chainman;
    CConnman& m_connman;
    Mutex m_mutex;
    std::condition_variable m_condition;
    bool m_open GUARDED_BY(m_mutex){true};
    bool m_running GUARDED_BY(m_mutex){false};
    std::optional<BlockProcessingJob> m_job GUARDED_BY(m_mutex);
    std::optional<BlockProcessingResult> m_result GUARDED_BY(m_mutex);
    std::thread m_thread; // Controller-owned; Stop/Start never run concurrently.
};
} // namespace node

#endif // BITCOIN_NODE_BLOCKPROCESSING_H

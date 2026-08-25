// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_processing.h>

#include <sync.h>
#include <util/check.h>
#include <util/thread.h>

#include <array>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>

namespace node {
namespace {

class P2PBlockProcessingImpl final : public P2PBlockProcessing
{
private:
    P2PBlockProcessor m_processor;
    P2PBlockProcessingStateChanged m_state_changed;

    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    std::array<std::optional<P2PBlockProcessingJob>, P2P_BLOCK_PROCESSING_MAX_JOBS> m_jobs GUARDED_BY(m_mutex);
    size_t m_head GUARDED_BY(m_mutex){0};
    size_t m_tail GUARDED_BY(m_mutex){0};
    size_t m_queued_jobs GUARDED_BY(m_mutex){0};
    size_t m_job_count GUARDED_BY(m_mutex){0};
    uint64_t m_job_bytes GUARDED_BY(m_mutex){0};
    bool m_active GUARDED_BY(m_mutex){false};
    bool m_interrupted GUARDED_BY(m_mutex){false};
    std::thread m_thread;

    bool CanSubmitLocked(uint32_t serialized_size) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
    {
        return !m_interrupted &&
               m_job_count < P2P_BLOCK_PROCESSING_MAX_JOBS &&
               serialized_size <= P2P_BLOCK_PROCESSING_MAX_BYTES &&
               m_job_bytes <= P2P_BLOCK_PROCESSING_MAX_BYTES - serialized_size;
    }

    void Worker() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        while (true) {
            P2PBlockProcessingJob job{};
            {
                WAIT_LOCK(m_mutex, lock);
                m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                    return m_interrupted || m_queued_jobs > 0;
                });
                if (m_interrupted) return;

                Assert(m_queued_jobs > 0);
                Assert(!m_active);
                Assert(m_jobs[m_head].has_value());
                job = std::move(*m_jobs[m_head]);
                m_jobs[m_head].reset();
                m_head = (m_head + 1) % m_jobs.size();
                --m_queued_jobs;
                m_active = true;
            }

            // The processor owns validation and owner bookkeeping. Never hold
            // the FIFO mutex while it takes another lock or invokes PNB.
            m_processor(job);
            const uint32_t serialized_size{job.serialized_size};
            job.block.reset();

            {
                LOCK(m_mutex);
                Assert(m_active);
                Assert(m_job_count > 0);
                Assert(m_job_bytes >= serialized_size);
                m_active = false;
                --m_job_count;
                m_job_bytes -= serialized_size;
            }
            // Wake only after processing cleanup and capacity release are both
            // complete. The callback must not re-enter while the mutex is held.
            m_state_changed();
        }
    }

public:
    P2PBlockProcessingImpl(
        P2PBlockProcessor processor,
        P2PBlockProcessingStateChanged state_changed)
        : m_processor{std::move(processor)},
          m_state_changed{std::move(state_changed)},
          m_thread{&util::TraceThread, "pnb", [this] { Worker(); }}
    {
    }

    ~P2PBlockProcessingImpl() override
    {
        (void)Stop();
    }

    bool CanSubmit(uint32_t serialized_size) const noexcept override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return CanSubmitLocked(serialized_size);
    }

    bool IsIdle() const noexcept override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_job_count == 0;
    }

    P2PBlockProcessingSubmit Submit(P2PBlockProcessingJob job) noexcept override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        static_assert(std::is_nothrow_move_constructible_v<P2PBlockProcessingJob>);
        {
            LOCK(m_mutex);
            if (m_interrupted) return P2PBlockProcessingSubmit::INTERRUPTED;
            Assert(job.block != nullptr);
            Assert(CanSubmitLocked(job.serialized_size));
            const uint32_t serialized_size{job.serialized_size};
            Assert(m_queued_jobs < m_jobs.size());
            Assert(!m_jobs[m_tail].has_value());
            m_jobs[m_tail].emplace(std::move(job));
            m_tail = (m_tail + 1) % m_jobs.size();
            ++m_queued_jobs;
            ++m_job_count;
            m_job_bytes += serialized_size;
        }
        m_cv.notify_one();
        return P2PBlockProcessingSubmit::ACCEPTED;
    }

    void Interrupt() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_interrupted = true;
        }
        m_cv.notify_one();
    }

    P2PBlockProcessingCanceled Stop() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        static_assert(std::is_nothrow_move_assignable_v<P2PBlockProcessingJob>);
        Interrupt();
        if (m_thread.joinable()) m_thread.join();

        P2PBlockProcessingCanceled canceled;
        {
            LOCK(m_mutex);
            Assert(!m_active);
            while (m_queued_jobs > 0) {
                Assert(m_jobs[m_head].has_value());
                Assert(m_job_count > 0);
                Assert(m_job_bytes >= m_jobs[m_head]->serialized_size);
                --m_job_count;
                m_job_bytes -= m_jobs[m_head]->serialized_size;
                Assert(canceled.count < canceled.jobs.size());
                canceled.jobs[canceled.count++] = std::move(*m_jobs[m_head]);
                m_jobs[m_head].reset();
                m_head = (m_head + 1) % m_jobs.size();
                --m_queued_jobs;
            }
            Assert(m_head == m_tail);
            Assert(m_job_count == 0);
            Assert(m_job_bytes == 0);
        }
        return canceled;
    }
};

} // namespace

std::unique_ptr<P2PBlockProcessing> MakeP2PBlockProcessing(
    P2PBlockProcessor processor,
    P2PBlockProcessingStateChanged state_changed)
{
    Assert(processor);
    Assert(state_changed);
    return std::make_unique<P2PBlockProcessingImpl>(
        std::move(processor), std::move(state_changed));
}

} // namespace node

// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <logging.h>
#include <primitives/block.h>
#include <sync.h>
#include <util/check.h>
#include <util/thread.h>
#include <util/time.h>
#include <validation.h>

#include <condition_variable>
#include <memory>
#include <optional>
#include <thread>
#include <utility>

namespace node {
namespace {

class P2PBlockValidationImpl final : public P2PBlockValidation
{
private:
    P2PBlockValidationFn m_process_new_block;
    P2PBlockValidationResultReady m_result_ready;

    // Lock boundary: the worker releases this sole component mutex before
    // entering PNB or any synchronous validation callback. Callers never hold
    // it while taking cs_main or g_msgproc_mutex.
    Mutex m_mutex;
    std::condition_variable m_cv;
    std::optional<P2PBlockValidationRequest> m_request GUARDED_BY(m_mutex);
    std::optional<P2PBlockValidationResult> m_result GUARDED_BY(m_mutex);
    bool m_running GUARDED_BY(m_mutex){false};
    bool m_started GUARDED_BY(m_mutex){false};
    bool m_stopping GUARDED_BY(m_mutex){false};
    std::thread m_thread;

    void Worker() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex, !cs_main)
    {
        for (;;) {
            P2PBlockValidationRequest request{
                .block = nullptr,
                .force_processing = false,
                .min_pow_checked = false,
            };
            {
                WAIT_LOCK(m_mutex, lock);
                m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                    return m_stopping || m_request.has_value();
                });
                if (!m_request) return;

                request = std::move(*m_request);
                m_request.reset();
                Assert(!m_running);
                m_running = true;
            }

            const uint256 hash{request.block->GetHash()};
            LogInfo("ASYNC_PNB_PEER_SERVICE event=worker_wake job=%d hash=%s steady_ns=%d active_slot=1\n",
                    request.job_id, hash.ToString(),
                    TicksSinceEpoch<std::chrono::nanoseconds>(SteadyClock::now()));
            bool new_block{false};
            const auto pnb_start{SteadyClock::now()};
            LogInfo("ASYNC_PNB_PEER_SERVICE event=pnb_start job=%d hash=%s steady_ns=%d active_slot=1\n",
                    request.job_id, hash.ToString(),
                    TicksSinceEpoch<std::chrono::nanoseconds>(pnb_start));
            (void)m_process_new_block(
                request.block,
                request.force_processing,
                request.min_pow_checked,
                &new_block);
            const auto pnb_end{SteadyClock::now()};
            LogInfo("ASYNC_PNB_PEER_SERVICE event=pnb_end job=%d hash=%s steady_ns=%d duration_ns=%d new_block=%d active_slot=1\n",
                    request.job_id, hash.ToString(),
                    TicksSinceEpoch<std::chrono::nanoseconds>(pnb_end),
                    Ticks<std::chrono::nanoseconds>(pnb_end - pnb_start), new_block);
            request.block.reset();

            SteadyClock::time_point publication_time;
            {
                LOCK(m_mutex);
                Assert(m_running);
                Assert(!m_result);
                m_running = false;
                publication_time = SteadyClock::now();
                m_result = P2PBlockValidationResult{new_block};
            }
            // Publication precedes the wake and the callback never runs under
            // the component mutex.
            LogInfo("ASYNC_PNB_PEER_SERVICE event=result_publication job=%d hash=%s steady_ns=%d new_block=%d active_slot=1\n",
                    request.job_id, hash.ToString(),
                    TicksSinceEpoch<std::chrono::nanoseconds>(publication_time), new_block);
            m_result_ready();

            {
                LOCK(m_mutex);
                if (m_stopping) return;
            }
        }
    }

public:
    P2PBlockValidationImpl(
        P2PBlockValidationFn process_new_block,
        P2PBlockValidationResultReady result_ready)
        : m_process_new_block{std::move(process_new_block)},
          m_result_ready{std::move(result_ready)}
    {
        Assert(m_process_new_block);
        Assert(m_result_ready);
    }

    ~P2PBlockValidationImpl() override { StopAndJoin(); }

    void Start() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        Assert(!m_started);
        Assert(!m_stopping);
        m_thread = std::thread{&util::TraceThread, "p2p-pnb", [this] { Worker(); }};
        m_started = true;
    }

    P2PBlockValidationSubmit Submit(P2PBlockValidationRequest request) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            if (m_stopping) return P2PBlockValidationSubmit::STOPPING;
            Assert(m_started);
            if (m_request || m_running || m_result) return P2PBlockValidationSubmit::FULL;
            Assert(request.block != nullptr);
            m_request = std::move(request);
        }
        m_cv.notify_one();
        return P2PBlockValidationSubmit::ACCEPTED;
    }

    std::optional<P2PBlockValidationResult> TakeResult() override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        auto result{std::move(m_result)};
        m_result.reset();
        return result;
    }

    void StopAndJoin() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_stopping = true;
        }
        m_cv.notify_one();
        if (m_thread.joinable()) m_thread.join();
    }
};

} // namespace

std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidation(
    ChainstateManager& chainman,
    P2PBlockValidationResultReady result_ready)
{
    return MakeP2PBlockValidationForTest(
        [&chainman](const std::shared_ptr<const CBlock>& block,
                    bool force_processing,
                    bool min_pow_checked,
                    bool* new_block) {
            return chainman.ProcessNewBlock(
                block, force_processing, min_pow_checked, new_block);
        },
        std::move(result_ready));
}

std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidationForTest(
    P2PBlockValidationFn process_new_block,
    P2PBlockValidationResultReady result_ready)
{
    return std::make_unique<P2PBlockValidationImpl>(
        std::move(process_new_block), std::move(result_ready));
}

} // namespace node

// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <node/async_pnb_peer_service_probe.h>

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
    const std::shared_ptr<AsyncPNBPeerServiceProbe> m_probe;
    const P2PBlockValidationTestStateHook m_test_state_hook;

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
            uint64_t queued_job{0};
            std::optional<uint256> queued_hash;
            {
                WAIT_LOCK(m_mutex, lock);
                m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                    return m_stopping || m_request.has_value();
                });
                if (!m_request) return;
                if (m_probe && m_probe->TestGatesEnabled()) {
                    queued_job = m_request->job_id;
                    queued_hash = m_request->block->GetHash();
                }
            }
            if (queued_hash) {
                (void)m_probe->TestGate(AsyncPNBProbeTestGate::WORKER_QUEUED,
                                        queued_job, /*peer=*/-1, &*queued_hash);
            }
            if (m_test_state_hook) {
                m_test_state_hook(P2PBlockValidationTestState::QUEUED);
            }
            {
                LOCK(m_mutex);
                Assert(m_request);

                request = std::move(*m_request);
                m_request.reset();
                Assert(!m_running);
                m_running = true;
            }
            if (m_test_state_hook) {
                m_test_state_hook(P2PBlockValidationTestState::RUNNING);
            }

            std::optional<uint256> probe_hash;
            if (m_probe) {
                probe_hash = request.block->GetHash();
                const auto worker_wake{SteadyClock::now()};
                m_probe->Record(AsyncPNBProbeEvent::WORKER_WAKE, worker_wake,
                                {static_cast<int64_t>(request.job_id), 1}, {}, {}, &*probe_hash);
                if (m_probe->TestGatesEnabled()) m_probe->SetActiveJob(request.job_id);
            }
            bool new_block{false};
            SteadyClock::time_point pnb_start;
            if (m_probe) {
                pnb_start = SteadyClock::now();
                m_probe->Record(AsyncPNBProbeEvent::PNB_START, pnb_start,
                                {static_cast<int64_t>(request.job_id), 1}, {}, {}, &*probe_hash);
            }
            const bool process_new_block{m_process_new_block(
                request.block,
                request.force_processing,
                request.min_pow_checked,
                &new_block)};
            if (m_probe) {
                const auto pnb_end{SteadyClock::now()};
                if (m_probe->TestGatesEnabled()) m_probe->SetActiveJob(0);
                m_probe->Record(
                    AsyncPNBProbeEvent::PNB_END, pnb_end,
                    {static_cast<int64_t>(request.job_id),
                     Ticks<std::chrono::nanoseconds>(pnb_end - pnb_start),
                     process_new_block, new_block, 1},
                    {}, {}, &*probe_hash);
            }
            request.block.reset();

            SteadyClock::time_point publication_time;
            {
                LOCK(m_mutex);
                Assert(m_running);
                Assert(!m_result);
                m_running = false;
                if (m_probe) publication_time = SteadyClock::now();
                m_result = P2PBlockValidationResult{process_new_block, new_block};
            }
            if (m_test_state_hook) {
                m_test_state_hook(P2PBlockValidationTestState::RESULT_READY);
            }
            if (m_probe) {
                m_probe->Record(
                    AsyncPNBProbeEvent::RESULT_PUBLICATION, publication_time,
                    {static_cast<int64_t>(request.job_id), process_new_block,
                     new_block, 1}, {}, {}, &*probe_hash);
                if (m_probe->TestGatesEnabled()) {
                    (void)m_probe->TestGate(AsyncPNBProbeTestGate::RESULT_READY,
                                            request.job_id, /*peer=*/-1, &*probe_hash);
                }
            }
            // Publication precedes the wake and the callback never runs under
            // the component mutex.
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
        P2PBlockValidationResultReady result_ready,
        P2PBlockValidationTestStateHook state_hook,
        std::shared_ptr<AsyncPNBPeerServiceProbe> probe)
        : m_process_new_block{std::move(process_new_block)},
          m_result_ready{std::move(result_ready)},
          m_probe{std::move(probe)},
          m_test_state_hook{std::move(state_hook)}
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
    P2PBlockValidationResultReady result_ready,
    std::shared_ptr<AsyncPNBPeerServiceProbe> probe)
{
    return std::make_unique<P2PBlockValidationImpl>(
        [&chainman](const std::shared_ptr<const CBlock>& block,
                    bool force_processing,
                    bool min_pow_checked,
                    bool* new_block) {
            return chainman.ProcessNewBlock(
                block, force_processing, min_pow_checked, new_block);
        },
        std::move(result_ready),
        P2PBlockValidationTestStateHook{},
        std::move(probe));
}

std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidationForTest(
    P2PBlockValidationFn process_new_block,
    P2PBlockValidationResultReady result_ready,
    P2PBlockValidationTestStateHook state_hook)
{
    return std::make_unique<P2PBlockValidationImpl>(
        std::move(process_new_block), std::move(result_ready), std::move(state_hook),
        /*probe=*/nullptr);
}

} // namespace node

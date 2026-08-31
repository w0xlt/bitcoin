// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <logging.h>
#include <sync.h>
#include <util/check.h>
#include <util/thread.h>

#include <condition_variable>
#include <exception>
#include <optional>
#include <thread>
#include <utility>

namespace node {
namespace {

class P2PBlockValidationImpl final : public P2PBlockValidation
{
private:
    P2PBlockValidationProcessor m_processor;
    P2PBlockValidationResultReady m_result_ready;

    Mutex m_mutex;
    std::condition_variable m_cv;
    std::optional<P2PBlockValidationRequest> m_request GUARDED_BY(m_mutex);
    std::optional<P2PBlockValidationResult> m_result GUARDED_BY(m_mutex);
    bool m_running GUARDED_BY(m_mutex){false};
    bool m_started GUARDED_BY(m_mutex){false};
    bool m_stopping GUARDED_BY(m_mutex){false};
    std::thread m_thread;

    void Worker() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        for (;;) {
            std::optional<P2PBlockValidationRequest> request;
            {
                WAIT_LOCK(m_mutex, lock);
                m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                    return m_stopping || m_request.has_value();
                });
                if (!m_request) return;

                request = std::move(m_request);
                m_request.reset();
                Assert(!m_running);
                m_running = true;
            }

            P2PBlockValidationResult result;
            try {
                result.new_block = m_processor(
                    request->block,
                    request->force_processing,
                    request->min_pow_checked);
            } catch (...) {
                result.error = std::current_exception();
            }

            // The terminal result never owns the block. Release it before
            // publication so collection and wakeup cannot prolong its lifetime.
            request.reset();
            {
                LOCK(m_mutex);
                Assert(m_running);
                Assert(!m_result);
                m_running = false;
                m_result = std::move(result);
            }

            // Publication precedes wakeup. A throwing wake callback is a local
            // contract violation and cannot replace or lose the terminal result.
            try {
                m_result_ready();
            } catch (...) {
                LogError("P2P block validation result callback threw\n");
            }

            {
                LOCK(m_mutex);
                if (m_stopping) return;
            }
        }
    }

public:
    P2PBlockValidationImpl(P2PBlockValidationProcessor processor,
                           P2PBlockValidationResultReady result_ready)
        : m_processor{std::move(processor)},
          m_result_ready{std::move(result_ready)}
    {
        Assert(m_processor);
        Assert(m_result_ready);
    }

    ~P2PBlockValidationImpl() override { Stop(); }

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
            Assert(request.block);
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

    void Interrupt() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_stopping = true;
        }
        m_cv.notify_one();
    }

    void Stop() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        Interrupt();
        if (m_thread.joinable()) m_thread.join();
    }
};

} // namespace

std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidation(
    P2PBlockValidationProcessor processor,
    P2PBlockValidationResultReady result_ready)
{
    return std::make_unique<P2PBlockValidationImpl>(
        std::move(processor), std::move(result_ready));
}

} // namespace node

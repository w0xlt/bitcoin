// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <sync.h>
#include <util/check.h>
#include <util/thread.h>
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
    ChainstateManager& m_chainman;
    P2PBlockValidationResultReady m_result_ready;
    Mutex m_mutex;
    std::condition_variable m_cv;
    std::optional<P2PBlockValidationRequest> m_request GUARDED_BY(m_mutex);
    std::optional<P2PBlockValidationResult> m_result GUARDED_BY(m_mutex);
    bool m_running GUARDED_BY(m_mutex){false};
    bool m_interrupted GUARDED_BY(m_mutex){false};
    std::thread m_thread;

    void Worker() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
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
                    return m_interrupted || m_request.has_value();
                });
                if (m_interrupted && !m_request) return;

                Assert(m_request.has_value());
                request = std::move(*m_request);
                m_request.reset();
                Assert(!m_running);
                m_running = true;
            }

            bool new_block{false};
            (void)m_chainman.ProcessNewBlock(
                request.block,
                request.force_processing,
                request.min_pow_checked,
                &new_block);
            request.block.reset();

            {
                LOCK(m_mutex);
                Assert(m_running);
                Assert(!m_result.has_value());
                m_running = false;
                m_result = P2PBlockValidationResult{new_block};
            }
            m_result_ready();

            {
                LOCK(m_mutex);
                if (m_interrupted && !m_request) return;
            }
        }
    }

public:
    P2PBlockValidationImpl(
        ChainstateManager& chainman,
        P2PBlockValidationResultReady result_ready)
        : m_chainman{chainman},
          m_result_ready{std::move(result_ready)},
          m_thread{&util::TraceThread, "p2p-pnb", [this] { Worker(); }}
    {
    }

    ~P2PBlockValidationImpl() override
    {
        Stop();
    }

    P2PBlockValidationSubmit Submit(P2PBlockValidationRequest request) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            if (m_interrupted) return P2PBlockValidationSubmit::INTERRUPTED;
            Assert(!m_request && !m_running && !m_result);
            Assert(request.block != nullptr);
            m_request = std::move(request);
        }
        m_cv.notify_one();
        return P2PBlockValidationSubmit::ACCEPTED;
    }

    std::optional<P2PBlockValidationResult> TakeResult() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
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
            m_interrupted = true;
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
    ChainstateManager& chainman,
    P2PBlockValidationResultReady result_ready)
{
    Assert(result_ready);
    return std::make_unique<P2PBlockValidationImpl>(chainman, std::move(result_ready));
}

} // namespace node

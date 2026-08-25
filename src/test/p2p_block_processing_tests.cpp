// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_processing.h>

#include <primitives/block.h>
#include <sync.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr auto TEST_WAIT_TIMEOUT{std::chrono::seconds{120}};

node::P2PBlockProcessingJob Job(int64_t source, uint32_t serialized_size)
{
    return {
        .source = source,
        .block = std::make_shared<const CBlock>(),
        .serialized_size = serialized_size,
        .force_processing = false,
    };
}

class FirstJobGate
{
public:
    void Wait() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        m_entered = true;
        m_cv.notify_all();
        m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_released; });
    }

    bool WaitForEntry() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, TEST_WAIT_TIMEOUT, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_entered;
        });
    }

    void Release() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_released = true;
        }
        m_cv.notify_all();
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    bool m_entered GUARDED_BY(m_mutex){false};
    bool m_released GUARDED_BY(m_mutex){false};
};

class CallbackWaiter
{
public:
    void Notify() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            ++m_count;
        }
        m_cv.notify_all();
    }

    bool WaitForCount(size_t count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, TEST_WAIT_TIMEOUT, [this, count]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_count >= count;
        });
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    size_t m_count GUARDED_BY(m_mutex){0};
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2p_block_processing_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fifo_count_capacity_and_callback_order)
{
    FirstJobGate gate;
    CallbackWaiter callbacks;
    Mutex order_mutex;
    std::vector<int64_t> order;
    std::atomic<int> active{0};
    std::atomic<int> max_active{0};
    std::atomic<bool> processor_mutex_probe{false};
    std::atomic<bool> final_callback_saw_idle{false};
    node::P2PBlockProcessing* processing_ptr{nullptr};

    auto processing{node::MakeP2PBlockProcessing(
        [&](const node::P2PBlockProcessingJob& job) {
            const int now_active{++active};
            max_active = std::max(max_active.load(), now_active);
            // Both callbacks must run without the component mutex held.
            processor_mutex_probe = processing_ptr->CanSubmit(/*serialized_size=*/0);
            {
                LOCK(order_mutex);
                order.push_back(job.source);
            }
            if (job.source == 0) gate.Wait();
            --active;
        },
        [&] {
            final_callback_saw_idle = processing_ptr->IsIdle();
            (void)processing_ptr->CanSubmit(/*serialized_size=*/0);
            callbacks.Notify();
        })};
    processing_ptr = processing.get();

    BOOST_REQUIRE(processing->CanSubmit(/*serialized_size=*/1));
    BOOST_REQUIRE(processing->Submit(Job(/*source=*/0, /*serialized_size=*/1)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);
    BOOST_REQUIRE(gate.WaitForEntry());

    // Admission remains nonblocking while the active processor is held. The
    // active job and seven queued jobs consume the complete count capacity.
    for (int64_t source{1}; source < int64_t{node::P2P_BLOCK_PROCESSING_MAX_JOBS}; ++source) {
        BOOST_REQUIRE(processing->CanSubmit(/*serialized_size=*/1));
        BOOST_REQUIRE(processing->Submit(Job(source, /*serialized_size=*/1)) ==
                      node::P2PBlockProcessingSubmit::ACCEPTED);
    }
    BOOST_CHECK(!processing->CanSubmit(/*serialized_size=*/1));
    BOOST_CHECK(!processing->IsIdle());

    gate.Release();
    BOOST_REQUIRE(callbacks.WaitForCount(node::P2P_BLOCK_PROCESSING_MAX_JOBS));
    BOOST_CHECK(processing->IsIdle());
    BOOST_CHECK(final_callback_saw_idle);
    BOOST_CHECK(processor_mutex_probe);
    BOOST_CHECK_EQUAL(max_active.load(), 1);

    std::vector<int64_t> observed;
    {
        LOCK(order_mutex);
        observed = order;
    }
    std::vector<int64_t> expected;
    for (int64_t source{0}; source < int64_t{node::P2P_BLOCK_PROCESSING_MAX_JOBS}; ++source) {
        expected.push_back(source);
    }
    BOOST_CHECK(observed == expected);
    BOOST_CHECK(processing->Stop().empty());
}

BOOST_AUTO_TEST_CASE(byte_capacity_includes_active_and_queued)
{
    FirstJobGate gate;
    CallbackWaiter callbacks;
    node::P2PBlockProcessing* processing_ptr{nullptr};
    auto processing{node::MakeP2PBlockProcessing(
        [&](const node::P2PBlockProcessingJob& job) {
            (void)processing_ptr->IsIdle();
            if (job.source == 0) gate.Wait();
        },
        [&] {
            (void)processing_ptr->CanSubmit(/*serialized_size=*/0);
            callbacks.Notify();
        })};
    processing_ptr = processing.get();

    BOOST_REQUIRE(processing->Submit(Job(/*source=*/0, /*serialized_size=*/1)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);
    BOOST_REQUIRE(gate.WaitForEntry());
    BOOST_REQUIRE(processing->CanSubmit(node::P2P_BLOCK_PROCESSING_MAX_BYTES - 1));
    BOOST_REQUIRE(processing->Submit(Job(
                      /*source=*/1, node::P2P_BLOCK_PROCESSING_MAX_BYTES - 1)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);
    BOOST_CHECK(!processing->CanSubmit(/*serialized_size=*/1));
    BOOST_CHECK(!processing->CanSubmit(node::P2P_BLOCK_PROCESSING_MAX_BYTES + 1U));

    gate.Release();
    BOOST_REQUIRE(callbacks.WaitForCount(2));
    BOOST_CHECK(processing->IsIdle());
    BOOST_CHECK(processing->Stop().empty());
}

BOOST_AUTO_TEST_CASE(payload_released_before_state_change)
{
    CallbackWaiter callbacks;
    std::weak_ptr<const CBlock> retained;
    std::atomic<bool> callback_saw_release{false};
    auto processing{node::MakeP2PBlockProcessing(
        [](const node::P2PBlockProcessingJob&) {},
        [&] {
            callback_saw_release = retained.expired();
            callbacks.Notify();
        })};

    auto job{Job(/*source=*/0, /*serialized_size=*/1)};
    retained = job.block;
    BOOST_REQUIRE(processing->Submit(std::move(job)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);
    BOOST_REQUIRE(callbacks.WaitForCount(1));
    BOOST_CHECK(callback_saw_release);
    BOOST_CHECK(processing->IsIdle());
    BOOST_CHECK(processing->Stop().empty());
}

BOOST_AUTO_TEST_CASE(interrupt_finishes_active_and_cancels_queue)
{
    FirstJobGate gate;
    CallbackWaiter callbacks;
    std::atomic<int> process_count{0};
    node::P2PBlockProcessing* processing_ptr{nullptr};
    auto processing{node::MakeP2PBlockProcessing(
        [&](const node::P2PBlockProcessingJob& job) {
            ++process_count;
            (void)processing_ptr->CanSubmit(/*serialized_size=*/0);
            if (job.source == 0) gate.Wait();
        },
        [&] {
            (void)processing_ptr->IsIdle();
            callbacks.Notify();
        })};
    processing_ptr = processing.get();

    BOOST_REQUIRE(processing->Submit(Job(/*source=*/0, /*serialized_size=*/1)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);
    BOOST_REQUIRE(gate.WaitForEntry());
    BOOST_REQUIRE(processing->Submit(Job(/*source=*/1, /*serialized_size=*/2)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);
    BOOST_REQUIRE(processing->Submit(Job(/*source=*/2, /*serialized_size=*/3)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);

    std::promise<void> stop_started;
    auto stop_started_future{stop_started.get_future()};
    std::promise<node::P2PBlockProcessingCanceled> stopped;
    auto stopped_future{stopped.get_future()};
    std::thread stop_thread{[&] {
        stop_started.set_value();
        stopped.set_value(processing->Stop());
    }};
    BOOST_REQUIRE(stop_started_future.wait_for(TEST_WAIT_TIMEOUT) == std::future_status::ready);
    BOOST_CHECK(stopped_future.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
    BOOST_CHECK_EQUAL(process_count.load(), 1);

    gate.Release();
    BOOST_REQUIRE(stopped_future.wait_for(TEST_WAIT_TIMEOUT) == std::future_status::ready);
    auto canceled{stopped_future.get()};
    stop_thread.join();

    BOOST_REQUIRE(callbacks.WaitForCount(1));
    BOOST_CHECK_EQUAL(process_count.load(), 1);
    BOOST_REQUIRE_EQUAL(canceled.size(), 2U);
    BOOST_CHECK_EQUAL(canceled[0].source, 1);
    BOOST_CHECK_EQUAL(canceled[1].source, 2);
    BOOST_CHECK(processing->IsIdle());
    BOOST_CHECK(!processing->CanSubmit(/*serialized_size=*/1));
    BOOST_CHECK(processing->Submit(Job(/*source=*/3, /*serialized_size=*/1)) ==
                node::P2PBlockProcessingSubmit::INTERRUPTED);

    processing->Interrupt();
    processing->Interrupt();
    BOOST_CHECK(processing->Stop().empty());
    BOOST_CHECK(processing->Stop().empty());
}

BOOST_AUTO_TEST_CASE(active_processor_interrupt_prevents_queue_promotion)
{
    FirstJobGate gate;
    CallbackWaiter callbacks;
    std::atomic<int> process_count{0};
    node::P2PBlockProcessing* processing_ptr{nullptr};
    auto processing{node::MakeP2PBlockProcessing(
        [&](const node::P2PBlockProcessingJob& job) {
            ++process_count;
            if (job.source == 0) {
                gate.Wait();
                // Production uses this exact nonjoining transition when the
                // active PNB synchronously requests shutdown (-stopatheight).
                processing_ptr->Interrupt();
            }
        },
        [&] { callbacks.Notify(); })};
    processing_ptr = processing.get();

    BOOST_REQUIRE(processing->Submit(Job(/*source=*/0, /*serialized_size=*/1)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);
    BOOST_REQUIRE(gate.WaitForEntry());
    BOOST_REQUIRE(processing->Submit(Job(/*source=*/1, /*serialized_size=*/1)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);
    BOOST_REQUIRE(processing->Submit(Job(/*source=*/2, /*serialized_size=*/1)) ==
                  node::P2PBlockProcessingSubmit::ACCEPTED);

    gate.Release();
    BOOST_REQUIRE(callbacks.WaitForCount(1));
    const auto canceled{processing->Stop()};
    BOOST_CHECK_EQUAL(process_count.load(), 1);
    BOOST_REQUIRE_EQUAL(canceled.size(), 2U);
    BOOST_CHECK_EQUAL(canceled[0].source, 1);
    BOOST_CHECK_EQUAL(canceled[1].source, 2);
}

BOOST_AUTO_TEST_SUITE_END()

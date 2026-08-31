// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <primitives/block.h>
#include <sync.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace {

class ProcessorGate
{
public:
    bool Process(const std::shared_ptr<const CBlock>&,
                 bool force_processing,
                 bool min_pow_checked) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        const int call{++m_calls};
        ++m_active;
        m_max_active = std::max(m_max_active, m_active);
        m_force_processing = force_processing;
        m_min_pow_checked = min_pow_checked;
        m_cv.notify_all();
        m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_released >= call;
        });
        --m_active;
        if (m_throw_call == call) throw std::runtime_error{"processor failure"};
        return call % 2 != 0;
    }

    void WaitForCalls(int count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_calls >= count;
        });
    }

    void Release(int count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_released = count;
        }
        m_cv.notify_all();
    }

    void ThrowOnCall(int call) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_throw_call = call;
    }

    int MaxActive() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_max_active;
    }

    bool ForceProcessing() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_force_processing;
    }

    bool MinPowChecked() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_min_pow_checked;
    }

private:
    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    int m_calls GUARDED_BY(m_mutex){0};
    int m_active GUARDED_BY(m_mutex){0};
    int m_max_active GUARDED_BY(m_mutex){0};
    int m_released GUARDED_BY(m_mutex){0};
    int m_throw_call GUARDED_BY(m_mutex){0};
    bool m_force_processing GUARDED_BY(m_mutex){false};
    bool m_min_pow_checked GUARDED_BY(m_mutex){false};
};

class ReadySignal
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

    void WaitFor(int count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_count >= count;
        });
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    int m_count GUARDED_BY(m_mutex){0};
};

node::P2PBlockValidationRequest Request(
    std::shared_ptr<const CBlock> block = std::make_shared<const CBlock>(),
    bool force_processing = true,
    bool min_pow_checked = true)
{
    return {
        .block = std::move(block),
        .force_processing = force_processing,
        .min_pow_checked = min_pow_checked,
    };
}

} // namespace

BOOST_AUTO_TEST_SUITE(p2p_block_validation_tests)

BOOST_AUTO_TEST_CASE(single_slot_is_serial_and_collectible_once)
{
    ProcessorGate gate;
    ReadySignal ready;
    auto validation{node::MakeP2PBlockValidation(
        [&](const auto& block, bool force, bool min_pow) {
            return gate.Process(block, force, min_pow);
        },
        [&] { ready.Notify(); })};
    validation->Start();

    BOOST_REQUIRE(validation->Submit(Request(std::make_shared<const CBlock>(), true, false)) ==
                  node::P2PBlockValidationSubmit::ACCEPTED);
    gate.WaitForCalls(1);
    BOOST_CHECK(validation->Submit(Request()) == node::P2PBlockValidationSubmit::FULL);
    gate.Release(1);
    ready.WaitFor(1);
    BOOST_CHECK(validation->Submit(Request()) == node::P2PBlockValidationSubmit::FULL);

    auto first{validation->TakeResult()};
    BOOST_REQUIRE(first);
    BOOST_CHECK(first->new_block);
    BOOST_CHECK(!first->error);
    BOOST_CHECK(!validation->TakeResult());
    BOOST_CHECK(gate.ForceProcessing());
    BOOST_CHECK(!gate.MinPowChecked());

    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    gate.WaitForCalls(2);
    BOOST_CHECK(validation->Submit(Request()) == node::P2PBlockValidationSubmit::FULL);
    gate.Release(2);
    ready.WaitFor(2);

    auto second{validation->TakeResult()};
    BOOST_REQUIRE(second);
    BOOST_CHECK(!second->new_block);
    BOOST_CHECK(!second->error);
    BOOST_CHECK(!validation->TakeResult());
    BOOST_CHECK_EQUAL(gate.MaxActive(), 1);
    validation->Stop();
}

BOOST_AUTO_TEST_CASE(result_is_published_before_wake_and_taken_once)
{
    ReadySignal callback_done;
    node::P2PBlockValidation* validation_ptr{nullptr};
    std::optional<node::P2PBlockValidationResult> callback_result;
    auto validation{node::MakeP2PBlockValidation(
        [](const auto&, bool, bool) { return true; },
        [&] {
            callback_result = validation_ptr->TakeResult();
            callback_done.Notify();
        })};
    validation_ptr = validation.get();
    validation->Start();

    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    callback_done.WaitFor(1);
    BOOST_REQUIRE(callback_result);
    BOOST_CHECK(callback_result->new_block);
    BOOST_CHECK(!callback_result->error);
    BOOST_CHECK(!validation->TakeResult());
    validation->Stop();
}

BOOST_AUTO_TEST_CASE(processor_exception_is_terminal_and_worker_survives)
{
    ProcessorGate gate;
    gate.ThrowOnCall(1);
    ReadySignal ready;
    auto validation{node::MakeP2PBlockValidation(
        [&](const auto& block, bool force, bool min_pow) {
            return gate.Process(block, force, min_pow);
        },
        [&] { ready.Notify(); })};
    validation->Start();

    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    gate.WaitForCalls(1);
    gate.Release(1);
    ready.WaitFor(1);
    auto failed{validation->TakeResult()};
    BOOST_REQUIRE(failed);
    BOOST_CHECK(!failed->new_block);
    BOOST_REQUIRE(failed->error);
    BOOST_CHECK_EXCEPTION(std::rethrow_exception(failed->error), std::runtime_error,
                          [](const std::runtime_error& e) {
                              return std::string{e.what()} == "processor failure";
                          });

    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    gate.WaitForCalls(2);
    gate.Release(2);
    ready.WaitFor(2);
    auto recovered{validation->TakeResult()};
    BOOST_REQUIRE(recovered);
    BOOST_CHECK(!recovered->new_block);
    BOOST_CHECK(!recovered->error);
    validation->Stop();
}

BOOST_AUTO_TEST_CASE(throwing_wake_preserves_result_and_worker)
{
    ReadySignal wake_entered;
    auto validation{node::MakeP2PBlockValidation(
        [](const auto&, bool, bool) { return true; },
        [&] {
            wake_entered.Notify();
            throw std::runtime_error{"wake failure"};
        })};
    validation->Start();

    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    wake_entered.WaitFor(1);
    auto first{validation->TakeResult()};
    BOOST_REQUIRE(first);
    BOOST_CHECK(first->new_block);
    BOOST_CHECK(!first->error);

    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    wake_entered.WaitFor(2);
    auto second{validation->TakeResult()};
    BOOST_REQUIRE(second);
    BOOST_CHECK(second->new_block);
    BOOST_CHECK(!second->error);
    validation->Stop();
}

BOOST_AUTO_TEST_CASE(interrupt_drains_active_work_and_is_idempotent)
{
    ProcessorGate gate;
    ReadySignal ready;
    auto validation{node::MakeP2PBlockValidation(
        [&](const auto& block, bool force, bool min_pow) {
            return gate.Process(block, force, min_pow);
        },
        [&] { ready.Notify(); })};
    validation->Start();
    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    gate.WaitForCalls(1);

    validation->Interrupt();
    validation->Interrupt();
    BOOST_CHECK(validation->Submit(Request()) == node::P2PBlockValidationSubmit::STOPPING);
    gate.Release(1);
    ready.WaitFor(1);
    validation->Stop();
    validation->Stop();
    validation->Interrupt();

    auto result{validation->TakeResult()};
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->new_block);
    BOOST_CHECK(!result->error);
}

BOOST_AUTO_TEST_CASE(stop_joins_active_work)
{
    ProcessorGate gate;
    ReadySignal ready;
    auto validation{node::MakeP2PBlockValidation(
        [&](const auto& block, bool force, bool min_pow) {
            return gate.Process(block, force, min_pow);
        },
        [&] { ready.Notify(); })};
    validation->Start();
    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    gate.WaitForCalls(1);

    std::promise<void> stop_started;
    std::promise<void> stop_completed;
    auto started{stop_started.get_future()};
    auto completed{stop_completed.get_future()};
    std::thread stopper{[&] {
        stop_started.set_value();
        validation->Stop();
        stop_completed.set_value();
    }};
    started.wait();
    BOOST_CHECK(completed.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
    gate.Release(1);
    completed.wait();
    stopper.join();

    auto result{validation->TakeResult()};
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->new_block);
    BOOST_CHECK(!result->error);
}

BOOST_AUTO_TEST_CASE(result_ready_stop_preserves_result)
{
    ReadySignal ready;
    auto validation{node::MakeP2PBlockValidation(
        [](const auto&, bool, bool) { return true; },
        [&] { ready.Notify(); })};
    validation->Start();
    BOOST_REQUIRE(validation->Submit(Request()) == node::P2PBlockValidationSubmit::ACCEPTED);
    ready.WaitFor(1);

    validation->Stop();
    validation->Stop();
    BOOST_CHECK(validation->Submit(Request()) == node::P2PBlockValidationSubmit::STOPPING);
    auto result{validation->TakeResult()};
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->new_block);
    BOOST_CHECK(!result->error);
}

BOOST_AUTO_TEST_CASE(block_ownership_is_released_before_wake)
{
    ReadySignal ready;
    std::weak_ptr<const CBlock> weak_block;
    std::atomic<bool> expired_on_wake{false};
    auto validation{node::MakeP2PBlockValidation(
        [](const auto&, bool, bool) { return false; },
        [&] {
            expired_on_wake = weak_block.expired();
            ready.Notify();
        })};
    validation->Start();

    auto block{std::make_shared<const CBlock>()};
    weak_block = block;
    BOOST_REQUIRE(validation->Submit(Request(std::move(block))) ==
                  node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_CHECK(!block);
    ready.WaitFor(1);
    BOOST_CHECK(expired_on_wake);
    BOOST_CHECK(weak_block.expired());
    BOOST_REQUIRE(validation->TakeResult());
    validation->Stop();
}

BOOST_AUTO_TEST_CASE(idle_and_prestart_stop_are_idempotent)
{
    ReadySignal ready;
    {
        auto validation{node::MakeP2PBlockValidation(
            [](const auto&, bool, bool) { return false; },
            [&] { ready.Notify(); })};
        validation->Stop();
        validation->Stop();
        validation->Interrupt();
        BOOST_CHECK(validation->Submit(Request()) == node::P2PBlockValidationSubmit::STOPPING);
        BOOST_CHECK(!validation->TakeResult());
    }
    {
        auto validation{node::MakeP2PBlockValidation(
            [](const auto&, bool, bool) { return false; },
            [&] { ready.Notify(); })};
        validation->Start();
        validation->Stop();
        validation->Stop();
        BOOST_CHECK(validation->Submit(Request()) == node::P2PBlockValidationSubmit::STOPPING);
        BOOST_CHECK(!validation->TakeResult());
    }
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <util/task_runner.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <thread>
#include <utility>

namespace {

constexpr auto TEST_WAIT_TIMEOUT{std::chrono::seconds{120}};

class ResultWaiter
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

    bool WaitForCount(int expected) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, TEST_WAIT_TIMEOUT, [this, expected]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_count >= expected;
        });
    }

    int Count() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_count;
    }

private:
    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    int m_count GUARDED_BY(m_mutex){0};
};

class BlockCheckedRecorder final : public CValidationInterface
{
public:
    int Count() const { return m_count.load(); }
    bool Invalid() const { return m_invalid.load(); }

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState& state) override
    {
        m_invalid = state.IsInvalid();
        ++m_count;
    }

private:
    std::atomic<int> m_count{0};
    std::atomic<bool> m_invalid{false};
};

class DirectCallbackSequence final : public CValidationInterface
{
public:
    int RecordReady() { return ++m_sequence; }
    int ValidBlockChecked() const { return m_valid_block_checked.load(); }
    int InvalidBlockChecked() const { return m_invalid_block_checked.load(); }
    int NewPoWValidBlockSequence() const { return m_new_pow_valid_block.load(); }

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState& state) override
    {
        const int sequence{++m_sequence};
        if (state.IsInvalid()) {
            m_invalid_block_checked = sequence;
        } else if (state.IsValid()) {
            m_valid_block_checked = sequence;
        }
    }

    void NewPoWValidBlock(const CBlockIndex*, const std::shared_ptr<const CBlock>&) override
    {
        m_new_pow_valid_block = ++m_sequence;
    }

private:
    std::atomic<int> m_sequence{0};
    std::atomic<int> m_valid_block_checked{0};
    std::atomic<int> m_invalid_block_checked{0};
    std::atomic<int> m_new_pow_valid_block{0};
};

class ManualTaskRunner final : public util::TaskRunnerInterface
{
public:
    void insert(std::function<void()> func) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            if (m_hold) {
                m_tasks.push_back(std::move(func));
                m_cv.notify_all();
                return;
            }
        }
        func();
    }

    void flush() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) { RunAll(); }

    size_t size() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_tasks.size();
    }

    void Hold() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_hold = true;
    }

    bool WaitForSize(size_t expected) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, TEST_WAIT_TIMEOUT, [this, expected]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_tasks.size() >= expected;
        });
    }

    void RunAll() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        for (;;) {
            std::function<void()> task;
            {
                LOCK(m_mutex);
                if (m_tasks.empty()) return;
                task = std::move(m_tasks.front());
                m_tasks.pop_front();
            }
            task();
        }
    }

    void ReleaseAndRunAll() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_hold = false;
        }
        RunAll();
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::function<void()>> m_tasks GUARDED_BY(m_mutex);
    bool m_hold GUARDED_BY(m_mutex){false};
};

class ManualTaskRunnerSetup : public ChainTestingSetup
{
public:
    ManualTaskRunner* m_task_runner{nullptr};

    ManualTaskRunnerSetup()
        : ChainTestingSetup{ChainType::REGTEST, TestOpts{.setup_net = false, .setup_validation_interface = false}}
    {
        m_node.chainman.reset();
        auto task_runner{std::make_unique<ManualTaskRunner>()};
        m_task_runner = task_runner.get();
        m_node.validation_signals = std::make_unique<ValidationSignals>(std::move(task_runner));
        m_make_chainman();
        LoadVerifyActivateChainstate();
    }
};

class BlockingBlockChecked final : public CValidationInterface
{
public:
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
            m_release = true;
        }
        m_cv.notify_all();
    }

    bool Completed() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_completed;
    }

    bool ReleaseObserved() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_release_observed;
    }

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState&) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        m_entered = true;
        m_cv.notify_all();
        m_release_observed = m_cv.wait_for(lock, TEST_WAIT_TIMEOUT, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_release;
        });
        m_completed = true;
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    bool m_entered GUARDED_BY(m_mutex){false};
    bool m_release GUARDED_BY(m_mutex){false};
    bool m_release_observed GUARDED_BY(m_mutex){false};
    bool m_completed GUARDED_BY(m_mutex){false};
};

node::P2PBlockValidationRequest GenesisRequest()
{
    return {
        .block = std::make_shared<const CBlock>(Params().GenesisBlock()),
        .force_processing = true,
        .min_pow_checked = true,
    };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2p_block_validation_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(duplicate_known_block_result)
{
    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};

    BOOST_REQUIRE(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(ready.WaitForCount(1));
    BOOST_CHECK_EQUAL(ready.Count(), 1);

    const auto result{validation->TakeResult()};
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(!result->new_block);
    BOOST_CHECK(!validation->TakeResult().has_value());
}

BOOST_AUTO_TEST_CASE(processing_failure_is_not_validity)
{
    auto block_checked{std::make_shared<BlockCheckedRecorder>()};
    m_node.validation_signals->RegisterSharedValidationInterface(block_checked);

    ResultWaiter ready;
    std::atomic<bool> block_checked_before_ready{false};
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] {
        block_checked_before_ready = block_checked->Count() == 1 && block_checked->Invalid();
        ready.Notify();
    })};

    BOOST_REQUIRE(validation->Submit({
        .block = std::make_shared<const CBlock>(),
        .force_processing = true,
        .min_pow_checked = true,
    }) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(ready.WaitForCount(1));
    validation->Stop();
    const auto result{validation->TakeResult()};
    m_node.validation_signals->UnregisterSharedValidationInterface(block_checked);

    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(!result->new_block);
    BOOST_CHECK_EQUAL(block_checked->Count(), 1);
    BOOST_CHECK(block_checked->Invalid());
    BOOST_CHECK(block_checked_before_ready);
}

BOOST_AUTO_TEST_CASE(sequential_reuse_after_collection)
{
    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};

    BOOST_REQUIRE(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(ready.WaitForCount(1));
    const auto first_result{validation->TakeResult()};
    BOOST_REQUIRE(first_result.has_value());
    BOOST_CHECK(!first_result->new_block);

    BOOST_REQUIRE(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(ready.WaitForCount(2));
    validation->Stop();
    const auto second_result{validation->TakeResult()};

    BOOST_REQUIRE(second_result.has_value());
    BOOST_CHECK(!second_result->new_block);
    BOOST_CHECK_EQUAL(ready.Count(), 2);
    BOOST_CHECK(!validation->TakeResult().has_value());
}

BOOST_AUTO_TEST_CASE(interrupt_before_submission)
{
    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};

    validation->Interrupt();
    validation->Interrupt();
    BOOST_CHECK(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::INTERRUPTED);
    BOOST_CHECK(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::INTERRUPTED);
    validation->Stop();
    validation->Stop();
    validation->Interrupt();

    BOOST_CHECK_EQUAL(ready.Count(), 0);
    BOOST_CHECK(!validation->TakeResult().has_value());
}

BOOST_AUTO_TEST_CASE(stop_preserves_accepted_work)
{
    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};

    BOOST_REQUIRE(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::ACCEPTED);
    validation->Stop();

    BOOST_CHECK_EQUAL(ready.Count(), 1);
    const auto result{validation->TakeResult()};
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(!result->new_block);
    BOOST_CHECK(!validation->TakeResult().has_value());
}

BOOST_AUTO_TEST_CASE(idle_repeated_lifecycle)
{
    ResultWaiter ready;
    {
        auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};
        validation->Interrupt();
        validation->Interrupt();
        validation->Stop();
        validation->Stop();
    }
    BOOST_CHECK_EQUAL(ready.Count(), 0);
}

BOOST_FIXTURE_TEST_CASE(direct_callbacks_precede_result_publication, TestChain100Setup)
{
    auto sequence{std::make_shared<DirectCallbackSequence>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sequence);
    auto& chainman{static_cast<TestChainstateManager&>(*m_node.chainman)};
    if (chainman.IsInitialBlockDownload()) chainman.JumpOutOfIbd();

    const CScript script_pub_key{CScript{} << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    const auto valid_block{std::make_shared<const CBlock>(CreateBlock({}, script_pub_key))};
    ResultWaiter valid_ready;
    std::atomic<int> valid_ready_sequence{0};
    auto valid_validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] {
        valid_ready_sequence = sequence->RecordReady();
        valid_ready.Notify();
    })};
    const auto valid_submit{valid_validation->Submit({valid_block, true, true})};
    const bool valid_completed{valid_ready.WaitForCount(1)};
    valid_validation->Stop();
    const auto valid_result{valid_validation->TakeResult()};

    ResultWaiter invalid_ready;
    std::atomic<int> invalid_ready_sequence{0};
    auto invalid_validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] {
        invalid_ready_sequence = sequence->RecordReady();
        invalid_ready.Notify();
    })};
    const auto invalid_submit{invalid_validation->Submit({std::make_shared<const CBlock>(), true, true})};
    const bool invalid_completed{invalid_ready.WaitForCount(1)};
    invalid_validation->Stop();
    const auto invalid_result{invalid_validation->TakeResult()};
    m_node.validation_signals->UnregisterSharedValidationInterface(sequence);

    BOOST_REQUIRE(valid_submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(valid_completed);
    BOOST_REQUIRE(valid_result.has_value());
    BOOST_CHECK(valid_result->new_block);
    BOOST_CHECK(sequence->ValidBlockChecked() > 0);
    BOOST_CHECK(sequence->NewPoWValidBlockSequence() > 0);
    BOOST_CHECK(sequence->ValidBlockChecked() < valid_ready_sequence.load());
    BOOST_CHECK(sequence->NewPoWValidBlockSequence() < valid_ready_sequence.load());
    BOOST_REQUIRE(invalid_submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(invalid_completed);
    BOOST_REQUIRE(invalid_result.has_value());
    BOOST_CHECK(!invalid_result->new_block);
    BOOST_CHECK(sequence->InvalidBlockChecked() > 0);
    BOOST_CHECK(sequence->InvalidBlockChecked() < invalid_ready_sequence.load());
}

BOOST_FIXTURE_TEST_CASE(validation_interface_queue_pressure, ManualTaskRunnerSetup)
{
    const auto block{CreateBlockChain(1, Params()).front()};
    m_task_runner->Hold();
    for (int i{0}; i < 11; ++i) {
        m_node.validation_signals->CallFunctionInValidationInterfaceQueue([] {});
    }
    BOOST_REQUIRE_EQUAL(m_task_runner->size(), 11U);

    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};
    const auto submit{validation->Submit({block, true, true})};
    const bool queue_limited{m_task_runner->WaitForSize(12)};
    const size_t held_size{m_task_runner->size()};
    const int ready_while_held{ready.Count()};
    m_task_runner->ReleaseAndRunAll();
    const bool completed{ready.WaitForCount(1)};
    validation->Stop();
    const auto result{validation->TakeResult()};
    m_node.validation_signals->FlushBackgroundCallbacks();

    BOOST_REQUIRE(submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(queue_limited);
    BOOST_CHECK_EQUAL(held_size, 12U);
    BOOST_CHECK_EQUAL(ready_while_held, 0);
    BOOST_REQUIRE(completed);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(result->new_block);
    BOOST_CHECK_EQUAL(ready.Count(), 1);
}

BOOST_AUTO_TEST_CASE(stop_while_direct_callback_held)
{
    auto block_checked{std::make_shared<BlockingBlockChecked>()};
    m_node.validation_signals->RegisterSharedValidationInterface(block_checked);
    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};
    const auto submit{validation->Submit({std::make_shared<const CBlock>(), true, true})};
    const bool callback_entered{block_checked->WaitForEntry()};
    if (!callback_entered) {
        block_checked->Release();
        validation->Stop();
        m_node.validation_signals->UnregisterSharedValidationInterface(block_checked);
        BOOST_REQUIRE(callback_entered);
    }

    std::promise<void> stop_started;
    auto stop_started_future{stop_started.get_future()};
    std::thread stop_thread{[&] {
        stop_started.set_value();
        validation->Stop();
    }};
    const bool stop_started_observed{stop_started_future.wait_for(TEST_WAIT_TIMEOUT) == std::future_status::ready};
    block_checked->Release();
    stop_thread.join();

    const auto result{validation->TakeResult()};
    m_node.validation_signals->UnregisterSharedValidationInterface(block_checked);
    BOOST_REQUIRE(submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(stop_started_observed);
    BOOST_CHECK(block_checked->Completed());
    BOOST_CHECK(block_checked->ReleaseObserved());
    BOOST_CHECK_EQUAL(ready.Count(), 1);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(!result->new_block);
}

BOOST_AUTO_TEST_SUITE_END()

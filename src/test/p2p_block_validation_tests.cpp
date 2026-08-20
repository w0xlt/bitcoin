// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <node/mining_types.h>
#include <primitives/block.h>
#include <scheduler.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <test/util/validation.h>
#include <util/task_runner.h>
#include <util/translation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
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
        m_cv.notify_one();
    }

    bool WaitForCount(int expected) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, TEST_WAIT_TIMEOUT, [this, expected]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_count.load() >= expected;
        });
    }

    int Count() const
    {
        return m_count.load();
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<int> m_count{0};
};

class BlockCheckedRecorder final : public CValidationInterface
{
public:
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState& state) override
    {
        m_invalid = state.IsInvalid();
        ++m_count;
    }

    int Count() const
    {
        return m_count.load();
    }

    bool Invalid() const
    {
        return m_invalid.load();
    }

private:
    std::atomic<int> m_count{0};
    std::atomic<bool> m_invalid{false};
};

class ThrowOnceBlockChecked final : public CValidationInterface
{
public:
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState&) override
    {
        if (!m_thrown.exchange(true)) {
            throw std::runtime_error{"test P2P block validation exception"};
        }
    }

    bool Thrown() const { return m_thrown.load(); }

private:
    std::atomic<bool> m_thrown{false};
};

class DirectCallbackSequence final : public CValidationInterface
{
public:
    int RecordReady() { return ++m_sequence; }
    int ValidBlockChecked() const { return m_valid_block_checked.load(); }
    int InvalidBlockChecked() const { return m_invalid_block_checked.load(); }
    int NewPoWValidBlockSequence() const { return m_new_pow_valid_block.load(); }

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

class BlockingBlockChecked final : public CValidationInterface
{
public:
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

BOOST_AUTO_TEST_CASE(exact_duplicate_result)
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

BOOST_AUTO_TEST_CASE(capacity_busy_until_result_taken)
{
    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};

    BOOST_REQUIRE(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_CHECK(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::BUSY);

    BOOST_REQUIRE(ready.WaitForCount(1));
    BOOST_CHECK(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::BUSY);

    const auto first_result{validation->TakeResult()};
    BOOST_REQUIRE(first_result.has_value());
    BOOST_CHECK(!first_result->new_block);
    BOOST_CHECK(!validation->TakeResult().has_value());

    BOOST_REQUIRE(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(ready.WaitForCount(2));
    BOOST_CHECK_EQUAL(ready.Count(), 2);

    const auto second_result{validation->TakeResult()};
    BOOST_REQUIRE(second_result.has_value());
    BOOST_CHECK(!second_result->new_block);
    BOOST_CHECK(!validation->TakeResult().has_value());
}

BOOST_AUTO_TEST_CASE(processing_failure_is_not_validity)
{
    BlockCheckedRecorder block_checked;
    m_node.validation_signals->RegisterValidationInterface(&block_checked);

    ResultWaiter ready;
    std::atomic<bool> block_checked_before_ready{false};
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] {
        block_checked_before_ready = block_checked.Count() == 1 && block_checked.Invalid();
        ready.Notify();
    })};

    BOOST_REQUIRE(validation->Submit({
        .block = std::make_shared<const CBlock>(),
        .force_processing = true,
        .min_pow_checked = true,
    }) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(ready.WaitForCount(1));
    BOOST_CHECK_EQUAL(block_checked.Count(), 1);
    BOOST_CHECK(block_checked.Invalid());
    BOOST_CHECK(block_checked_before_ready);
    BOOST_CHECK_EQUAL(ready.Count(), 1);

    const auto result{validation->TakeResult()};
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(!result->new_block);
    BOOST_CHECK(!validation->TakeResult().has_value());

    validation->Stop();
    m_node.validation_signals->UnregisterValidationInterface(&block_checked);
}

BOOST_AUTO_TEST_CASE(process_exception_publishes_result_and_worker_survives)
{
    auto throw_once{std::make_shared<ThrowOnceBlockChecked>()};
    m_node.validation_signals->RegisterSharedValidationInterface(throw_once);
    // The exception skips signal cleanup, so keep this registration until fixture teardown.

    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};

    BOOST_REQUIRE(validation->Submit({
        .block = std::make_shared<const CBlock>(),
        .force_processing = true,
        .min_pow_checked = true,
    }) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(ready.WaitForCount(1));
    BOOST_CHECK_EQUAL(ready.Count(), 1);

    const auto first_result{validation->TakeResult()};
    BOOST_REQUIRE(first_result.has_value());
    BOOST_REQUIRE(!first_result->new_block);
    BOOST_REQUIRE(throw_once->Thrown());
    BOOST_CHECK(!validation->TakeResult().has_value());

    BOOST_REQUIRE(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(ready.WaitForCount(2));
    BOOST_CHECK_EQUAL(ready.Count(), 2);

    const auto second_result{validation->TakeResult()};
    BOOST_REQUIRE(second_result.has_value());
    BOOST_REQUIRE(!second_result->new_block);
    BOOST_CHECK(!validation->TakeResult().has_value());
    validation->Stop();
}

BOOST_AUTO_TEST_CASE(interrupt_before_submission)
{
    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};

    validation->Interrupt();
    validation->Interrupt();
    BOOST_CHECK(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::INTERRUPTED);
    BOOST_CHECK(validation->Submit(GenesisRequest()) == node::P2PBlockValidationSubmit::INTERRUPTED);
    BOOST_CHECK(!validation->TakeResult().has_value());
    validation->Stop();
    validation->Stop();
    BOOST_CHECK_EQUAL(ready.Count(), 0);
}

BOOST_AUTO_TEST_CASE(stop_preserves_accepted_work)
{
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

    ResultWaiter ready;
    Mutex callback_mutex;
    std::condition_variable callback_cv;
    bool first_callback_entered{false};
    bool release_first_callback{false};
    std::atomic<int> callback_count{0};
    std::atomic<bool> first_callback_released{false};
    auto first_request{GenesisRequest()};
    auto second_request{GenesisRequest()};
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] {
        const int count{++callback_count};
        if (count == 1) {
            WAIT_LOCK(callback_mutex, lock);
            first_callback_entered = true;
            callback_cv.notify_one();
            first_callback_released = callback_cv.wait_for(
                lock, TEST_WAIT_TIMEOUT, [&]() EXCLUSIVE_LOCKS_REQUIRED(callback_mutex) {
                    return release_first_callback;
                });
        }
        ready.Notify();
    })};

    const auto first_submit{validation->Submit(std::move(first_request))};
    bool callback_entered{false};
    if (first_submit == node::P2PBlockValidationSubmit::ACCEPTED) {
        WAIT_LOCK(callback_mutex, lock);
        callback_entered = callback_cv.wait_for(
            lock, TEST_WAIT_TIMEOUT, [&]() EXCLUSIVE_LOCKS_REQUIRED(callback_mutex) {
                return first_callback_entered;
            });
    }

    std::optional<node::P2PBlockValidationResult> first_result;
    node::P2PBlockValidationSubmit second_submit{node::P2PBlockValidationSubmit::BUSY};
    if (callback_entered) {
        first_result = validation->TakeResult();
        second_submit = validation->Submit(std::move(second_request));
    }
    validation->Interrupt();

    {
        LOCK(callback_mutex);
        release_first_callback = true;
    }
    callback_cv.notify_one();
    validation->Stop();

    BOOST_REQUIRE(first_submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(callback_entered);
    BOOST_REQUIRE(first_result.has_value());
    BOOST_CHECK(!first_result->new_block);
    BOOST_REQUIRE(second_submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_CHECK_EQUAL(callback_count.load(), 2);
    BOOST_CHECK(first_callback_released);
    BOOST_CHECK_EQUAL(ready.Count(), 2);

    const auto second_result{validation->TakeResult()};
    BOOST_REQUIRE(second_result.has_value());
    BOOST_CHECK(!second_result->new_block);
    BOOST_CHECK(!validation->TakeResult().has_value());
}

BOOST_AUTO_TEST_CASE(idle_repeated_stop)
{
    ResultWaiter ready;
    {
        auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};
        validation->Stop();
        validation->Stop();
    }
    BOOST_CHECK_EQUAL(ready.Count(), 0);
}

BOOST_FIXTURE_TEST_CASE(direct_callbacks_precede_result_publication, TestChain100Setup)
{
    DirectCallbackSequence sequence;
    m_node.validation_signals->RegisterValidationInterface(&sequence);
    auto& chainman{static_cast<TestChainstateManager&>(*m_node.chainman)};
    if (chainman.IsInitialBlockDownload()) chainman.JumpOutOfIbd();

    const CScript script_pub_key{CScript{} << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    const auto valid_block{std::make_shared<const CBlock>(CreateBlock({}, script_pub_key))};
    ResultWaiter valid_ready;
    std::atomic<int> valid_ready_sequence{0};
    auto valid_validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] {
        valid_ready_sequence = sequence.RecordReady();
        valid_ready.Notify();
    })};
    const auto valid_submit{valid_validation->Submit({valid_block, true, true})};
    const bool valid_completed{valid_ready.WaitForCount(1)};
    valid_validation->Stop();
    const auto valid_result{valid_validation->TakeResult()};

    ResultWaiter invalid_ready;
    std::atomic<int> invalid_ready_sequence{0};
    auto invalid_validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] {
        invalid_ready_sequence = sequence.RecordReady();
        invalid_ready.Notify();
    })};
    const auto invalid_submit{invalid_validation->Submit({std::make_shared<const CBlock>(), true, true})};
    const bool invalid_completed{invalid_ready.WaitForCount(1)};
    invalid_validation->Stop();
    const auto invalid_result{invalid_validation->TakeResult()};
    m_node.validation_signals->UnregisterValidationInterface(&sequence);

    BOOST_REQUIRE(valid_submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(valid_completed);
    BOOST_REQUIRE(valid_result.has_value());
    BOOST_CHECK(valid_result->new_block);
    BOOST_CHECK(sequence.ValidBlockChecked() > 0);
    BOOST_CHECK(sequence.NewPoWValidBlockSequence() > 0);
    BOOST_CHECK(sequence.ValidBlockChecked() < valid_ready_sequence.load());
    BOOST_CHECK(sequence.NewPoWValidBlockSequence() < valid_ready_sequence.load());
    BOOST_REQUIRE(invalid_submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(invalid_completed);
    BOOST_REQUIRE(invalid_result.has_value());
    BOOST_CHECK(!invalid_result->new_block);
    BOOST_CHECK(sequence.InvalidBlockChecked() > 0);
    BOOST_CHECK(sequence.InvalidBlockChecked() < invalid_ready_sequence.load());
}

BOOST_FIXTURE_TEST_CASE(validation_interface_queue_pressure, TestChain100Setup)
{
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    m_node.peerman->Interrupt();
    m_node.peerman->Stop();
    m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
    Assert(m_node.scheduler)->stop();
    m_node.validation_signals->FlushBackgroundCallbacks();
    connman.SetMsgProc(nullptr);
    m_node.peerman.reset();

    auto task_runner{std::make_unique<ManualTaskRunner>()};
    auto* const task_runner_observer{task_runner.get()};
    m_clock.set(m_node.chainman->GetParams().GenesisBlock().Time());
    m_node.chainman.reset();
    m_node.mempool.reset();
    m_node.validation_signals = std::make_unique<ValidationSignals>(std::move(task_runner));
    bilingual_str error{};
    m_node.mempool = std::make_unique<CTxMemPool>(MemPoolOptionsForTest(m_node), error);
    BOOST_REQUIRE(error.empty());
    m_make_chainman();
    LoadVerifyActivateChainstate();
    const node::BlockCreateOptions options{.coinbase_output_script = P2WSH_OP_TRUE};
    for (int i{0}; i < 2 * COINBASE_MATURITY; ++i) {
        (void)MineBlock(m_node, options);
    }

    const CScript script_pub_key{CScript{} << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    const auto block{std::make_shared<const CBlock>(CreateBlock({}, script_pub_key))};
    task_runner_observer->Hold();
    for (int i{0}; i < 11; ++i) {
        m_node.validation_signals->CallFunctionInValidationInterfaceQueue([] {});
    }
    BOOST_REQUIRE_EQUAL(task_runner_observer->size(), 11U);

    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};
    BOOST_REQUIRE(validation->Submit({block, true, true}) == node::P2PBlockValidationSubmit::ACCEPTED);
    const bool queue_limited{task_runner_observer->WaitForSize(12)};
    if (queue_limited) {
        task_runner_observer->RunAll();
    } else {
        task_runner_observer->ReleaseAndRunAll();
    }
    BOOST_REQUIRE(queue_limited);

    const bool completed{ready.WaitForCount(1)};
    validation->Stop();
    const auto result{validation->TakeResult()};
    task_runner_observer->RunAll();
    m_node.validation_signals->FlushBackgroundCallbacks();

    BOOST_REQUIRE(completed);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(result->new_block);
    BOOST_CHECK_EQUAL(ready.Count(), 1);
}

BOOST_AUTO_TEST_CASE(stop_while_direct_callback_held)
{
    BlockingBlockChecked block_checked;
    m_node.validation_signals->RegisterValidationInterface(&block_checked);
    ResultWaiter ready;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ready.Notify(); })};
    const auto submit{validation->Submit({std::make_shared<const CBlock>(), true, true})};
    const bool callback_entered{block_checked.WaitForEntry()};
    if (!callback_entered) {
        block_checked.Release();
        validation->Stop();
        m_node.validation_signals->UnregisterValidationInterface(&block_checked);
        BOOST_REQUIRE(callback_entered);
    }

    std::promise<void> stop_started;
    auto stop_started_future{stop_started.get_future()};
    std::thread stop_thread{[&] {
        stop_started.set_value();
        validation->Stop();
    }};
    stop_started_future.wait();
    block_checked.Release();
    stop_thread.join();

    const auto result{validation->TakeResult()};
    m_node.validation_signals->UnregisterValidationInterface(&block_checked);
    BOOST_REQUIRE(submit == node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_CHECK(block_checked.Completed());
    BOOST_CHECK(block_checked.ReleaseObserved());
    BOOST_CHECK_EQUAL(ready.Count(), 1);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(!result->new_block);
}

BOOST_AUTO_TEST_SUITE_END()

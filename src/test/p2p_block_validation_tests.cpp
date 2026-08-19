// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <optional>
#include <stdexcept>
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

BOOST_AUTO_TEST_SUITE_END()

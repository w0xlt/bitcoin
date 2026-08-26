// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <consensus/validation.h>
#include <primitives/block.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <optional>

namespace {

constexpr auto TEST_TIMEOUT{std::chrono::seconds{30}};

class BlockingBlockChecked final : public CValidationInterface
{
public:
    bool WaitForEntry() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, TEST_TIMEOUT, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
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

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState&) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        m_entered = true;
        m_cv.notify_all();
        (void)m_cv.wait_for(lock, TEST_TIMEOUT, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_release;
        });
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    bool m_entered GUARDED_BY(m_mutex){false};
    bool m_release GUARDED_BY(m_mutex){false};
};

node::P2PBlockValidationRequest InvalidRequest(std::shared_ptr<const CBlock> block)
{
    return {
        .block = std::move(block),
        .force_processing = true,
        .min_pow_checked = true,
    };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2p_block_validation_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(single_slot_lifetime_and_publication)
{
    auto blocker{std::make_shared<BlockingBlockChecked>()};
    m_node.validation_signals->RegisterSharedValidationInterface(blocker);

    node::P2PBlockValidation* validation_ptr{nullptr};
    std::optional<node::P2PBlockValidationResult> result_from_wake;
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] {
        result_from_wake = validation_ptr->TakeResult();
    })};
    validation_ptr = validation.get();
    validation->Start();

    auto owned_block{std::make_shared<const CBlock>()};
    std::weak_ptr<const CBlock> weak_block{owned_block};
    BOOST_REQUIRE(validation->Submit(InvalidRequest(owned_block)) ==
                  node::P2PBlockValidationSubmit::ACCEPTED);
    owned_block.reset();
    BOOST_REQUIRE(blocker->WaitForEntry());
    BOOST_CHECK(!weak_block.expired());

    auto second_block{std::make_shared<const CBlock>()};
    BOOST_CHECK(validation->Submit(InvalidRequest(second_block)) ==
                node::P2PBlockValidationSubmit::FULL);
    BOOST_CHECK(second_block.use_count() == 1);

    auto stop{std::async(std::launch::async, [&] { validation->StopAndJoin(); })};
    BOOST_CHECK(stop.wait_for(std::chrono::milliseconds{20}) == std::future_status::timeout);
    blocker->Release();
    BOOST_REQUIRE(stop.wait_for(TEST_TIMEOUT) == std::future_status::ready);
    stop.get();
    validation->StopAndJoin();
    m_node.validation_signals->UnregisterSharedValidationInterface(blocker);

    BOOST_REQUIRE(result_from_wake);
    BOOST_CHECK(!result_from_wake->new_block);
    BOOST_CHECK(!validation->TakeResult());
    BOOST_CHECK(weak_block.expired());
}

BOOST_AUTO_TEST_CASE(result_ready_occupies_slot_and_is_taken_once)
{
    Mutex mutex;
    std::condition_variable cv;
    bool ready GUARDED_BY(mutex){false};
    std::atomic<int> calls{0};
    std::atomic<bool> force_processing{false};
    std::atomic<bool> min_pow_checked{true};

    auto validation{node::MakeP2PBlockValidationForTest(
        [&](const std::shared_ptr<const CBlock>&,
            bool force,
            bool min_pow,
            bool* new_block) {
            ++calls;
            force_processing = force;
            min_pow_checked = min_pow;
            *new_block = true;
            return false;
        },
        [&] {
            {
                LOCK(mutex);
                ready = true;
            }
            cv.notify_all();
        })};
    validation->Start();

    auto owned_block{std::make_shared<const CBlock>()};
    std::weak_ptr<const CBlock> weak_block{owned_block};
    BOOST_REQUIRE(validation->Submit({
                      .block = owned_block,
                      .force_processing = true,
                      .min_pow_checked = false,
                      .job_id = 9,
                  }) == node::P2PBlockValidationSubmit::ACCEPTED);
    owned_block.reset();
    {
        WAIT_LOCK(mutex, lock);
        BOOST_REQUIRE(cv.wait_for(lock, TEST_TIMEOUT, [&]() EXCLUSIVE_LOCKS_REQUIRED(mutex) {
            return ready;
        }));
    }

    BOOST_CHECK_EQUAL(calls.load(), 1);
    BOOST_CHECK(force_processing.load());
    BOOST_CHECK(!min_pow_checked.load());
    BOOST_CHECK(weak_block.expired());
    BOOST_CHECK(validation->Submit(InvalidRequest(std::make_shared<const CBlock>())) ==
                node::P2PBlockValidationSubmit::FULL);

    // An uncollected result remains available across drain-only stop.
    validation->StopAndJoin();
    validation->StopAndJoin();
    auto result{validation->TakeResult()};
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->new_block);
    BOOST_CHECK(!validation->TakeResult());
    BOOST_CHECK(validation->Submit(InvalidRequest(std::make_shared<const CBlock>())) ==
                node::P2PBlockValidationSubmit::STOPPING);
}

BOOST_AUTO_TEST_CASE(process_and_wake_run_outside_component_mutex)
{
    node::P2PBlockValidation* validation_ptr{nullptr};
    std::promise<node::P2PBlockValidationSubmit> reentrant_submit;
    std::promise<void> entered;
    std::promise<void> release;
    auto release_future{release.get_future().share()};
    std::optional<node::P2PBlockValidationResult> result_from_wake;
    std::atomic<int> calls{0};
    std::atomic<int> wakes{0};
    auto rejected_block{std::make_shared<const CBlock>()};

    auto validation{node::MakeP2PBlockValidationForTest(
        [&](const std::shared_ptr<const CBlock>&,
            bool,
            bool,
            bool* new_block) {
            ++calls;
            reentrant_submit.set_value(
                validation_ptr->Submit(InvalidRequest(rejected_block)));
            entered.set_value();
            release_future.wait();
            *new_block = false;
            return true;
        },
        [&] {
            ++wakes;
            result_from_wake = validation_ptr->TakeResult();
        })};
    validation_ptr = validation.get();
    validation->Start();

    BOOST_REQUIRE(validation->Submit(InvalidRequest(std::make_shared<const CBlock>())) ==
                  node::P2PBlockValidationSubmit::ACCEPTED);
    BOOST_REQUIRE(entered.get_future().wait_for(TEST_TIMEOUT) == std::future_status::ready);
    BOOST_CHECK(reentrant_submit.get_future().get() == node::P2PBlockValidationSubmit::FULL);
    BOOST_CHECK_EQUAL(rejected_block.use_count(), 1);

    auto stop{std::async(std::launch::async, [&] { validation->StopAndJoin(); })};
    BOOST_CHECK(stop.wait_for(std::chrono::milliseconds{20}) == std::future_status::timeout);
    release.set_value();
    BOOST_REQUIRE(stop.wait_for(TEST_TIMEOUT) == std::future_status::ready);
    stop.get();

    BOOST_CHECK_EQUAL(calls.load(), 1);
    BOOST_CHECK_EQUAL(wakes.load(), 1);
    BOOST_REQUIRE(result_from_wake);
    BOOST_CHECK(!result_from_wake->new_block);
    BOOST_CHECK(!validation->TakeResult());
}

BOOST_AUTO_TEST_CASE(stop_before_start_and_idle_stop_are_idempotent)
{
    std::atomic<int> calls{0};
    std::atomic<int> wakes{0};
    auto before_start{node::MakeP2PBlockValidationForTest(
        [&](const std::shared_ptr<const CBlock>&, bool, bool, bool*) {
            ++calls;
            return false;
        },
        [&] { ++wakes; })};
    before_start->StopAndJoin();
    before_start->StopAndJoin();
    BOOST_CHECK(before_start->Submit(InvalidRequest(std::make_shared<const CBlock>())) ==
                node::P2PBlockValidationSubmit::STOPPING);
    BOOST_CHECK(!before_start->TakeResult());

    auto idle_started{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ++wakes; })};
    idle_started->Start();
    idle_started->StopAndJoin();
    idle_started->StopAndJoin();
    BOOST_CHECK(idle_started->Submit(InvalidRequest(std::make_shared<const CBlock>())) ==
                node::P2PBlockValidationSubmit::STOPPING);
    BOOST_CHECK_EQUAL(calls.load(), 0);
    BOOST_CHECK_EQUAL(wakes.load(), 0);
    BOOST_CHECK(!idle_started->TakeResult());
}

BOOST_AUTO_TEST_SUITE_END()

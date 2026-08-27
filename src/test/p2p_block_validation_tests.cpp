// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/p2p_block_validation.h>

#include <consensus/validation.h>
#include <node/async_pnb_peer_service_probe.h>
#include <primitives/block.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <validationinterface.h>

#ifndef WIN32
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <optional>
#include <vector>

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

class ValidationStateBarrier
{
public:
    explicit ValidationStateBarrier(node::P2PBlockValidationTestState target)
        : m_target{target}
    {
    }

    void Hook(node::P2PBlockValidationTestState state)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        if (state != m_target) return;
        WAIT_LOCK(m_mutex, lock);
        m_entered = true;
        m_cv.notify_all();
        (void)m_cv.wait_for(lock, TEST_TIMEOUT, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_released;
        });
    }

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
            m_released = true;
        }
        m_cv.notify_all();
    }

private:
    const node::P2PBlockValidationTestState m_target;
    Mutex m_mutex;
    std::condition_variable m_cv;
    bool m_entered GUARDED_BY(m_mutex){false};
    bool m_released GUARDED_BY(m_mutex){false};
};

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
    BOOST_CHECK(!result_from_wake->process_new_block);
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
    // Preserve the ProcessNewBlock return independently from new_block.
    BOOST_CHECK(!result->process_new_block);
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
    BOOST_CHECK(result_from_wake->process_new_block);
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

BOOST_AUTO_TEST_CASE(stop_drains_each_occupied_state_once)
{
    for (const auto target : {
             node::P2PBlockValidationTestState::QUEUED,
             node::P2PBlockValidationTestState::RUNNING,
             node::P2PBlockValidationTestState::RESULT_READY,
         }) {
        auto barrier{std::make_shared<ValidationStateBarrier>(target)};
        std::atomic<int> calls{0};
        std::atomic<int> wakes{0};
        auto validation{node::MakeP2PBlockValidationForTest(
            [&](const std::shared_ptr<const CBlock>&, bool, bool, bool* new_block) {
                ++calls;
                *new_block = true;
                return true;
            },
            [&] { ++wakes; },
            [barrier](node::P2PBlockValidationTestState state) {
                barrier->Hook(state);
            })};
        validation->Start();

        auto owned_block{std::make_shared<const CBlock>()};
        std::weak_ptr<const CBlock> weak_block{owned_block};
        BOOST_REQUIRE(validation->Submit(InvalidRequest(owned_block)) ==
                      node::P2PBlockValidationSubmit::ACCEPTED);
        owned_block.reset();
        BOOST_REQUIRE(barrier->WaitForEntry());

        auto stop{std::async(std::launch::async, [&] { validation->StopAndJoin(); })};
        BOOST_CHECK(stop.wait_for(std::chrono::milliseconds{20}) == std::future_status::timeout);
        barrier->Release();
        BOOST_REQUIRE(stop.wait_for(TEST_TIMEOUT) == std::future_status::ready);
        stop.get();
        validation->StopAndJoin();

        BOOST_CHECK_EQUAL(calls.load(), 1);
        BOOST_CHECK_EQUAL(wakes.load(), 1);
        BOOST_CHECK(weak_block.expired());
        auto result{validation->TakeResult()};
        BOOST_REQUIRE(result);
        BOOST_CHECK(result->process_new_block);
        BOOST_CHECK(result->new_block);
        BOOST_CHECK(!validation->TakeResult());
        BOOST_CHECK(validation->Submit(InvalidRequest(std::make_shared<const CBlock>())) ==
                    node::P2PBlockValidationSubmit::STOPPING);
    }
}

BOOST_AUTO_TEST_CASE(probe_gate_disabled_and_overflow_authority)
{
#ifndef WIN32
    const fs::path disabled_dir{m_path_root / "disabled"};
    BOOST_REQUIRE(fs::create_directory(disabled_dir));
    auto disabled_probe{node::AsyncPNBPeerServiceProbe::Create(
        disabled_dir, /*test_gates=*/false)};
    std::vector<fs::path> disabled_files;
    for (const auto& entry : fs::directory_iterator{disabled_dir}) {
        if (fs::PathToString(entry.path().filename()).starts_with("async-pnb-probe-")) {
            disabled_files.push_back(entry.path());
        }
    }
    BOOST_REQUIRE_EQUAL(disabled_files.size(), 1U);
    const int disabled_fd{open(fs::PathToString(disabled_files[0]).c_str(), O_RDWR | O_CLOEXEC)};
    BOOST_REQUIRE(disabled_fd >= 0);
    constexpr size_t mapping_size{
        sizeof(node::AsyncPNBProbeFileHeader) +
        node::ASYNC_PNB_PROBE_CAPACITY * sizeof(node::AsyncPNBProbeSlot)};
    void* disabled_mapping{mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, disabled_fd, 0)};
    BOOST_REQUIRE(disabled_mapping != MAP_FAILED);
    auto* disabled_header{
        static_cast<node::AsyncPNBProbeFileHeader*>(disabled_mapping)};
    disabled_header->test_gate.store(
        static_cast<uint32_t>(node::AsyncPNBProbeTestGate::PNB_HEADER_TIP),
        std::memory_order_relaxed);
    disabled_header->test_gate_generation.store(1, std::memory_order_release);
    disabled_probe->SetActiveJob(8);
    // All disabled test-gate entry points return before recording or waiting.
    BOOST_CHECK(!disabled_probe->TestGate(
        node::AsyncPNBProbeTestGate::WORKER_QUEUED,
        /*job=*/8, /*peer=*/-1, /*hash=*/nullptr));
    BOOST_CHECK(!disabled_probe->TestHeaderTipGate(/*height=*/1, /*timestamp=*/2));
    disabled_probe->RecordTargetDisconnect(/*peer=*/7);
    BOOST_CHECK(!disabled_probe->ResultReadyCollectionDeferred());
    BOOST_CHECK_EQUAL(disabled_header->next_sequence.load(std::memory_order_acquire), 0U);
    BOOST_CHECK_EQUAL(disabled_header->status.load(std::memory_order_acquire), 0U);
    BOOST_CHECK_EQUAL(munmap(disabled_mapping, mapping_size), 0);
    BOOST_CHECK_EQUAL(close(disabled_fd), 0);

    auto probe{node::AsyncPNBPeerServiceProbe::Create(m_path_root, /*test_gates=*/true)};
    std::vector<fs::path> probe_files;
    for (const auto& entry : fs::directory_iterator{m_path_root}) {
        if (fs::PathToString(entry.path().filename()).starts_with("async-pnb-probe-")) {
            probe_files.push_back(entry.path());
        }
    }
    BOOST_REQUIRE_EQUAL(probe_files.size(), 1U);
    const int fd{open(fs::PathToString(probe_files[0]).c_str(), O_RDWR | O_CLOEXEC)};
    BOOST_REQUIRE(fd >= 0);
    void* mapping{mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)};
    BOOST_REQUIRE(mapping != MAP_FAILED);
    auto* header{static_cast<node::AsyncPNBProbeFileHeader*>(mapping)};
    header->test_gate.store(
        static_cast<uint32_t>(node::AsyncPNBProbeTestGate::RESULT_READY),
        std::memory_order_relaxed);
    header->test_gate_generation.store(1, std::memory_order_release);
    BOOST_CHECK(probe->ResultReadyCollectionDeferred());
    header->test_gate_release.store(1, std::memory_order_release);
    BOOST_CHECK(!probe->ResultReadyCollectionDeferred());

    // Reservations beyond the fixed capacity are hard-invalid and never
    // modulo-wrap onto a published slot.
    auto* slots{reinterpret_cast<node::AsyncPNBProbeSlot*>(
        static_cast<unsigned char*>(mapping) + sizeof(node::AsyncPNBProbeFileHeader))};
    BOOST_REQUIRE_EQUAL(header->next_sequence.load(std::memory_order_acquire), 0U);
    for (uint32_t index{0}; index < node::ASYNC_PNB_PROBE_CAPACITY; ++index) {
        probe->Record(node::AsyncPNBProbeEvent::TEST_INTERFACE_REGISTERED,
                      std::chrono::steady_clock::time_point{});
    }
    const uint64_t first_checksum{slots[0].checksum};
    BOOST_CHECK_EQUAL(header->next_sequence.load(std::memory_order_acquire),
                      node::ASYNC_PNB_PROBE_CAPACITY);
    BOOST_CHECK_EQUAL(slots[node::ASYNC_PNB_PROBE_CAPACITY - 1]
                          .published_sequence.load(std::memory_order_acquire),
                      node::ASYNC_PNB_PROBE_CAPACITY);
    probe->Record(node::AsyncPNBProbeEvent::TEST_INTERFACE_REGISTERED,
                  std::chrono::steady_clock::time_point{});
    BOOST_CHECK_EQUAL(header->next_sequence.load(std::memory_order_acquire),
                      node::ASYNC_PNB_PROBE_CAPACITY + 1U);
    BOOST_CHECK_EQUAL(header->overflow_count.load(std::memory_order_acquire), 1U);
    BOOST_CHECK_EQUAL(header->status.load(std::memory_order_acquire),
                      node::ASYNC_PNB_PROBE_FLAG_TEST_GATES |
                          node::ASYNC_PNB_PROBE_FLAG_OVERFLOW);
    BOOST_CHECK_EQUAL(slots[0].published_sequence.load(std::memory_order_acquire), 1U);
    BOOST_CHECK_EQUAL(slots[0].record.sequence, 1U);
    BOOST_CHECK_EQUAL(slots[0].record.event,
                      static_cast<uint32_t>(node::AsyncPNBProbeEvent::TEST_INTERFACE_REGISTERED));
    BOOST_CHECK_EQUAL(slots[0].checksum, first_checksum);

    BOOST_CHECK_EQUAL(munmap(mapping, mapping_size), 0);
    BOOST_CHECK_EQUAL(close(fd), 0);
#else
    BOOST_TEST_MESSAGE("async-PNB mmap probe is explicitly unsupported on Windows");
#endif
}

BOOST_AUTO_TEST_SUITE_END()

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

#include <chrono>
#include <condition_variable>
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

    blocker->Release();
    validation->Stop();
    validation->Stop();
    m_node.validation_signals->UnregisterSharedValidationInterface(blocker);

    BOOST_REQUIRE(result_from_wake);
    BOOST_CHECK(!result_from_wake->new_block);
    BOOST_CHECK(!validation->TakeResult());
    BOOST_CHECK(weak_block.expired());
}

BOOST_AUTO_TEST_CASE(interrupt_rejects_new_work_and_stop_is_idempotent)
{
    int wakes{0};
    auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [&] { ++wakes; })};
    validation->Interrupt();
    validation->Interrupt();
    BOOST_CHECK(validation->Submit(InvalidRequest(std::make_shared<const CBlock>())) ==
                node::P2PBlockValidationSubmit::INTERRUPTED);
    validation->Stop();
    validation->Stop();
    BOOST_CHECK_EQUAL(wakes, 0);
    BOOST_CHECK(!validation->TakeResult());
}

BOOST_AUTO_TEST_SUITE_END()

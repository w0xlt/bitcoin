// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <consensus/validation.h>
#include <pow.h>
#include <primitives/block.h>
#include <scheduler.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <atomic>
#include <memory>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(validationinterface_tests, ChainTestingSetup)

struct TestSubscriberNoop final : public CValidationInterface {
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState&) override {}
};

BOOST_AUTO_TEST_CASE(unregister_validation_interface_race)
{
    std::atomic<bool> generate{true};

    // Start thread to generate notifications
    std::thread gen{[&] {
        BlockValidationState state_dummy;
        while (generate) {
            m_node.validation_signals->BlockChecked(std::make_shared<const CBlock>(), state_dummy);
        }
    }};

    // Start thread to consume notifications
    std::thread sub{[&] {
        // keep going for about 1 sec, which is 250k iterations
        for (int i = 0; i < 250000; i++) {
            auto sub = std::make_shared<TestSubscriberNoop>();
            m_node.validation_signals->RegisterSharedValidationInterface(sub);
            m_node.validation_signals->UnregisterSharedValidationInterface(sub);
        }
        // tell the other thread we are done
        generate = false;
    }};

    gen.join();
    sub.join();
    BOOST_CHECK(!generate);
}

class TestInterface : public CValidationInterface
{
public:
    TestInterface(ValidationSignals& signals, std::function<void()> on_call = nullptr, std::function<void()> on_destroy = nullptr)
        : m_on_call(std::move(on_call)), m_on_destroy(std::move(on_destroy)), m_signals{signals}
    {
    }
    virtual ~TestInterface()
    {
        if (m_on_destroy) m_on_destroy();
    }
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& state) override
    {
        if (m_on_call) m_on_call();
    }
    void Call()
    {
        BlockValidationState state;
        m_signals.BlockChecked(std::make_shared<const CBlock>(), state);
    }
    std::function<void()> m_on_call;
    std::function<void()> m_on_destroy;
    ValidationSignals& m_signals;
};

// Regression test to ensure UnregisterAllValidationInterfaces calls don't
// destroy a validation interface while it is being called. Bug:
// https://github.com/bitcoin/bitcoin/pull/18551
BOOST_AUTO_TEST_CASE(unregister_all_during_call)
{
    bool destroyed = false;
    auto shared{std::make_shared<TestInterface>(
        *m_node.validation_signals,
        [&] {
            // First call should decrements reference count 2 -> 1
            m_node.validation_signals->UnregisterAllValidationInterfaces();
            BOOST_CHECK(!destroyed);
            // Second call should not decrement reference count 1 -> 0
            m_node.validation_signals->UnregisterAllValidationInterfaces();
            BOOST_CHECK(!destroyed);
        },
        [&] { destroyed = true; })};
    m_node.validation_signals->RegisterSharedValidationInterface(shared);
    BOOST_CHECK(shared.use_count() == 2);
    shared->Call();
    BOOST_CHECK(shared.use_count() == 1);
    BOOST_CHECK(!destroyed);
    shared.reset();
    BOOST_CHECK(destroyed);
}

BOOST_FIXTURE_TEST_CASE(processnewblockheaders_coalesces_accepted_not_active, TestChain100Setup)
{
    struct TestSubscriber final : CValidationInterface {
        std::vector<const CBlockIndex*> m_accepted_not_active;

        bool WantsAcceptedNotActive() const override { return true; }

        void AcceptedNotActive(const CBlockIndex* pindex) override
        {
            m_accepted_not_active.push_back(pindex);
        }
    };

    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const auto sub{std::make_shared<TestSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    const auto& consensus{Params().GetConsensus()};
    const CBlockIndex* fork{nullptr};
    {
        LOCK(cs_main);
        fork = Assert(m_node.chainman->ActiveChain().Tip())->GetAncestor(97);
    }
    uint256 prev_hash{fork->GetBlockHash()};
    uint32_t time{static_cast<uint32_t>(fork->GetBlockTime() + 1)};
    std::vector<CBlockHeader> headers;
    for (uint32_t i{0}; i < 3; ++i) {
        CBlockHeader header;
        header.nVersion = 4;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = uint256{static_cast<uint8_t>(i + 1)};
        header.nTime = time++;
        header.nBits = fork->nBits;
        while (!CheckProofOfWork(header.GetHash(), header.nBits, consensus)) ++header.nNonce;
        prev_hash = header.GetHash();
        headers.push_back(header);
    }

    BlockValidationState state;
    const CBlockIndex* tip{nullptr};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state, &tip));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    BOOST_REQUIRE_EQUAL(sub->m_accepted_not_active.size(), 1U);
    BOOST_CHECK_EQUAL(sub->m_accepted_not_active.front()->GetBlockHash().ToString(),
                      Assert(tip)->GetBlockHash().ToString());
}

BOOST_AUTO_TEST_SUITE_END()

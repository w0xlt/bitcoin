// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <interfaces/mining.h>
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

struct StaleTipSubscriber final : CValidationInterface {
    std::vector<const CBlockIndex*> m_accepted_stale_tips;

    bool WantsAcceptedStaleTip() const override { return true; }

    void AcceptedStaleTip(const CBlockIndex* pindex) override
    {
        m_accepted_stale_tips.push_back(pindex);
    }
};

struct StaleTipChainSetup : public TestChain100Setup {
    // Build a valid block on an arbitrary parent so it forks off the active chain.
    CBlock CreateBlock(const CBlockIndex* prev, const CScript& script_pubkey)
    {
        auto mining{interfaces::MakeMining(m_node)};
        auto tmpl{mining->createNewBlock({.coinbase_output_script = script_pubkey}, /*cooldown=*/false)};
        BOOST_REQUIRE(tmpl);
        CBlock block{tmpl->getBlock()};
        block.hashPrevBlock = prev->GetBlockHash();
        block.nTime = prev->nTime + 1;

        CMutableTransaction cb{*block.vtx.at(0)};
        cb.nLockTime = static_cast<uint32_t>(prev->nHeight);
        cb.vin.at(0).scriptSig = CScript{} << prev->nHeight + 1;
        block.vtx.at(0) = MakeTransactionRef(std::move(cb));
        block.hashMerkleRoot = BlockMerkleRoot(block);

        while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;
        return block;
    }
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

BOOST_FIXTURE_TEST_CASE(processnewblockheaders_coalesces_accepted_stale_tip, TestChain100Setup)
{
    struct UninterestedSubscriber final : CValidationInterface {
        size_t m_calls{0};

        void AcceptedStaleTip(const CBlockIndex*) override { ++m_calls; }
    };

    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const auto sub{std::make_shared<StaleTipSubscriber>()};
    const auto uninterested{std::make_shared<UninterestedSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);
    m_node.validation_signals->RegisterSharedValidationInterface(uninterested);

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

    BOOST_REQUIRE_EQUAL(sub->m_accepted_stale_tips.size(), 1U);
    BOOST_CHECK_EQUAL(sub->m_accepted_stale_tips.front()->GetBlockHash().ToString(),
                      Assert(tip)->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(uninterested->m_calls, 0U);

    BlockValidationState duplicate_state;
    const CBlockIndex* duplicate_tip{nullptr};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, duplicate_state, &duplicate_tip));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(sub->m_accepted_stale_tips.size(), 1U);
    BOOST_CHECK_EQUAL(Assert(duplicate_tip)->GetBlockHash().ToString(), Assert(tip)->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(uninterested->m_calls, 0U);

    // A header with more work than the active tip is not a stale tip, even
    // though header acceptance does not activate it.
    CBlockHeader better_work_header;
    better_work_header.nVersion = 4;
    better_work_header.hashPrevBlock = Assert(tip)->GetBlockHash();
    better_work_header.hashMerkleRoot = uint256{uint8_t{4}};
    better_work_header.nTime = time;
    better_work_header.nBits = fork->nBits;
    while (!CheckProofOfWork(better_work_header.GetHash(), better_work_header.nBits, consensus)) ++better_work_header.nNonce;
    const std::vector<CBlockHeader> better_work_headers{better_work_header};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders(better_work_headers, /*min_pow_checked=*/true, state));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(sub->m_accepted_stale_tips.size(), 1U);
}

BOOST_FIXTURE_TEST_CASE(processnewblockheaders_notifies_accepted_prefix_before_failure, TestChain100Setup)
{
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const auto sub{std::make_shared<StaleTipSubscriber>()};
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
    for (uint32_t i{0}; i < 2; ++i) {
        CBlockHeader header;
        header.nVersion = 4;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = uint256{static_cast<uint8_t>(i + 10)};
        header.nTime = time++;
        header.nBits = fork->nBits;
        while (!CheckProofOfWork(header.GetHash(), header.nBits, consensus)) ++header.nNonce;
        prev_hash = header.GetHash();
        headers.push_back(header);
    }

    CBlockHeader invalid_header;
    invalid_header.nVersion = 4;
    invalid_header.hashPrevBlock = prev_hash;
    invalid_header.hashMerkleRoot = uint256{uint8_t{12}};
    invalid_header.nTime = time;
    invalid_header.nBits = 0;
    headers.push_back(invalid_header);

    BlockValidationState state;
    const CBlockIndex* accepted_prefix_tip{nullptr};
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state, &accepted_prefix_tip));
    BOOST_CHECK(state.IsInvalid());
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    BOOST_REQUIRE_EQUAL(sub->m_accepted_stale_tips.size(), 1U);
    BOOST_CHECK_EQUAL(sub->m_accepted_stale_tips.front()->GetBlockHash().ToString(), headers[1].GetHash().ToString());
    BOOST_CHECK_EQUAL(Assert(accepted_prefix_tip)->GetBlockHash().ToString(), headers[1].GetHash().ToString());

    const std::vector<CBlockHeader> valid_prefix{headers.begin(), headers.end() - 1};
    BlockValidationState duplicate_state;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders(valid_prefix, /*min_pow_checked=*/true, duplicate_state));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(sub->m_accepted_stale_tips.size(), 1U);

    const std::vector<CBlockHeader> invalid_only{invalid_header};
    BlockValidationState invalid_only_state;
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlockHeaders(invalid_only, /*min_pow_checked=*/true, invalid_only_state));
    BOOST_CHECK(invalid_only_state.IsInvalid());
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(sub->m_accepted_stale_tips.size(), 1U);
}

BOOST_FIXTURE_TEST_CASE(receivedblocktransactions_notifies_when_block_data_arrives, StaleTipChainSetup)
{
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const auto sub{std::make_shared<StaleTipSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    const CBlockIndex* fork{WITH_LOCK(::cs_main,
        return Assert(m_node.chainman->ActiveChain().Tip())->pprev)};
    const CBlock stale_block{CreateBlock(fork, CScript() << OP_TRUE)};
    const auto stale_ptr{std::make_shared<const CBlock>(stale_block)};

    std::vector<CBlockHeader> headers{CBlockHeader{stale_block}};
    BlockValidationState header_state;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, header_state));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(sub->m_accepted_stale_tips.size(), 1U);

    bool is_new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(stale_ptr, /*force_processing=*/true, /*min_pow_checked=*/true, &is_new_block));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(sub->m_accepted_stale_tips.size(), 2U);
    BOOST_CHECK_EQUAL(sub->m_accepted_stale_tips.back()->GetBlockHash().ToString(), stale_block.GetHash().ToString());
}

BOOST_FIXTURE_TEST_CASE(acceptblock_notifies_new_stale_block_header, StaleTipChainSetup)
{
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const auto sub{std::make_shared<StaleTipSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    const CBlockIndex* fork{WITH_LOCK(::cs_main, return Assert(m_node.chainman->ActiveChain().Tip())->pprev)};
    const CBlock stale_block{CreateBlock(fork, CScript() << OP_TRUE)};
    const auto stale_ptr{std::make_shared<const CBlock>(stale_block)};

    bool is_new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(stale_ptr, /*force_processing=*/true, /*min_pow_checked=*/true, &is_new_block));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(sub->m_accepted_stale_tips.size(), 2U);
    BOOST_CHECK_EQUAL(sub->m_accepted_stale_tips.front()->GetBlockHash().ToString(), stale_block.GetHash().ToString());
}

BOOST_AUTO_TEST_SUITE_END()

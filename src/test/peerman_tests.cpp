// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <interfaces/mining.h>
#include <netmessagemaker.h>
#include <net_processing.h>
#include <node/p2p_block_validation.h>
#include <pow.h>
#include <primitives/block.h>
#include <protocol.h>
#include <sync.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace {

class FakeP2PBlockValidation final : public node::P2PBlockValidation
{
public:
    node::P2PBlockValidationSubmit Submit(node::P2PBlockValidationRequest request) override
    {
        ++m_submit_count;
        if (m_interrupted) return node::P2PBlockValidationSubmit::INTERRUPTED;
        if (m_request || m_result) return node::P2PBlockValidationSubmit::BUSY;
        Assert(request.block != nullptr);
        m_request = std::move(request);
        return node::P2PBlockValidationSubmit::ACCEPTED;
    }

    std::optional<node::P2PBlockValidationResult> TakeResult() override
    {
        auto result{std::move(m_result)};
        m_result.reset();
        return result;
    }

    void Interrupt() override { m_interrupted = true; }

    void Stop() override
    {
        Interrupt();
        m_stopped = true;
    }

    const node::P2PBlockValidationRequest& Request() const
    {
        Assert(m_request.has_value());
        return *m_request;
    }

    size_t SubmitCount() const { return m_submit_count; }

    void Complete(bool new_block)
    {
        Assert(m_request.has_value());
        Assert(!m_result.has_value());
        m_request.reset();
        m_result = node::P2PBlockValidationResult{new_block};
    }

    bool Interrupted() const { return m_interrupted; }
    bool Stopped() const { return m_stopped; }

private:
    std::optional<node::P2PBlockValidationRequest> m_request;
    std::optional<node::P2PBlockValidationResult> m_result;
    size_t m_submit_count{0};
    bool m_interrupted{false};
    bool m_stopped{false};
};

struct P2PBlockPeerManagerTest : RegTestingSetup {
    P2PBlockPeerManagerTest()
        : m_connman{static_cast<ConnmanTestMsg&>(*m_node.connman)}
    {
        Assert(m_node.peerman)->Interrupt();
        m_node.peerman->Stop();
        m_node.peerman.reset();

        auto block_validation{std::make_unique<FakeP2PBlockValidation>()};
        m_block_validation = block_validation.get();
        PeerManager::Options options;
        options.deterministic_rng = true;
        m_node.peerman = PeerManager::make(
            m_connman, *m_node.addrman, m_node.banman.get(), *m_node.chainman,
            *m_node.mempool, *m_node.warnings, options, std::move(block_validation));
        m_connman.SetMsgProc(m_node.peerman.get());
    }

    ~P2PBlockPeerManagerTest() { Shutdown(); }

    CNode& AddNode()
    {
        auto* node{new CNode{
            m_next_node_id++,
            /*sock=*/nullptr,
            CAddress{},
            /*nKeyedNetGroupIn=*/0,
            /*nLocalHostNonceIn=*/0,
            CAddress{},
            /*addrNameIn=*/"",
            ConnectionType::INBOUND,
            /*inbound_onion=*/false,
            /*network_key=*/0}};
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->nVersion = PROTOCOL_VERSION;
        Assert(m_node.peerman)->InitializeNode(*node, ServiceFlags{NODE_NETWORK | NODE_WITNESS});
        node->fSuccessfullyConnected = true;
        m_connman.AddTestNode(*node);
        return *node;
    }

    bool ProcessMessagesOnce(CNode& node)
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        return m_connman.ProcessMessagesOnce(node);
    }

    void ReceiveMsgFrom(CNode& node, CSerializedNetMsg msg)
    {
        Assert(m_connman.ReceiveMsgFrom(node, std::move(msg)));
    }

    CBlock NextBlock(uint32_t variant = 0)
    {
        auto mining{interfaces::MakeMining(m_node)};
        auto block_template{mining->createNewBlock({}, /*cooldown=*/false)};
        CBlock block{Assert(block_template)->getBlock()};
        block.nTime += variant;
        block.hashMerkleRoot = BlockMerkleRoot(block);
        while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;
        return block;
    }

    FakeP2PBlockValidation& BlockValidation() { return *Assert(m_block_validation); }
    PeerManager& Peerman() { return *Assert(m_node.peerman); }

    void FlushSendBuffer(CNode& node)
    {
        m_connman.FlushSendBuffer(node);
        node.fPauseSend = false;
    }

    bool Shutdown()
    {
        if (!m_node.peerman) return m_stopped;
        m_node.peerman->Interrupt();
        m_node.peerman->Stop();
        m_stopped = Assert(m_block_validation)->Stopped();
        m_connman.StopNodes();
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();
        m_block_validation = nullptr;
        return m_stopped;
    }

private:
    ConnmanTestMsg& m_connman;
    FakeP2PBlockValidation* m_block_validation{nullptr};
    NodeId m_next_node_id{0};
    bool m_stopped{false};
};

bool HasSendMessage(CNode& node, std::string_view msg_type)
{
    LOCK(node.cs_vSend);
    const auto& [to_send, _more, transport_msg_type]{node.m_transport->GetBytesToSend(false)};
    if (!to_send.empty() && transport_msg_type == msg_type) return true;
    return std::any_of(node.vSendMsg.begin(), node.vSendMsg.end(), [&](const CSerializedNetMsg& msg) {
        return msg.m_type == msg_type;
    });
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(peerman_tests, RegTestingSetup)

/** Window, in blocks, for connecting to NODE_NETWORK_LIMITED peers */
static constexpr int64_t NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS = 144;

static void mineBlock(node::NodeContext& node, FakeNodeClock& clock, std::chrono::seconds block_time)
{
    auto curr_time = GetTime<std::chrono::seconds>();
    clock.set(block_time); // update time so the block is created with it
    auto mining{interfaces::MakeMining(node)};
    auto block_template{mining->createNewBlock({}, /*cooldown=*/false)};
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    while (!CheckProofOfWork(block.GetHash(), block.nBits, node.chainman->GetConsensus())) ++block.nNonce;
    block.fChecked = true; // little speedup
    clock.set(curr_time); // process block at current time
    Assert(node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    node.validation_signals->SyncWithValidationInterfaceQueue(); // drain events queue
}

static void TestP2PBlockAdmissionOrdering(P2PBlockPeerManagerTest& test, bool first_new_block)
{
    {
        CNode& source{test.AddNode()};
        CNode& unrelated{test.AddNode()};
        const CBlock source_block{test.NextBlock(/*variant=*/1)};
        const CBlock unrelated_block{test.NextBlock(/*variant=*/2)};
        const auto source_last_block_time{source.m_last_block_time.load()};

        test.ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(source_block)));
        test.ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{1}));
        test.ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::PING, uint64_t{2}));
        test.ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(unrelated_block)));

        (void)test.ProcessMessagesOnce(source);
        auto& block_validation{test.BlockValidation()};
        BOOST_CHECK_EQUAL(block_validation.SubmitCount(), 1U);
        BOOST_CHECK(block_validation.Request().block->GetHash() == source_block.GetHash());
        BOOST_CHECK(!block_validation.Request().force_processing);
        BOOST_CHECK(block_validation.Request().min_pow_checked);
        BOOST_CHECK_EQUAL(source.PeekMessageType().value_or(""), NetMsgType::PING);

        BOOST_CHECK(!test.ProcessMessagesOnce(source));
        BOOST_CHECK_EQUAL(source.PeekMessageType().value_or(""), NetMsgType::PING);
        BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));

        BOOST_CHECK(test.ProcessMessagesOnce(unrelated));
        BOOST_CHECK(HasSendMessage(unrelated, NetMsgType::PONG));
        test.FlushSendBuffer(unrelated);
        BOOST_CHECK_EQUAL(unrelated.PeekMessageType().value_or(""), NetMsgType::BLOCK);
        BOOST_CHECK(!test.ProcessMessagesOnce(unrelated));
        BOOST_CHECK_EQUAL(unrelated.PeekMessageType().value_or(""), NetMsgType::BLOCK);
        BOOST_CHECK_EQUAL(block_validation.SubmitCount(), 1U);

        block_validation.Complete(first_new_block);
        (void)test.ProcessMessagesOnce(source);
        BOOST_CHECK(!source.PeekMessageType().has_value());
        BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));
        if (first_new_block) {
            BOOST_CHECK_NE(source.m_last_block_time.load(), source_last_block_time);
        } else {
            BOOST_CHECK_EQUAL(source.m_last_block_time.load(), source_last_block_time);
        }

        (void)test.ProcessMessagesOnce(unrelated);
        BOOST_CHECK_EQUAL(block_validation.SubmitCount(), 2U);
        BOOST_CHECK(block_validation.Request().block->GetHash() == unrelated_block.GetHash());
        BOOST_CHECK(!block_validation.Request().force_processing);
        BOOST_CHECK(block_validation.Request().min_pow_checked);
        block_validation.Complete(/*new_block=*/false);
        (void)test.ProcessMessagesOnce(unrelated);
        BOOST_CHECK(!block_validation.TakeResult().has_value());
    }
    BOOST_CHECK(test.Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_admission_ordering_new, P2PBlockPeerManagerTest)
{
    TestP2PBlockAdmissionOrdering(*this, /*first_new_block=*/true);
}

BOOST_FIXTURE_TEST_CASE(p2p_block_admission_ordering_not_new, P2PBlockPeerManagerTest)
{
    TestP2PBlockAdmissionOrdering(*this, /*first_new_block=*/false);
}

BOOST_FIXTURE_TEST_CASE(p2p_block_disconnect_completion, P2PBlockPeerManagerTest)
{
    {
        CNode& source{AddNode()};
        CNode& unrelated{AddNode()};
        const CBlock source_block{NextBlock(/*variant=*/3)};
        const CBlock unrelated_block{NextBlock(/*variant=*/4)};
        const auto source_last_block_time{source.m_last_block_time.load()};

        ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(source_block)));
        (void)ProcessMessagesOnce(source);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
        source.fDisconnect = true;
        BlockValidation().Complete(/*new_block=*/true);
        BOOST_CHECK(!ProcessMessagesOnce(unrelated));
        BOOST_CHECK_EQUAL(source.m_last_block_time.load(), source_last_block_time);

        ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(unrelated_block)));
        (void)ProcessMessagesOnce(unrelated);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 2U);
        BOOST_CHECK(BlockValidation().Request().block->GetHash() == unrelated_block.GetHash());
        BlockValidation().Complete(/*new_block=*/false);
        (void)ProcessMessagesOnce(unrelated);
        BOOST_CHECK(!BlockValidation().TakeResult().has_value());
    }
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_stop_drains_completion, P2PBlockPeerManagerTest)
{
    {
        CNode& source{AddNode()};
        const CBlock block{NextBlock(/*variant=*/5)};
        ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
        (void)ProcessMessagesOnce(source);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);

        BlockValidation().Complete(/*new_block=*/true);
        Peerman().Stop();
        BOOST_CHECK(BlockValidation().Stopped());
        BOOST_CHECK(!BlockValidation().TakeResult().has_value());
    }
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_interrupt_before_submit, P2PBlockPeerManagerTest)
{
    {
        CNode& source{AddNode()};
        const CBlock block{NextBlock(/*variant=*/6)};
        ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
        ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{3}));

        Peerman().Interrupt();
        BOOST_CHECK(BlockValidation().Interrupted());
        (void)ProcessMessagesOnce(source);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
        BOOST_CHECK(!BlockValidation().TakeResult().has_value());
        BOOST_CHECK_EQUAL(source.PeekMessageType().value_or(""), NetMsgType::PING);
        BOOST_CHECK(!ProcessMessagesOnce(source));
        BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));
    }
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_global_bound, P2PBlockPeerManagerTest)
{
    {
        std::array<CNode*, 3> nodes{&AddNode(), &AddNode(), &AddNode()};
        const std::array<CBlock, 3> blocks{
            NextBlock(/*variant=*/7),
            NextBlock(/*variant=*/8),
            NextBlock(/*variant=*/9),
        };
        for (size_t i{0}; i < nodes.size(); ++i) {
            ReceiveMsgFrom(*nodes[i], NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(blocks[i])));
        }

        (void)ProcessMessagesOnce(*nodes[0]);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
        BOOST_CHECK(BlockValidation().Request().block->GetHash() == blocks[0].GetHash());
        BOOST_CHECK(!ProcessMessagesOnce(*nodes[1]));
        BOOST_CHECK(!ProcessMessagesOnce(*nodes[2]));
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
        BOOST_CHECK_EQUAL(nodes[1]->PeekMessageType().value_or(""), NetMsgType::BLOCK);
        BOOST_CHECK_EQUAL(nodes[2]->PeekMessageType().value_or(""), NetMsgType::BLOCK);

        BlockValidation().Complete(/*new_block=*/false);
        (void)ProcessMessagesOnce(*nodes[0]);
        (void)ProcessMessagesOnce(*nodes[1]);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 2U);
        BOOST_CHECK(BlockValidation().Request().block->GetHash() == blocks[1].GetHash());
        BOOST_CHECK_EQUAL(nodes[2]->PeekMessageType().value_or(""), NetMsgType::BLOCK);
        BlockValidation().Complete(/*new_block=*/false);
        (void)ProcessMessagesOnce(*nodes[1]);

        (void)ProcessMessagesOnce(*nodes[2]);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 3U);
        BOOST_CHECK(BlockValidation().Request().block->GetHash() == blocks[2].GetHash());
        BlockValidation().Complete(/*new_block=*/false);
        (void)ProcessMessagesOnce(*nodes[2]);
        BOOST_CHECK(!BlockValidation().TakeResult().has_value());
    }
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_getdata_deferral_and_ordering, P2PBlockPeerManagerTest)
{
    {
        CNode& source{AddNode()};
        CNode& backlogged{AddNode()};
        CNode& deferred{AddNode()};
        const CBlock source_block{NextBlock(/*variant=*/11)};
        const uint256 first_backlogged_hash{NextBlock(/*variant=*/12).GetHash()};
        const uint256 second_backlogged_hash{NextBlock(/*variant=*/13).GetHash()};

        ReceiveMsgFrom(backlogged, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
            CInv{MSG_BLOCK, first_backlogged_hash},
            CInv{MSG_BLOCK, second_backlogged_hash},
        }));
        (void)ProcessMessagesOnce(backlogged);

        ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(source_block)));
        (void)ProcessMessagesOnce(source);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
        BOOST_CHECK(BlockValidation().Request().block->GetHash() == source_block.GetHash());

        ReceiveMsgFrom(backlogged, NetMsg::Make(NetMsgType::PING, uint64_t{4}));
        const uint256 deferred_hash{NextBlock(/*variant=*/14).GetHash()};
        ReceiveMsgFrom(deferred, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
            CInv{MSG_BLOCK, deferred_hash},
        }));
        ReceiveMsgFrom(deferred, NetMsg::Make(NetMsgType::PING, uint64_t{5}));

        BOOST_CHECK(!ProcessMessagesOnce(backlogged));
        BOOST_CHECK_EQUAL(backlogged.PeekMessageType().value_or(""), NetMsgType::PING);
        BOOST_CHECK(!HasSendMessage(backlogged, NetMsgType::PONG));

        BOOST_CHECK(!ProcessMessagesOnce(deferred));
        BOOST_CHECK_EQUAL(deferred.PeekMessageType().value_or(""), NetMsgType::GETDATA);
        BOOST_CHECK(!HasSendMessage(deferred, NetMsgType::PONG));
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);

        BlockValidation().Complete(/*new_block=*/false);
        (void)ProcessMessagesOnce(source);

        (void)ProcessMessagesOnce(backlogged);
        BOOST_CHECK(HasSendMessage(backlogged, NetMsgType::PONG));
        BOOST_CHECK(!backlogged.PeekMessageType().has_value());

        (void)ProcessMessagesOnce(deferred);
        BOOST_CHECK_EQUAL(deferred.PeekMessageType().value_or(""), NetMsgType::PING);
        BOOST_CHECK(!HasSendMessage(deferred, NetMsgType::PONG));
        (void)ProcessMessagesOnce(deferred);
        BOOST_CHECK(HasSendMessage(deferred, NetMsgType::PONG));
        BOOST_CHECK(!deferred.PeekMessageType().has_value());
    }
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_repeated_interrupt_stop, P2PBlockPeerManagerTest)
{
    {
        CNode& source{AddNode()};
        const CBlock block{NextBlock(/*variant=*/10)};
        ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
        (void)ProcessMessagesOnce(source);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
        BlockValidation().Complete(/*new_block=*/false);
        (void)ProcessMessagesOnce(source);
        BOOST_CHECK(!BlockValidation().TakeResult().has_value());

        Peerman().Interrupt();
        Peerman().Interrupt();
        Peerman().Stop();
        Peerman().Stop();
        BOOST_CHECK(BlockValidation().Interrupted());
        BOOST_CHECK(BlockValidation().Stopped());
    }
    BOOST_CHECK(Shutdown());
}

// Verifying when network-limited peer connections are desirable based on the node's proximity to the tip
BOOST_AUTO_TEST_CASE(connections_desirable_service_flags)
{
    FakeNodeClock clock{};
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    auto consensus = m_node.chainman->GetParams().GetConsensus();

    // Check we start connecting to full nodes
    ServiceFlags peer_flags{NODE_WITNESS | NODE_NETWORK_LIMITED};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // Make peerman aware of the initial best block and verify we accept limited peers when we start close to the tip time.
    auto tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    uint64_t tip_block_time = tip->GetBlockTime();
    int tip_block_height = tip->nHeight;
    peerman->SetBestBlock(tip_block_height, std::chrono::seconds{tip_block_time});

    clock.set(std::chrono::seconds{tip_block_time + 1}); // Set node time to tip time
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Check we don't disallow limited peers connections when we are behind but still recoverable (below the connection safety window)
    clock += std::chrono::seconds{consensus.nPowTargetSpacing * (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS - 1)};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Check we disallow limited peers connections when we are further than the limited peers safety window
    clock += std::chrono::seconds{consensus.nPowTargetSpacing * 2};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // By now, we tested that the connections desirable services flags change based on the node's time proximity to the tip.
    // Now, perform the same tests for when the node receives a block.
    m_node.validation_signals->RegisterValidationInterface(peerman.get());

    // First, verify a block in the past doesn't enable limited peers connections
    // At this point, our time is (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1) * 10 minutes ahead the tip's time.
    mineBlock(m_node, clock, /*block_time=*/std::chrono::seconds{tip_block_time + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // Verify a block close to the tip enables limited peers connections
    mineBlock(m_node, clock, /*block_time=*/GetTime<std::chrono::seconds>());
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Lastly, verify the stale tip checks can disallow limited peers connections after not receiving blocks for a prolonged period.
    clock += std::chrono::seconds{consensus.nPowTargetSpacing * NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    peerman->Stop();
    m_node.validation_signals->UnregisterValidationInterface(peerman.get());
}

BOOST_AUTO_TEST_SUITE_END()

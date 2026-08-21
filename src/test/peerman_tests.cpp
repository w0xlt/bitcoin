// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <interfaces/mining.h>
#include <netmessagemaker.h>
#include <net_processing.h>
#include <node/miner.h>
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
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

class FakeP2PBlockValidation final : public node::P2PBlockValidation
{
public:
    node::P2PBlockValidationSubmit Submit(node::P2PBlockValidationRequest request) override
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        ++m_submit_count;
        if (m_interrupted) return node::P2PBlockValidationSubmit::INTERRUPTED;
        Assert(!m_request && !m_result);
        Assert(request.block != nullptr);
        m_request = std::move(request);
        return node::P2PBlockValidationSubmit::ACCEPTED;
    }

    std::optional<node::P2PBlockValidationResult> TakeResult() override
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        auto result{std::move(m_result)};
        m_result.reset();
        return result;
    }

    void Interrupt() override
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        m_interrupted = true;
    }

    void Stop() override
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        m_interrupted = true;
        if (m_request) {
            m_stop_waiting = true;
            m_stop_cv.notify_all();
        }
        m_cv.wait(lock, [this] { return !m_request; });
        m_stop_waiting = false;
        m_stopped = true;
    }

    node::P2PBlockValidationRequest Request() const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return *Assert(m_request);
    }

    size_t SubmitCount() const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return m_submit_count;
    }

    bool HasRequest() const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return m_request.has_value();
    }

    bool WaitForStopBlocked(std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        return m_stop_cv.wait_for(lock, timeout, [this] {
            return m_stop_waiting && m_request.has_value();
        });
    }

    void Complete(bool new_block)
    {
        {
            std::lock_guard<std::mutex> lock{m_mutex};
            Assert(m_request);
            Assert(!m_result);
            m_request.reset();
            m_result = node::P2PBlockValidationResult{new_block};
        }
        m_cv.notify_all();
    }

    bool Interrupted() const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return m_interrupted;
    }

    bool Stopped() const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return m_stopped;
    }

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::condition_variable m_stop_cv;
    std::optional<node::P2PBlockValidationRequest> m_request;
    std::optional<node::P2PBlockValidationResult> m_result;
    size_t m_submit_count{0};
    bool m_interrupted{false};
    bool m_stop_waiting{false};
    bool m_stopped{false};
};

class PrefilledCompactBlock final : public CBlockHeaderAndShortTxIDs
{
public:
    PrefilledCompactBlock(const CBlock& block, uint64_t nonce)
        : CBlockHeaderAndShortTxIDs{block, nonce}
    {
    }

    void PrefillAll(const CBlock& block)
    {
        shorttxids.clear();
        prefilledtxn.clear();
        for (const CTransactionRef& tx : block.vtx) {
            prefilledtxn.push_back(PrefilledTransaction{/*index=*/0, tx});
        }
    }
};

struct P2PBlockPeerManagerTest : RegTestingSetup {
    P2PBlockPeerManagerTest()
        : m_connman{static_cast<ConnmanTestMsg&>(*m_node.connman)}
    {
        Assert(m_node.peerman)->Interrupt();
        m_node.peerman->Stop();
        m_connman.StopNodes();
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();

        auto block_validation{std::make_unique<FakeP2PBlockValidation>()};
        m_block_validation = block_validation.get();
        PeerManager::Options options;
        options.deterministic_rng = true;
        m_node.peerman = PeerManager::make(
            m_connman, *m_node.addrman, m_node.banman.get(), *m_node.chainman,
            *m_node.mempool, *m_node.warnings, options, std::move(block_validation));
        m_connman.SetMsgProc(m_node.peerman.get());
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
    }

    ~P2PBlockPeerManagerTest() { Shutdown(); }

    CNode& AddNode(
        bool successfully_connected = true,
        ConnectionType connection_type = ConnectionType::INBOUND)
    {
        const NodeId node_id{m_next_node_id++};
        struct in_addr raw_address;
        raw_address.s_addr = 0xa0b0c001 + node_id;
        const CAddress address{
            CService{CNetAddr{raw_address}, Params().GetDefaultPort()},
            ServiceFlags{NODE_NETWORK | NODE_WITNESS}};
        auto* node{new CNode{
            node_id,
            /*sock=*/nullptr,
            address,
            /*nKeyedNetGroupIn=*/0,
            /*nLocalHostNonceIn=*/0,
            CAddress{},
            /*addrNameIn=*/"",
            connection_type,
            /*inbound_onion=*/false,
            /*network_key=*/0}};
        m_connman.AddTestNode(*node);
        LOCK(NetEventsInterface::g_msgproc_mutex);
        m_connman.Handshake(
            *node,
            successfully_connected,
            /*remote_services=*/ServiceFlags{NODE_NETWORK | NODE_WITNESS},
            /*local_services=*/ServiceFlags{NODE_NETWORK | NODE_WITNESS},
            /*version=*/PROTOCOL_VERSION,
            /*relay_txs=*/true);
        m_connman.FlushSendBuffer(*node);
        node->fPauseSend = false;
        return *node;
    }

    bool ProcessMessagesOnce(CNode& node)
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        return m_connman.ProcessMessagesOnce(node);
    }

    bool SendMessagesOnce(CNode& node)
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        return Peerman().SendMessages(node);
    }

    void ReceiveMsgFrom(CNode& node, CSerializedNetMsg msg)
    {
        Assert(m_connman.ReceiveMsgFrom(node, std::move(msg)));
    }

    CBlock NextBlock(uint32_t variant, bool extra_tx = false)
    {
        auto mining{interfaces::MakeMining(m_node)};
        auto block_template{mining->createNewBlock({}, /*cooldown=*/false)};
        CBlock block{Assert(block_template)->getBlock()};
        block.nTime += variant;
        if (extra_tx) {
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
            tx.vout.emplace_back(0, CScript{} << OP_TRUE);
            block.vtx.push_back(MakeTransactionRef(std::move(tx)));
            node::RegenerateCommitments(block, *m_node.chainman);
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;
        return block;
    }

    const CBlockIndex& ProcessHeader(const CBlock& block)
    {
        BlockValidationState state;
        const CBlockIndex* index{nullptr};
        Assert(m_node.chainman->ProcessNewBlockHeaders({{block}}, /*min_pow_checked=*/true, state, &index));
        return *Assert(index);
    }

    CBlockHeaderAndShortTxIDs CompactBlock(const CBlock& block, bool prefill_all)
    {
        PrefilledCompactBlock compact{block, /*nonce=*/0};
        if (prefill_all) compact.PrefillAll(block);
        return compact;
    }

    FakeP2PBlockValidation& BlockValidation() { return *Assert(m_block_validation); }
    PeerManager& Peerman() { return *Assert(m_node.peerman); }

    void SignalBlockChecked(const CBlock& block, const BlockValidationState& state)
    {
        m_node.validation_signals->BlockChecked(std::make_shared<const CBlock>(block), state);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
    }

    void FlushSendBuffer(CNode& node)
    {
        m_connman.FlushSendBuffer(node);
        node.fPauseSend = false;
    }

    bool Shutdown()
    {
        if (!m_node.peerman) return m_stopped;
        m_node.peerman->Interrupt();
        if (Assert(m_block_validation)->HasRequest()) m_block_validation->Complete(/*new_block=*/false);
        m_node.peerman->Stop();
        m_stopped = Assert(m_block_validation)->Stopped();
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
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

std::string FirstSendMessageType(CNode& node)
{
    LOCK(node.cs_vSend);
    const auto& [to_send, _more, transport_msg_type]{node.m_transport->GetBytesToSend(false)};
    if (!to_send.empty()) return transport_msg_type;
    return node.vSendMsg.empty() ? std::string{} : node.vSendMsg.front().m_type;
}

bool HasBlocksInFlight(PeerManager& peerman, NodeId node_id)
{
    CNodeStateStats stats;
    Assert(peerman.GetNodeStateStats(node_id, stats));
    return !stats.vHeightInFlight.empty();
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

static void TestP2PBlockSourceOrdering(P2PBlockPeerManagerTest& test, bool new_block)
{
    CNode& source{test.AddNode()};
    CNode& request_peer{test.AddNode()};
    CNode& unrelated{test.AddNode()};
    const CBlock block{test.NextBlock(/*variant=*/1)};
    const CBlockIndex& index{test.ProcessHeader(block)};
    const auto source_last_block_time{source.m_last_block_time.load()};
    const auto fetch_result{test.Peerman().FetchBlock(request_peer.GetId(), index)};
    const bool fetch_ok{bool{fetch_result}};
    const std::string fetch_error{fetch_ok ? "" : fetch_result.error()};
    BOOST_REQUIRE_MESSAGE(fetch_ok, fetch_error);
    BOOST_CHECK(HasBlocksInFlight(test.Peerman(), request_peer.GetId()));

    test.ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    if (new_block) {
        test.ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PONG, uint64_t{1}));
    }
    test.ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{2}));
    test.ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::PING, uint64_t{3}));

    (void)test.ProcessMessagesOnce(source);
    auto& block_validation{test.BlockValidation()};
    BOOST_CHECK_EQUAL(block_validation.SubmitCount(), 1U);
    BOOST_CHECK(block_validation.Request().block->GetHash() == block.GetHash());
    BOOST_CHECK(block_validation.Request().force_processing);
    BOOST_CHECK(block_validation.Request().min_pow_checked);

    BOOST_CHECK(!test.ProcessMessagesOnce(source));
    BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
    if (new_block) {
        BOOST_CHECK(!test.ProcessMessagesOnce(source));
        BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
    }
    BOOST_CHECK(!test.ProcessMessagesOnce(unrelated));
    BOOST_CHECK(HasSendMessage(unrelated, NetMsgType::PONG));

    block_validation.Complete(new_block);
    if (new_block) {
        BOOST_CHECK(test.ProcessMessagesOnce(source));
        BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
    }
    BOOST_CHECK(!test.ProcessMessagesOnce(source));
    BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));
    if (new_block) {
        BOOST_CHECK_NE(source.m_last_block_time.load(), source_last_block_time);
        BOOST_CHECK(!HasBlocksInFlight(test.Peerman(), request_peer.GetId()));
    } else {
        BOOST_CHECK_EQUAL(source.m_last_block_time.load(), source_last_block_time);
        BOOST_CHECK(HasBlocksInFlight(test.Peerman(), request_peer.GetId()));

        BlockValidationState invalid;
        invalid.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "test-invalid");
        test.SignalBlockChecked(block, invalid);
        BOOST_CHECK(test.SendMessagesOnce(source));
        BOOST_CHECK(!source.fDisconnect);
    }

    BOOST_CHECK(test.Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_source_ordering_new, P2PBlockPeerManagerTest)
{
    TestP2PBlockSourceOrdering(*this, /*new_block=*/true);
}

BOOST_FIXTURE_TEST_CASE(p2p_block_source_ordering_not_new, P2PBlockPeerManagerTest)
{
    TestP2PBlockSourceOrdering(*this, /*new_block=*/false);
}

BOOST_FIXTURE_TEST_CASE(p2p_block_exact_unrelated_allowlist, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& unrelated{AddNode()};
    const CBlock block{NextBlock(/*variant=*/2)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    (void)ProcessMessagesOnce(source);

    ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::PONG, uint64_t{3}));
    ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::PING, uint64_t{4}));
    BOOST_CHECK(ProcessMessagesOnce(unrelated));
    BOOST_CHECK(!HasSendMessage(unrelated, NetMsgType::PONG));
    BOOST_CHECK(!ProcessMessagesOnce(unrelated));
    BOOST_CHECK(HasSendMessage(unrelated, NetMsgType::PONG));
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);

    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_default_deny_and_allowed_then_denied, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& denied_first{AddNode()};
    CNode& allowed_first{AddNode()};
    const CBlock block{NextBlock(/*variant=*/3)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    (void)ProcessMessagesOnce(source);

    ReceiveMsgFrom(denied_first, NetMsg::Make("futuremsg"));
    ReceiveMsgFrom(denied_first, NetMsg::Make(NetMsgType::PING, uint64_t{5}));
    BOOST_CHECK(!ProcessMessagesOnce(denied_first));
    BOOST_CHECK(!ProcessMessagesOnce(denied_first));
    BOOST_CHECK(!HasSendMessage(denied_first, NetMsgType::PONG));

    ReceiveMsgFrom(allowed_first, NetMsg::Make(NetMsgType::PING, uint64_t{6}));
    ReceiveMsgFrom(allowed_first, NetMsg::Make("futuremsg"));
    ReceiveMsgFrom(allowed_first, NetMsg::Make(NetMsgType::PING, uint64_t{7}));
    BOOST_CHECK(!ProcessMessagesOnce(allowed_first));
    BOOST_CHECK(HasSendMessage(allowed_first, NetMsgType::PONG));
    FlushSendBuffer(allowed_first);
    BOOST_CHECK(!ProcessMessagesOnce(allowed_first));
    BOOST_CHECK(!HasSendMessage(allowed_first, NetMsgType::PONG));

    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(source);

    BOOST_CHECK(ProcessMessagesOnce(denied_first));
    BOOST_CHECK(!HasSendMessage(denied_first, NetMsgType::PONG));
    BOOST_CHECK(!ProcessMessagesOnce(denied_first));
    BOOST_CHECK(HasSendMessage(denied_first, NetMsgType::PONG));

    BOOST_CHECK(ProcessMessagesOnce(allowed_first));
    BOOST_CHECK(!HasSendMessage(allowed_first, NetMsgType::PONG));
    BOOST_CHECK(!ProcessMessagesOnce(allowed_first));
    BOOST_CHECK(HasSendMessage(allowed_first, NetMsgType::PONG));
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_empty_front_and_global_bound, P2PBlockPeerManagerTest)
{
    std::array<CNode*, 3> nodes{&AddNode(), &AddNode(), &AddNode()};
    const std::array<CBlock, 3> blocks{
        NextBlock(/*variant=*/4),
        NextBlock(/*variant=*/5),
        NextBlock(/*variant=*/6),
    };
    ReceiveMsgFrom(*nodes[0], NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(blocks[0])));
    (void)ProcessMessagesOnce(*nodes[0]);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
    BOOST_CHECK(BlockValidation().Request().block->GetHash() == blocks[0].GetHash());
    BOOST_CHECK(!BlockValidation().Request().force_processing);
    BOOST_CHECK(BlockValidation().Request().min_pow_checked);

    BOOST_CHECK(!ProcessMessagesOnce(*nodes[1]));
    ReceiveMsgFrom(*nodes[1], NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(blocks[1])));
    ReceiveMsgFrom(*nodes[2], NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(blocks[2])));
    BOOST_CHECK(!ProcessMessagesOnce(*nodes[1]));
    BOOST_CHECK(!ProcessMessagesOnce(*nodes[2]));
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);

    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(*nodes[0]);
    (void)ProcessMessagesOnce(*nodes[1]);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 2U);
    BOOST_CHECK(BlockValidation().Request().block->GetHash() == blocks[1].GetHash());

    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(*nodes[1]);
    (void)ProcessMessagesOnce(*nodes[2]);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 3U);
    BOOST_CHECK(BlockValidation().Request().block->GetHash() == blocks[2].GetHash());
    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(*nodes[2]);
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_send_deferral_and_mandatory_disconnect, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& send_peer{AddNode()};
    CNode& discouraged{AddNode()};
    const CBlock block{NextBlock(/*variant=*/7)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    (void)ProcessMessagesOnce(source);

    Peerman().SendPings();
    BOOST_CHECK(SendMessagesOnce(send_peer));
    BOOST_CHECK(!HasSendMessage(send_peer, NetMsgType::PING));

    Peerman().UnitTestMisbehaving(discouraged.GetId());
    BOOST_CHECK(SendMessagesOnce(discouraged));
    BOOST_CHECK(discouraged.fDisconnect);

    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK(SendMessagesOnce(send_peer));
    BOOST_CHECK(HasSendMessage(send_peer, NetMsgType::PING));
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_getdata_deferral_and_ordering, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& raw_getdata{AddNode()};
    CNode& parsed_getdata{AddNode()};

    ReceiveMsgFrom(parsed_getdata, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
        CInv{MSG_BLOCK, NextBlock(/*variant=*/8).GetHash()},
        CInv{MSG_BLOCK, NextBlock(/*variant=*/9).GetHash()},
    }));
    BOOST_CHECK(ProcessMessagesOnce(parsed_getdata));

    const CBlock source_block{NextBlock(/*variant=*/10)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(source_block)));
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);

    ReceiveMsgFrom(raw_getdata, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
        CInv{MSG_TX, uint256::ONE},
    }));
    ReceiveMsgFrom(raw_getdata, NetMsg::Make(NetMsgType::PING, uint64_t{8}));
    BOOST_CHECK(!ProcessMessagesOnce(raw_getdata));
    BOOST_CHECK(!ProcessMessagesOnce(raw_getdata));
    BOOST_CHECK(!HasSendMessage(raw_getdata, NetMsgType::PONG));

    ReceiveMsgFrom(parsed_getdata, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
        CInv{MSG_BLOCK, NextBlock(/*variant=*/11).GetHash()},
        CInv{MSG_BLOCK, NextBlock(/*variant=*/12).GetHash()},
    }));
    ReceiveMsgFrom(parsed_getdata, NetMsg::Make(NetMsgType::PING, uint64_t{9}));
    BOOST_CHECK(!ProcessMessagesOnce(parsed_getdata));
    BOOST_CHECK(!ProcessMessagesOnce(parsed_getdata));
    BOOST_CHECK(!HasSendMessage(parsed_getdata, NetMsgType::PONG));

    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(source);

    BOOST_CHECK(ProcessMessagesOnce(raw_getdata));
    BOOST_CHECK(!HasSendMessage(raw_getdata, NetMsgType::PONG));
    BOOST_CHECK(!ProcessMessagesOnce(raw_getdata));
    BOOST_CHECK_EQUAL(FirstSendMessageType(raw_getdata), NetMsgType::NOTFOUND);
    BOOST_CHECK(!HasSendMessage(raw_getdata, NetMsgType::PONG));
    FlushSendBuffer(raw_getdata);
    BOOST_CHECK(!ProcessMessagesOnce(raw_getdata));
    BOOST_CHECK(HasSendMessage(raw_getdata, NetMsgType::PONG));

    BOOST_CHECK(ProcessMessagesOnce(parsed_getdata));
    BOOST_CHECK(!HasSendMessage(parsed_getdata, NetMsgType::PONG));
    for (size_t pass{0}; pass < 4 && !HasSendMessage(parsed_getdata, NetMsgType::PONG); ++pass) {
        (void)ProcessMessagesOnce(parsed_getdata);
    }
    BOOST_CHECK(HasSendMessage(parsed_getdata, NetMsgType::PONG));
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_unconnected_peer_not_allowlisted, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& unconnected{AddNode(/*successfully_connected=*/false)};
    const CBlock block{NextBlock(/*variant=*/13)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    (void)ProcessMessagesOnce(source);

    ReceiveMsgFrom(unconnected, NetMsg::Make(NetMsgType::PING, uint64_t{10}));
    BOOST_CHECK(!ProcessMessagesOnce(unconnected));
    BOOST_CHECK(!HasSendMessage(unconnected, NetMsgType::PONG));
    unconnected.fSuccessfullyConnected = true;
    BOOST_CHECK(!ProcessMessagesOnce(unconnected));
    BOOST_CHECK(HasSendMessage(unconnected, NetMsgType::PONG));

    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_source_disconnect_releases_slot, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& replacement{AddNode()};
    const CBlock source_block{NextBlock(/*variant=*/14)};
    const CBlock replacement_block{NextBlock(/*variant=*/15)};
    const auto source_last_block_time{source.m_last_block_time.load()};

    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(source_block)));
    (void)ProcessMessagesOnce(source);
    source.fDisconnect = true;
    BlockValidation().Complete(/*new_block=*/true);
    BOOST_CHECK(!ProcessMessagesOnce(replacement));
    BOOST_CHECK_EQUAL(source.m_last_block_time.load(), source_last_block_time);

    ReceiveMsgFrom(replacement, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(replacement_block)));
    (void)ProcessMessagesOnce(replacement);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 2U);
    BOOST_CHECK(BlockValidation().Request().block->GetHash() == replacement_block.GetHash());
    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(replacement);
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_interrupt_before_submit_and_repeated_lifecycle, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock(/*variant=*/16)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{11}));

    Peerman().Interrupt();
    Peerman().Interrupt();
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
    BOOST_CHECK(!BlockValidation().HasRequest());
    BOOST_CHECK(!BlockValidation().TakeResult());
    BOOST_CHECK(!ProcessMessagesOnce(source));
    BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));

    Peerman().Stop();
    Peerman().Stop();
    BOOST_CHECK(BlockValidation().Interrupted());
    BOOST_CHECK(BlockValidation().Stopped());
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_stop_drains_accepted_request, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock(/*variant=*/17)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK(BlockValidation().HasRequest());

    auto stop{std::async(std::launch::async, [this] { Peerman().Stop(); })};
    BOOST_CHECK(BlockValidation().WaitForStopBlocked(5s));
    BOOST_CHECK(stop.wait_for(0ms) == std::future_status::timeout);
    BlockValidation().Complete(/*new_block=*/true);
    BOOST_REQUIRE(stop.wait_for(5s) == std::future_status::ready);
    stop.get();
    BOOST_CHECK(BlockValidation().Stopped());
    BOOST_CHECK(!BlockValidation().TakeResult());
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_blocktxn_origin, P2PBlockPeerManagerTest)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock(/*variant=*/18, /*extra_tx=*/true)};
    const CBlockIndex& index{ProcessHeader(block)};

    ReceiveMsgFrom(source, NetMsg::Make(
                               NetMsgType::SENDCMPCT,
                               /*high_bandwidth=*/false,
                               /*version=*/uint64_t{CMPCTBLOCKS_VERSION}));
    (void)ProcessMessagesOnce(source);
    FlushSendBuffer(source);

    const auto fetch_result{Peerman().FetchBlock(source.GetId(), index)};
    const bool fetch_ok{bool{fetch_result}};
    const std::string fetch_error{fetch_ok ? "" : fetch_result.error()};
    BOOST_REQUIRE_MESSAGE(fetch_ok, fetch_error);
    FlushSendBuffer(source);

    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::CMPCTBLOCK, CompactBlock(block, /*prefill_all=*/false)));
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 0U);
    BOOST_CHECK(HasSendMessage(source, NetMsgType::GETBLOCKTXN));
    FlushSendBuffer(source);

    BlockTransactions response;
    response.blockhash = block.GetHash();
    response.txn = {block.vtx[1]};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCKTXN, response));
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
    BOOST_CHECK(BlockValidation().Request().block->GetHash() == block.GetHash());
    BOOST_CHECK(BlockValidation().Request().force_processing);
    BOOST_CHECK(BlockValidation().Request().min_pow_checked);

    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(source);
    BOOST_CHECK(Shutdown());
}

BOOST_FIXTURE_TEST_CASE(p2p_block_optimistic_cmpctblock_origin_and_continuation, P2PBlockPeerManagerTest)
{
    std::array<CNode*, 4> peers{
        &AddNode(/*successfully_connected=*/true, ConnectionType::OUTBOUND_FULL_RELAY),
        &AddNode(),
        &AddNode(),
        &AddNode(),
    };
    const CBlock block{NextBlock(/*variant=*/19, /*extra_tx=*/true)};
    const CBlockIndex& index{ProcessHeader(block)};

    for (CNode* peer : peers) {
        ReceiveMsgFrom(*peer, NetMsg::Make(
                                  NetMsgType::SENDCMPCT,
                                  /*high_bandwidth=*/false,
                                  /*version=*/uint64_t{CMPCTBLOCKS_VERSION}));
        (void)ProcessMessagesOnce(*peer);
        peer->m_bip152_highbandwidth_to = true;
        FlushSendBuffer(*peer);
    }

    const auto fetch_result{Peerman().FetchBlock(peers[0]->GetId(), index)};
    BOOST_REQUIRE(bool{fetch_result});
    FlushSendBuffer(*peers[0]);

    const auto partial_compact{CompactBlock(block, /*prefill_all=*/false)};
    for (size_t peer_index{0}; peer_index < 3; ++peer_index) {
        ReceiveMsgFrom(*peers[peer_index], NetMsg::Make(NetMsgType::CMPCTBLOCK, partial_compact));
        (void)ProcessMessagesOnce(*peers[peer_index]);
        BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 0U);
        BOOST_CHECK(HasBlocksInFlight(Peerman(), peers[peer_index]->GetId()));
        FlushSendBuffer(*peers[peer_index]);
    }

    ReceiveMsgFrom(*peers[3], NetMsg::Make(NetMsgType::CMPCTBLOCK, CompactBlock(block, /*prefill_all=*/true)));
    (void)ProcessMessagesOnce(*peers[3]);
    BOOST_CHECK_EQUAL(BlockValidation().SubmitCount(), 1U);
    BOOST_CHECK(BlockValidation().Request().block->GetHash() == block.GetHash());
    BOOST_CHECK(BlockValidation().Request().force_processing);
    BOOST_CHECK(BlockValidation().Request().min_pow_checked);

    {
        LOCK(cs_main);
        CBlockIndex* mutable_index{Assert(m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash()))};
        BOOST_CHECK(mutable_index->RaiseValidity(BLOCK_VALID_TRANSACTIONS));
    }
    BlockValidation().Complete(/*new_block=*/false);
    (void)ProcessMessagesOnce(*peers[3]);
    for (size_t peer_index{0}; peer_index < 3; ++peer_index) {
        BOOST_CHECK(!HasBlocksInFlight(Peerman(), peers[peer_index]->GetId()));
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

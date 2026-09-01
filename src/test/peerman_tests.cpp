// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <banman.h>
#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <interfaces/mining.h>
#include <logging.h>
#include <netmessagemaker.h>
#include <net_processing.h>
#include <node/p2p_block_validation.h>
#include <pow.h>
#include <primitives/block.h>
#include <protocol.h>
#include <sync.h>
#include <test/util/logging.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>

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
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

constexpr auto ASYNC_PNB_TEST_TIMEOUT{std::chrono::seconds{30}};

class P2PBlockProcessorGate
{
public:
    struct Call {
        uint256 hash;
        bool force_processing;
        bool min_pow_checked;
    };

    explicit P2PBlockProcessorGate(ChainstateManager& chainman) : m_chainman{chainman} {}

    bool Process(const std::shared_ptr<const CBlock>& block, bool force_processing,
                 bool min_pow_checked) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        int call;
        bool throw_exception;
        std::optional<bool> new_block_override;
        {
            WAIT_LOCK(m_mutex, lock);
            call = ++m_calls;
            m_call.emplace_back(block->GetHash(), force_processing, min_pow_checked);
            m_cv.notify_all();
            m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_allowed >= call; });
            ++m_entered;
            m_cv.notify_all();
            m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_released >= call; });
            throw_exception = m_throw_on == call;
            if (m_new_block_override && m_new_block_override->first == call) {
                new_block_override = m_new_block_override->second;
            }
        }
        if (throw_exception) throw std::runtime_error{"test P2P block processor failure"};
        bool new_block{false};
        (void)m_chainman.ProcessNewBlock(
            block, force_processing, min_pow_checked, &new_block);
        if (new_block_override) new_block = *new_block_override;
        return new_block;
    }

    bool WaitForCalls(int count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, ASYNC_PNB_TEST_TIMEOUT,
                             [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                                 return m_calls >= count;
                             });
    }

    bool WaitForEntry(int count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, ASYNC_PNB_TEST_TIMEOUT,
                             [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                                 return m_entered >= count;
                             });
    }

    bool WaitForReady(int count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, ASYNC_PNB_TEST_TIMEOUT,
                             [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                                 return m_ready >= count;
                             });
    }

    void Allow(int call) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_allowed = std::max(m_allowed, call);
        }
        m_cv.notify_all();
    }

    void Release(int call) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_released = std::max(m_released, call);
        }
        m_cv.notify_all();
    }

    void ReleaseAll() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        Allow(std::numeric_limits<int>::max());
        Release(std::numeric_limits<int>::max());
    }

    void ThrowOn(int call) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_throw_on = call;
    }

    void OverrideNewBlock(int call, bool new_block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_new_block_override = std::pair{call, new_block};
    }

    void ResultReady() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            ++m_ready;
        }
        m_cv.notify_all();
    }

    int Calls() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_calls;
    }

    Call GetCall(int call) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_call.at(call - 1);
    }

private:
    ChainstateManager& m_chainman;
    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<Call> m_call GUARDED_BY(m_mutex);
    int m_calls GUARDED_BY(m_mutex){0};
    int m_allowed GUARDED_BY(m_mutex){0};
    int m_entered GUARDED_BY(m_mutex){0};
    int m_released GUARDED_BY(m_mutex){0};
    int m_ready GUARDED_BY(m_mutex){0};
    int m_throw_on GUARDED_BY(m_mutex){-1};
    std::optional<std::pair<int, bool>> m_new_block_override GUARDED_BY(m_mutex);
};

struct P2PBlockProcessingSetup : TestChain100Setup {
    P2PBlockProcessingSetup()
        : m_connman{static_cast<ConnmanTestMsg&>(*m_node.connman)},
          m_gate{*m_node.chainman}
    {
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();

        auto worker{node::MakeP2PBlockValidation(
            [this](const std::shared_ptr<const CBlock>& block, bool force_processing,
                   bool min_pow_checked) {
                return m_gate.Process(block, force_processing, min_pow_checked);
            },
            [this] {
                m_gate.ResultReady();
                m_connman.WakeMessageHandler();
            })};
        PeerManager::Options options;
        options.deterministic_rng = true;
        m_node.peerman = PeerManager::make(
            m_connman, *m_node.addrman, m_node.banman.get(), *m_node.chainman,
            *m_node.mempool, *m_node.warnings, options, std::move(worker));
        m_connman.SetMsgProc(m_node.peerman.get());
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
    }

    ~P2PBlockProcessingSetup()
    {
        m_gate.ReleaseAll();
        if (!m_node.peerman) return;
        m_node.peerman->StopP2PBlockValidation();
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_connman.StopNodes();
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();
    }

    CNode& AddNode(ConnectionType connection_type = ConnectionType::INBOUND)
    {
        const NodeId id{m_next_node_id++};
        in_addr raw_address{};
        raw_address.s_addr = 0xa0b0c001 + id;
        auto* node{new CNode{
            id,
            /*sock=*/nullptr,
            CAddress{CService{CNetAddr{raw_address}, Params().GetDefaultPort()},
                     ServiceFlags{NODE_NETWORK | NODE_WITNESS}},
            /*nKeyedNetGroupIn=*/0,
            /*nLocalHostNonceIn=*/0,
            CAddress{},
            /*addrNameIn=*/"",
            connection_type,
            /*inbound_onion=*/false,
            /*network_key=*/0}};
        node->AddRef();
        m_connman.AddTestNode(*node);
        LOCK(NetEventsInterface::g_msgproc_mutex);
        m_connman.Handshake(
            *node, /*successfully_connected=*/true,
            ServiceFlags{NODE_NETWORK | NODE_WITNESS},
            ServiceFlags{NODE_NETWORK | NODE_WITNESS},
            PROTOCOL_VERSION, /*relay_txs=*/true);
        m_connman.FlushSendBuffer(*node);
        node->fPauseSend = false;
        Assert(m_connman.ReceiveMsgFrom(
            *node, NetMsg::Make(NetMsgType::SENDCMPCT,
                                /*high_bandwidth=*/true,
                                CMPCTBLOCKS_VERSION)));
        for (int turns{0}; !node->m_bip152_highbandwidth_from && turns < 16; ++turns) {
            (void)m_connman.ProcessMessagesOnce(*node);
        }
        BOOST_REQUIRE(node->m_bip152_highbandwidth_from);
        node->m_bip152_highbandwidth_to = true;
        m_connman.FlushSendBuffer(*node);
        node->fPauseSend = false;
        return *node;
    }

    CBlock NextBlock(const std::vector<CMutableTransaction>& transactions = {})
    {
        return CreateBlock(transactions, CScript{} << OP_TRUE);
    }

    std::pair<CBlock, CTransactionRef> NextBlockWithMissingTransaction()
    {
        CMutableTransaction tx{CreateValidMempoolTransaction(
            m_coinbase_txns.at(0), /*input_vout=*/0, /*input_height=*/1,
            coinbaseKey, GetScriptForDestination(PKHash{coinbaseKey.GetPubKey()}),
            /*output_amount=*/1 * COIN,
            /*submit=*/false)};
        return {NextBlock({tx}), MakeTransactionRef(std::move(tx))};
    }

    void Receive(CNode& node, CSerializedNetMsg message)
    {
        // The test transport is reused bidirectionally; finish any response
        // inspected by the caller before injecting the next peer message.
        m_connman.FlushSendBuffer(node);
        node.fPauseSend = false;
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(node, std::move(message)));
    }

    bool Process(CNode& node)
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        return m_connman.ProcessMessagesOnce(node);
    }

    bool Send(CNode& node)
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        return m_node.peerman->SendMessages(node);
    }

    void ProcessEvents()
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        m_node.peerman->ProcessEvents();
    }

    int Height() const
    {
        return WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    }

    ConnmanTestMsg& m_connman;
    P2PBlockProcessorGate m_gate;
    NodeId m_next_node_id{0};
};

bool HasSendMessage(CNode& node, std::string_view message_type)
{
    LOCK(node.cs_vSend);
    const auto& [to_send, _more, transport_type]{node.m_transport->GetBytesToSend(false)};
    if (!to_send.empty() && transport_type == message_type) return true;
    return std::any_of(node.vSendMsg.begin(), node.vSendMsg.end(),
                       [&](const CSerializedNetMsg& message) {
                           return message.m_type == message_type;
                       });
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2p_block_processing_tests, P2PBlockProcessingSetup)

BOOST_AUTO_TEST_CASE(full_block_source_fence_and_unrelated_fifo)
{
    CNode& source{AddNode()};
    CNode& unrelated{AddNode()};
    CNode& producer_front{AddNode()};
    const CBlock block{NextBlock()};
    const CBlock blocked_block{NextBlock()};
    const int initial_height{Height()};
    const auto initial_last_block_time{source.m_last_block_time.load()};

    m_gate.Allow(1);
    Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    BOOST_CHECK(!Process(source));
    BOOST_REQUIRE(m_gate.WaitForEntry(1));

    Receive(source, NetMsg::Make(NetMsgType::PING, uint64_t{1}));
    Receive(unrelated, NetMsg::Make(NetMsgType::PING, uint64_t{2}));
    Receive(producer_front, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(blocked_block)));
    Receive(producer_front, NetMsg::Make(NetMsgType::PING, uint64_t{3}));

    BOOST_CHECK(!Process(source));
    BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
    BOOST_CHECK(!Process(unrelated));
    BOOST_CHECK(HasSendMessage(unrelated, NetMsgType::PONG));
    BOOST_CHECK(!Process(producer_front));
    BOOST_CHECK(!HasSendMessage(producer_front, NetMsgType::PONG));

    m_node.peerman->SendPings();
    BOOST_CHECK(Send(source));
    BOOST_CHECK(!HasSendMessage(source, NetMsgType::PING));
    BOOST_CHECK(Send(unrelated));
    BOOST_CHECK(HasSendMessage(unrelated, NetMsgType::PING));

    m_gate.Release(1);
    BOOST_REQUIRE(m_gate.WaitForReady(1));
    ProcessEvents();
    BOOST_CHECK_EQUAL(source.m_last_block_time.load(), initial_last_block_time);
    BOOST_CHECK(!Process(unrelated));
    BOOST_CHECK(Process(source));
    BOOST_CHECK_EQUAL(Height(), initial_height + 1);
    BOOST_CHECK_NE(source.m_last_block_time.load(), initial_last_block_time);
    BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
    m_connman.FlushSendBuffer(source);
    source.fPauseSend = false;
    BOOST_CHECK(!Process(source));
    BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));

    auto front{producer_front.PollMessage()};
    BOOST_REQUIRE(front);
    BOOST_CHECK_EQUAL(front->first.m_type, NetMsgType::BLOCK);
    BOOST_CHECK_EQUAL(m_gate.Calls(), 1);
}

BOOST_AUTO_TEST_CASE(zero_missing_compact_block_uses_worker)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock()};
    const int initial_height{Height()};
    const auto initial_last_block_time{source.m_last_block_time.load()};
    const CBlockHeaderAndShortTxIDs compact{block, /*nonce=*/0};

    m_gate.Allow(1);
    Receive(source, NetMsg::Make(NetMsgType::CMPCTBLOCK, TX_WITH_WITNESS(compact)));
    BOOST_CHECK(!Process(source));
    BOOST_REQUIRE(m_gate.WaitForEntry(1));
    const auto call{m_gate.GetCall(1)};
    BOOST_CHECK(call.hash == block.GetHash());
    BOOST_CHECK(call.force_processing);
    BOOST_CHECK(call.min_pow_checked);
    BOOST_CHECK_EQUAL(Height(), initial_height);

    m_gate.Release(1);
    BOOST_REQUIRE(m_gate.WaitForReady(1));
    BOOST_CHECK(Process(source));
    BOOST_CHECK_EQUAL(Height(), initial_height + 1);
    BOOST_CHECK_NE(source.m_last_block_time.load(), initial_last_block_time);
    BOOST_CHECK_EQUAL(m_gate.Calls(), 1);
}

BOOST_AUTO_TEST_CASE(wire_blocktxn_uses_worker)
{
    CNode& source{AddNode()};
    auto [block, missing_tx]{NextBlockWithMissingTransaction()};
    const int initial_height{Height()};
    const CBlockHeaderAndShortTxIDs compact{block, /*nonce=*/1};

    Receive(source, NetMsg::Make(NetMsgType::CMPCTBLOCK, TX_WITH_WITNESS(compact)));
    BOOST_CHECK(!Process(source));
    BOOST_CHECK_EQUAL(m_gate.Calls(), 0);
    BOOST_CHECK(HasSendMessage(source, NetMsgType::GETBLOCKTXN));

    BlockTransactions response;
    response.blockhash = block.GetHash();
    response.txn.push_back(missing_tx);
    m_gate.Allow(1);
    Receive(source, NetMsg::Make(NetMsgType::BLOCKTXN, response));
    BOOST_CHECK(!Process(source));
    BOOST_REQUIRE(m_gate.WaitForEntry(1));
    const auto call{m_gate.GetCall(1)};
    BOOST_CHECK(call.hash == block.GetHash());
    BOOST_CHECK(call.force_processing);
    BOOST_CHECK(call.min_pow_checked);
    BOOST_CHECK_EQUAL(Height(), initial_height);

    m_gate.Release(1);
    BOOST_REQUIRE(m_gate.WaitForReady(1));
    BOOST_CHECK(Process(source));
    BOOST_CHECK_EQUAL(Height(), initial_height + 1);
    BOOST_CHECK_EQUAL(m_gate.Calls(), 1);
}

BOOST_AUTO_TEST_CASE(optimistic_compact_block_uses_worker_and_cleans_request)
{
    std::vector<CNode*> downloaders{
        &AddNode(ConnectionType::OUTBOUND_FULL_RELAY),
        &AddNode(),
        &AddNode(),
    };
    CNode& source{AddNode()};
    auto [block, missing_tx]{NextBlockWithMissingTransaction()};
    const int initial_height{Height()};
    const CBlockHeaderAndShortTxIDs compact{block, /*nonce=*/2};

    BOOST_REQUIRE_EQUAL(downloaders.size(), MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);
    for (CNode* downloader : downloaders) {
        Receive(*downloader,
                NetMsg::Make(NetMsgType::CMPCTBLOCK, TX_WITH_WITNESS(compact)));
        BOOST_CHECK(!Process(*downloader));
        BOOST_CHECK_EQUAL(m_gate.Calls(), 0);
        BOOST_CHECK(HasSendMessage(*downloader, NetMsgType::GETBLOCKTXN));
    }

    {
        LOCK(cs_main);
        const MempoolAcceptResult result{m_node.chainman->ProcessTransaction(missing_tx)};
        BOOST_REQUIRE_MESSAGE(
            result.m_result_type == MempoolAcceptResult::ResultType::VALID,
            result.m_state.ToString());
    }

    // Three real download attempts force this fourth high-bandwidth source
    // through the optimistic reconstruction branch. Expose new_block=false
    // after real validation so only that branch's validity-based removal can
    // clear all three requests.
    m_gate.OverrideNewBlock(1, false);
    m_gate.Allow(1);
    Receive(source, NetMsg::Make(NetMsgType::CMPCTBLOCK, TX_WITH_WITNESS(compact)));
    BOOST_CHECK(!Process(source));
    BOOST_REQUIRE(m_gate.WaitForEntry(1));
    BOOST_CHECK(m_gate.GetCall(1).hash == block.GetHash());
    BOOST_CHECK(m_gate.GetCall(1).force_processing);

    m_gate.Release(1);
    BOOST_REQUIRE(m_gate.WaitForReady(1));
    BOOST_CHECK(Process(source));
    BOOST_CHECK_EQUAL(Height(), initial_height + 1);

    // A repeated full block reaches PNB without force processing only if the
    // optimistic path removed every saturated request after validation.
    m_gate.Allow(2);
    Receive(*downloaders.front(),
            NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    BOOST_CHECK(!Process(*downloaders.front()));
    BOOST_REQUIRE(m_gate.WaitForEntry(2));
    BOOST_CHECK(!m_gate.GetCall(2).force_processing);
    m_gate.Release(2);
    BOOST_REQUIRE(m_gate.WaitForReady(2));
    BOOST_CHECK(Process(*downloaders.front()));
    BOOST_CHECK_EQUAL(m_gate.Calls(), 2);
}

BOOST_AUTO_TEST_CASE(processor_exception_is_logged_collected_and_recoverable)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock()};
    const int initial_height{Height()};
    const auto initial_last_block_time{source.m_last_block_time.load()};
    const bool net_logging_enabled{LogInstance().WillLogCategory(BCLog::NET)};
    LogInstance().EnableCategory(BCLog::NET);
    int exception_logs{0};

    {
        DebugLogHelper capture{"test P2P block processor failure",
            [&](const std::string* line) {
                if (line) ++exception_logs;
                return false;
            }};
        m_gate.ThrowOn(1);
        m_gate.Allow(1);
        Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
        BOOST_CHECK(!Process(source));
        BOOST_REQUIRE(m_gate.WaitForEntry(1));
        Receive(source, NetMsg::Make(NetMsgType::PING, uint64_t{1}));
        m_gate.Release(1);
        BOOST_REQUIRE(m_gate.WaitForReady(1));
        BOOST_CHECK(Process(source));
        BOOST_CHECK_EQUAL(Height(), initial_height);
        BOOST_CHECK_EQUAL(source.m_last_block_time.load(), initial_last_block_time);
        BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
        BOOST_CHECK(!Process(source));
        BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));
    }
    BOOST_CHECK_EQUAL(exception_logs, 1);
    if (!net_logging_enabled) LogInstance().DisableCategory(BCLog::NET);

    // Current synchronous unwind retains mapBlockSource. Processing the same
    // block through an unchanged non-P2P caller therefore attributes its valid
    // result to the original source and selects it for compact announcements.
    bool new_block{false};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(block), /*force_processing=*/true,
        /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(source.m_bip152_highbandwidth_to);

    // A terminal error frees the sole slot for the next P2P block.
    const CBlock recovery{NextBlock()};
    m_gate.Allow(2);
    Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(recovery)));
    BOOST_CHECK(!Process(source));
    BOOST_REQUIRE(m_gate.WaitForEntry(2));
    m_gate.Release(2);
    BOOST_REQUIRE(m_gate.WaitForReady(2));
    BOOST_CHECK(Process(source));
    BOOST_CHECK_EQUAL(Height(), initial_height + 2);
}

BOOST_AUTO_TEST_CASE(invalid_attribution_precedes_later_source_work)
{
    CNode& source{AddNode()};
    m_gate.Allow(1);
    Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(CBlock{})));
    BOOST_CHECK(!Process(source));
    BOOST_REQUIRE(m_gate.WaitForEntry(1));
    Receive(source, NetMsg::Make(NetMsgType::PING, uint64_t{1}));

    m_gate.Release(1);
    BOOST_REQUIRE(m_gate.WaitForReady(1));
    BOOST_CHECK(Process(source));
    BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
    BOOST_CHECK(Send(source));
    BOOST_CHECK(source.fDisconnect);
    BOOST_CHECK(m_node.banman->IsDiscouraged(source.addr));
    BOOST_CHECK(!Process(source));
    BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
}

BOOST_AUTO_TEST_CASE(disconnect_is_safe_in_each_job_phase)
{
    const int initial_height{Height()};

    for (int call{1}; call <= 3; ++call) {
        CNode& source{AddNode()};
        const CBlock block{NextBlock()};
        if (call != 1) m_gate.Allow(call);
        Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
        BOOST_CHECK(!Process(source));
        BOOST_REQUIRE(m_gate.WaitForCalls(call));
        if (call != 1) BOOST_REQUIRE(m_gate.WaitForEntry(call));
        if (call == 3) {
            m_gate.Release(call);
            BOOST_REQUIRE(m_gate.WaitForReady(call));
        }

        source.fDisconnect = true;
        m_connman.DisconnectNodesPublic();
        BOOST_CHECK(m_connman.TestNodes().empty());
        if (call == 1) {
            m_gate.Allow(call);
            BOOST_REQUIRE(m_gate.WaitForEntry(call));
        }
        if (call != 3) m_gate.Release(call);
        BOOST_REQUIRE(m_gate.WaitForReady(call));
        ProcessEvents();
        BOOST_CHECK_EQUAL(Height(), initial_height + call);
    }
    BOOST_CHECK_EQUAL(m_gate.Calls(), 3);
}

BOOST_AUTO_TEST_CASE(active_shutdown_drains_and_collects)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock()};
    const int initial_height{Height()};
    const auto initial_last_block_time{source.m_last_block_time.load()};

    m_gate.Allow(1);
    Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    BOOST_CHECK(!Process(source));
    BOOST_REQUIRE(m_gate.WaitForEntry(1));

    std::promise<void> stop_started;
    auto started{stop_started.get_future()};
    std::thread stop{[&] {
        stop_started.set_value();
        m_node.peerman->StopP2PBlockValidation();
    }};
    started.wait();
    m_gate.Release(1);
    stop.join();

    BOOST_CHECK_EQUAL(Height(), initial_height + 1);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash()) ==
                block.GetHash());
    BOOST_CHECK_NE(source.m_last_block_time.load(), initial_last_block_time);
    m_node.peerman->StopP2PBlockValidation();
}

BOOST_AUTO_TEST_CASE(processor_exception_after_disconnect_and_during_shutdown)
{
    const int initial_height{Height()};
    const bool net_logging_enabled{LogInstance().WillLogCategory(BCLog::NET)};
    LogInstance().EnableCategory(BCLog::NET);
    std::atomic<int> exception_logs{0};

    {
        DebugLogHelper capture{"test P2P block processor failure",
            [&](const std::string* line) {
                if (line) ++exception_logs;
                return false;
            }};

        CNode& disconnected_source{AddNode()};
        m_gate.ThrowOn(1);
        m_gate.Allow(1);
        Receive(disconnected_source,
                NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(NextBlock())));
        BOOST_CHECK(!Process(disconnected_source));
        BOOST_REQUIRE(m_gate.WaitForEntry(1));
        disconnected_source.fDisconnect = true;
        m_connman.DisconnectNodesPublic();
        BOOST_CHECK(m_connman.TestNodes().empty());
        m_gate.Release(1);
        BOOST_REQUIRE(m_gate.WaitForReady(1));
        ProcessEvents();
        BOOST_CHECK_EQUAL(Height(), initial_height);

        CNode& shutdown_source{AddNode()};
        m_gate.ThrowOn(2);
        m_gate.Allow(2);
        Receive(shutdown_source,
                NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(NextBlock())));
        BOOST_CHECK(!Process(shutdown_source));
        BOOST_REQUIRE(m_gate.WaitForEntry(2));

        std::promise<void> stop_started;
        auto started{stop_started.get_future()};
        std::thread stop{[&] {
            stop_started.set_value();
            m_node.peerman->StopP2PBlockValidation();
        }};
        started.wait();
        m_gate.Release(2);
        stop.join();
        BOOST_CHECK_EQUAL(Height(), initial_height);
    }
    BOOST_CHECK_EQUAL(exception_logs.load(), 2);
    if (!net_logging_enabled) LogInstance().DisableCategory(BCLog::NET);
}

BOOST_AUTO_TEST_SUITE_END()

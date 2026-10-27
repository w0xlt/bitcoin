// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/block_template_manager.h>
#include <node/miner.h>
#include <node/protocol_version.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <set>
#include <string>
#include <utility>

BOOST_FIXTURE_TEST_SUITE(peerman_tests, RegTestingSetup)

/** Window, in blocks, for connecting to NODE_NETWORK_LIMITED peers */
static constexpr int64_t NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS = 144;

static void mineBlock(node::NodeContext& node, FakeNodeClock& clock, std::chrono::seconds block_time)
{
    auto curr_time = GetTime<std::chrono::seconds>();
    clock.set(block_time); // update time so the block is created with it
    auto& block_template_manager{*Assert(node.block_template_manager)};
    auto block_template{block_template_manager.CreateNewTemplate({})};
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->block};
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

namespace {
/** Holds the thread connecting a block in BlockChecked(), which validation calls with cs_main held. */
class BlockCheckedGate final : public CValidationInterface
{
public:
    std::promise<void> entered;

    void Release()
    {
        if (!m_released.exchange(true)) m_release.set_value();
    }

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState&) override
    {
        if (m_used.exchange(true)) return;
        entered.set_value();
        m_release_future.wait();
    }

private:
    std::promise<void> m_release;
    std::shared_future<void> m_release_future{m_release.get_future().share()};
    std::atomic_bool m_used{false};
    std::atomic_bool m_released{false};
};

CService ip(uint32_t i)
{
    struct in_addr s;
    s.s_addr = i;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}
} // namespace

// While the activation thread connects a block, holding cs_main, the message
// handler serves lock-free messages from other peers and processes nothing
// from the peer that sent the block.
BOOST_FIXTURE_TEST_CASE(serve_peers_while_connecting_block, TestChain100Setup)
{
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    auto& chainman{static_cast<TestChainstateManager&>(*m_node.chainman)};
    PeerManager& peerman{*m_node.peerman};
    // Receive NewPoWValidBlock(), which caches the most recent block for
    // GETBLOCKTXN outside of IBD, and BlockChecked(), as a node does.
    if (chainman.IsInitialBlockDownload()) chainman.JumpOutOfIbd();
    m_node.validation_signals->RegisterValidationInterface(&peerman);

    // Record the messages sent to each peer, some of which the activation thread sends.
    Mutex sent_mutex;
    std::multiset<std::pair<std::string, std::string>> sent;
    const auto capture_orig{CaptureMessage};
    CaptureMessage = [&](const CAddress& addr, const std::string& msg_type, std::span<const unsigned char>, bool is_incoming) {
        if (!is_incoming) WITH_LOCK(sent_mutex, sent.emplace(addr.ToStringAddrPort(), msg_type));
    };
    connman.SetCaptureMessages(true);
    const auto count_sent{[&](const CNode& peer, const std::string& msg_type) {
        return WITH_LOCK(sent_mutex, return sent.count(std::make_pair(peer.addr.ToStringAddrPort(), msg_type)));
    }};

    const auto make_peer{[](NodeId id, uint32_t addr) {
        return std::make_unique<CNode>(id, /*sock=*/nullptr, CAddress{ip(addr), NODE_NONE}, /*nKeyedNetGroupIn=*/0,
                                       /*nLocalHostNonceIn=*/0, CAddress{}, /*addrNameIn=*/"", ConnectionType::OUTBOUND_FULL_RELAY,
                                       /*inbound_onion=*/false, /*network_key=*/0);
    }};
    const auto sender{make_peer(0, 0xa0b0c001)};
    const auto other{make_peer(1, 0xa0b0c002)};

    const uint256 old_hash{WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()->GetBlockHash())};
    const CBlock block{CreateBlock({}, CScript{} << OP_TRUE)};

    // Queue all messages up front: the fake peers share their transport with
    // us, so it must not be used while the activation thread sends messages.
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        for (CNode* peer : {sender.get(), other.get()}) {
            connman.Handshake(*peer, /*successfully_connected=*/true, ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                              ServiceFlags(NODE_NETWORK | NODE_WITNESS), PROTOCOL_VERSION, /*relay_txs=*/true);
            connman.FlushSendBuffer(*peer);
        }
    }
    BOOST_REQUIRE(connman.ReceiveMsgFrom(*sender, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block))));
    BOOST_REQUIRE(connman.ReceiveMsgFrom(*sender, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
    BOOST_REQUIRE(connman.ReceiveMsgFrom(*other, NetMsg::Make(NetMsgType::PING, uint64_t{2})));
    BOOST_REQUIRE(connman.ReceiveMsgFrom(*other, NetMsg::Make(NetMsgType::GETBLOCKTXN, BlockTransactionsRequest{block.GetHash(), {0}})));
    BOOST_REQUIRE(connman.ReceiveMsgFrom(*other, NetMsg::Make(NetMsgType::GETBLOCKTXN, BlockTransactionsRequest{old_hash, {0}})));
    BOOST_REQUIRE(connman.ReceiveMsgFrom(*other, NetMsg::Make(NetMsgType::PING, uint64_t{3})));

    const auto process_all{[&] {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        for (int i{0}; i < 5; ++i) {
            for (CNode* peer : {sender.get(), other.get()}) {
                peer->fPauseSend = false;
                connman.ProcessMessagesOnce(*peer);
            }
        }
    }};

    const auto gate{std::make_shared<BlockCheckedGate>()};
    // However this test exits, let the activation thread finish.
    struct ReleaseOnExit {
        BlockCheckedGate& gate;
        ~ReleaseOnExit() { gate.Release(); }
    } release_on_exit{*gate};
    m_node.validation_signals->RegisterSharedValidationInterface(gate);
    peerman.StartBlockActivation();

    // The block is stored on this thread, then connected on the activation thread.
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        sender->fPauseSend = false;
        connman.ProcessMessagesOnce(*sender);
    }
    BOOST_REQUIRE(gate->entered.get_future().wait_for(1min) == std::future_status::ready);
    {
        TRY_LOCK(::cs_main, main_lock);
        BOOST_CHECK(!main_lock);
    }

    // Process messages on another thread, so that taking cs_main fails the
    // test instead of hanging it.
    auto processed{std::async(std::launch::async, process_all)};
    BOOST_CHECK(processed.wait_for(10s) == std::future_status::ready);
    gate->Release();
    processed.wait();

    BOOST_CHECK_EQUAL(count_sent(*sender, NetMsgType::PONG), 0U);
    BOOST_CHECK_EQUAL(count_sent(*other, NetMsgType::PONG), 1U);
    // GETBLOCKTXN for the block being connected is served, the one for an older block waits.
    BOOST_CHECK_EQUAL(count_sent(*other, NetMsgType::BLOCKTXN), 1U);

    // Once the block is connected, all messages are processed.
    peerman.StopBlockActivation();
    process_all();
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()->GetBlockHash()) == block.GetHash());
    BOOST_CHECK_EQUAL(count_sent(*sender, NetMsgType::PONG), 1U);
    BOOST_CHECK_EQUAL(count_sent(*other, NetMsgType::PONG), 2U);
    BOOST_CHECK_EQUAL(count_sent(*other, NetMsgType::BLOCKTXN), 2U);

    m_node.validation_signals->UnregisterSharedValidationInterface(gate);
    m_node.validation_signals->UnregisterValidationInterface(&peerman);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    CaptureMessage = capture_orig;
    connman.SetCaptureMessages(false);
    for (CNode* peer : {sender.get(), other.get()}) peerman.FinalizeNode(*peer);
}

BOOST_AUTO_TEST_SUITE_END()

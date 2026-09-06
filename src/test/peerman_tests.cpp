// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <interfaces/mining.h>
#include <net_processing.h>
#include <node/kernel_notifications.h>
#include <pow.h>
#include <primitives/block.h>
#include <protocol.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <util/check.h>
#include <util/fs.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

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

namespace {
struct GetDataDuringWriteSetup : RegTestingSetup {
    ConnmanTestMsg& m_connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};

    GetDataDuringWriteSetup()
    {
        CConnman::Options opts{};
        opts.m_msgproc = m_node.peerman.get();
        opts.nSendBufferMaxSize = 1000000;
        m_connman.Init(opts);
        static_cast<TestChainstateManager&>(*m_node.chainman).JumpOutOfIbd();
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
    }

    ~GetDataDuringWriteSetup()
    {
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
        for (const auto* peer : m_connman.TestNodes()) m_node.peerman->FinalizeNode(*peer);
        m_connman.ClearTestNodes();
    }

    bool Receive(CNode& peer, CSerializedNetMsg msg) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(peer, std::move(msg)));
        return m_connman.ProcessMessagesOnce(peer);
    }

    void ExpectMessages(CNode& peer, std::initializer_list<std::string> expected)
    {
        std::vector<std::string> messages;
        {
            LOCK(peer.cs_vSend);
            // With no socket, the optimistic send leaves the first message in
            // the transport and subsequent messages in vSendMsg.
            const auto& [bytes, more, type] = peer.m_transport->GetBytesToSend(false);
            if (!bytes.empty()) messages.push_back(type);
            for (const auto& msg : peer.vSendMsg) messages.push_back(msg.m_type);
        }
        BOOST_CHECK_EQUAL_COLLECTIONS(messages.begin(), messages.end(), expected.begin(), expected.end());
        m_connman.FlushSendBuffer(peer);
        peer.fPauseSend = false;
    }

    CNode& AddPeer() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        auto* peer = new CNode{static_cast<NodeId>(m_connman.TestNodes().size()), /*sock=*/nullptr, CAddress{},
                              /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0, CAddress{}, /*addrNameIn=*/"",
                              ConnectionType::OUTBOUND_FULL_RELAY, /*inbound_onion=*/false, /*network_key=*/0};
        m_connman.AddTestNode(*peer);
        const auto services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
        m_connman.Handshake(*peer, true, services, services, PROTOCOL_VERSION, true);
        m_connman.FlushSendBuffer(*peer);
        peer->fPauseSend = false;
        Receive(*peer, NetMsg::Make(NetMsgType::SENDCMPCT, true, CMPCTBLOCKS_VERSION));
        ExpectMessages(*peer, {});
        // Establish knowledge of the parent so NewPoWValidBlock announces the
        // next block to this peer before writing it, as with submitblock/IPC.
        Receive(*peer, NetMsg::Make(NetMsgType::GETHEADERS, CBlockLocator{}, Params().GenesisBlock().GetHash()));
        ExpectMessages(*peer, {NetMsgType::HEADERS});
        return *peer;
    }
};
} // namespace

BOOST_FIXTURE_TEST_CASE(getdata_during_block_write, GetDataDuringWriteSetup)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto& peer{AddPeer()};
    auto& witness_peer{AddPeer()};
    auto& chainman{*m_node.chainman};
    const auto block{CreateBlockChain(1, Params()).front()};
    PausedAcceptance pending{chainman, block};
    ExpectMessages(peer, {NetMsgType::CMPCTBLOCK});
    ExpectMessages(witness_peer, {NetMsgType::CMPCTBLOCK});
    {
        LOCK(cs_main);
        const auto* index{chainman.m_blockman.LookupBlockIndex(block->GetHash())};
        BOOST_REQUIRE(index);
        BOOST_CHECK(!index->HaveNumChainTxs());
        BOOST_CHECK(!(index->nStatus & BLOCK_HAVE_DATA));
    }

    // Transaction responses preceding the blocked request must still be sent
    // once, and subsequent block requests must remain in order.
    const auto genesis_hash{Params().GenesisBlock().GetHash()};
    Receive(peer, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
        {MSG_TX, uint256::ONE}, {MSG_BLOCK, block->GetHash()}, {MSG_BLOCK, genesis_hash}}));
    ExpectMessages(peer, {NetMsgType::NOTFOUND});
    Receive(witness_peer, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{{MSG_WITNESS_BLOCK, block->GetHash()}}));
    ExpectMessages(witness_peer, {});
    BOOST_REQUIRE(m_connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
    for (int i{0}; i < 3; ++i) {
        // A pending write must not advertise runnable work and cause a busy
        // loop, nor allow later requests/messages to overtake this request.
        BOOST_CHECK(!m_connman.ProcessMessagesOnce(peer));
        BOOST_CHECK(!m_connman.ProcessMessagesOnce(witness_peer));
        ExpectMessages(peer, {});
        ExpectMessages(witness_peer, {});
    }

    pending.Finish();
    BOOST_REQUIRE(pending.m_accepted);
    BOOST_CHECK(WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()->GetBlockHash()) == genesis_hash);
    // No new GETDATA or incoming message: the existing retry must activate
    // the published block and serve both requests, including the cached path.
    BOOST_CHECK(m_connman.ProcessMessagesOnce(peer));
    ExpectMessages(peer, {NetMsgType::BLOCK});
    BOOST_CHECK(WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()->GetBlockHash()) == block->GetHash());
    BOOST_CHECK(!m_connman.ProcessMessagesOnce(peer));
    ExpectMessages(peer, {NetMsgType::BLOCK, NetMsgType::PONG});
    BOOST_CHECK(!m_connman.ProcessMessagesOnce(witness_peer));
    ExpectMessages(witness_peer, {NetMsgType::BLOCK});
    BOOST_CHECK(!m_connman.ProcessMessagesOnce(peer));
    ExpectMessages(peer, {});
}

BOOST_FIXTURE_TEST_CASE(getdata_during_other_block_write, GetDataDuringWriteSetup)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto& peer{AddPeer()};
    const auto blocks{CreateBlockChain(2, Params())};
    BlockValidationState state;
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders({{*blocks[0], *blocks[1]}}, true, state));
    PausedAcceptance pending{*m_node.chainman, blocks[0]};
    ExpectMessages(peer, {NetMsgType::CMPCTBLOCK});

    // An unrelated stored block is served normally. A header-only block, an
    // unknown hash, and an unknown inventory type must not remain pending.
    Receive(peer, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
        {MSG_WITNESS_BLOCK, Params().GenesisBlock().GetHash()}, {MSG_BLOCK, blocks[1]->GetHash()},
        {MSG_BLOCK, uint256::ONE}, {0, uint256::ONE}}));
    ExpectMessages(peer, {NetMsgType::BLOCK});
    BOOST_REQUIRE(m_connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
    BOOST_CHECK(m_connman.ProcessMessagesOnce(peer));
    BOOST_CHECK(m_connman.ProcessMessagesOnce(peer));
    BOOST_CHECK(!m_connman.ProcessMessagesOnce(peer));
    ExpectMessages(peer, {NetMsgType::PONG});
    pending.Finish();
    BOOST_CHECK(pending.m_accepted);
}

BOOST_FIXTURE_TEST_CASE(getdata_after_block_write_failure, GetDataDuringWriteSetup)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto& peer{AddPeer()};
    auto& chainman{*m_node.chainman};
    const auto block{CreateBlockChain(1, Params()).front()};
    const auto path{chainman.m_blockman.GetBlockPosFilename(FlatFilePos{0, 0})};
    const auto saved_path{path.parent_path() / "blk00000.saved"};
    // Force a real open failure, confined to this fixture's temporary files.
    fs::rename(path, saved_path);
    BOOST_REQUIRE(fs::create_directory(path));
    m_node.notifications->m_shutdown_on_fatal_error = false;
    PausedAcceptance pending{chainman, block};
    ExpectMessages(peer, {NetMsgType::CMPCTBLOCK});
    Receive(peer, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{{MSG_BLOCK, block->GetHash()}}));
    ExpectMessages(peer, {});
    BOOST_REQUIRE(m_connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
    BOOST_CHECK(!m_connman.ProcessMessagesOnce(peer));
    ExpectMessages(peer, {});
    pending.Finish();
    BOOST_REQUIRE(!pending.m_accepted);
    BOOST_CHECK(pending.m_state.IsError());
    BOOST_REQUIRE(fs::remove(path));
    fs::rename(saved_path, path);

    // The early-announcement cache must not bypass the normal serving checks.
    // A failed write stops deferral and lets the queue progress without a block.
    BOOST_CHECK(!m_connman.ProcessMessagesOnce(peer));
    ExpectMessages(peer, {NetMsgType::PONG});
}

BOOST_FIXTURE_TEST_CASE(getdata_after_invalidation_during_write, GetDataDuringWriteSetup)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto& peer{AddPeer()};
    auto& chainman{*m_node.chainman};
    const auto block{CreateBlockChain(1, Params()).front()};
    PausedAcceptance pending{chainman, block};
    ExpectMessages(peer, {NetMsgType::CMPCTBLOCK});
    Receive(peer, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{{MSG_WITNESS_BLOCK, block->GetHash()}}));
    ExpectMessages(peer, {});
    BOOST_REQUIRE(m_connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
    BOOST_CHECK(!m_connman.ProcessMessagesOnce(peer));
    ExpectMessages(peer, {});
    auto* index{WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block->GetHash()))};
    BOOST_REQUIRE(index);
    BlockValidationState state;
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(state, index));
    pending.Finish();
    BOOST_REQUIRE(!pending.m_accepted);
    BOOST_CHECK(pending.m_state.GetResult() == BlockValidationResult::BLOCK_CACHED_INVALID);
    BOOST_CHECK(!m_connman.ProcessMessagesOnce(peer));
    ExpectMessages(peer, {NetMsgType::PONG});
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <net.h>
#include <net_processing.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <node/block_template_manager.h>
#include <node/connection_types.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <sync.h>
#include <test/util/mining.h>
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
#include <cstdint>
#include <future>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace {
// Grind the nonce until the block has valid proof of work.
void SolvePow(CBlock& block, const Consensus::Params& params)
{
    while (!CheckProofOfWork(block.GetHash(), block.nBits, params)) ++block.nNonce;
}

struct NetLockTestingSetup : RegTestingSetup {
    ConnmanTestMsg& Connman() { return static_cast<ConnmanTestMsg&>(*m_node.connman); }
    PeerManager& Peerman() { return *m_node.peerman; }

    NetLockTestingSetup()
    {
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
    }

    ~NetLockTestingSetup()
    {
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
        for (const auto node : Connman().TestNodes())
            Peerman().FinalizeNode(*node);
        Connman().ClearTestNodes();
    }

    CNode& AddPeer(NodeId id) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        // Connman owns these nodes until ClearTestNodes().
        auto node{std::make_unique<CNode>(id, /*sock=*/nullptr,
                                          CAddress{LookupNumeric("127.0.0.1", 18444), NODE_NONE}, /*nKeyedNetGroupIn=*/0,
                                          /*nLocalHostNonceIn=*/0, CAddress{}, /*addrNameIn=*/"", ConnectionType::INBOUND,
                                          /*inbound_onion=*/false, /*network_key=*/0)};
        auto& result{*node};
        Connman().AddTestNode(*node.release());
        Connman().Handshake(result, /*successfully_connected=*/true,
                            /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                            /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                            PROTOCOL_VERSION, /*relay_txs=*/true);
        FlushSends(result);
        return result;
    }

    // Drop the messages queued for the peer, and resume processing its messages,
    // which a full send buffer pauses.
    void FlushSends(CNode& node)
    {
        Connman().FlushSendBuffer(node);
        node.fPauseSend = false;
    }

    CNodeStateStats Stats(NodeId id)
    {
        CNodeStateStats stats;
        BOOST_REQUIRE(Peerman().GetNodeStateStats(id, stats));
        return stats;
    }

    // A high-bandwidth peer that announces new blocks with compact blocks.
    CNode& AddCompactBlockPeer(NodeId id)
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        CNode& peer{AddPeer(id)};
        BOOST_REQUIRE(Connman().ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/false, /*version=*/CMPCTBLOCKS_VERSION)));
        Connman().ProcessMessagesOnce(peer);
        peer.m_bip152_highbandwidth_to = true;
        return peer;
    }

    // A new block whose transaction is missing from the mempool, so that its
    // reconstruction requests it with GETBLOCKTXN.
    std::shared_ptr<CBlock> NewBlockMissingTx()
    {
        auto block{PrepareBlock(m_node, {})};
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vout.resize(1);
        block->vtx.push_back(MakeTransactionRef(tx));
        node::RegenerateCommitments(*block, *m_node.chainman);
        SolvePow(*block, m_node.chainman->GetConsensus());
        return block;
    }

    // A new block whose header, but not the block itself, has been accepted.
    std::pair<std::shared_ptr<CBlock>, const CBlockIndex*> NewBlockWithKnownHeader()
    {
        auto block{PrepareBlock(m_node, {})};
        SolvePow(*block, m_node.chainman->GetConsensus());
        BlockValidationState state;
        const CBlockIndex* index{nullptr};
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders({{*block}}, /*min_pow_checked=*/true, state, &index));
        BOOST_REQUIRE(index);
        return {block, index};
    }

    // Finalize the peer as a disconnection does, instead of at teardown.
    void DisconnectPeer(CNode& node)
    {
        // Like CConnman, stop listing the node before finalizing it.
        Connman().RemoveTestNode(node);
        Peerman().FinalizeNode(node);
        delete &node;
    }

    // Let the handler process the peer's queued compact block on another thread
    // while a third thread holds the mempool lock. Once the handler waits in its
    // mempool scan without cs_main, call during_scan, then let it finish. Return
    // whether that point was reached.
    bool ProcessDuringScan(CNode& node, auto&& during_scan)
    {
        std::promise<void> mempool_locked;
        std::promise<void> release_mempool;
        auto holder{std::async(std::launch::async, [&, released = release_mempool.get_future()] {
            LOCK(m_node.mempool->cs);
            mempool_locked.set_value();
            released.wait_for(std::chrono::seconds{10});
        })};
        mempool_locked.get_future().wait();
        auto handling{std::async(std::launch::async, [&] {
            LOCK(NetEventsInterface::g_msgproc_mutex);
            Connman().ProcessMessagesOnce(node);
        })};

        // The request is registered before the scan, so a registered request, an
        // unfinished handler and a free cs_main mean that the scan runs without it.
        bool scanning{false};
        for (int i{0}; i < 10'000 && !scanning && handling.wait_for(std::chrono::milliseconds{1}) != std::future_status::ready; ++i) {
            TRY_LOCK(cs_main, chain_lock);
            scanning = chain_lock && !Stats(node.GetId()).vHeightInFlight.empty();
        }
        if (scanning) during_scan();
        release_mempool.set_value();
        holder.get();
        handling.get();
        return scanning;
    }

    static bool HasMessage(CNode& node, std::string_view msg_type)
    {
        LOCK(node.cs_vSend);
        const auto& [data, more, transport_msg_type]{node.m_transport->GetBytesToSend(!node.vSendMsg.empty())};
        return (!data.empty() && transport_msg_type == msg_type) ||
               std::ranges::any_of(node.vSendMsg, [&](const auto& msg) { return msg.m_type == msg_type; });
    }
};
} // namespace

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

BOOST_AUTO_TEST_CASE(process_messages_without_orphan_work)
{
    CNode node{/*id=*/0,
               /*sock=*/nullptr,
               CAddress{},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"",
               ConnectionType::INBOUND,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    m_node.peerman->InitializeNode(node, NODE_NETWORK);

    // A peer with no orphan work is processed while cs_main is held elsewhere.
    // The future outlives the lock, so a regression fails instead of hanging.
    std::future<void> processed;
    {
        LOCK(cs_main);
        processed = std::async(std::launch::async, [&] {
            std::atomic<bool> interrupt{false};
            LOCK(NetEventsInterface::g_msgproc_mutex);
            m_node.peerman->ProcessMessages(node, interrupt);
        });
        BOOST_CHECK(processed.wait_for(10s) == std::future_status::ready);
    }
    processed.get();

    m_node.peerman->FinalizeNode(node);
}

BOOST_FIXTURE_TEST_CASE(compact_block_scan_does_not_hold_cs_main, NetLockTestingSetup)
{
    auto& chainman{*m_node.chainman};
    FakeNodeClock clock{chainman.GetParams().GenesisBlock().Time() + 1h};
    const auto blocks{CreateBlockChain(1, chainman.GetParams())};
    CNode& source{AddCompactBlockPeer(0)};
    BOOST_REQUIRE(Connman().ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::CMPCTBLOCK, CBlockHeaderAndShortTxIDs{*blocks.front(), /*nonce=*/0})));

    BOOST_CHECK(ProcessDuringScan(source, [] {}));
    BOOST_CHECK(!source.fDisconnect);
    BOOST_CHECK(Stats(source.GetId()).vHeightInFlight.empty());
}

BOOST_FIXTURE_TEST_CASE(compact_block_leaves_replaced_request, NetLockTestingSetup)
{
    FakeNodeClock clock{m_node.chainman->GetParams().GenesisBlock().Time() + 1h};
    const auto block{NewBlockMissingTx()};
    CNode& source{AddCompactBlockPeer(0)};
    BOOST_REQUIRE(Connman().ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::CMPCTBLOCK, CBlockHeaderAndShortTxIDs{*block, /*nonce=*/0})));

    // getblockfrompeer replaces the request with a full-block request from the
    // same peer during the scan. Reconstruction must leave that request alone.
    BOOST_CHECK(ProcessDuringScan(source, [&] {
        const CBlockIndex* index{WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(block->GetHash()))};
        BOOST_CHECK(Peerman().FetchBlock(source.GetId(), *Assert(index)).has_value());
    }));
    BOOST_CHECK(HasMessage(source, NetMsgType::GETDATA));
    BOOST_CHECK(!HasMessage(source, NetMsgType::GETBLOCKTXN));
    BOOST_CHECK_EQUAL(Stats(source.GetId()).vHeightInFlight.size(), 1);
}

BOOST_FIXTURE_TEST_CASE(compact_block_rereads_requests_after_scan, NetLockTestingSetup)
{
    FakeNodeClock clock{m_node.chainman->GetParams().GenesisBlock().Time() + 1h};
    const auto block{NewBlockMissingTx()};
    const CBlockHeaderAndShortTxIDs compact{*block, /*nonce=*/0};
    CNode& first{AddCompactBlockPeer(0)};
    CNode& second{AddCompactBlockPeer(1)};
    CNode& third{AddCompactBlockPeer(2)};
    for (CNode* peer : {&first, &second}) {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        BOOST_REQUIRE(Connman().ReceiveMsgFrom(*peer, NetMsg::Make(NetMsgType::CMPCTBLOCK, compact)));
        Connman().ProcessMessagesOnce(*peer);
        BOOST_REQUIRE(HasMessage(*peer, NetMsgType::GETBLOCKTXN));
    }

    // The first requester disconnects during the third peer's scan, so the third
    // request is only second in line. As such, this inbound peer is still asked
    // for the missing transaction, instead of giving up as a third request would.
    BOOST_REQUIRE(Connman().ReceiveMsgFrom(third, NetMsg::Make(NetMsgType::CMPCTBLOCK, compact)));
    BOOST_CHECK(ProcessDuringScan(third, [&] { DisconnectPeer(first); }));
    BOOST_CHECK(HasMessage(third, NetMsgType::GETBLOCKTXN));
    BOOST_CHECK_EQUAL(Stats(third.GetId()).vHeightInFlight.size(), 1);
}

BOOST_FIXTURE_TEST_CASE(block_request_moves_between_peers, NetLockTestingSetup)
{
    const CBlockIndex* index{NewBlockWithKnownHeader().second};
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        AddPeer(0);
        AddPeer(1);
    }

    BOOST_REQUIRE(Peerman().FetchBlock(0, *index).has_value());
    BOOST_CHECK(Stats(0).vHeightInFlight == std::vector<int>{index->nHeight});
    BOOST_CHECK(Stats(1).vHeightInFlight.empty());

    // Requesting the block from another peer clears the first peer's bookkeeping.
    BOOST_REQUIRE(Peerman().FetchBlock(1, *index).has_value());
    BOOST_CHECK(Stats(0).vHeightInFlight.empty());
    BOOST_CHECK(Stats(1).vHeightInFlight == std::vector<int>{index->nHeight});
    // Fixture teardown finalizes a peer with an outstanding request and checks the global counters.
}

BOOST_AUTO_TEST_SUITE_END()

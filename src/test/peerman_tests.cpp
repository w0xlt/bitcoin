// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <net.h>
#include <net_processing.h>
#include <netbase.h>
#include <node/block_template_manager.h>
#include <node/connection_types.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
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

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <utility>
#include <vector>

namespace {
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
        Connman().FlushSendBuffer(result);
        result.fPauseSend = false;
        return result;
    }

    CNodeStateStats Stats(NodeId id)
    {
        CNodeStateStats stats;
        BOOST_REQUIRE(Peerman().GetNodeStateStats(id, stats));
        return stats;
    }
};

// Release cs_main before joining, even if the check fails or an exception is thrown.
// A regression that takes cs_main should fail the test instead of hanging it.
bool RunsWithoutChainLock(auto&& action)
{
    std::future<void> done;
    bool ready;
    {
        LOCK(cs_main);
        done = std::async(std::launch::async, std::forward<decltype(action)>(action));
        ready = done.wait_for(std::chrono::seconds{10}) == std::future_status::ready;
    }
    done.get();
    return ready;
}
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

BOOST_FIXTURE_TEST_CASE(block_requests_do_not_wait_for_cs_main, NetLockTestingSetup)
{
    auto& chainman{*m_node.chainman};
    auto block{PrepareBlock(m_node, {})};
    while (!CheckProofOfWork(block->GetHash(), block->nBits, chainman.GetConsensus()))
        ++block->nNonce;
    BlockValidationState state;
    const CBlockIndex* index{nullptr};
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({{*block}}, /*min_pow_checked=*/true, state, &index));
    BOOST_REQUIRE(index);
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        AddPeer(0);
        AddPeer(1);
    }

    bool requested{false};
    BOOST_CHECK(RunsWithoutChainLock([&] {
        requested = bool{Peerman().FetchBlock(0, *index)};
    }));
    BOOST_REQUIRE(requested);
    BOOST_CHECK(Stats(0).vHeightInFlight == std::vector<int>{index->nHeight});
    BOOST_CHECK(Stats(1).vHeightInFlight.empty());

    // Reassigning the request also clears the first peer's bookkeeping without cs_main.
    BOOST_CHECK(RunsWithoutChainLock([&] {
        requested = bool{Peerman().FetchBlock(1, *index)};
    }));
    BOOST_REQUIRE(requested);
    BOOST_CHECK(Stats(0).vHeightInFlight.empty());
    BOOST_CHECK(Stats(1).vHeightInFlight == std::vector<int>{index->nHeight});
    // Fixture teardown finalizes a peer with an outstanding request and checks the global counters.
}

BOOST_AUTO_TEST_SUITE_END()

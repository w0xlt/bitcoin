// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <interfaces/mining.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockdownloadchain_impl.h>
#include <node/blockdownloadman.h>
#include <pow.h>
#include <primitives/block.h>
#include <protocol.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace {

struct FakeBlockDownloadManagerState {
    std::optional<NodeId> m_connected_peer;
    std::optional<NodeId> m_disconnected_peer;
    bool m_connected_inbound{false};
    int m_empty_checks{0};
    bool m_destroyed{false};
};

class FakeBlockDownloadManager final : public node::BlockDownloadManager
{
public:
    explicit FakeBlockDownloadManager(FakeBlockDownloadManagerState& state) : m_state{state} {}
    ~FakeBlockDownloadManager() override { m_state.m_destroyed = true; }

    void ConnectedPeer(NodeId peer, const node::BlockDownloadConnectionInfo& info) override
    {
        m_state.m_connected_peer = peer;
        m_state.m_connected_inbound = info.m_is_inbound;
    }
    void DisconnectedPeer(NodeId peer) override { m_state.m_disconnected_peer = peer; }
    void ProcessBlockAvailability(NodeId) override {}
    void UpdateBlockAvailability(NodeId, const uint256&) override {}
    bool PeerHasHeader(NodeId, const uint256&) const override { return false; }
    void RecordBestHeaderSent(NodeId, const node::BlockDownloadBlock&) override {}
    node::BlockDownloadBatch PlanAndReserve(NodeId, unsigned int, std::chrono::microseconds, bool) override { return {}; }
    node::BlockRequestReservation ReserveBlockRequest(
        NodeId,
        const node::BlockDownloadBlock&,
        std::chrono::microseconds,
        std::shared_ptr<PartiallyDownloadedBlock>) override
    {
        return {
            .m_status = node::BlockRequestStatus::PEER_NOT_FOUND,
            .m_requests_before = 0,
            .m_first_in_flight = true,
            .m_partial_block = {},
        };
    }
    node::BlockRequestRemoval RemoveBlockRequest(
        const uint256&, std::optional<NodeId>, std::chrono::microseconds) override
    {
        return {};
    }
    bool IsBlockRequested(const uint256&) const override { return false; }
    bool IsBlockRequestedFromOutbound(const uint256&) const override { return false; }
    node::BlockInFlightInfo GetBlockInFlightInfo(const uint256&, NodeId) const override { return {}; }
    std::optional<node::PeerBlockDownloadSnapshot> GetPeerSnapshot(NodeId) const override { return std::nullopt; }
    node::BlockDownloadGlobalSnapshot GetGlobalSnapshot() const override { return {}; }
    bool AllRequestsAreFor(const uint256&) const override { return false; }
    bool StartStalling(NodeId, std::chrono::microseconds) override { return false; }
    bool ClearStalling(NodeId) override { return false; }
    bool StartSync(NodeId) override { return false; }
    bool ClearSync(NodeId) override { return false; }
    bool RecordBlockSource(const uint256&, NodeId, bool) override { return false; }
    std::optional<node::BlockSource> ConsumeBlockSource(const uint256&) override { return std::nullopt; }
    bool EraseBlockSource(const uint256&) override { return false; }
    bool TipMayBeStale(std::chrono::seconds, std::chrono::seconds) override { return false; }
    void UpdatedBlockTip(std::chrono::seconds) override {}
    std::optional<std::chrono::seconds> TryIncreaseBlockStallingTimeout(std::chrono::seconds) override { return std::nullopt; }
    std::optional<std::chrono::seconds> TryDecreaseBlockStallingTimeout(std::chrono::seconds) override { return std::nullopt; }
    bool CheckConsistency() const override { return true; }
    void CheckIsEmpty() const override { ++m_state.m_empty_checks; }

private:
    FakeBlockDownloadManagerState& m_state;
};

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

// Verifying when network-limited peer connections are desirable based on the node's proximity to the tip
BOOST_AUTO_TEST_CASE(connections_desirable_service_flags)
{
    FakeNodeClock clock{};
    auto block_download_chain{node::MakeValidationBlockDownloadChain(*m_node.chainman)};
    auto block_downloadman{node::MakeBlockDownloadManager(std::move(block_download_chain))};
    std::unique_ptr<PeerManager> peerman = PeerManager::make(
        *m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool,
        *m_node.warnings, std::move(block_downloadman), {});
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

BOOST_AUTO_TEST_CASE(block_download_manager_is_injected_and_owned)
{
    FakeBlockDownloadManagerState state;
    auto block_downloadman{std::make_unique<FakeBlockDownloadManager>(state)};
    auto peerman{PeerManager::make(
        *m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool,
        *m_node.warnings, std::move(block_downloadman), {})};
    BOOST_CHECK(!block_downloadman);

    const NodeId peer_id{123};
    CNode peer{
        peer_id,
        /*sock=*/nullptr,
        CAddress{},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        CAddress{},
        /*addrNameIn=*/"",
        ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        /*network_key=*/0,
    };
    peerman->InitializeNode(peer, NODE_NETWORK);
    BOOST_CHECK(state.m_connected_peer == peer_id);
    BOOST_CHECK(state.m_connected_inbound);

    peerman->FinalizeNode(peer);
    BOOST_CHECK(state.m_disconnected_peer == peer_id);
    BOOST_CHECK_EQUAL(state.m_empty_checks, 1);
    BOOST_CHECK(!state.m_destroyed);

    peerman.reset();
    BOOST_CHECK(state.m_destroyed);
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <interfaces/mining.h>
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockdownloadchain_impl.h>
#include <node/blockdownloadman.h>
#include <pow.h>
#include <primitives/block.h>
#include <protocol.h>
#include <sync.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

struct FakeBlockDownloadManagerState {
    std::optional<NodeId> m_connected_peer;
    std::optional<NodeId> m_disconnected_peer;
    bool m_connected_inbound{false};
    int m_empty_checks{0};
    bool m_destroyed{false};
    std::optional<node::PeerBlockDownloadSnapshot> m_peer_snapshot;
    std::function<void(NodeId)> m_before_peer_snapshot;
    std::function<void(NodeId)> m_process_block_availability;
    int m_peer_snapshot_calls{0};
    std::optional<node::BlockSource> m_block_source;
    bool m_all_requests_are_for{false};
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
    void ProcessBlockAvailability(NodeId peer) override
    {
        if (m_state.m_process_block_availability) m_state.m_process_block_availability(peer);
    }
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
    std::optional<node::PeerBlockDownloadSnapshot> GetPeerSnapshot(NodeId peer) const override
    {
        ++m_state.m_peer_snapshot_calls;
        if (m_state.m_before_peer_snapshot) m_state.m_before_peer_snapshot(peer);
        return m_state.m_peer_snapshot;
    }
    node::BlockDownloadGlobalSnapshot GetGlobalSnapshot() const override { return {}; }
    bool AllRequestsAreFor(const uint256&) const override { return m_state.m_all_requests_are_for; }
    bool StartStalling(NodeId, std::chrono::microseconds) override { return false; }
    bool ClearStalling(NodeId) override { return false; }
    bool StartSync(NodeId) override { return false; }
    bool ClearSync(NodeId) override { return false; }
    bool RecordBlockSource(const uint256&, NodeId, bool) override { return false; }
    std::optional<node::BlockSource> ConsumeBlockSource(const uint256&) override { return m_state.m_block_source; }
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

BOOST_AUTO_TEST_CASE(compact_block_relay_negotiation)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    auto connman{std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params())};
    FakeBlockDownloadManagerState state;
    auto peerman{PeerManager::make(
        *connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool,
        *m_node.warnings, std::make_unique<FakeBlockDownloadManager>(state), {})};
    connman->SetMsgProc(peerman.get());

    CNode* peer{new CNode{
        /*id=*/123,
        /*sock=*/nullptr,
        CAddress{},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        CAddress{},
        /*addrNameIn=*/"",
        ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        /*network_key=*/0,
    }};
    peer->nVersion = PROTOCOL_VERSION;
    peer->SetCommonVersion(PROTOCOL_VERSION);
    peerman->InitializeNode(*peer, NODE_NETWORK);
    peer->fSuccessfullyConnected = true;
    connman->AddTestNode(*peer);

    BOOST_REQUIRE(connman->ReceiveMsgFrom(
        *peer, NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/true, /*version=*/CMPCTBLOCKS_VERSION)));
    connman->ProcessMessagesOnce(*peer);
    BOOST_CHECK(peer->m_bip152_highbandwidth_from.load());

    BOOST_REQUIRE(connman->ReceiveMsgFrom(
        *peer, NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/false, /*version=*/CMPCTBLOCKS_VERSION)));
    connman->ProcessMessagesOnce(*peer);
    BOOST_CHECK(!peer->m_bip152_highbandwidth_from.load());

    // A valid block from this peer selects it for high-bandwidth announcements.
    // Invalidate the first list commit after its high-bandwidth message is
    // queued, and verify the bounded path sends a rollback before retrying.
    auto& chainman{static_cast<TestChainstateManager&>(*m_node.chainman)};
    if (chainman.IsInitialBlockDownload()) chainman.JumpOutOfIbd();
    const auto block{std::make_shared<const CBlock>()};
    state.m_block_source = node::BlockSource{peer->GetId(), /*m_punish_on_invalid=*/false};
    state.m_all_requests_are_for = true;

    std::mutex signal_mutex;
    std::condition_variable signal_cv;
    bool first_send_started{false};
    const bool net_logging_enabled{LogInstance().WillLogCategory(BCLog::NET)};
    if (!net_logging_enabled) LogInstance().EnableCategory(BCLog::NET);
    const auto print_connection{LogInstance().PushBackCallback([&](const std::string& line) {
        if (line.find("sending sendcmpct") == std::string::npos) return;
        {
            std::lock_guard<std::mutex> lock{signal_mutex};
            first_send_started = true;
        }
        signal_cv.notify_one();
    })};

    BlockValidationState valid_state;
    m_node.validation_signals->RegisterValidationInterface(peerman.get());
    bool reached_send{false};
    std::thread block_checked;
    {
        WAIT_LOCK(peer->cs_vSend, send_lock);
        block_checked = std::thread{[&] { m_node.validation_signals->BlockChecked(block, valid_state); }};
        {
            std::unique_lock<std::mutex> lock{signal_mutex};
            reached_send = signal_cv.wait_for(lock, 5s, [&] { return first_send_started; });
        }
        if (reached_send) peerman->UpdateLastBlockAnnounceTime(peer->GetId(), 1);
    }
    block_checked.join();
    LogInstance().DeleteCallback(print_connection);
    if (!net_logging_enabled) LogInstance().DisableCategory(BCLog::NET);

    if (!reached_send) {
        m_node.validation_signals->UnregisterValidationInterface(peerman.get());
        peerman->FinalizeNode(*peer);
        connman->ClearTestNodes();
        BOOST_FAIL("high-bandwidth selection did not reach its network send");
        return;
    }

    std::vector<bool> queued_high_bandwidth;
    {
        LOCK(peer->cs_vSend);
        for (const CSerializedNetMsg& message : peer->vSendMsg) {
            if (message.m_type != NetMsgType::SENDCMPCT) continue;
            DataStream stream{std::span<const uint8_t>{message.data.data(), message.data.size()}};
            bool high_bandwidth;
            uint64_t version;
            stream >> high_bandwidth >> version;
            BOOST_CHECK_EQUAL(version, CMPCTBLOCKS_VERSION);
            queued_high_bandwidth.push_back(high_bandwidth);
        }
    }
    BOOST_REQUIRE_EQUAL(queued_high_bandwidth.size(), 2);
    BOOST_CHECK(!queued_high_bandwidth[0]);
    BOOST_CHECK(queued_high_bandwidth[1]);
    BOOST_CHECK(peer->m_bip152_highbandwidth_to.load());

    // The retry committed the global announcing list. Selecting the same peer
    // again only refreshes its list position and queues no further message.
    m_node.validation_signals->BlockChecked(block, valid_state);
    {
        LOCK(peer->cs_vSend);
        BOOST_CHECK_EQUAL(peer->vSendMsg.size(), 2);
    }

    // A relay-generation race in SendMessages must retry once, then leave
    // the block-announcement queue intact for the next normal cycle.
    const CBlockIndex* tip;
    {
        LOCK(cs_main);
        tip = Assert(m_node.chainman->ActiveChain().Tip());
        m_node.validation_signals->UpdatedBlockTip(tip, tip->pprev, /*fInitialDownload=*/false);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    state.m_peer_snapshot.emplace();
    int availability_calls{0};
    state.m_process_block_availability = [&](NodeId id) {
        peerman->UpdateLastBlockAnnounceTime(id, ++availability_calls);
    };
    BOOST_CHECK(peerman->SendMessages(*peer));
    BOOST_CHECK_EQUAL(availability_calls, 2);
    {
        LOCK(peer->cs_vSend);
        BOOST_CHECK_EQUAL(std::ranges::count_if(peer->vSendMsg, [](const CSerializedNetMsg& message) {
            return message.m_type == NetMsgType::INV;
        }), 0);
    }

    state.m_process_block_availability = {};
    BOOST_CHECK(peerman->SendMessages(*peer));
    BOOST_CHECK_EQUAL(availability_calls, 2);
    {
        LOCK(peer->cs_vSend);
        BOOST_CHECK_EQUAL(std::ranges::count_if(peer->vSendMsg, [](const CSerializedNetMsg& message) {
            return message.m_type == NetMsgType::INV;
        }), 1);
    }

    m_node.validation_signals->UnregisterValidationInterface(peerman.get());
    peerman->FinalizeNode(*peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(compact_block_relay_claim_failure_preserves_rng)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    const auto run_announcement = [&](bool fail_claims) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        auto connman{std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params())};
        FakeBlockDownloadManagerState state;
        state.m_peer_snapshot.emplace();
        PeerManager::Options options;
        options.ignore_incoming_txs = true;
        options.deterministic_rng = true;
        auto peerman{PeerManager::make(
            *connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool,
            *m_node.warnings, std::make_unique<FakeBlockDownloadManager>(state), options)};
        connman->SetMsgProc(peerman.get());

        auto peer{std::make_unique<CNode>(
            /*id=*/123,
            /*sock=*/nullptr,
            CAddress{},
            /*nKeyedNetGroupIn=*/0,
            /*nLocalHostNonceIn=*/0,
            CAddress{},
            /*addrNameIn=*/"",
            ConnectionType::INBOUND,
            /*inbound_onion=*/false,
            /*network_key=*/0)};
        peer->nVersion = PROTOCOL_VERSION;
        peer->SetCommonVersion(PROTOCOL_VERSION);
        peerman->InitializeNode(*peer, NODE_NETWORK);
        peer->fSuccessfullyConnected = true;

        BOOST_REQUIRE(connman->ReceiveMsgFrom(
            *peer, NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/true, /*version=*/CMPCTBLOCKS_VERSION)));
        connman->ProcessMessagesOnce(*peer);
        BOOST_REQUIRE(peer->m_bip152_highbandwidth_from.load());

        const CBlockIndex* tip;
        {
            LOCK(cs_main);
            tip = Assert(m_node.chainman->ActiveChain().Tip());
        }
        // This manager never receives NewPoWValidBlock, so its compact-block
        // cache is empty and this announcement must use the disk fallback.
        m_node.validation_signals->RegisterValidationInterface(peerman.get());
        m_node.validation_signals->UpdatedBlockTip(tip, tip->pprev, /*fInitialDownload=*/false);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();

        int invalidated_claims{0};
        if (fail_claims) {
            state.m_process_block_availability = [&](NodeId id) {
                peerman->UpdateLastBlockAnnounceTime(id, ++invalidated_claims);
            };
            BOOST_REQUIRE(peerman->SendMessages(*peer));
            BOOST_CHECK_EQUAL(invalidated_claims, 2);
            {
                LOCK(peer->cs_vSend);
                BOOST_CHECK(peer->vSendMsg.empty());
            }
            state.m_process_block_availability = {};
        }

        // No block is re-enqueued here. A compact announcement therefore also
        // proves that both rejected attempts retained the original queue entry.
        BOOST_REQUIRE(peerman->SendMessages(*peer));
        std::vector<uint8_t> compact_payload;
        {
            LOCK(peer->cs_vSend);
            BOOST_REQUIRE_EQUAL(peer->vSendMsg.size(), 1);
            BOOST_REQUIRE_EQUAL(peer->vSendMsg.front().m_type, NetMsgType::CMPCTBLOCK);
            compact_payload = peer->vSendMsg.front().data;
        }

        m_node.validation_signals->UnregisterValidationInterface(peerman.get());
        peerman->FinalizeNode(*peer);
        return compact_payload;
    };

    const std::vector<uint8_t> raced_payload{run_announcement(/*fail_claims=*/true)};
    const std::vector<uint8_t> control_payload{run_announcement(/*fail_claims=*/false)};
    BOOST_CHECK(raced_payload == control_payload);
}

BOOST_AUTO_TEST_CASE(block_relay_generation_invalidates_eviction)
{
    FakeNodeClock clock{};
    auto connman{std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params())};
    CConnman::Options options;
    options.m_max_automatic_connections = DEFAULT_MAX_PEER_CONNECTIONS;
    connman->Init(options);

    FakeBlockDownloadManagerState state;
    auto peerman{PeerManager::make(
        *connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool,
        *m_node.warnings, std::make_unique<FakeBlockDownloadManager>(state), {})};

    std::vector<CNode*> nodes;
    for (NodeId id{0}; id <= MAX_OUTBOUND_FULL_RELAY_CONNECTIONS; ++id) {
        nodes.push_back(new CNode{
            id,
            /*sock=*/nullptr,
            CAddress{},
            /*nKeyedNetGroupIn=*/0,
            /*nLocalHostNonceIn=*/0,
            CAddress{},
            /*addrNameIn=*/"",
            ConnectionType::OUTBOUND_FULL_RELAY,
            /*inbound_onion=*/false,
            /*network_key=*/0,
        });
        nodes.back()->SetCommonVersion(PROTOCOL_VERSION);
        peerman->InitializeNode(*nodes.back(), ServiceFlags(NODE_NETWORK | NODE_WITNESS));
        nodes.back()->fSuccessfullyConnected = true;
        connman->AddTestNode(*nodes.back());
    }
    clock += 31s;

    // Mutating a non-selected candidate from the manager query invalidates
    // the candidate-wide generation set captured by eviction. Both bounded
    // attempts must fail and defer disconnection to the next scheduled check.
    int64_t announcement_time{1};
    state.m_before_peer_snapshot = [&](NodeId) {
        peerman->UpdateLastBlockAnnounceTime(nodes.front()->GetId(), announcement_time++);
    };
    peerman->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK_EQUAL(state.m_peer_snapshot_calls, 2);
    BOOST_CHECK(std::ranges::none_of(nodes, [](const CNode* node) { return node->fDisconnect.load(); }));

    // With a stable generation, the same conditional path commits and one
    // extra full-relay peer is disconnected.
    state.m_before_peer_snapshot = {};
    state.m_peer_snapshot_calls = 0;
    peerman->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK_EQUAL(state.m_peer_snapshot_calls, 1);
    BOOST_CHECK_EQUAL(std::ranges::count_if(nodes, [](const CNode* node) { return node->fDisconnect.load(); }), 1);

    for (const CNode* node : nodes) peerman->FinalizeNode(*node);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(block_relay_reconnect_generation_invalidates_eviction)
{
    FakeNodeClock clock{};
    auto connman{std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params())};
    CConnman::Options options;
    options.m_max_automatic_connections = DEFAULT_MAX_PEER_CONNECTIONS;
    connman->Init(options);

    FakeBlockDownloadManagerState state;
    auto peerman{PeerManager::make(
        *connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool,
        *m_node.warnings, std::make_unique<FakeBlockDownloadManager>(state), {})};

    std::vector<CNode*> nodes;
    for (NodeId id{0}; id <= MAX_BLOCK_RELAY_ONLY_CONNECTIONS; ++id) {
        nodes.push_back(new CNode{
            id,
            /*sock=*/nullptr,
            CAddress{},
            /*nKeyedNetGroupIn=*/0,
            /*nLocalHostNonceIn=*/0,
            CAddress{},
            /*addrNameIn=*/"",
            ConnectionType::BLOCK_RELAY,
            /*inbound_onion=*/false,
            /*network_key=*/0,
        });
        nodes.back()->SetCommonVersion(PROTOCOL_VERSION);
        peerman->InitializeNode(*nodes.back(), ServiceFlags(NODE_NETWORK | NODE_WITNESS));
        nodes.back()->fSuccessfullyConnected = true;
        connman->AddTestNode(*nodes.back());
    }
    clock += 31s;

    // Recreate the selected relay state with the same node id between its
    // snapshot and per-peer commit. A fresh unique generation must reject
    // both bounded attempts instead of ABA-matching the stale snapshot.
    state.m_before_peer_snapshot = [&](NodeId id) {
        const auto node{std::ranges::find(nodes, id, &CNode::GetId)};
        BOOST_REQUIRE(node != nodes.end());
        peerman->FinalizeNode(**node);
        peerman->InitializeNode(**node, ServiceFlags(NODE_NETWORK | NODE_WITNESS));
    };
    peerman->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK_EQUAL(state.m_peer_snapshot_calls, 2);
    BOOST_CHECK(std::ranges::none_of(nodes, [](const CNode* node) { return node->fDisconnect.load(); }));

    state.m_before_peer_snapshot = {};
    state.m_peer_snapshot_calls = 0;
    peerman->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK_EQUAL(state.m_peer_snapshot_calls, 1);
    BOOST_CHECK_EQUAL(std::ranges::count_if(nodes, [](const CNode* node) { return node->fDisconnect.load(); }), 1);

    for (const CNode* node : nodes) peerman->FinalizeNode(*node);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(block_relay_snapshot_update_race)
{
    auto connman{std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params())};
    FakeBlockDownloadManagerState state;
    state.m_peer_snapshot.emplace();
    auto peerman{PeerManager::make(
        *connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool,
        *m_node.warnings, std::make_unique<FakeBlockDownloadManager>(state), {})};

    CNode peer{
        /*id=*/123,
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
    peerman->InitializeNode(peer, ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    std::atomic<bool> start{false};
    bool all_reads_succeeded{true};
    std::thread writer{[&] {
        while (!start.load(std::memory_order_acquire)) {}
        for (int64_t time{0}; time < 5000; ++time) {
            peerman->UpdateLastBlockAnnounceTime(peer.GetId(), time);
        }
    }};
    std::thread reader{[&] {
        while (!start.load(std::memory_order_acquire)) {}
        for (int i{0}; i < 5000; ++i) {
            CNodeStateStats stats;
            all_reads_succeeded &= peerman->GetNodeStateStats(peer.GetId(), stats);
        }
    }};
    start.store(true, std::memory_order_release);
    writer.join();
    reader.join();
    BOOST_CHECK(all_reads_succeeded);

    peerman->FinalizeNode(peer);
}

BOOST_AUTO_TEST_SUITE_END()

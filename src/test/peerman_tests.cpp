// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <interfaces/mining.h>
#include <netmessagemaker.h>
#include <net_processing.h>
#include <node/p2p_block_processing.h>
#include <pow.h>
#include <primitives/block.h>
#include <protocol.h>
#include <sync.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <util/check.h>
#include <util/signalinterrupt.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
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
#include <utility>
#include <vector>

namespace {

class FakeP2PBlockProcessing final : public node::P2PBlockProcessing
{
public:
    FakeP2PBlockProcessing() { m_jobs.reserve(node::P2P_BLOCK_PROCESSING_MAX_JOBS); }

    bool CanSubmit(uint32_t serialized_size) const noexcept override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return !m_interrupted && !m_external_active &&
               m_jobs.size() < node::P2P_BLOCK_PROCESSING_MAX_JOBS &&
               serialized_size <= node::P2P_BLOCK_PROCESSING_MAX_BYTES &&
               m_bytes <= node::P2P_BLOCK_PROCESSING_MAX_BYTES - serialized_size;
    }

    bool IsIdle() const noexcept override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        util::SignalInterrupt* interrupt{nullptr};
        bool idle{false};
        {
            LOCK(m_mutex);
            ++m_is_idle_calls;
            if (m_interrupt_on_idle_call &&
                m_is_idle_calls == *m_interrupt_on_idle_call) {
                interrupt = m_idle_interrupt;
                m_interrupt_on_idle_call.reset();
                m_idle_interrupt = nullptr;
            }
            idle = !m_external_active && m_jobs.empty();
        }
        if (interrupt) (void)(*interrupt)();
        return idle;
    }

    node::P2PBlockProcessingSubmit Submit(node::P2PBlockProcessingJob job) noexcept override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        TestChainstateManager* leave_ibd{nullptr};
        {
            LOCK(m_mutex);
            if (m_interrupted) return node::P2PBlockProcessingSubmit::INTERRUPTED;
            if (m_interrupt_on_submit) {
                m_interrupted = true;
                return node::P2PBlockProcessingSubmit::INTERRUPTED;
            }
            Assert(!m_external_active);
            Assert(m_jobs.size() < node::P2P_BLOCK_PROCESSING_MAX_JOBS);
            Assert(job.serialized_size <= node::P2P_BLOCK_PROCESSING_MAX_BYTES - m_bytes);
            const uint32_t serialized_size{job.serialized_size};
            m_jobs.push_back(std::move(job));
            m_bytes += serialized_size;
            leave_ibd = m_leave_ibd_on_submit;
        }
        if (leave_ibd) leave_ibd->JumpOutOfIbd();
        return node::P2PBlockProcessingSubmit::ACCEPTED;
    }

    void Interrupt() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_interrupted = true;
    }

    node::P2PBlockProcessingCanceled Stop() override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_interrupted = true;
        m_external_active = false;
        m_bytes = 0;
        node::P2PBlockProcessingCanceled canceled;
        for (auto& job : m_jobs) {
            canceled.jobs[canceled.count++] = std::move(job);
        }
        m_jobs.clear();
        return canceled;
    }

    void SetExternalActive(bool active) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        Assert(m_jobs.empty());
        m_external_active = active;
    }

    void InterruptOnSubmit(bool value) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_interrupt_on_submit = value;
    }

    void LeaveIbdOnSubmit(TestChainstateManager& chainman)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_leave_ibd_on_submit = &chainman;
    }

    void InterruptOnIdleCall(util::SignalInterrupt& interrupt, size_t call)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        Assert(call > 0);
        m_is_idle_calls = 0;
        m_interrupt_on_idle_call = call;
        m_idle_interrupt = &interrupt;
    }

    size_t JobCount() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_jobs.size();
    }

    node::P2PBlockProcessingJob Job(size_t index) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_jobs.at(index);
    }

private:
    mutable Mutex m_mutex;
    std::vector<node::P2PBlockProcessingJob> m_jobs GUARDED_BY(m_mutex);
    uint64_t m_bytes GUARDED_BY(m_mutex){0};
    bool m_external_active GUARDED_BY(m_mutex){false};
    bool m_interrupted GUARDED_BY(m_mutex){false};
    bool m_interrupt_on_submit GUARDED_BY(m_mutex){false};
    TestChainstateManager* m_leave_ibd_on_submit GUARDED_BY(m_mutex){nullptr};
    mutable size_t m_is_idle_calls GUARDED_BY(m_mutex){0};
    mutable std::optional<size_t> m_interrupt_on_idle_call GUARDED_BY(m_mutex);
    mutable util::SignalInterrupt* m_idle_interrupt GUARDED_BY(m_mutex){nullptr};
};

bool HasSendMessage(CNode& node, std::string_view msg_type)
{
    LOCK(node.cs_vSend);
    const auto& [to_send, _more, transport_msg_type]{node.m_transport->GetBytesToSend(false)};
    if (!to_send.empty() && transport_msg_type == msg_type) return true;
    return std::ranges::any_of(node.vSendMsg, [&](const CSerializedNetMsg& msg) {
        return msg.m_type == msg_type;
    });
}

struct AsyncPeerManagerTest : RegTestingSetup {
    AsyncPeerManagerTest()
        : m_connman{static_cast<ConnmanTestMsg&>(*m_node.connman)}
    {
        m_connman.StopNodes();
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();

        auto processing{std::make_unique<FakeP2PBlockProcessing>()};
        m_processing = processing.get();
        PeerManager::Options options;
        options.deterministic_rng = true;
        options.async_pnb = true;
        m_node.peerman = PeerManager::make(
            m_connman, *m_node.addrman, m_node.banman.get(), *m_node.chainman,
            *m_node.mempool, *m_node.warnings, options, std::move(processing));
        m_connman.SetMsgProc(m_node.peerman.get());
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
        static_cast<TestChainstateManager&>(*m_node.chainman).ResetIbd();
    }

    ~AsyncPeerManagerTest()
    {
        if (!m_node.peerman) return;
        m_node.peerman->InterruptAsyncBlockProcessing();
        m_node.peerman->StopAsyncBlockProcessing();
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
        m_connman.StopNodes();
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();
        m_processing = nullptr;
    }

    CNode& AddNode(ConnectionType connection_type = ConnectionType::INBOUND)
    {
        const NodeId node_id{m_next_node_id++};
        in_addr raw_address{};
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
            /*successfully_connected=*/true,
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
        return m_node.peerman->SendMessages(node);
    }

    void ReceiveMsgFrom(CNode& node, CSerializedNetMsg msg)
    {
        Assert(m_connman.ReceiveMsgFrom(node, std::move(msg)));
    }

    void FlushSendBuffer(CNode& node)
    {
        m_connman.FlushSendBuffer(node);
        node.fPauseSend = false;
    }

    static CBlock UnknownBlock(uint32_t nonce)
    {
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = uint256::ONE;
        block.nTime = nonce;
        block.nBits = 0x207fffff;
        block.nNonce = nonce;
        return block;
    }

    CBlock NextBlock(uint32_t variant)
    {
        auto mining{interfaces::MakeMining(m_node)};
        auto block_template{mining->createNewBlock({}, /*cooldown=*/false)};
        CBlock block{Assert(block_template)->getBlock()};
        // The interface exposes a dummy coinbase in getBlock(); commit to the
        // returned transaction before using it as a validation fixture.
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.nTime += variant;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) {
            ++block.nNonce;
        }
        return block;
    }

    const CBlockIndex& ProcessHeader(const CBlock& block)
    {
        BlockValidationState state;
        const CBlockIndex* index{nullptr};
        Assert(m_node.chainman->ProcessNewBlockHeaders(
            {{block}}, /*min_pow_checked=*/true, state, &index));
        return *Assert(index);
    }

    void ProcessBlockSynchronously(const CBlock& block)
    {
        bool new_block{false};
        Assert(m_node.chainman->ProcessNewBlock(
            std::make_shared<const CBlock>(block),
            /*force_processing=*/true,
            /*min_pow_checked=*/true,
            &new_block));
        Assert(new_block);
    }

    void UseRealProcessing()
    {
        m_node.peerman->InterruptAsyncBlockProcessing();
        m_node.peerman->StopAsyncBlockProcessing();
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();
        m_processing = nullptr;

        PeerManager::Options options;
        options.deterministic_rng = true;
        options.async_pnb = true;
        m_node.peerman = PeerManager::make(
            m_connman, *m_node.addrman, m_node.banman.get(), *m_node.chainman,
            *m_node.mempool, *m_node.warnings, options);
        m_connman.SetMsgProc(m_node.peerman.get());
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
        static_cast<TestChainstateManager&>(*m_node.chainman).ResetIbd();
    }

    FakeP2PBlockProcessing& Processing() { return *Assert(m_processing); }

private:
    ConnmanTestMsg& m_connman;
    FakeP2PBlockProcessing* m_processing{nullptr};
    NodeId m_next_node_id{0};
};

class BlockCheckedCounter final : public CValidationInterface
{
public:
    void Watch(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_hash = hash;
        m_count = 0;
    }

    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState&) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            if (block->GetHash() != m_hash) return;
            ++m_count;
        }
        m_cv.notify_all();
    }

    bool WaitFor(size_t count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, std::chrono::seconds{120}, [&, count]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_count >= count;
        });
    }

    size_t Count() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_count;
    }

private:
    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    uint256 m_hash GUARDED_BY(m_mutex);
    size_t m_count GUARDED_BY(m_mutex){0};
};

class BlockCheckedGate final : public CValidationInterface
{
public:
    void Hold(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_hash = hash;
        m_entered = false;
        m_release = false;
        m_armed = true;
    }

    void Release() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_release = true;
        }
        m_cv.notify_all();
    }

    bool WaitUntilEntered() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, std::chrono::seconds{5}, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_entered;
        });
    }

    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState&) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        if (!m_armed || block->GetHash() != m_hash) return;
        m_entered = true;
        m_cv.notify_all();
        m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_release; });
        m_armed = false;
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    uint256 m_hash GUARDED_BY(m_mutex);
    bool m_armed GUARDED_BY(m_mutex){false};
    bool m_entered GUARDED_BY(m_mutex){false};
    bool m_release GUARDED_BY(m_mutex){true};
};

class BlockCheckedThrower final : public CValidationInterface
{
public:
    void Arm(const uint256& standard, const uint256& nonstandard)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_standard = standard;
        m_nonstandard = nonstandard;
    }

    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState&) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        enum class Throw { NONE, STANDARD, NONSTANDARD } action{Throw::NONE};
        {
            LOCK(m_mutex);
            if (block->GetHash() == m_standard) {
                m_standard.SetNull();
                action = Throw::STANDARD;
            } else if (block->GetHash() == m_nonstandard) {
                m_nonstandard.SetNull();
                action = Throw::NONSTANDARD;
            }
        }
        if (action == Throw::STANDARD) throw std::runtime_error{"test BlockChecked exception"};
        if (action == Throw::NONSTANDARD) throw 1;
    }

private:
    Mutex m_mutex;
    uint256 m_standard GUARDED_BY(m_mutex);
    uint256 m_nonstandard GUARDED_BY(m_mutex);
};

struct RealAsyncPeerManagerTest : AsyncPeerManagerTest {
    RealAsyncPeerManagerTest()
    {
        UseRealProcessing();
        m_node.validation_signals->RegisterValidationInterface(&m_checked);
        m_node.validation_signals->RegisterValidationInterface(&m_gate);
        m_node.validation_signals->RegisterValidationInterface(&m_thrower);
    }

    ~RealAsyncPeerManagerTest()
    {
        m_gate.Release();
        m_node.peerman->InterruptAsyncBlockProcessing();
        m_node.peerman->StopAsyncBlockProcessing();
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.validation_signals->UnregisterValidationInterface(&m_thrower);
        m_node.validation_signals->UnregisterValidationInterface(&m_gate);
        m_node.validation_signals->UnregisterValidationInterface(&m_checked);
    }

    BlockCheckedCounter m_checked;
    BlockCheckedGate m_gate;
    BlockCheckedThrower m_thrower;
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

BOOST_FIXTURE_TEST_CASE(async_block_capacity_preserves_front_and_peer_fairness, AsyncPeerManagerTest)
{
    CNode& hostile{AddNode()};
    CNode& unrelated{AddNode()};
    BOOST_REQUIRE(m_node.chainman->IsInitialBlockDownload());

    for (uint32_t nonce{0}; nonce < node::P2P_BLOCK_PROCESSING_MAX_JOBS + 1; ++nonce) {
        ReceiveMsgFrom(hostile, NetMsg::Make(
            NetMsgType::BLOCK, TX_WITH_WITNESS(UnknownBlock(nonce + 1))));
    }
    ReceiveMsgFrom(hostile, NetMsg::Make(NetMsgType::PING, uint64_t{1}));

    // One invocation fills active-plus-queued capacity. The ninth block stays
    // at the exact front, so the following PING cannot be skipped.
    BOOST_CHECK(ProcessMessagesOnce(hostile));
    BOOST_CHECK_EQUAL(Processing().JobCount(), node::P2P_BLOCK_PROCESSING_MAX_JOBS);
    BOOST_CHECK(!ProcessMessagesOnce(hostile));
    BOOST_CHECK(!HasSendMessage(hostile, NetMsgType::PONG));

    // No validation wait holds g_msgproc_mutex: another peer remains live.
    ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::PING, uint64_t{2}));
    BOOST_CHECK(!ProcessMessagesOnce(unrelated));
    BOOST_CHECK(HasSendMessage(unrelated, NetMsgType::PONG));

    // Cancellation returns all eight admitted jobs to PeerManager, which
    // removes every pending count before nodes are destroyed.
    m_node.peerman->InterruptAsyncBlockProcessing();
    m_node.peerman->StopAsyncBlockProcessing();
    BOOST_CHECK_EQUAL(Processing().JobCount(), 0U);
}

BOOST_FIXTURE_TEST_CASE(async_block_ping_and_ibd_exit_are_not_stranded, AsyncPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& post_ibd{AddNode()};
    const CBlock block{UnknownBlock(/*nonce=*/100)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{3}));
    Processing().LeaveIbdOnSubmit(
        static_cast<TestChainstateManager&>(*m_node.chainman));

    // The fake latches IBD false before Submit returns. The already-admitted
    // block is final, and this invocation requests a fresh pass instead of
    // stranding its ordinary front PING behind the held job.
    BOOST_CHECK(ProcessMessagesOnce(source));
    BOOST_REQUIRE_EQUAL(Processing().JobCount(), 1U);
    BOOST_CHECK(!ProcessMessagesOnce(source));
    BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));

    ReceiveMsgFrom(post_ibd, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(UnknownBlock(/*nonce=*/101))));
    ReceiveMsgFrom(post_ibd, NetMsg::Make(NetMsgType::PING, uint64_t{4}));
    BOOST_CHECK(!ProcessMessagesOnce(post_ibd));
    BOOST_CHECK(!HasSendMessage(post_ibd, NetMsgType::PONG));
    BOOST_CHECK_EQUAL(Processing().JobCount(), 1U);
}

BOOST_FIXTURE_TEST_CASE(async_deferred_peer_send_does_not_race_stale_timeout, AsyncPeerManagerTest)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock(/*variant=*/102)};
    const CBlockIndex& index{ProcessHeader(block)};
    FakeNodeClock clock{};
    BOOST_REQUIRE(m_node.peerman->FetchBlock(source.GetId(), index));
    FlushSendBuffer(source);

    static_cast<TestChainstateManager&>(*m_node.chainman).JumpOutOfIbd();
    Processing().SetExternalActive(true);
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    BOOST_CHECK(!ProcessMessagesOnce(source));

    // Model the worker becoming idle between this peer's ProcessMessages and
    // SendMessages calls. Its requested BLOCK remains at the exact front and
    // owns a fairness claim, so an aged download timer must not fire first.
    Processing().SetExternalActive(false);
    clock += 601s;
    BOOST_CHECK(SendMessagesOnce(source));
    BOOST_CHECK(!source.fDisconnect);

    (void)ProcessMessagesOnce(source);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) ==
                block.GetHash());
}

BOOST_FIXTURE_TEST_CASE(async_completed_drain_gates_same_pass_send, AsyncPeerManagerTest)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock(/*variant=*/103)};
    const CBlockIndex& index{ProcessHeader(block)};
    FakeNodeClock clock{};
    BOOST_REQUIRE(m_node.peerman->FetchBlock(source.GetId(), index));
    FlushSendBuffer(source);

    Processing().SetExternalActive(true);
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::SENDHEADERS));
    ReceiveMsgFrom(source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    BOOST_CHECK(!ProcessMessagesOnce(source));

    Processing().SetExternalActive(false);
    // Consume the sole drain owner's first untouched message. Its requested
    // BLOCK is still the front because the closed epoch rejects it when
    // PollMessage classifies the new front.
    BOOST_CHECK(!ProcessMessagesOnce(source));
    clock += 601s;
    BOOST_CHECK(SendMessagesOnce(source));
    BOOST_CHECK(!source.fDisconnect);

    // The next idle pass reopens the epoch and admits the exact retained
    // BLOCK before downloader timeout enforcement can run.
    BOOST_CHECK(ProcessMessagesOnce(source));
    BOOST_REQUIRE_EQUAL(Processing().JobCount(), 1U);
    BOOST_CHECK(Processing().Job(0).block->GetHash() == block.GetHash());
}

BOOST_FIXTURE_TEST_CASE(async_compact_protocol_messages_defer_without_skipping, AsyncPeerManagerTest)
{
    CNode& compact_peer{AddNode()};
    CNode& blocktxn_peer{AddNode()};
    CNode& unrelated{AddNode()};
    Processing().SetExternalActive(true);

    const CBlock compact_source{NextBlock(/*variant=*/200)};
    const CBlockHeaderAndShortTxIDs compact{compact_source, /*nonce=*/0};
    ReceiveMsgFrom(compact_peer, NetMsg::Make(NetMsgType::CMPCTBLOCK, compact));
    ReceiveMsgFrom(compact_peer, NetMsg::Make(NetMsgType::PING, uint64_t{5}));

    BlockTransactions unsolicited;
    unsolicited.blockhash = uint256::ONE;
    ReceiveMsgFrom(blocktxn_peer, NetMsg::Make(NetMsgType::BLOCKTXN, unsolicited));
    ReceiveMsgFrom(blocktxn_peer, NetMsg::Make(NetMsgType::PING, uint64_t{6}));

    BOOST_CHECK(!ProcessMessagesOnce(compact_peer));
    BOOST_CHECK(!ProcessMessagesOnce(blocktxn_peer));
    BOOST_CHECK(!HasSendMessage(compact_peer, NetMsgType::PONG));
    BOOST_CHECK(!HasSendMessage(blocktxn_peer, NetMsgType::PONG));

    ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::PING, uint64_t{7}));
    BOOST_CHECK(!ProcessMessagesOnce(unrelated));
    BOOST_CHECK(HasSendMessage(unrelated, NetMsgType::PONG));

    Processing().SetExternalActive(false);
    BOOST_CHECK(ProcessMessagesOnce(compact_peer));
    BOOST_CHECK(!ProcessMessagesOnce(compact_peer));
    BOOST_CHECK(HasSendMessage(compact_peer, NetMsgType::PONG));
    BOOST_CHECK(ProcessMessagesOnce(blocktxn_peer));
    BOOST_CHECK(!ProcessMessagesOnce(blocktxn_peer));
    BOOST_CHECK(HasSendMessage(blocktxn_peer, NetMsgType::PONG));
}

BOOST_FIXTURE_TEST_CASE(async_shutdown_during_idle_snapshot_preserves_front, AsyncPeerManagerTest)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock(/*variant=*/201)};
    const CBlockHeaderAndShortTxIDs compact{block, /*nonce=*/0};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::CMPCTBLOCK, compact));
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{8}));

    // Raise the same chainman signal used by -stopatheight from the sole
    // authoritative IsIdle snapshot. The second shutdown check must leave the
    // synchronous compact-block front (and its following PING) untouched.
    Processing().InterruptOnIdleCall(m_interrupt, /*call=*/1);
    BOOST_CHECK(!ProcessMessagesOnce(source));
    BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));

    BOOST_REQUIRE(m_interrupt.reset());
    BOOST_CHECK(ProcessMessagesOnce(source));
    BOOST_CHECK(!ProcessMessagesOnce(source));
    BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));
}

BOOST_FIXTURE_TEST_CASE(async_receive_pending_request_transition_and_cancel, AsyncPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& replacement{AddNode()};
    const CBlock block{NextBlock(/*variant=*/1)};
    const CBlockIndex& index{ProcessHeader(block)};

    BOOST_REQUIRE(m_node.peerman->FetchBlock(source.GetId(), index));
    CNodeStateStats source_stats;
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(source.GetId(), source_stats));
    BOOST_REQUIRE_EQUAL(source_stats.vHeightInFlight.size(), 1U);
    FlushSendBuffer(source);

    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    BOOST_CHECK(ProcessMessagesOnce(source));
    BOOST_REQUIRE_EQUAL(Processing().JobCount(), 1U);
    BOOST_CHECK(Processing().Job(0).force_processing);

    source_stats.vHeightInFlight.clear();
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(source.GetId(), source_stats));
    BOOST_CHECK(source_stats.vHeightInFlight.empty());
    const auto pending_fetch{m_node.peerman->FetchBlock(replacement.GetId(), index)};
    BOOST_CHECK(!pending_fetch);
    BOOST_CHECK_EQUAL(pending_fetch.error(), "Block already received and pending validation");

    m_node.peerman->InterruptAsyncBlockProcessing();
    m_node.peerman->StopAsyncBlockProcessing();
    BOOST_CHECK(m_node.peerman->FetchBlock(replacement.GetId(), index));
}

BOOST_FIXTURE_TEST_CASE(async_receipt_consumes_only_its_logical_request, AsyncPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& fallback{AddNode()};

    const CBlock requested_from_source{NextBlock(/*variant=*/10)};
    const CBlockIndex& source_index{ProcessHeader(requested_from_source)};
    BOOST_REQUIRE(m_node.peerman->FetchBlock(source.GetId(), source_index));
    FlushSendBuffer(source);

    ReceiveMsgFrom(source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(requested_from_source)));
    ReceiveMsgFrom(source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(requested_from_source)));
    BOOST_CHECK(ProcessMessagesOnce(source));
    BOOST_REQUIRE_EQUAL(Processing().JobCount(), 2U);
    BOOST_CHECK(Processing().Job(0).force_processing);
    BOOST_CHECK(!Processing().Job(1).force_processing);

    const CBlock requested_elsewhere{NextBlock(/*variant=*/11)};
    const CBlockIndex& fallback_index{ProcessHeader(requested_elsewhere)};
    BOOST_REQUIRE(m_node.peerman->FetchBlock(fallback.GetId(), fallback_index));
    FlushSendBuffer(fallback);

    // A receipt from an unrequested source leaves the fallback source's
    // logical request intact, so both queued duplicates retain master's
    // any-source force-processing behavior.
    ReceiveMsgFrom(source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(requested_elsewhere)));
    ReceiveMsgFrom(source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(requested_elsewhere)));
    BOOST_CHECK(ProcessMessagesOnce(source));
    BOOST_REQUIRE_EQUAL(Processing().JobCount(), 4U);
    BOOST_CHECK(Processing().Job(2).force_processing);
    BOOST_CHECK(Processing().Job(3).force_processing);
}

BOOST_FIXTURE_TEST_CASE(async_interrupted_submit_is_cleaned_at_stop, AsyncPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& replacement{AddNode()};
    const CBlock block{NextBlock(/*variant=*/300)};
    const CBlockIndex& index{ProcessHeader(block)};
    BOOST_REQUIRE(m_node.peerman->FetchBlock(source.GetId(), index));
    FlushSendBuffer(source);

    Processing().InterruptOnSubmit(true);
    ReceiveMsgFrom(source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{8}));

    BOOST_CHECK(ProcessMessagesOnce(source));
    BOOST_CHECK_EQUAL(Processing().JobCount(), 0U);
    BOOST_CHECK(!ProcessMessagesOnce(source));
    BOOST_CHECK(HasSendMessage(source, NetMsgType::PONG));

    // Stop drains the receipt that raced interruption without requiring the
    // message handler to acquire cs_main.
    m_node.peerman->StopAsyncBlockProcessing();
    BOOST_CHECK(m_node.peerman->FetchBlock(replacement.GetId(), index));
}

BOOST_FIXTURE_TEST_CASE(async_pending_first_block_suppresses_later_window_staller, AsyncPeerManagerTest)
{
    CNode& scanner{AddNode(ConnectionType::OUTBOUND_FULL_RELAY)};
    CNode& staller{AddNode()};
    CNode& supplier{AddNode()};

    CBlock first{NextBlock(/*variant=*/320)};
    std::vector<CBlockHeader> headers;
    headers.reserve(1025);
    headers.push_back(first);
    while (headers.size() < 1025) {
        CBlockHeader next{headers.back()};
        next.hashPrevBlock = headers.back().GetHash();
        ++next.nTime;
        next.nNonce = 0;
        while (!CheckProofOfWork(next.GetHash(), next.nBits,
                                 m_node.chainman->GetConsensus())) {
            ++next.nNonce;
        }
        headers.push_back(next);
    }

    std::vector<CBlock> header_message;
    header_message.reserve(headers.size());
    for (const CBlockHeader& header : headers) header_message.emplace_back(header);
    ReceiveMsgFrom(scanner, NetMsg::Make(
        NetMsgType::HEADERS, TX_WITH_WITNESS(header_message)));
    (void)ProcessMessagesOnce(scanner);

    std::vector<const CBlockIndex*> indexes;
    indexes.reserve(headers.size());
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            indexes.push_back(Assert(
                m_node.chainman->m_blockman.LookupBlockIndex(header.GetHash())));
        }
    }

    // Fill H2..H1024 from one peer. H1025 is the +1 probe just beyond the
    // 1024-block download window. Without pending-aware first-blocker logic,
    // scanning this window incorrectly starts a stalling timer on `staller`.
    for (size_t i{1}; i < 1024; ++i) {
        BOOST_REQUIRE(m_node.peerman->FetchBlock(staller.GetId(), *indexes[i]));
    }
    FlushSendBuffer(staller);

    BOOST_REQUIRE(m_node.peerman->FetchBlock(supplier.GetId(), *indexes[0]));
    FlushSendBuffer(supplier);
    Processing().InterruptOnSubmit(true);
    ReceiveMsgFrom(supplier, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(first)));
    (void)ProcessMessagesOnce(supplier);

    FakeNodeClock clock{};
    BOOST_CHECK(SendMessagesOnce(scanner));
    clock += 3s;
    BOOST_CHECK(SendMessagesOnce(staller));
    BOOST_CHECK(!staller.fDisconnect);

    // Stop drains the interrupt-racing fixed pending slot and its request.
    m_node.peerman->StopAsyncBlockProcessing();
}

BOOST_FIXTURE_TEST_CASE(async_busy_message_paths_do_not_wait_for_validation, RealAsyncPeerManagerTest)
{
    CNode& source{AddNode()};
    CNode& inv_peer{AddNode()};
    CNode& headers_peer{AddNode()};
    CNode& live_peer{AddNode()};
    CNode& discouraged_peer{AddNode()};

    const CBlock held{UnknownBlock(/*nonce=*/350)};
    m_gate.Hold(held.GetHash());
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(held)));
    BOOST_CHECK(ProcessMessagesOnce(source));
    BOOST_REQUIRE(m_gate.WaitUntilEntered());

    // Exercise SendMessages' pre-flagged disconnect path too. While the worker
    // is active it must leave the flag untouched instead of waiting for a
    // validation callback that may own CConnman's nodes mutex.
    m_node.peerman->UnitTestMisbehaving(discouraged_peer.GetId());

    ReceiveMsgFrom(source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(UnknownBlock(/*nonce=*/351))));
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{9}));
    ReceiveMsgFrom(inv_peer, NetMsg::Make(
        NetMsgType::INV, std::vector{CInv{MSG_BLOCK, uint256::ONE}}));
    ReceiveMsgFrom(inv_peer, NetMsg::Make(NetMsgType::PING, uint64_t{10}));
    ReceiveMsgFrom(headers_peer, NetMsg::Make(
        NetMsgType::HEADERS, std::vector<CBlockHeader>{}));
    ReceiveMsgFrom(headers_peer, NetMsg::Make(NetMsgType::PING, uint64_t{11}));
    ReceiveMsgFrom(live_peer, NetMsg::Make(NetMsgType::PING, uint64_t{12}));

    struct Results {
        bool block_more_work;
        bool block_ping_more_work;
        bool inv_more_work;
        bool headers_more_work;
        bool live_more_work;
        bool source_pong;
        bool inv_pong;
        bool headers_pong;
        bool live_pong;
        bool send_result;
    };
    auto attempt{std::async(std::launch::async, [&] {
        Results result;
        result.block_more_work = ProcessMessagesOnce(source);
        result.block_ping_more_work = ProcessMessagesOnce(source);
        result.inv_more_work = ProcessMessagesOnce(inv_peer);
        result.headers_more_work = ProcessMessagesOnce(headers_peer);
        result.live_more_work = ProcessMessagesOnce(live_peer);
        result.source_pong = HasSendMessage(source, NetMsgType::PONG);
        result.inv_pong = HasSendMessage(inv_peer, NetMsgType::PONG);
        result.headers_pong = HasSendMessage(headers_peer, NetMsgType::PONG);
        result.live_pong = HasSendMessage(live_peer, NetMsgType::PONG);
        result.send_result = SendMessagesOnce(discouraged_peer);
        return result;
    })};

    const bool completed_without_validation{
        attempt.wait_for(std::chrono::seconds{5}) == std::future_status::ready};
    m_gate.Release();
    const Results result{attempt.get()};

    BOOST_REQUIRE(completed_without_validation);
    BOOST_CHECK(result.block_more_work);
    BOOST_CHECK(!result.block_ping_more_work);
    BOOST_CHECK(!result.inv_more_work);
    BOOST_CHECK(!result.headers_more_work);
    BOOST_CHECK(!result.live_more_work);
    BOOST_CHECK(result.source_pong);
    BOOST_CHECK(!result.inv_pong);
    BOOST_CHECK(!result.headers_pong);
    BOOST_CHECK(result.live_pong);
    BOOST_CHECK(result.send_result);
    BOOST_CHECK(!discouraged_peer.fDisconnect);
}

BOOST_FIXTURE_TEST_CASE(async_fairness_drain_cohort_is_sealed, RealAsyncPeerManagerTest)
{
    CNode& block_source{AddNode()};
    CNode& owner_a{AddNode()};
    CNode& owner_b{AddNode()};
    CNode& late_peer{AddNode()};
    CNode& next_block_source{AddNode()};

    const CBlock first{UnknownBlock(/*nonce=*/370)};
    m_gate.Hold(first.GetHash());
    ReceiveMsgFrom(block_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(first)));
    for (uint32_t nonce{371};
         nonce < 370 + node::P2P_BLOCK_PROCESSING_MAX_JOBS; ++nonce) {
        ReceiveMsgFrom(block_source, NetMsg::Make(
            NetMsgType::BLOCK, TX_WITH_WITNESS(UnknownBlock(nonce))));
    }
    BOOST_CHECK(ProcessMessagesOnce(block_source));
    BOOST_REQUIRE(m_gate.WaitUntilEntered());

    ReceiveMsgFrom(owner_a, NetMsg::Make(NetMsgType::SENDHEADERS));
    ReceiveMsgFrom(owner_a, NetMsg::Make(NetMsgType::PING, uint64_t{20}));
    ReceiveMsgFrom(owner_b, NetMsg::Make(NetMsgType::SENDHEADERS));
    ReceiveMsgFrom(owner_b, NetMsg::Make(NetMsgType::PING, uint64_t{21}));
    BOOST_CHECK(!ProcessMessagesOnce(owner_a));
    BOOST_CHECK(!ProcessMessagesOnce(owner_b));

    m_gate.Release();
    const auto service_until_pong{[&](CNode& owner) {
        const auto deadline{std::chrono::steady_clock::now() + std::chrono::seconds{5}};
        while (!HasSendMessage(owner, NetMsgType::PONG) &&
               std::chrono::steady_clock::now() < deadline) {
            (void)ProcessMessagesOnce(owner);
            std::this_thread::yield();
        }
        return HasSendMessage(owner, NetMsgType::PONG);
    }};

    // Reaching A's PONG proves the worker became idle, sealed {A,B}, and gave
    // A exactly one untouched-front opportunity. B keeps that drain active.
    BOOST_REQUIRE(service_until_pong(owner_a));

    ReceiveMsgFrom(late_peer, NetMsg::Make(NetMsgType::SENDHEADERS));
    ReceiveMsgFrom(late_peer, NetMsg::Make(NetMsgType::PING, uint64_t{22}));
    ReceiveMsgFrom(next_block_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(UnknownBlock(/*nonce=*/379))));
    BOOST_CHECK(!ProcessMessagesOnce(late_peer));
    BOOST_CHECK(!ProcessMessagesOnce(next_block_source));
    BOOST_CHECK(!HasSendMessage(late_peer, NetMsgType::PONG));

    // A peer first encountered during the active drain cannot extend its
    // sealed cohort. A current owner whose send side pauses is released after
    // its bounded opportunity instead of holding the global gate hostage.
    owner_b.fPauseSend = true;
    BOOST_CHECK(!ProcessMessagesOnce(owner_b));
    owner_b.fPauseSend = false;
    // The late peer was not allowed to join the sealed {A,B} cohort, so the
    // next BLOCK is admissible immediately, before servicing late_peer.
    BOOST_CHECK(ProcessMessagesOnce(next_block_source));
    BOOST_CHECK(!HasSendMessage(late_peer, NetMsgType::PONG));
}

BOOST_FIXTURE_TEST_CASE(async_worker_survives_validation_callback_exceptions, RealAsyncPeerManagerTest)
{
    CNode& standard_source{AddNode()};
    CNode& nonstandard_source{AddNode()};
    CNode& sentinel_source{AddNode()};
    const CBlock standard{UnknownBlock(/*nonce=*/380)};
    const CBlock nonstandard{UnknownBlock(/*nonce=*/381)};
    const CBlock sentinel{UnknownBlock(/*nonce=*/382)};

    m_thrower.Arm(standard.GetHash(), nonstandard.GetHash());
    m_checked.Watch(sentinel.GetHash());
    ReceiveMsgFrom(standard_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(standard)));
    ReceiveMsgFrom(nonstandard_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(nonstandard)));
    ReceiveMsgFrom(sentinel_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(sentinel)));

    BOOST_CHECK(ProcessMessagesOnce(standard_source));
    BOOST_CHECK(ProcessMessagesOnce(nonstandard_source));
    BOOST_CHECK(ProcessMessagesOnce(sentinel_source));
    // Both exception kinds unwind through PNB, but the production processor
    // catches them, performs exact pending/source cleanup, releases capacity,
    // and continues to the later FIFO job.
    BOOST_REQUIRE(m_checked.WaitFor(/*count=*/1));
}

BOOST_FIXTURE_TEST_CASE(async_stop_finishes_active_and_cancels_queued_jobs, RealAsyncPeerManagerTest)
{
    CNode& active_source{AddNode()};
    CNode& active_fallback{AddNode()};
    CNode& queued_source_one{AddNode()};
    CNode& queued_source_two{AddNode()};
    CNode& synchronous_source{AddNode()};
    CBlock active{NextBlock(/*variant=*/390)};
    CMutableTransaction coinbase{*active.vtx.at(0)};
    coinbase.vout.at(0).nValue = MAX_MONEY + 1;
    active.vtx.at(0) = MakeTransactionRef(std::move(coinbase));
    active.hashMerkleRoot = BlockMerkleRoot(active);
    active.nNonce = 0;
    while (!CheckProofOfWork(active.GetHash(), active.nBits,
                             m_node.chainman->GetConsensus())) {
        ++active.nNonce;
    }
    const CBlockIndex& active_index{ProcessHeader(active)};
    BOOST_REQUIRE(m_node.peerman->FetchBlock(active_fallback.GetId(), active_index));
    FlushSendBuffer(active_fallback);
    const CBlock queued_one{UnknownBlock(/*nonce=*/391)};
    const CBlock queued_two{UnknownBlock(/*nonce=*/392)};
    const CBlock compact_block{NextBlock(/*variant=*/393)};
    const CBlockHeaderAndShortTxIDs compact{compact_block, /*nonce=*/0};

    m_gate.Hold(active.GetHash());
    m_checked.Watch(queued_one.GetHash());
    ReceiveMsgFrom(active_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(active)));
    ReceiveMsgFrom(queued_source_one, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(queued_one)));
    ReceiveMsgFrom(queued_source_two, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(queued_two)));
    ReceiveMsgFrom(synchronous_source, NetMsg::Make(NetMsgType::CMPCTBLOCK, compact));
    ReceiveMsgFrom(synchronous_source, NetMsg::Make(NetMsgType::PING, uint64_t{30}));
    BOOST_CHECK(ProcessMessagesOnce(active_source));
    BOOST_CHECK(ProcessMessagesOnce(queued_source_one));
    BOOST_CHECK(ProcessMessagesOnce(queued_source_two));
    BOOST_REQUIRE(m_gate.WaitUntilEntered());

    // Jobs retain only stable NodeIds/shared blocks. Disconnect flags can be
    // set while active and queued jobs exist without leaving peer pointers in
    // the worker handoff.
    BOOST_CHECK(m_node.connman->DisconnectNode(active_source.GetId()));
    BOOST_CHECK(m_node.connman->DisconnectNode(queued_source_one.GetId()));

    // Model -stopatheight's synchronous shutdown signal while the active PNB
    // is still unwinding. ProcessAsyncBlock observes this same chainman signal
    // after cleanup and interrupts promotion at the worker boundary.
    BOOST_REQUIRE((*Assert(m_node.shutdown_signal))());

    m_gate.Release();
    // While pending, state reporting hides the fallback request. Once it is
    // visible again, ProcessAsyncBlock has removed the pending slot and set
    // the queue interruption under the same cs_main critical section.
    CNodeStateStats fallback_stats;
    const auto deadline{std::chrono::steady_clock::now() + std::chrono::seconds{5}};
    do {
        BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(
            active_fallback.GetId(), fallback_stats));
        if (!fallback_stats.vHeightInFlight.empty()) break;
        std::this_thread::yield();
    } while (std::chrono::steady_clock::now() < deadline);
    BOOST_REQUIRE_EQUAL(fallback_stats.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(fallback_stats.vHeightInFlight.front(), active_index.nHeight);

    // No explicit Interrupt here: the production processor observed the
    // shutdown signal and closed promotion at its completion boundary.
    m_node.peerman->StopAsyncBlockProcessing();
    // Only the held active job ran. Stop returned the two queued jobs to
    // PeerManager, whose internal pending/request assertions passed.
    BOOST_CHECK_EQUAL(m_checked.Count(), 0U);
    // Even after Stop made the component idle, the chainman shutdown signal
    // prevents a synchronous-only front from being popped before CConnman's
    // external interrupt is propagated.
    BOOST_CHECK(!ProcessMessagesOnce(synchronous_source));
    BOOST_CHECK(!HasSendMessage(synchronous_source, NetMsgType::PONG));
}

BOOST_FIXTURE_TEST_CASE(async_completion_preserves_other_source_request_semantics, RealAsyncPeerManagerTest)
{
    CNode& valid_source{AddNode()};
    CNode& valid_fallback{AddNode()};
    CNode& invalid_source{AddNode()};
    CNode& invalid_fallback{AddNode()};
    CNode& sentinel_source{AddNode()};

    const CBlock valid{NextBlock(/*variant=*/400)};
    const CBlockIndex& valid_index{ProcessHeader(valid)};
    BOOST_REQUIRE(m_node.peerman->FetchBlock(valid_fallback.GetId(), valid_index));
    FlushSendBuffer(valid_fallback);
    const CBlock valid_sentinel{UnknownBlock(/*nonce=*/401)};
    m_checked.Watch(valid_sentinel.GetHash());
    ReceiveMsgFrom(valid_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(valid)));
    ReceiveMsgFrom(sentinel_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(valid_sentinel)));
    BOOST_CHECK(ProcessMessagesOnce(valid_source));
    BOOST_CHECK(ProcessMessagesOnce(sentinel_source));
    BOOST_REQUIRE(m_checked.WaitFor(/*count=*/1));

    CNodeStateStats fallback_stats;
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(valid_fallback.GetId(), fallback_stats));
    BOOST_CHECK(fallback_stats.vHeightInFlight.empty());

    // The valid tip leaves IBD. Re-enter the fixture's IBD state so the
    // invalid receipt below exercises the asynchronous completion path too.
    static_cast<TestChainstateManager&>(*m_node.chainman).ResetIbd();

    CBlock invalid{NextBlock(/*variant=*/402)};
    const CBlockIndex& invalid_index{ProcessHeader(invalid)};
    CMutableTransaction coinbase{*invalid.vtx.at(0)};
    BOOST_REQUIRE(!coinbase.vin.at(0).scriptWitness.stack.empty());
    BOOST_REQUIRE(!coinbase.vin.at(0).scriptWitness.stack.at(0).empty());
    coinbase.vin.at(0).scriptWitness.stack.at(0).at(0) ^= 1;
    invalid.vtx.at(0) = MakeTransactionRef(std::move(coinbase));
    BOOST_REQUIRE(invalid.GetHash() == invalid_index.GetBlockHash());

    BOOST_REQUIRE(m_node.peerman->FetchBlock(invalid_fallback.GetId(), invalid_index));
    FlushSendBuffer(invalid_fallback);
    const CBlock invalid_sentinel{UnknownBlock(/*nonce=*/403)};
    m_checked.Watch(invalid_sentinel.GetHash());
    ReceiveMsgFrom(invalid_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(invalid)));
    ReceiveMsgFrom(sentinel_source, NetMsg::Make(
        NetMsgType::BLOCK, TX_WITH_WITNESS(invalid_sentinel)));
    (void)ProcessMessagesOnce(invalid_source);
    (void)ProcessMessagesOnce(sentinel_source);
    BOOST_REQUIRE(m_checked.WaitFor(/*count=*/1));

    fallback_stats.vHeightInFlight.clear();
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(invalid_fallback.GetId(), fallback_stats));
    BOOST_REQUIRE_EQUAL(fallback_stats.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(fallback_stats.vHeightInFlight.front(), invalid_index.nHeight);
}

BOOST_FIXTURE_TEST_CASE(async_same_hash_invalid_jobs_punish_each_source_once, RealAsyncPeerManagerTest)
{
    CNode& first{AddNode()};
    CNode& second{AddNode()};
    const CBlock invalid{UnknownBlock(/*nonce=*/400)};
    m_checked.Watch(invalid.GetHash());

    ReceiveMsgFrom(first, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(invalid)));
    ReceiveMsgFrom(second, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(invalid)));
    BOOST_CHECK(ProcessMessagesOnce(first));
    BOOST_CHECK(ProcessMessagesOnce(second));
    BOOST_REQUIRE(m_checked.WaitFor(/*count=*/2));
    // BlockChecked notification can precede the remainder of the worker's
    // completion path. Join it before checking observable punishment state.
    m_node.peerman->InterruptAsyncBlockProcessing();
    m_node.peerman->StopAsyncBlockProcessing();

    // Each worker job installs and consumes the ordinary hash-keyed source
    // before the next FIFO job starts.
    BOOST_CHECK(SendMessagesOnce(first));
    BOOST_CHECK(SendMessagesOnce(second));
    BOOST_CHECK(first.fDisconnect);
    BOOST_CHECK(second.fDisconnect);
}

BOOST_FIXTURE_TEST_CASE(async_non_tip_source_survives_mutated_variant, RealAsyncPeerManagerTest)
{
    CNode& accepted_source{AddNode()};
    CNode& mutated_source{AddNode()};
    CNode& sentinel_source{AddNode()};

    // Save a valid height-one side block, then build a longer active branch so
    // accepting it stores a non-tip block with no immediate BlockChecked.
    const CBlock side{NextBlock(/*variant=*/0)};
    CBlock main_one{side};
    do {
        ++main_one.nNonce;
    } while (!CheckProofOfWork(
        main_one.GetHash(), main_one.nBits, m_node.chainman->GetConsensus()));
    ProcessBlockSynchronously(main_one);
    const CBlock main_two{NextBlock(/*variant=*/0)};
    ProcessBlockSynchronously(main_two);
    const CBlockIndex& side_index{ProcessHeader(side)};

    CBlock witness_mutated{side};
    CMutableTransaction coinbase{*witness_mutated.vtx.at(0)};
    BOOST_REQUIRE(!coinbase.vin.at(0).scriptWitness.stack.empty());
    BOOST_REQUIRE(!coinbase.vin.at(0).scriptWitness.stack.at(0).empty());
    coinbase.vin.at(0).scriptWitness.stack.at(0).at(0) ^= 1;
    witness_mutated.vtx.at(0) = MakeTransactionRef(std::move(coinbase));
    BOOST_REQUIRE(witness_mutated.GetHash() == side.GetHash());

    const CBlock sentinel{UnknownBlock(/*nonce=*/401)};
    m_checked.Watch(sentinel.GetHash());
    static_cast<TestChainstateManager&>(*m_node.chainman).ResetIbd();
    BOOST_REQUIRE(m_node.peerman->FetchBlock(accepted_source.GetId(), side_index));
    FlushSendBuffer(accepted_source);

    ReceiveMsgFrom(accepted_source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(side)));
    ReceiveMsgFrom(mutated_source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(witness_mutated)));
    ReceiveMsgFrom(sentinel_source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(sentinel)));
    BOOST_CHECK(ProcessMessagesOnce(accepted_source));
    BOOST_CHECK(ProcessMessagesOnce(mutated_source));
    BOOST_CHECK(ProcessMessagesOnce(sentinel_source));
    BOOST_REQUIRE(m_checked.WaitFor(/*count=*/1));

    // The early mutation path never attempts PNB and therefore does not erase
    // the accepted non-tip block's retained source.
    BlockValidationState invalid;
    invalid.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "test-deferred-source");
    m_node.validation_signals->BlockChecked(std::make_shared<const CBlock>(side), invalid);

    BOOST_CHECK(SendMessagesOnce(accepted_source));
    BOOST_CHECK(SendMessagesOnce(mutated_source));
    BOOST_CHECK(accepted_source.fDisconnect);
    BOOST_CHECK(mutated_source.fDisconnect);
}

BOOST_FIXTURE_TEST_CASE(async_non_tip_source_is_erased_by_ordinary_duplicate, RealAsyncPeerManagerTest)
{
    CNode& accepted_source{AddNode()};
    CNode& duplicate_source{AddNode()};
    CNode& sentinel_source{AddNode()};

    const CBlock side{NextBlock(/*variant=*/1)};
    CBlock main_one{side};
    do {
        ++main_one.nNonce;
    } while (!CheckProofOfWork(
        main_one.GetHash(), main_one.nBits, m_node.chainman->GetConsensus()));
    ProcessBlockSynchronously(main_one);
    const CBlock main_two{NextBlock(/*variant=*/1)};
    ProcessBlockSynchronously(main_two);
    const CBlockIndex& side_index{ProcessHeader(side)};

    const CBlock sentinel{UnknownBlock(/*nonce=*/404)};
    m_checked.Watch(sentinel.GetHash());
    static_cast<TestChainstateManager&>(*m_node.chainman).ResetIbd();
    BOOST_REQUIRE(m_node.peerman->FetchBlock(accepted_source.GetId(), side_index));
    FlushSendBuffer(accepted_source);

    ReceiveMsgFrom(accepted_source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(side)));
    ReceiveMsgFrom(duplicate_source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(side)));
    ReceiveMsgFrom(sentinel_source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(sentinel)));
    BOOST_CHECK(ProcessMessagesOnce(accepted_source));
    BOOST_CHECK(ProcessMessagesOnce(duplicate_source));
    BOOST_CHECK(ProcessMessagesOnce(sentinel_source));
    BOOST_REQUIRE(m_checked.WaitFor(/*count=*/1));

    // Match serial BLOCK processing: the later PNB attempt is non-new, so it
    // erases the older retained hash entry even though no callback fired.
    BlockValidationState invalid;
    invalid.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "test-erased-source");
    m_node.validation_signals->BlockChecked(std::make_shared<const CBlock>(side), invalid);
    BOOST_CHECK(SendMessagesOnce(accepted_source));
    BOOST_CHECK(SendMessagesOnce(duplicate_source));
    BOOST_CHECK(!accepted_source.fDisconnect);
    BOOST_CHECK(!duplicate_source.fDisconnect);
}

BOOST_AUTO_TEST_SUITE_END()

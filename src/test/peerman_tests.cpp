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
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <limits>
#include <memory>
#include <string_view>

namespace {

constexpr auto ASYNC_TEST_TIMEOUT{std::chrono::seconds{30}};

class AsyncResultWaiter
{
public:
    void Notify() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            ++m_count;
        }
        m_cv.notify_all();
    }

    bool WaitForCount(int count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, ASYNC_TEST_TIMEOUT, [this, count]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_count >= count;
        });
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    int m_count GUARDED_BY(m_mutex){0};
};

class BlockingBlockCheckedSequence final : public CValidationInterface
{
public:
    bool WaitForCount(int count) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, ASYNC_TEST_TIMEOUT, [this, count]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_entered >= count;
        });
    }

    void ReleaseOne() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            ++m_released;
        }
        m_cv.notify_all();
    }

    void ReleaseAll() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_released = std::numeric_limits<int>::max();
        }
        m_cv.notify_all();
    }

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState&) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        const int sequence{++m_entered};
        m_cv.notify_all();
        (void)m_cv.wait_for(lock, ASYNC_TEST_TIMEOUT, [this, sequence]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_released >= sequence;
        });
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    int m_entered GUARDED_BY(m_mutex){0};
    int m_released GUARDED_BY(m_mutex){0};
};

class AsyncPNBLockOrderGate
{
public:
    void Arm() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_armed = true;
    }

    void Hook(std::string_view event) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        if (!m_armed) return;
        if (event == "tx_download_locked") {
            m_tx_download_locked = true;
            m_cv.notify_all();
            m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_released; });
        } else if (event == "post_block_handler") {
            m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_tx_download_locked; });
        }
    }

    bool WaitForTxDownloadLocked() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_cv.wait_for(lock, ASYNC_TEST_TIMEOUT, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_tx_download_locked;
        });
    }

    void Release() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_released = true;
        }
        m_cv.notify_all();
    }

private:
    Mutex m_mutex;
    std::condition_variable m_cv;
    bool m_armed GUARDED_BY(m_mutex){false};
    bool m_tx_download_locked GUARDED_BY(m_mutex){false};
    bool m_released GUARDED_BY(m_mutex){false};
};

struct AsyncPNBPeerServiceSetup : RegTestingSetup {
    AsyncPNBPeerServiceSetup()
        : m_connman{static_cast<ConnmanTestMsg&>(*m_node.connman)},
          m_blocker{std::make_shared<BlockingBlockCheckedSequence>()}
    {
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();

        PeerManager::Options options;
        options.deterministic_rng = true;
        options.async_pnb_peer_service = true;
        options.unit_test_async_pnb_hook = [this](std::string_view event) {
            m_lock_order_gate.Hook(event);
        };
        auto validation{node::MakeP2PBlockValidation(*m_node.chainman, [this] {
            m_results.Notify();
            m_connman.WakeMessageHandler();
        })};
        m_node.peerman = PeerManager::make(
            m_connman, *m_node.addrman, m_node.banman.get(), *m_node.chainman,
            *m_node.mempool, *m_node.warnings, options, std::move(validation));
        m_connman.SetMsgProc(m_node.peerman.get());
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
        m_node.validation_signals->RegisterSharedValidationInterface(m_blocker);
    }

    ~AsyncPNBPeerServiceSetup()
    {
        if (!m_node.peerman) return;
        m_lock_order_gate.Release();
        m_node.peerman->InterruptAsyncPNBPeerService();
        m_blocker->ReleaseAll();
        m_node.peerman->StopAsyncPNBPeerService();
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
        m_node.validation_signals->UnregisterSharedValidationInterface(m_blocker);
        m_connman.StopNodes();
        m_connman.SetMsgProc(nullptr);
        m_node.peerman.reset();
    }

    CNode& AddNode()
    {
        const NodeId id{m_next_node_id++};
        struct in_addr raw_address;
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
            ConnectionType::INBOUND,
            /*inbound_onion=*/false,
            /*network_key=*/0}};
        m_connman.AddTestNode(*node);
        LOCK(NetEventsInterface::g_msgproc_mutex);
        m_connman.Handshake(
            *node, /*successfully_connected=*/true,
            ServiceFlags{NODE_NETWORK | NODE_WITNESS},
            ServiceFlags{NODE_NETWORK | NODE_WITNESS},
            PROTOCOL_VERSION, /*relay_txs=*/true);
        m_connman.FlushSendBuffer(*node);
        node->fPauseSend = false;
        return *node;
    }

    CBlock NextBlock(uint32_t variant)
    {
        auto mining{interfaces::MakeMining(m_node)};
        CBlock block{Assert(mining->createNewBlock({}, /*cooldown=*/false))->getBlock()};
        block.nTime += variant;
        block.hashMerkleRoot = BlockMerkleRoot(block);
        while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;
        return block;
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

    ConnmanTestMsg& m_connman;
    AsyncResultWaiter m_results;
    std::shared_ptr<BlockingBlockCheckedSequence> m_blocker;
    AsyncPNBLockOrderGate m_lock_order_gate;
    NodeId m_next_node_id{0};
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

BOOST_FIXTURE_TEST_CASE(async_pnb_peer_service_fencing_and_fifo, AsyncPNBPeerServiceSetup)
{
    CNode& source{AddNode()};
    CNode& unrelated{AddNode()};
    CNode& refused_front{AddNode()};
    CNode& second_source{AddNode()};
    CNode& discouraged{AddNode()};
    const CBlock first_block{NextBlock(/*variant=*/1)};
    const CBlock second_block{NextBlock(/*variant=*/2)};

    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(first_block)));
    (void)ProcessMessagesOnce(source);
    BOOST_REQUIRE(m_blocker->WaitForCount(1));

    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{1}));
    ReceiveMsgFrom(unrelated, NetMsg::Make(NetMsgType::PING, uint64_t{2}));
    unrelated.m_bip152_highbandwidth_from = true;
    ReceiveMsgFrom(refused_front, NetMsg::Make(NetMsgType::SENDHEADERS));
    ReceiveMsgFrom(refused_front, NetMsg::Make(NetMsgType::PING, uint64_t{3}));
    ReceiveMsgFrom(second_source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(second_block)));

    BOOST_CHECK(!ProcessMessagesOnce(source));
    BOOST_CHECK(!HasSendMessage(source, NetMsgType::PONG));
    BOOST_CHECK(!ProcessMessagesOnce(unrelated));
    BOOST_CHECK(!HasSendMessage(unrelated, NetMsgType::PONG));
    unrelated.m_bip152_highbandwidth_from = false;
    BOOST_CHECK(!ProcessMessagesOnce(unrelated));
    BOOST_CHECK(HasSendMessage(unrelated, NetMsgType::PONG));
    BOOST_CHECK(!ProcessMessagesOnce(refused_front));
    BOOST_CHECK(!HasSendMessage(refused_front, NetMsgType::PONG));
    BOOST_CHECK(!ProcessMessagesOnce(second_source));

    m_node.peerman->UnitTestMisbehaving(discouraged.GetId());
    BOOST_CHECK(SendMessagesOnce(discouraged));
    BOOST_CHECK(discouraged.fDisconnect);

    m_blocker->ReleaseOne();
    BOOST_REQUIRE(m_results.WaitForCount(1));
    BOOST_CHECK(ProcessMessagesOnce(unrelated)); // Collect, then yield a service window.

    // The refused BLOCK remained at the exact front while the slot was busy.
    auto queued_block{second_source.PollMessage()};
    BOOST_REQUIRE(queued_block);
    BOOST_CHECK_EQUAL(queued_block->first.m_type, NetMsgType::BLOCK);

    BOOST_CHECK(ProcessMessagesOnce(refused_front));
    BOOST_CHECK(!HasSendMessage(refused_front, NetMsgType::PONG));
    BOOST_CHECK(!ProcessMessagesOnce(refused_front));
    BOOST_CHECK(HasSendMessage(refused_front, NetMsgType::PONG));
}

BOOST_FIXTURE_TEST_CASE(async_pnb_peer_service_disconnect_and_active_stop, AsyncPNBPeerServiceSetup)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock(/*variant=*/3)};
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
    (void)ProcessMessagesOnce(source);
    BOOST_REQUIRE(m_blocker->WaitForCount(1));
    source.fDisconnect = true;

    auto stop{std::async(std::launch::async, [this] {
        m_node.peerman->StopAsyncPNBPeerService();
    })};
    BOOST_CHECK(stop.wait_for(std::chrono::milliseconds{20}) == std::future_status::timeout);
    m_blocker->ReleaseOne();
    BOOST_REQUIRE(m_results.WaitForCount(1));
    BOOST_REQUIRE(stop.wait_for(ASYNC_TEST_TIMEOUT) == std::future_status::ready);
    stop.get();
}

BOOST_FIXTURE_TEST_CASE(async_pnb_post_block_tail_skips_tx_download_mutex, AsyncPNBPeerServiceSetup)
{
    CNode& source{AddNode()};
    const CBlock block{NextBlock(/*variant=*/4)};
    m_lock_order_gate.Arm();
    // Let BlockChecked pass so the worker reaches the later ActiveTipChange
    // callback where the tx-download mutex is held.
    m_blocker->ReleaseOne();
    ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));

    auto process{std::async(std::launch::async, [this, &source] {
        return ProcessMessagesOnce(source);
    })};
    // The worker's ActiveTipChange callback is blocked while holding the real
    // tx-download mutex. The initiating BLOCK handler must return without
    // entering its ordinary post-message transaction tail.
    BOOST_REQUIRE(m_lock_order_gate.WaitForTxDownloadLocked());
    BOOST_REQUIRE(process.wait_for(ASYNC_TEST_TIMEOUT) == std::future_status::ready);
    BOOST_CHECK(!process.get());

    m_lock_order_gate.Release();
    BOOST_REQUIRE(m_blocker->WaitForCount(1));
    BOOST_REQUIRE(m_results.WaitForCount(1));
    BOOST_CHECK(ProcessMessagesOnce(source));
}

BOOST_AUTO_TEST_CASE(async_pnb_peer_service_default_off)
{
    BOOST_CHECK(!m_node.peerman->HasAsyncPNBPeerService());

    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    struct in_addr raw_address;
    raw_address.s_addr = 0xa0b0c001;
    auto* source{new CNode{
        /*id=*/0,
        /*sock=*/nullptr,
        CAddress{CService{CNetAddr{raw_address}, Params().GetDefaultPort()},
                 ServiceFlags{NODE_NETWORK | NODE_WITNESS}},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        CAddress{},
        /*addrNameIn=*/"",
        ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        /*network_key=*/0}};
    connman.AddTestNode(*source);
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.Handshake(
            *source, /*successfully_connected=*/true,
            ServiceFlags{NODE_NETWORK | NODE_WITNESS},
            ServiceFlags{NODE_NETWORK | NODE_WITNESS},
            PROTOCOL_VERSION, /*relay_txs=*/true);
        connman.FlushSendBuffer(*source);
    }
    source->fPauseSend = false;

    auto mining{interfaces::MakeMining(m_node)};
    CBlock block{Assert(mining->createNewBlock({}, /*cooldown=*/false))->getBlock()};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;
    auto recorder{std::make_shared<BlockingBlockCheckedSequence>()};
    recorder->ReleaseAll();
    m_node.validation_signals->RegisterSharedValidationInterface(recorder);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block))));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        (void)connman.ProcessMessagesOnce(*source);
    }
    BOOST_CHECK(recorder->WaitForCount(1));
    m_node.validation_signals->UnregisterSharedValidationInterface(recorder);
}

BOOST_AUTO_TEST_SUITE_END()

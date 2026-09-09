// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <banman.h>
#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <interfaces/mining.h>
#include <net_processing.h>
#include <netbase.h>
#include <node/blockprocessing.h>
#include <node/kernel_notifications.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <sync.h>
#include <test/util/logging.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/string.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <future>
#include <initializer_list>
#include <latch>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
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
    block.m_validation_cache.m_checked.store(true); // little speedup
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
struct BlockProcessingTestSetup : RegTestingSetup {
    FakeNodeClock m_clock;
    ConnmanTestMsg& m_connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    std::shared_ptr<CValidationInterface> m_observer;

    BlockProcessingTestSetup()
    {
        CConnman::Options opts{};
        opts.m_msgproc = m_node.peerman.get();
        opts.nSendBufferMaxSize = 1000000;
        m_connman.Init(opts);
        static_cast<TestChainstateManager&>(*m_node.chainman).JumpOutOfIbd();
        m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
    }

    ~BlockProcessingTestSetup()
    {
        AssertLockNotHeld(cs_main);
        AssertLockNotHeld(NetEventsInterface::g_msgproc_mutex);
        m_node.peerman->StopBlockProcessing();
        // Test-body locks have unwound. Keep subscribers, peers and the clock
        // alive until all queued validation callbacks have finished.
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        if (m_observer) {
            m_node.validation_signals->UnregisterSharedValidationInterface(m_observer);
            m_observer.reset();
        }
        m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
        for (const auto* peer : m_connman.TestNodes()) {
            m_node.peerman->FinalizeNode(*peer);
        }
        m_connman.ClearTestNodes();
    }

    void RegisterObserver(std::shared_ptr<CValidationInterface> observer)
    {
        Assert(!m_observer);
        m_observer = std::move(observer);
        m_node.validation_signals->RegisterSharedValidationInterface(m_observer);
    }

    bool Receive(CNode& peer, CSerializedNetMsg msg) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(peer, std::move(msg)));
        return m_connman.ProcessMessagesOnce(peer);
    }

    bool FinishBlock(CNode& consumer, UniqueLock<Mutex>& lock) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        bool ready;
        {
            REVERSE_LOCK(lock, NetEventsInterface::g_msgproc_mutex);
            ready = m_node.peerman->WaitForBlockProcessing();
        }
        BOOST_REQUIRE(ready);
        return m_connman.ProcessMessagesOnce(consumer);
    }

    void RequestBlock(CNode& peer, const CBlock& block)
    {
        BlockValidationState state;
        const CBlockIndex* index{nullptr};
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders({{block}}, true, state, &index));
        BOOST_REQUIRE(index);
        BOOST_REQUIRE(m_node.peerman->FetchBlock(peer.GetId(), *index));
        ExpectMessages(peer, {NetMsgType::GETDATA});
    }

    std::vector<int> BlocksInFlight(const CNode& peer)
    {
        CNodeStateStats stats;
        BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
        return stats.vHeightInFlight;
    }

    std::vector<std::string> SentMessages(CNode& peer)
    {
        std::vector<std::string> messages;
        {
            LOCK(peer.cs_vSend);
            // With no socket, the optimistic send leaves the first message in
            // the transport and subsequent messages in vSendMsg.
            const auto& [bytes, more, type] = peer.m_transport->GetBytesToSend(false);
            if (!bytes.empty()) messages.push_back(type);
            for (const auto& msg : peer.vSendMsg) {
                messages.push_back(msg.m_type);
            }
        }
        m_connman.FlushSendBuffer(peer);
        peer.fPauseSend = false;
        return messages;
    }

    void ExpectMessages(CNode& peer, std::initializer_list<std::string> expected)
    {
        const auto messages{SentMessages(peer)};
        BOOST_CHECK_EQUAL_COLLECTIONS(messages.begin(), messages.end(), expected.begin(), expected.end());
    }

    CNode& AddPeer(const CAddress& address = {}, ConnectionType connection = ConnectionType::OUTBOUND_FULL_RELAY,
                   CNodeOptions options = {}) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        auto peer{std::make_unique<CNode>(static_cast<NodeId>(m_connman.TestNodes().size()), /*sock=*/nullptr, address,
                                          /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0, CAddress{}, /*addrNameIn=*/"",
                                          connection, /*inbound_onion=*/false, /*network_key=*/0, std::move(options))};
        m_connman.AddTestNode(*peer);
        auto& node{*peer.release()}; // ClearTestNodes owns it after insertion.
        const auto services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
        m_connman.Handshake(node, true, services, services, PROTOCOL_VERSION, true);
        m_connman.FlushSendBuffer(node);
        node.fPauseSend = false;
        Receive(node, NetMsg::Make(NetMsgType::SENDCMPCT, true, CMPCTBLOCKS_VERSION));
        ExpectMessages(node, {});
        // Establish knowledge of the parent before the next block is announced.
        Receive(node, NetMsg::Make(NetMsgType::GETHEADERS, CBlockLocator{}, Params().GenesisBlock().GetHash()));
        ExpectMessages(node, {NetMsgType::HEADERS});
        return node;
    }
};
} // namespace

BOOST_FIXTURE_TEST_CASE(block_processing_completion_duplicate, BlockProcessingTestSetup)
{
    WAIT_LOCK(NetEventsInterface::g_msgproc_mutex, lock);
    auto& source{AddPeer(CAddress{LookupNumeric("1.2.3.4", Params().GetDefaultPort()), NODE_NONE})};
    auto& requested{AddPeer(CAddress{LookupNumeric("5.6.7.8", Params().GetDefaultPort()), NODE_NONE})};
    const auto block{CreateBlockChain(1, Params()).front()};
    RequestBlock(requested, *block);
    BOOST_REQUIRE_EQUAL(BlocksInFlight(requested).size(), 1);

    Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block)));
    FinishBlock(source, lock);
    const auto received_at{source.m_last_block_time.load()};
    BOOST_CHECK(received_at == GetTime<std::chrono::seconds>());
    BOOST_CHECK(BlocksInFlight(requested).empty());
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == block->GetHash());
    m_connman.FlushSendBuffer(source);

    m_clock += 1s;
    Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block)));
    FinishBlock(source, lock);
    BOOST_CHECK(source.m_last_block_time.load() == received_at);

    // A later invalid RPC-style submission with this header must not be
    // attributed to the peer that sent the already-known valid block.
    auto mutated{std::make_shared<CBlock>(*block)};
    mutated->vtx.clear();
    mutated->m_validation_cache = {};
    bool new_block{true};
    BOOST_CHECK(!m_node.chainman->ProcessNewBlock(mutated, true, true, &new_block));
    BOOST_CHECK(!new_block);
    m_node.peerman->SendMessages(source);
    BOOST_CHECK(!source.fDisconnect);
}

BOOST_FIXTURE_TEST_CASE(block_processing_completion_invalid, BlockProcessingTestSetup)
{
    WAIT_LOCK(NetEventsInterface::g_msgproc_mutex, lock);
    auto& source{AddPeer(CAddress{LookupNumeric("1.2.3.4", Params().GetDefaultPort()), NODE_NONE})};
    auto& requested{AddPeer(CAddress{LookupNumeric("5.6.7.8", Params().GetDefaultPort()), NODE_NONE})};
    const auto block{CreateBlockChain(1, Params()).front()};
    CMutableTransaction coinbase{*block->vtx[0]};
    coinbase.vout[0].nValue = -1;
    block->vtx[0] = MakeTransactionRef(std::move(coinbase));
    block->hashMerkleRoot = BlockMerkleRoot(*block);
    while (!CheckProofOfWork(block->GetHash(), block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
    }
    RequestBlock(requested, *block);

    Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block)));
    FinishBlock(source, lock);
    BOOST_CHECK(source.m_last_block_time.load() == 0s);
    // An invalid body must not cancel a different peer's pending download.
    BOOST_CHECK_EQUAL(BlocksInFlight(requested).size(), 1);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == Params().GenesisBlock().GetHash());
    m_node.peerman->SendMessages(source);
    BOOST_CHECK(source.fDisconnect);
}

BOOST_FIXTURE_TEST_CASE(block_processing_completion_write_failure, BlockProcessingTestSetup)
{
    WAIT_LOCK(NetEventsInterface::g_msgproc_mutex, lock);
    auto& source{AddPeer(CAddress{LookupNumeric("1.2.3.4", Params().GetDefaultPort()), NODE_NONE})};
    auto& requested{AddPeer(CAddress{LookupNumeric("5.6.7.8", Params().GetDefaultPort()), NODE_NONE})};
    const auto block{CreateBlockChain(1, Params()).front()};
    RequestBlock(requested, *block);

    struct Checked final : CValidationInterface {
        bool m_error{false};
        void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState& state) override
        {
            m_error = state.IsError();
        }
    };
    auto checked{std::make_shared<Checked>()};
    RegisterObserver(checked);
    const auto path{m_node.chainman->m_blockman.GetBlockPosFilename(FlatFilePos{0, 0})};
    const auto saved_path{path.parent_path() / "blk00000.saved"};
    BOOST_REQUIRE(fs::is_regular_file(path));
    BOOST_REQUIRE(!fs::exists(saved_path));
    {
        struct RestoreBlockFile {
            node::KernelNotifications& notifications;
            const bool shutdown_on_fatal_error;
            const fs::path path;
            const fs::path saved_path;
            bool renamed{false};
            bool created_directory{false};

            ~RestoreBlockFile()
            {
                notifications.m_shutdown_on_fatal_error = shutdown_on_fatal_error;
                std::error_code error;
                if (created_directory) {
                    Assert(fs::remove(path, error));
                    Assert(!error);
                }
                if (renamed) {
                    fs::rename(saved_path, path, error);
                    Assert(!error);
                }
            }
        } restore{*m_node.notifications, m_node.notifications->m_shutdown_on_fatal_error, path, saved_path};
        struct SettleBeforeRestore {
            PeerManager& peerman;
            UniqueLock<Mutex>& controller_lock;
            ~SettleBeforeRestore() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
            {
                REVERSE_LOCK(controller_lock, NetEventsInterface::g_msgproc_mutex);
                peerman.StopBlockProcessing();
            }
        } settle{*m_node.peerman, lock};
        fs::rename(path, saved_path);
        restore.renamed = true;
        restore.created_directory = fs::create_directory(path);
        BOOST_REQUIRE(restore.created_directory);
        m_node.notifications->m_shutdown_on_fatal_error = false;
        Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block)));
        FinishBlock(source, lock);
    }
    BOOST_CHECK(fs::is_regular_file(path));
    BOOST_CHECK(!fs::exists(saved_path));

    // AcceptBlock sets new_block before the write. Preserve the existing
    // timestamp/request cleanup even though ProcessNewBlock returned false.
    BOOST_CHECK(checked->m_error);
    BOOST_CHECK(source.m_last_block_time.load() == GetTime<std::chrono::seconds>());
    BOOST_CHECK(BlocksInFlight(requested).empty());
    {
        LOCK(cs_main);
        const auto* index{m_node.chainman->m_blockman.LookupBlockIndex(block->GetHash())};
        BOOST_REQUIRE(index);
        BOOST_CHECK(!(index->nStatus & BLOCK_HAVE_DATA));
        BOOST_CHECK(m_node.chainman->ActiveTip()->GetBlockHash() == Params().GenesisBlock().GetHash());
    }
    m_node.peerman->SendMessages(source);
    BOOST_CHECK(!source.fDisconnect);
}

BOOST_FIXTURE_TEST_CASE(block_processing_completion_disconnected_source, BlockProcessingTestSetup)
{
    WAIT_LOCK(NetEventsInterface::g_msgproc_mutex, lock);
    auto& source{AddPeer(CAddress{LookupNumeric("1.2.3.4", Params().GetDefaultPort()), NODE_NONE})};
    auto& requested{AddPeer(CAddress{LookupNumeric("5.6.7.8", Params().GetDefaultPort()), NODE_NONE})};
    const auto block{CreateBlockChain(1, Params()).front()};
    RequestBlock(requested, *block);

    struct DisconnectOnPoW final : CValidationInterface {
        CConnman& m_connman;
        const NodeId m_source;
        bool m_disconnected{false};
        DisconnectOnPoW(CConnman& connman, NodeId source) : m_connman{connman}, m_source{source} {}
        void NewPoWValidBlock(const CBlockIndex*, const std::shared_ptr<const CBlock>&) override
        {
            m_disconnected = m_connman.DisconnectNode(m_source);
        }
    };
    auto disconnect{std::make_shared<DisconnectOnPoW>(m_connman, source.GetId())};
    RegisterObserver(disconnect);
    Receive(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block)));
    // Collect through a different peer even though the retained source is
    // disconnected. The worker owns no CNode reference.
    FinishBlock(requested, lock);

    BOOST_CHECK(disconnect->m_disconnected);
    BOOST_CHECK(source.fDisconnect);
    BOOST_CHECK(!m_connman.ForNode(source.GetId(), [](CNode*) { return true; }));
    // The node-list lock protects a registered, disconnected source during completion.
    BOOST_CHECK(source.m_last_block_time.load() == GetTime<std::chrono::seconds>());
    BOOST_CHECK(BlocksInFlight(requested).empty());
    BOOST_CHECK(!requested.fDisconnect);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == block->GetHash());
}

namespace {
/** No peer subscriber is registered by RegTestingSetup: only this job can wake. */
node::BlockProcessingResult RunWorkerJob(node::BlockProcessingWorker& worker, ConnmanTestMsg& connman, node::BlockProcessingJob job)
    LOCKS_EXCLUDED(cs_main)
{
    worker.Start();
    // Outlive the inner wake lock, but settle before the caller restores any
    // fixture state, including if submission or result inspection throws.
    struct StopOnExit {
        node::BlockProcessingWorker& worker;
        ~StopOnExit() { worker.Stop(); }
    } stop_on_exit{worker};
    connman.TakeMessageWake();
    bool admitted, ready, rejected;
    std::optional<node::BlockProcessingResult> result;
    {
        LOCK(connman.MessageWakeMutex());
        admitted = worker.Submit(job);
        ready = worker.Wait();
        rejected = !worker.Submit(job);
        result = worker.TakeResult();
    }
    worker.Stop();
    // Obtaining a result while the real wake mutex was held proves publication
    // came first. Assertions run only after releasing that mutex and joining.
    BOOST_CHECK(admitted);
    BOOST_CHECK(ready);
    BOOST_CHECK(rejected);
    BOOST_CHECK(connman.TakeMessageWake());
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(result->source, job.source);
    BOOST_CHECK(result->hash == job.block->GetHash());
    BOOST_CHECK_EQUAL(result->optimistic_reconstruction, job.optimistic_reconstruction);
    return std::move(*result);
}

/** Declare before the worker so every producer is joined before unregistering. */
struct WorkerObserver {
    ValidationSignals& m_signals;
    const std::shared_ptr<CValidationInterface> m_observer;
    bool m_registered{true};

    WorkerObserver(ValidationSignals& signals, std::shared_ptr<CValidationInterface> observer)
        : m_signals{signals}, m_observer{std::move(observer)}
    {
        m_signals.RegisterSharedValidationInterface(m_observer);
    }
    void Finish()
    {
        if (!m_registered) return;
        AssertLockNotHeld(cs_main);
        AssertLockNotHeld(NetEventsInterface::g_msgproc_mutex);
        m_signals.SyncWithValidationInterfaceQueue();
        m_signals.UnregisterSharedValidationInterface(m_observer);
        m_registered = false;
    }
    ~WorkerObserver() { Finish(); }
};

struct WorkerChecked final : CValidationInterface {
    std::vector<std::thread::id> m_threads; // Read only after worker joins.
    bool m_throw{false};
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState&) override
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        AssertLockHeld(cs_main);
        AssertLockNotHeld(NetEventsInterface::g_msgproc_mutex);
        m_threads.push_back(std::this_thread::get_id());
        if (m_throw) throw std::runtime_error{"block worker test exception"};
    }
};

/** The master-compatible running pause holds main; never take main to release it. */
struct WorkerPoWPause final : CValidationInterface {
    const uint256 m_hash;
    Mutex m_mutex;
    std::condition_variable m_condition;
    bool m_entered GUARDED_BY(m_mutex){false};
    bool m_released GUARDED_BY(m_mutex){false};
    std::thread::id m_thread; // Read only after worker joins.

    explicit WorkerPoWPause(const uint256& hash) : m_hash{hash} {}
    void NewPoWValidBlock(const CBlockIndex*, const std::shared_ptr<const CBlock>& block) override
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_mutex)
    {
        AssertLockHeld(cs_main);
        AssertLockNotHeld(NetEventsInterface::g_msgproc_mutex);
        if (block->GetHash() != m_hash) return;
        WAIT_LOCK(m_mutex, lock);
        m_thread = std::this_thread::get_id();
        m_entered = true;
        m_condition.notify_all();
        m_condition.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_released; });
    }
    bool WaitEntered() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_condition.wait_until(lock, std::chrono::steady_clock::now() + 5s,
                                      [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_entered; });
    }
    void Release() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_released = true;
        m_condition.notify_all();
    }
};
/** Hold the real wake mutex on a separate thread, never across controller locks. */
struct MessageWakeGate {
    Mutex m_mutex;
    std::condition_variable m_condition;
    bool m_locked GUARDED_BY(m_mutex){false};
    bool m_released GUARDED_BY(m_mutex){false};
    std::thread m_thread;

    explicit MessageWakeGate(ConnmanTestMsg& connman)
    {
        try {
            m_thread = std::thread{[&] {
                LOCK(connman.MessageWakeMutex());
                WAIT_LOCK(m_mutex, lock);
                m_locked = true;
                m_condition.notify_all();
                m_condition.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_released; });
            }};
            WAIT_LOCK(m_mutex, lock);
            if (!m_condition.wait_until(lock, std::chrono::steady_clock::now() + 5s,
                                        [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_locked; })) {
                throw std::runtime_error{"message wake gate did not enter"};
            }
        } catch (...) {
            Finish();
            throw;
        }
    }
    void Finish() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_released = true;
            m_condition.notify_all();
        }
        if (m_thread.joinable()) m_thread.join();
    }
    ~MessageWakeGate() { Finish(); }
};

/** Existing synchronous notifications pause the worker while it holds main. */
struct BlockProcessingPause final : CValidationInterface {
    PeerManager& m_peerman;
    ValidationSignals& m_signals;
    const uint256 m_hash;
    const bool m_on_check;
    Mutex m_mutex;
    std::condition_variable m_condition;
    bool m_entered GUARDED_BY(m_mutex){false};
    bool m_released GUARDED_BY(m_mutex){false};
    std::thread::id m_thread; // Read after the job settles.

    BlockProcessingPause(node::NodeContext& node, const CBlock& block, bool on_check)
        : m_peerman{*node.peerman}, m_signals{*node.validation_signals}, m_hash{block.GetHash()}, m_on_check{on_check}
    {
        m_signals.RegisterValidationInterface(this);
    }
    void Enter(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_mutex)
    {
        AssertLockHeld(cs_main);
        AssertLockNotHeld(NetEventsInterface::g_msgproc_mutex);
        if (block.GetHash() != m_hash) return;
        WAIT_LOCK(m_mutex, lock);
        m_thread = std::this_thread::get_id();
        m_entered = true;
        m_condition.notify_all();
        m_condition.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_released; });
    }
    void NewPoWValidBlock(const CBlockIndex*, const std::shared_ptr<const CBlock>& block) override
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_mutex)
    {
        if (!m_on_check) Enter(*block);
    }
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState&) override
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_mutex)
    {
        if (m_on_check) Enter(*block);
    }
    bool WaitEntered() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        return m_condition.wait_until(lock, std::chrono::steady_clock::now() + 5s,
                                      [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_entered; });
    }
    void Release() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_released = true;
        m_condition.notify_all();
    }
    ~BlockProcessingPause()
    {
        Release();
        m_peerman.WaitForBlockProcessing();
        // Readiness does not drain queued callbacks to this raw observer.
        m_signals.SyncWithValidationInterfaceQueue();
        m_signals.UnregisterValidationInterface(this);
    }
};

/** Younger than BOTH pauses, active before submission, and no waiting here. */
struct ReleaseBlockPauses {
    BlockProcessingPause& first;
    BlockProcessingPause* second{nullptr};
    void Release()
    {
        first.Release();
        if (second) second->Release();
    }
    ~ReleaseBlockPauses() { Release(); }
};

/** A hidden main detour fails only after all pauses are released and threads joined. */
template <typename Action, typename Release>
bool RunWhileBlocked(Action&& action, Release&& release_current, ReleaseBlockPauses& pauses)
{
    std::promise<void> finished;
    auto future{finished.get_future()};
    std::exception_ptr exception;
    std::jthread controller;
    struct ReleaseBeforeJoin {
        ReleaseBlockPauses& pauses;
        bool armed{true};
        ~ReleaseBeforeJoin()
        {
            if (armed) pauses.Release();
        }
    } cleanup{pauses};
    controller = std::jthread{[&] {
        try {
            LOCK(NetEventsInterface::g_msgproc_mutex);
            action();
        } catch (...) {
            exception = std::current_exception();
        }
        finished.set_value();
    }};
    const bool progressed{future.wait_for(5s) == std::future_status::ready};
    release_current();
    controller.join();
    if (exception) std::rethrow_exception(exception);
    cleanup.armed = false; // Do not prematurely release a later, not-yet-submitted pause.
    return progressed;
}

/** Observe ready-before-wake through the real peer manager, then consume once. */
void CheckAsyncTerminal(BlockProcessingTestSetup& setup, CNode& source, const CBlock& block, bool collect_on_send)
{
    auto& peerman{*setup.m_node.peerman};
    auto& connman{setup.m_connman};
    // Prepare potentially throwing owners before any job or waiter is launched.
    CNode absent{99, nullptr, CAddress{}, 0, 0, CService{}, "", ConnectionType::INBOUND, false, 0};
    std::promise<bool> result;
    auto future{result.get_future()};
    struct StopOnExit {
        PeerManager& peerman;
        bool armed{true};
        ~StopOnExit()
        {
            if (armed) peerman.StopBlockProcessing();
        }
    } stop_on_exit{peerman};
    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    connman.TakeMessageWake();
    setup.SentMessages(source);
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block))));
        BOOST_REQUIRE(connman.ReceiveMsgFrom(source, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
    }
    MessageWakeGate wake{connman};
    std::jthread waiter;
    struct ReleaseWakeBeforeJoin {
        MessageWakeGate& wake;
        ~ReleaseWakeBeforeJoin() { wake.Finish(); }
    } release_wake{wake};
    WITH_LOCK(NetEventsInterface::g_msgproc_mutex, connman.ProcessMessagesOnce(source));
    waiter = std::jthread{[&] { result.set_value(peerman.WaitForBlockProcessing()); }};
    const bool ready_before_wake{future.wait_for(5s) == std::future_status::ready};
    bool missing_peer_return{true};
    if (ready_before_wake) {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        missing_peer_return = collect_on_send ? peerman.SendMessages(absent) : connman.ProcessMessagesOnce(absent);
    }
    wake.Finish();
    waiter.join();
    peerman.StopBlockProcessing();
    stop_on_exit.armed = false;
    BOOST_CHECK_MESSAGE(ready_before_wake, "Terminal result must be available before the message-handler wake");
    BOOST_CHECK(future.get());
    BOOST_CHECK(!missing_peer_return);
    BOOST_CHECK(connman.TakeMessageWake());
    BOOST_CHECK(!peerman.WaitForBlockProcessing());
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        BOOST_CHECK(!connman.ProcessMessagesOnce(source));
    }
    const auto sent{setup.SentMessages(source)};
    BOOST_CHECK_EQUAL(std::count(sent.begin(), sent.end(), NetMsgType::PONG), 1);
    BOOST_CHECK(!source.fDisconnect);
    peerman.StartBlockProcessing();
}

void CheckAsyncBlockProgress(BlockProcessingTestSetup& setup)
{
    auto& node{setup.m_node};
    auto& connman{setup.m_connman};
    const auto block{CreateBlockChain(1, Params()).front()};
    CNode *source, *observer, *requests, *fifo;
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        source = &setup.AddPeer({}, ConnectionType::OUTBOUND_FULL_RELAY, CNodeOptions{.recv_flood_size = 0});
        observer = &setup.AddPeer({}, ConnectionType::OUTBOUND_FULL_RELAY, CNodeOptions{.recv_flood_size = 0});
        requests = &setup.AddPeer({}, ConnectionType::OUTBOUND_FULL_RELAY, CNodeOptions{.recv_flood_size = 0});
        fifo = &setup.AddPeer({}, ConnectionType::OUTBOUND_FULL_RELAY, CNodeOptions{.recv_flood_size = 0});
        // Leave an older GETDATA request that a later PING must not bypass.
        setup.Receive(*requests, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
                                                                       {MSG_BLOCK, Params().GenesisBlock().GetHash()}, {MSG_BLOCK, Params().GenesisBlock().GetHash()}}));
        setup.ExpectMessages(*requests, {NetMsgType::BLOCK});
        BOOST_REQUIRE(connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block))));
        BOOST_REQUIRE(connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
        BOOST_REQUIRE(connman.ReceiveMsgFrom(*observer, NetMsg::Make(NetMsgType::PING, uint64_t{2})));
        BOOST_REQUIRE(connman.ReceiveMsgFrom(*observer, NetMsg::Make(NetMsgType::PONG, uint64_t{0})));
        BOOST_REQUIRE(connman.ReceiveMsgFrom(*requests, NetMsg::Make(NetMsgType::PING, uint64_t{3})));
        BOOST_REQUIRE(connman.ReceiveMsgFrom(*fifo, NetMsg::Make(NetMsgType::HEADERS, std::vector<CBlockHeader>{})));
        BOOST_REQUIRE(connman.ReceiveMsgFrom(*fifo, NetMsg::Make(NetMsgType::PING, uint64_t{4})));
    }

    BlockProcessingPause pause{node, *block, /*on_check=*/false};
    ReleaseBlockPauses release_all{pause};
    const bool submitted_more{WITH_LOCK(NetEventsInterface::g_msgproc_mutex, return connman.ProcessMessagesOnce(*source))};
    BOOST_REQUIRE(pause.WaitEntered());
    setup.SentMessages(*source);
    setup.SentMessages(*observer);
    setup.SentMessages(*requests);
    setup.SentMessages(*fifo);
    const auto source_bytes{WITH_LOCK(source->cs_vRecv, return source->nRecvBytes)};
    const auto request_bytes{WITH_LOCK(requests->cs_vRecv, return requests->nRecvBytes)};
    bool first_more{false}, second_more{true}, source_more{true}, request_more{true}, fifo_more{true};
    bool send_more{true}, source_send_more{true}, still_paused{false};
    std::optional<std::string> source_front, request_front, fifo_front;
    std::vector<std::string> observer_messages, source_messages, request_messages, fifo_messages;
    const bool progressed{RunWhileBlocked([&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        first_more = connman.ProcessMessagesOnce(*observer);
        second_more = connman.ProcessMessagesOnce(*observer);
        source_more = connman.ProcessMessagesOnce(*source);
        request_more = connman.ProcessMessagesOnce(*requests);
        fifo_more = connman.ProcessMessagesOnce(*fifo);
        node.peerman->SendPings();
        send_more = node.peerman->SendMessages(*observer);
        source_send_more = node.peerman->SendMessages(*source);
        source_front = source->PeekMessageType();
        request_front = requests->PeekMessageType();
        fifo_front = fifo->PeekMessageType();
        still_paused = source->fPauseRecv && requests->fPauseRecv && fifo->fPauseRecv;
        observer_messages = setup.SentMessages(*observer);
        source_messages = setup.SentMessages(*source);
        request_messages = setup.SentMessages(*requests);
        fifo_messages = setup.SentMessages(*fifo); }, [&] { pause.Release(); }, release_all)};
    // This remains unconditional in the external hidden-main control. Later
    // observations cannot be called pre-release progress when it is false.
    BOOST_CHECK_MESSAGE(progressed, "Other-peer receive and send must finish before the block gate is released");
    if (progressed) {
        BOOST_CHECK(!submitted_more);
        BOOST_CHECK(first_more);
        BOOST_CHECK(!second_more && !source_more && !request_more && !fifo_more);
        BOOST_CHECK(!send_more && !source_send_more);
        BOOST_CHECK(source_front == NetMsgType::PING);
        BOOST_CHECK(request_front == NetMsgType::PING);
        BOOST_CHECK(fifo_front == NetMsgType::HEADERS);
        BOOST_CHECK(still_paused);
        const std::vector<std::string> expected{NetMsgType::PONG, NetMsgType::PING};
        BOOST_CHECK_EQUAL_COLLECTIONS(observer_messages.begin(), observer_messages.end(), expected.begin(), expected.end());
        BOOST_CHECK(source_messages.empty() && request_messages.empty() && fifo_messages.empty());

        // No new traffic is added. Completion lets the source barrier and the
        // earlier request/header resume in their original order.
        BOOST_REQUIRE(node.peerman->WaitForBlockProcessing());
        LOCK(NetEventsInterface::g_msgproc_mutex);
        BOOST_CHECK(!connman.ProcessMessagesOnce(*source));
        source_messages = setup.SentMessages(*source);
        BOOST_CHECK_EQUAL(std::count(source_messages.begin(), source_messages.end(), NetMsgType::PONG), 1);
        BOOST_CHECK(!connman.ProcessMessagesOnce(*requests));
        request_messages = setup.SentMessages(*requests);
        const auto block_pos{std::ranges::find(request_messages, NetMsgType::BLOCK)};
        const auto pong_pos{std::ranges::find(request_messages, NetMsgType::PONG)};
        BOOST_CHECK(block_pos != request_messages.end() && pong_pos != request_messages.end() && block_pos < pong_pos);
        BOOST_CHECK(connman.ProcessMessagesOnce(*fifo));
        BOOST_CHECK(fifo->PeekMessageType() == NetMsgType::PING);
        BOOST_CHECK(!connman.ProcessMessagesOnce(*fifo));
        BOOST_CHECK(!source->fPauseRecv && !requests->fPauseRecv && !fifo->fPauseRecv);
        BOOST_CHECK_EQUAL(WITH_LOCK(source->cs_vRecv, return source->nRecvBytes), source_bytes);
        BOOST_CHECK_EQUAL(WITH_LOCK(requests->cs_vRecv, return requests->nRecvBytes), request_bytes);
    }
    // Also required in the negative control: release, collect and join normally,
    // and prove that a failed progress assertion did not prevent block admission.
    node.peerman->StopBlockProcessing();
    BOOST_CHECK(pause.m_thread != std::this_thread::get_id());
    BOOST_CHECK(WITH_LOCK(cs_main, return node.chainman->ActiveTip()->GetBlockHash()) == block->GetHash());
}
} // namespace

BOOST_FIXTURE_TEST_CASE(async_block_progress_under_main, BlockProcessingTestSetup)
{
    CheckAsyncBlockProgress(*this);
}

BOOST_FIXTURE_TEST_CASE(async_block_discourage_before_pong, BlockProcessingTestSetup)
{
    struct PolicyCase {
        std::string_view message;
        NetPermissionFlags permission;
        ConnectionType connection;
        bool local, disconnect, discourage;
    };
    const std::array cases{
        PolicyCase{NetMsgType::BLOCK, NetPermissionFlags::None, ConnectionType::OUTBOUND_FULL_RELAY, false, true, true},
        PolicyCase{NetMsgType::BLOCK, NetPermissionFlags::NoBan, ConnectionType::OUTBOUND_FULL_RELAY, false, false, false},
        PolicyCase{NetMsgType::BLOCK, NetPermissionFlags::None, ConnectionType::MANUAL, false, false, false},
        PolicyCase{NetMsgType::BLOCK, NetPermissionFlags::None, ConnectionType::INBOUND, true, true, false},
        PolicyCase{NetMsgType::CMPCTBLOCK, NetPermissionFlags::None, ConnectionType::OUTBOUND_FULL_RELAY, false, false, false},
        PolicyCase{NetMsgType::BLOCKTXN, NetPermissionFlags::None, ConnectionType::OUTBOUND_FULL_RELAY, false, false, false},
    };
    const auto blocks{CreateBlockChain(cases.size(), Params())};
    for (size_t i{0}; i < cases.size(); ++i) {
        const auto& test{cases[i]};
        BOOST_TEST_CONTEXT("worker-invalid message=" << test.message << " variant=" << i)
        {
            auto invalid{std::make_shared<CBlock>(*blocks[i])};
            CMutableTransaction coinbase{*invalid->vtx[0]};
            coinbase.vout[0].nValue = -1;
            invalid->vtx[0] = MakeTransactionRef(std::move(coinbase));
            if (test.message == NetMsgType::BLOCKTXN) {
                CMutableTransaction tx;
                tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
                tx.vout.emplace_back(1, CScript{} << OP_TRUE);
                invalid->vtx.push_back(MakeTransactionRef(std::move(tx)));
            }
            invalid->hashMerkleRoot = BlockMerkleRoot(*invalid);
            invalid->m_validation_cache = {};
            while (!CheckProofOfWork(invalid->GetHash(), invalid->nBits, Params().GetConsensus()))
                ++invalid->nNonce;

            CNode *source, *next;
            {
                LOCK(NetEventsInterface::g_msgproc_mutex);
                const auto address{test.local ? "127.0.0.1" : "1.2.3." + util::ToString(i + 1)};
                source = &AddPeer(CAddress{LookupNumeric(address, Params().GetDefaultPort()), NODE_NONE}, test.connection,
                                  CNodeOptions{.permission_flags = test.permission});
                next = &AddPeer(CAddress{LookupNumeric("5.6.7." + util::ToString(i + 1), Params().GetDefaultPort()), NODE_NONE});
                RequestBlock(*source, *invalid);
                if (test.message == NetMsgType::BLOCKTXN) {
                    Receive(*source, NetMsg::Make(NetMsgType::CMPCTBLOCK, CBlockHeaderAndShortTxIDs{*invalid, 1}));
                    ExpectMessages(*source, {NetMsgType::GETBLOCKTXN});
                    BlockTransactions response;
                    response.blockhash = invalid->GetHash();
                    response.txn = {invalid->vtx[1]};
                    BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::BLOCKTXN, response)));
                } else if (test.message == NetMsgType::CMPCTBLOCK) {
                    BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::CMPCTBLOCK, CBlockHeaderAndShortTxIDs{*invalid, 1})));
                } else {
                    BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*invalid))));
                }
                BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
                BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*next, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*blocks[i]))));
            }

            // Correct merkle roots reach the worker, not inline mutation checks.
            // Construct both observers and their ALL-release owner before the
            // first submission: no destructor may wait on an unreleased peer.
            BlockProcessingPause invalid_pause{m_node, *invalid, /*on_check=*/true};
            BlockProcessingPause next_pause{m_node, *blocks[i], /*on_check=*/false};
            ReleaseBlockPauses release_all{invalid_pause, &next_pause};
            WITH_LOCK(NetEventsInterface::g_msgproc_mutex, m_connman.ProcessMessagesOnce(*source));
            BOOST_REQUIRE(invalid_pause.WaitEntered());
            bool source_more{true};
            std::vector<std::string> before;
            const bool first_progress{RunWhileBlocked([&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
                source_more = m_connman.ProcessMessagesOnce(*source);
                before = SentMessages(*source); }, [&] { invalid_pause.Release(); }, release_all)};
            BOOST_CHECK(first_progress);
            if (first_progress) BOOST_CHECK(!source_more && before.empty());
            BOOST_REQUIRE(m_node.peerman->WaitForBlockProcessing());
            BOOST_CHECK(invalid_pause.m_thread != std::this_thread::get_id());

            // Another peer consumes the invalid result AND submits a new job.
            // The original source still owes its policy action before its PING.
            WITH_LOCK(NetEventsInterface::g_msgproc_mutex, m_connman.ProcessMessagesOnce(*next));
            BOOST_REQUIRE(next_pause.WaitEntered());
            SentMessages(*source); // Drop the unrelated good block announcement.
            bool disconnected{false}, discouraged{false};
            std::optional<std::string> front;
            std::vector<std::string> after;
            const bool next_progress{RunWhileBlocked([&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
                source_more = m_connman.ProcessMessagesOnce(*source);
                disconnected = source->fDisconnect;
                discouraged = m_node.banman->IsDiscouraged(source->addr);
                front = source->PeekMessageType();
                after = SentMessages(*source); }, [&] { next_pause.Release(); }, release_all)};
            BOOST_CHECK(next_progress);
            if (next_progress) {
                BOOST_CHECK(!source_more);
                BOOST_CHECK_EQUAL(disconnected, test.disconnect);
                BOOST_CHECK_EQUAL(discouraged, test.discourage);
                BOOST_CHECK_EQUAL(std::count(after.begin(), after.end(), NetMsgType::PONG), test.disconnect ? 0 : 1);
                BOOST_CHECK(test.disconnect ? front == NetMsgType::PING : !front);
            }
            BOOST_REQUIRE(m_node.peerman->WaitForBlockProcessing());
            WITH_LOCK(NetEventsInterface::g_msgproc_mutex, m_connman.ProcessMessagesOnce(*next));
            BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == blocks[i]->GetHash());
        }
    }
}

BOOST_FIXTURE_TEST_CASE(async_block_deferred_stream, BlockProcessingTestSetup)
{
    const auto blocks{CreateBlockChain(5, Params())};
    CNode *source, *deferred;
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        source = &AddPeer({}, ConnectionType::OUTBOUND_FULL_RELAY, CNodeOptions{.recv_flood_size = 0});
        deferred = &AddPeer({}, ConnectionType::OUTBOUND_FULL_RELAY,
                            CNodeOptions{.permission_flags = NetPermissionFlags::NoBan, .recv_flood_size = 0});
        for (const auto& block : blocks) {
            BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block))));
        }
        // Rejection is unimportant; honor the empty transaction's FIFO position.
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*deferred, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(CTransaction{CMutableTransaction{}}))));
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*deferred, NetMsg::Make(NetMsgType::HEADERS, std::vector<CBlockHeader>{})));
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*deferred, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{{MSG_BLOCK, Params().GenesisBlock().GetHash()}})));
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*deferred, NetMsg::Make(NetMsgType::PING, uint64_t{1})));
    }
    const auto source_bytes{WITH_LOCK(source->cs_vRecv, return source->nRecvBytes)};
    const auto deferred_bytes{WITH_LOCK(deferred->cs_vRecv, return deferred->nRecvBytes)};
    const std::array<std::optional<std::string>, 5> fronts{
        NetMsgType::HEADERS, NetMsgType::GETDATA, NetMsgType::PING, std::nullopt, std::nullopt};
    for (size_t i{0}; i < blocks.size(); ++i) {
        {
            LOCK(NetEventsInterface::g_msgproc_mutex);
            BOOST_CHECK(!m_connman.ProcessMessagesOnce(*source));
        }
        BOOST_REQUIRE(m_node.peerman->WaitForBlockProcessing());
        {
            LOCK(NetEventsInterface::g_msgproc_mutex);
            // Ready-but-unconsumed is still the single controller reservation.
            BOOST_CHECK(i + 1 == blocks.size() ? !source->PeekMessageType() : source->PeekMessageType() == NetMsgType::BLOCK);
            m_connman.ProcessMessagesOnce(*deferred);
            BOOST_CHECK(deferred->PeekMessageType() == fronts[i]);
            BOOST_CHECK_EQUAL(WITH_LOCK(source->cs_vRecv, return source->nRecvBytes), source_bytes);
            BOOST_CHECK_EQUAL(WITH_LOCK(deferred->cs_vRecv, return deferred->nRecvBytes), deferred_bytes);
        }
        BOOST_CHECK(!m_node.peerman->WaitForBlockProcessing());
    }
    // All four messages progressed with more blocks already queued, without
    // adding traffic or waiting for the entire block stream to finish.
    const auto sent{SentMessages(*deferred)};
    const auto block_pos{std::ranges::find(sent, NetMsgType::BLOCK)};
    const auto pong_pos{std::ranges::find(sent, NetMsgType::PONG)};
    BOOST_CHECK(block_pos != sent.end() && pong_pos != sent.end() && block_pos < pong_pos);
    BOOST_CHECK(!source->fPauseRecv && !deferred->fPauseRecv);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == blocks.back()->GetHash());
}

BOOST_FIXTURE_TEST_CASE(async_block_optimistic_cleanup, BlockProcessingTestSetup)
{
    // Fill the current per-peer download limit to select optimistic reconstruction.
    constexpr size_t DOWNLOAD_SLOTS{16};
    const auto blocks{CreateBlockChain(DOWNLOAD_SLOTS + 2, Params())};
    CNode *source, *requested;
    {
        WAIT_LOCK(NetEventsInterface::g_msgproc_mutex, lock);
        source = &AddPeer();
        requested = &AddPeer();
        Receive(*source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*blocks[0])));
        FinishBlock(*requested, lock);
        BOOST_REQUIRE(source->m_bip152_highbandwidth_to);
        SentMessages(*source);
        ExpectMessages(*requested, {NetMsgType::CMPCTBLOCK});
        RequestBlock(*requested, *blocks[1]);
        for (size_t i{2}; i < blocks.size(); ++i)
            RequestBlock(*source, *blocks[i]);
        BOOST_REQUIRE_EQUAL(BlocksInFlight(*source).size(), DOWNLOAD_SLOTS);
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::CMPCTBLOCK, CBlockHeaderAndShortTxIDs{*blocks[1], 1})));
    }
    BlockProcessingPause pause{m_node, *blocks[1], /*on_check=*/false};
    ReleaseBlockPauses release_all{pause};
    WITH_LOCK(NetEventsInterface::g_msgproc_mutex, m_connman.ProcessMessagesOnce(*source));
    BOOST_REQUIRE(pause.WaitEntered());
    pause.Release();
    BOOST_REQUIRE(m_node.peerman->WaitForBlockProcessing());
    // Master holds main in the notification. Inspect request state only after
    // release: the result is ready, but optimistic controller cleanup is pending.
    BOOST_CHECK_EQUAL(BlocksInFlight(*requested).size(), 1);
    BOOST_CHECK_EQUAL(BlocksInFlight(*source).size(), DOWNLOAD_SLOTS);
    WITH_LOCK(NetEventsInterface::g_msgproc_mutex, m_connman.ProcessMessagesOnce(*requested));
    BOOST_CHECK(BlocksInFlight(*requested).empty());
    BOOST_CHECK_EQUAL(BlocksInFlight(*source).size(), DOWNLOAD_SLOTS);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == blocks[1]->GetHash());
}

BOOST_FIXTURE_TEST_CASE(async_block_source_removed, BlockProcessingTestSetup)
{
    const auto block{CreateBlockChain(1, Params()).front()};
    CNode absent{99, nullptr, CAddress{}, 0, 0, CService{}, "", ConnectionType::INBOUND, false, 0};
    CNode* source;
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        source = &AddPeer();
        BOOST_REQUIRE(m_connman.ReceiveMsgFrom(*source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block))));
    }
    BlockProcessingPause pause{m_node, *block, /*on_check=*/false};
    ReleaseBlockPauses release_all{pause};
    WITH_LOCK(NetEventsInterface::g_msgproc_mutex, m_connman.ProcessMessagesOnce(*source));
    BOOST_REQUIRE(pause.WaitEntered());
    pause.Release();
    BOOST_REQUIRE(m_node.peerman->WaitForBlockProcessing());
    // This is source removal with a ready-but-unconsumed result, not removal
    // while the running notification holds main or a claim of callback drain.
    m_node.peerman->FinalizeNode(*source);
    m_connman.ClearTestNodes();
    source = nullptr;
    // No registered peers remain. Collect before the missing-peer early return
    // without retaining or dereferencing the destroyed source CNode.
    BOOST_CHECK(!WITH_LOCK(NetEventsInterface::g_msgproc_mutex, return m_node.peerman->SendMessages(absent)));
    BOOST_CHECK(!m_node.peerman->WaitForBlockProcessing());
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == block->GetHash());
}

BOOST_FIXTURE_TEST_CASE(async_block_terminal_completion, BlockProcessingTestSetup)
{
    const auto blocks{CreateBlockChain(3, Params())};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(blocks[0], true, true, nullptr));
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(blocks[1], true, true, nullptr));
    CNode* source;
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        source = &AddPeer(CAddress{LookupNumeric("1.2.3.4", Params().GetDefaultPort()), NODE_NONE});
    }
    auto side{std::make_shared<CBlock>(*blocks[0])};
    do {
        ++side->nNonce;
    } while (!CheckProofOfWork(side->GetHash(), side->nBits, Params().GetConsensus()));
    side->m_validation_cache = {};

    CheckAsyncTerminal(*this, *source, *blocks[1], /*collect_on_send=*/false); // Duplicate.
    BOOST_CHECK(source->m_last_block_time.load() == 0s);
    CheckAsyncTerminal(*this, *source, *side, /*collect_on_send=*/true); // Ignored lower-work body.
    BOOST_CHECK(!(WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(side->GetHash())->nStatus) & BLOCK_HAVE_DATA));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        RequestBlock(*source, *side);
    }
    CheckAsyncTerminal(*this, *source, *side, /*collect_on_send=*/false); // Stored without changing the tip.
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == blocks[1]->GetHash());
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(side->GetHash())->nStatus) & BLOCK_HAVE_DATA);

    const auto path{m_node.chainman->m_blockman.GetBlockPosFilename(FlatFilePos{0, 0})};
    const auto saved_path{path.parent_path() / "blk00000.saved"};
    BOOST_REQUIRE(fs::is_regular_file(path));
    BOOST_REQUIRE(!fs::exists(saved_path));
    {
        struct RestoreBlockFile {
            node::KernelNotifications& notifications;
            const bool shutdown_on_fatal_error;
            const fs::path path;
            const fs::path saved_path;
            bool renamed{false};
            bool created_directory{false};

            ~RestoreBlockFile()
            {
                notifications.m_shutdown_on_fatal_error = shutdown_on_fatal_error;
                std::error_code error;
                if (created_directory) {
                    Assert(fs::remove(path, error));
                    Assert(!error);
                }
                if (renamed) {
                    fs::rename(saved_path, path, error);
                    Assert(!error);
                }
            }
        } restore{*m_node.notifications, m_node.notifications->m_shutdown_on_fatal_error, path, saved_path};
        fs::rename(path, saved_path);
        restore.renamed = true;
        restore.created_directory = fs::create_directory(path);
        BOOST_REQUIRE(restore.created_directory);
        m_node.notifications->m_shutdown_on_fatal_error = false;
        // The helper releases the wake and settles/joins on every exit before
        // this caller-owned restoration guard can touch the block-file path.
        CheckAsyncTerminal(*this, *source, *blocks[2], /*collect_on_send=*/true);
    }
    BOOST_CHECK(fs::is_regular_file(path));
    BOOST_CHECK(!fs::exists(saved_path));
    // An ordinary write failure still preserves the already-assigned output.
    BOOST_CHECK(source->m_last_block_time.load() == GetTime<std::chrono::seconds>());
    BOOST_CHECK(!(WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(blocks[2]->GetHash())->nStatus) & BLOCK_HAVE_DATA));
}

BOOST_FIXTURE_TEST_CASE(async_block_exception_completion, BlockProcessingTestSetup)
{
    auto invalid{CreateBlockChain(1, Params()).front()};
    CMutableTransaction coinbase{*invalid->vtx[0]};
    coinbase.vout[0].nValue = -1;
    invalid->vtx[0] = MakeTransactionRef(std::move(coinbase));
    invalid->hashMerkleRoot = BlockMerkleRoot(*invalid);
    invalid->m_validation_cache = {};
    while (!CheckProofOfWork(invalid->GetHash(), invalid->nBits, Params().GetConsensus()))
        ++invalid->nNonce;
    CNode* source;
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        source = &AddPeer(CAddress{LookupNumeric("1.2.3.4", Params().GetDefaultPort()), NODE_NONE});
    }
    // Throw before the peer subscriber runs: this runtime exception itself
    // must not manufacture punishment. Retain shared ownership through drain.
    auto checked{std::make_shared<WorkerChecked>()};
    checked->m_throw = true;
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    m_node.validation_signals->UnregisterValidationInterface(m_node.peerman.get());
    RegisterObserver(checked);
    m_node.validation_signals->RegisterValidationInterface(m_node.peerman.get());
    {
        ASSERT_DEBUG_LOG("Exception processing block");
        CheckAsyncTerminal(*this, *source, *invalid, /*collect_on_send=*/false);
    }
    // Iterate retains the throwing callback's count; the fixture keeps it
    // alive until signals destruction. No further ProcessNewBlock runs here.
    BOOST_REQUIRE_EQUAL(checked->m_threads.size(), 1);
    BOOST_CHECK(checked->m_threads.front() != std::this_thread::get_id());
    BOOST_CHECK(!source->fDisconnect);
    BOOST_CHECK(!m_node.banman->IsDiscouraged(source->addr));
    BOOST_CHECK(!WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(invalid->GetHash())));
}

BOOST_AUTO_TEST_CASE(block_worker_idle_and_ready)
{
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    node::BlockProcessingWorker worker{*m_node.chainman, connman};
    BOOST_CHECK(!worker.Wait());
    BOOST_CHECK(!worker.TakeResult());
    worker.Stop();
    worker.Stop();
    BOOST_CHECK(!worker.Submit({std::make_shared<const CBlock>(Params().GenesisBlock()), 3, true, true}));

    worker.Start();
    auto payload{std::make_shared<const CBlock>(Params().GenesisBlock())};
    std::weak_ptr<const CBlock> weak_payload{payload};
    connman.TakeMessageWake();
    bool admitted, ready, released, rejected;
    std::optional<node::BlockProcessingResult> result;
    {
        LOCK(connman.MessageWakeMutex());
        admitted = worker.Submit({std::move(payload), 3, true, true});
        ready = worker.Wait();
        released = weak_payload.expired();
        rejected = !worker.Submit({std::make_shared<const CBlock>(Params().GenesisBlock()), 4, true, true});
        result = worker.TakeResult();
    }
    worker.Stop();
    BOOST_CHECK(admitted);
    BOOST_CHECK(ready);
    BOOST_CHECK(released);
    BOOST_CHECK(rejected);
    BOOST_CHECK(connman.TakeMessageWake());
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->processing_success);
    BOOST_CHECK(!result->new_block);
    BOOST_CHECK(!result->exception);
    BOOST_CHECK_EQUAL(result->source, 3);
    BOOST_CHECK(result->hash == Params().GenesisBlock().GetHash());
    BOOST_CHECK(!worker.Wait());
    BOOST_CHECK(!worker.TakeResult());
}

BOOST_AUTO_TEST_CASE(block_worker_terminal_wakeups)
{
    auto& chainman{*m_node.chainman};
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const auto blocks{CreateBlockChain(3, Params())};
    auto side{std::make_shared<CBlock>(*blocks[0])};
    do {
        ++side->nNonce;
    } while (!CheckProofOfWork(side->GetHash(), side->nBits, Params().GetConsensus()));
    auto invalid{std::make_shared<CBlock>(*blocks[1])};
    invalid->vtx.clear();
    invalid->m_validation_cache = {};
    node::BlockProcessingWorker worker{chainman, connman};

    const auto valid{RunWorkerJob(worker, connman, {blocks[0], 7, true, true})};
    BOOST_CHECK(valid.processing_success && valid.new_block && !valid.exception);
    const auto duplicate{RunWorkerJob(worker, connman, {blocks[0], 7, true, true})};
    BOOST_CHECK(duplicate.processing_success && !duplicate.new_block && !duplicate.exception);
    const auto next{RunWorkerJob(worker, connman, {blocks[1], 7, true, true})};
    BOOST_CHECK(next.processing_success && next.new_block && !next.exception);

    // Lower-work, unrequested data is ignored; requesting it then stores a
    // side-chain block without changing the active tip. Both still need a wake.
    const auto ignored{RunWorkerJob(worker, connman, {side, 8, false, true})};
    BOOST_CHECK(ignored.processing_success && !ignored.new_block && !ignored.exception);
    BOOST_CHECK(!(WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(side->GetHash())->nStatus) & BLOCK_HAVE_DATA));
    const auto no_tip{RunWorkerJob(worker, connman, {side, 8, true, true, true})};
    BOOST_CHECK(no_tip.processing_success && no_tip.new_block && !no_tip.exception);
    BOOST_CHECK(WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()) == blocks[1]->GetHash());
    const auto failed{RunWorkerJob(worker, connman, {invalid, 9, true, true})};
    BOOST_CHECK(!failed.processing_success && !failed.new_block && !failed.exception);

    const auto path{chainman.m_blockman.GetBlockPosFilename(FlatFilePos{0, 0})};
    const auto saved_path{path.parent_path() / "blk00000.saved"};
    BOOST_REQUIRE(fs::is_regular_file(path));
    BOOST_REQUIRE(!fs::exists(saved_path));
    std::optional<node::BlockProcessingResult> write_failed;
    {
        struct RestoreBlockFile {
            node::KernelNotifications& notifications;
            const bool shutdown_on_fatal_error;
            const fs::path path;
            const fs::path saved_path;
            bool renamed{false};
            bool created_directory{false};

            ~RestoreBlockFile()
            {
                notifications.m_shutdown_on_fatal_error = shutdown_on_fatal_error;
                std::error_code error;
                if (created_directory) {
                    Assert(fs::remove(path, error));
                    Assert(!error);
                }
                if (renamed) {
                    fs::rename(saved_path, path, error);
                    Assert(!error);
                }
            }
        } restore{*m_node.notifications, m_node.notifications->m_shutdown_on_fatal_error, path, saved_path};
        fs::rename(path, saved_path);
        restore.renamed = true;
        restore.created_directory = fs::create_directory(path);
        BOOST_REQUIRE(restore.created_directory);
        m_node.notifications->m_shutdown_on_fatal_error = false;
        write_failed = RunWorkerJob(worker, connman, {blocks[2], 9, true, true});
    }
    BOOST_CHECK(fs::is_regular_file(path));
    BOOST_CHECK(!fs::exists(saved_path));
    BOOST_REQUIRE(write_failed);
    // The new_block output is assigned before the failed write.
    BOOST_CHECK(!write_failed->processing_success && write_failed->new_block && !write_failed->exception);
}

BOOST_AUTO_TEST_CASE(block_worker_queued_shutdown)
{
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    auto invalid{std::make_shared<CBlock>(Params().GenesisBlock())};
    invalid->vtx.clear();
    invalid->m_validation_cache = {};
    auto checked{std::make_shared<WorkerChecked>()};
    WorkerObserver observer{*m_node.validation_signals, checked};
    node::BlockProcessingWorker worker{*m_node.chainman, connman};
    std::latch stopping{1};
    std::thread::id stop_thread;
    std::jthread stopper;
    bool admitted, ready, queued;
    std::optional<node::BlockProcessingResult> first;
    connman.TakeMessageWake();
    {
        LOCK(connman.MessageWakeMutex());
        admitted = worker.Submit({invalid, 11, true, true});
        ready = worker.Wait();
        first = worker.TakeResult();
        // The worker cannot finish its first wake yet, so this second job is
        // queued, not already running. Stop must never process it on its caller.
        queued = worker.Submit({invalid, 12, true, true});
        stopper = std::jthread{[&] {
            stop_thread = std::this_thread::get_id();
            // Acknowledge arrival at Stop, not that admission is already closed.
            stopping.count_down();
            worker.Stop();
        }};
        stopping.wait();
    }
    stopper.join();
    observer.Finish();
    BOOST_CHECK(admitted && ready && queued);
    BOOST_REQUIRE(first);
    BOOST_CHECK(!first->processing_success && !first->exception);
    BOOST_CHECK(connman.TakeMessageWake());
    BOOST_REQUIRE_EQUAL(checked->m_threads.size(), 2);
    BOOST_CHECK(checked->m_threads[0] == checked->m_threads[1]);
    BOOST_CHECK(checked->m_threads[0] != std::this_thread::get_id());
    BOOST_CHECK(checked->m_threads[1] != stop_thread);
    BOOST_CHECK(!worker.Wait());
    BOOST_CHECK(!worker.TakeResult());
    BOOST_CHECK(!worker.Submit({invalid, 13, true, true}));
}

BOOST_AUTO_TEST_CASE(block_worker_running_shutdown)
{
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const auto block{CreateBlockChain(1, Params()).front()};
    static_cast<TestChainstateManager&>(*m_node.chainman).JumpOutOfIbd();
    auto paused{std::make_shared<WorkerPoWPause>(block->GetHash())};
    WorkerObserver observer{*m_node.validation_signals, paused};
    node::BlockProcessingWorker worker{*m_node.chainman, connman};
    std::latch stopping{1};
    std::thread::id stop_thread;
    std::jthread stopper;
    // Younger than both join owners: even failed stopper construction releases
    // the main-held notification before a worker destructor can wait for it.
    struct ReleaseOnExit {
        WorkerPoWPause& paused;
        ~ReleaseOnExit() { paused.Release(); }
    } release_on_exit{*paused};
    const bool admitted{worker.Submit({block, 14, true, true})};
    const bool entered{admitted && paused->WaitEntered()};
    const bool early_result{worker.TakeResult().has_value()};
    const bool rejected{!worker.Submit({block, 14, true, true})};
    stopper = std::jthread{[&] {
        stop_thread = std::this_thread::get_id();
        // Arrival only; the test does not infer that admission is closed yet.
        stopping.count_down();
        worker.Stop();
    }};
    stopping.wait();
    // Do not query chainstate or remove nodes while the notification holds main.
    paused->Release();
    stopper.join();
    observer.Finish();
    BOOST_CHECK(admitted);
    BOOST_CHECK(entered);
    BOOST_CHECK(!early_result);
    BOOST_CHECK(rejected);
    BOOST_CHECK(paused->m_thread != std::this_thread::get_id());
    BOOST_CHECK(paused->m_thread != stop_thread);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == block->GetHash());
    BOOST_CHECK(!worker.Wait());
    BOOST_CHECK(!worker.TakeResult());
    BOOST_CHECK(!worker.Submit({block, 14, true, true}));
}

BOOST_FIXTURE_TEST_CASE(block_worker_ready_source_gone, BlockProcessingTestSetup)
{
    const auto block{CreateBlockChain(1, Params()).front()};
    NodeId source_id;
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        source_id = AddPeer(CAddress{LookupNumeric("1.2.3.4", Params().GetDefaultPort()), NODE_NONE}).GetId();
    }
    node::BlockProcessingWorker worker{*m_node.chainman, m_connman};
    const bool admitted{worker.Submit({block, source_id, true, true})};
    const bool ready{worker.Wait()};
    const bool rejected{!worker.Submit({block, source_id, true, true})};
    // PNB has returned, but the ready result still owns the slot. Readiness is
    // not a queue drain; keep connman and all subscribers alive until Stop/drain.
    m_connman.StopNodes();
    const bool rejected_after_removal{!worker.Submit({block, source_id, true, true})};
    auto result{worker.TakeResult()};
    worker.Stop();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(admitted);
    BOOST_CHECK(ready);
    BOOST_CHECK(rejected);
    BOOST_CHECK(m_connman.TestNodes().empty());
    BOOST_CHECK(rejected_after_removal);
    BOOST_CHECK(!m_connman.ForNode(source_id, [](CNode*) { return true; }));
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(result->source, source_id);
    BOOST_CHECK(result->hash == block->GetHash());
    BOOST_CHECK(result->processing_success && result->new_block && !result->exception);
    BOOST_CHECK(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == block->GetHash());
    BOOST_CHECK(!worker.Wait());
    BOOST_CHECK(!worker.TakeResult());
}

BOOST_AUTO_TEST_CASE(block_worker_exception_delivery)
{
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    auto invalid{std::make_shared<CBlock>(Params().GenesisBlock())};
    invalid->vtx.clear();
    invalid->m_validation_cache = {};
    auto checked{std::make_shared<WorkerChecked>()};
    checked->m_throw = true;
    WorkerObserver observer{*m_node.validation_signals, checked};
    node::BlockProcessingWorker worker{*m_node.chainman, connman};
    for (int i{0}; i < 20; ++i) {
        worker.Start();
        connman.TakeMessageWake();
        bool admitted, ready, rejected;
        std::optional<node::BlockProcessingResult> result;
        std::string message;
        {
            LOCK(connman.MessageWakeMutex());
            admitted = worker.Submit({invalid, 15, true, true});
            ready = worker.Wait();
            rejected = !worker.Submit({invalid, 16, true, true});
            result = worker.TakeResult();
            // Inspect before the worker can wake or be joined, matching the
            // synchronous bridge's terminal-result ownership boundary.
            if (result && result->exception) {
                try {
                    std::rethrow_exception(result->exception);
                } catch (const std::runtime_error& e) {
                    message = e.what();
                }
            }
        }
        worker.Stop();
        BOOST_CHECK(admitted && ready && rejected);
        BOOST_CHECK(connman.TakeMessageWake());
        BOOST_REQUIRE(result);
        BOOST_CHECK(!result->processing_success && !result->new_block);
        BOOST_CHECK(result->exception);
        BOOST_CHECK_EQUAL(message, "block worker test exception");
    }
    // Shutdown must also observe an exceptional outcome nobody has consumed.
    worker.Start();
    const bool admitted{worker.Submit({invalid, 16, true, true})};
    const bool ready{worker.Wait()};
    {
        ASSERT_DEBUG_LOG("Exception while stopping block processing: block worker test exception");
        worker.Stop();
    }
    // Iterate retains its entry count if a subscriber throws. Keep this shared
    // subscriber owned through every join, with no later PNB call in the fixture.
    observer.Finish();
    BOOST_CHECK(admitted && ready);
    BOOST_CHECK(!worker.TakeResult());
    BOOST_CHECK_EQUAL(checked->m_threads.size(), 21);
}

BOOST_AUTO_TEST_SUITE_END()

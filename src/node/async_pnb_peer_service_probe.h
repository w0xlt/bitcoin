// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_ASYNC_PNB_PEER_SERVICE_PROBE_H
#define BITCOIN_NODE_ASYNC_PNB_PEER_SERVICE_PROBE_H

#include <validationinterface.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string_view>

class CBlock;
class uint256;

namespace fs {
class path;
}

namespace node {

inline constexpr uint32_t ASYNC_PNB_PROBE_SCHEMA{4};
inline constexpr uint32_t ASYNC_PNB_PROBE_CAPACITY{65'536};
inline constexpr uint32_t ASYNC_PNB_PROBE_ENDIAN{0x01020304};
inline constexpr uint32_t ASYNC_PNB_PROBE_FLAG_TEST_GATES{1U};
inline constexpr uint32_t ASYNC_PNB_PROBE_FLAG_LOSS{2U};
inline constexpr uint32_t ASYNC_PNB_PROBE_FLAG_CLOSED{4U};

enum class AsyncPNBProbeEvent : uint32_t {
    COMPLETE_MESSAGE_READY = 1,
    HANDLER_START,
    HANDLER_COMPLETE,
    RESPONSE_QUEUED,
    JOB_SUBMIT,
    SLOT_SUBMIT,
    WORKER_WAKE,
    PNB_START,
    PNB_END,
    RESULT_PUBLICATION,
    BUSY_SEND_PREFIX_SUMMARY,
    RESULT_COLLECTION,
    CONTINUATION,
    TEST_GATE_ENTERED,
    TEST_INTERFACE_REGISTERED,
    TEST_INTERFACE_UNREGISTERED,
    TEST_SHUTDOWN_STARTED,
    HANDLER_PREFIX_COMPLETE,
    HANDLER_TAIL_COMPLETE,
    TEST_TARGET_DISCONNECTED,
    MESSAGE_FRONT_READY,
    RECEIVE_QUEUE_STATE,
    OUTBOUND_QUEUED,
    SOCKET_SENT,
    OUTBOUND_DROPPED,
    CAUSAL_LINK,
    PEER_CREATED,
    HANDSHAKE_COMPLETE,
    PEER_FINALIZED,
    DISCOURAGEMENT,
    SEND_QUEUE_STATE,
    BLOCK_REQUESTED,
    BLOCK_REQUEST_REMOVED,
    BLOCK_TIMEOUT,
};

enum class AsyncPNBProbeTestGate : uint32_t {
    NONE = 0,
    WORKER_QUEUED,
    VALIDATION_RUNNING,
    RESULT_READY,
    PNB_HEADER_TIP,
};

/** Fixed mmap ABI. Create() rejects non-little-endian hosts. */
struct AsyncPNBProbeEventRecord {
    uint64_t sequence;
    uint64_t process_epoch;
    uint32_t event;
    uint32_t flags;
    int64_t steady_ns;
    std::array<int64_t, 16> values;
    std::array<char, 24> text1;
    std::array<char, 24> text2;
    std::array<unsigned char, 32> hash;
};
static_assert(sizeof(AsyncPNBProbeEventRecord) == 240);

struct alignas(64) AsyncPNBProbeSlot {
    std::atomic<uint64_t> published_sequence;
    AsyncPNBProbeEventRecord record;
    uint64_t checksum;
};
static_assert(sizeof(AsyncPNBProbeSlot) == 256);

struct alignas(64) AsyncPNBProbeFileHeader {
    std::array<char, 8> magic;
    uint32_t schema;
    uint32_t header_size;
    uint32_t record_size;
    uint32_t capacity;
    uint32_t endian;
    int32_t pid;
    std::atomic<uint32_t> status;
    uint64_t process_epoch;
    int64_t creation_wall_ns;
    int64_t creation_steady_ns;
    std::atomic<uint64_t> producer_sequence;
    std::atomic<uint64_t> consumer_ack;
    std::atomic<uint64_t> loss_count;
    std::atomic<uint32_t> test_gate;
    std::atomic<uint32_t> test_gate_generation;
    std::atomic<uint32_t> test_gate_release;
    std::atomic<uint32_t> test_gate_error;
    std::atomic<int32_t> test_gate_peer;
};
static_assert(sizeof(AsyncPNBProbeFileHeader) == 128);
static_assert(offsetof(AsyncPNBProbeFileHeader, pid) == 28);
static_assert(offsetof(AsyncPNBProbeFileHeader, status) == 32);
static_assert(offsetof(AsyncPNBProbeFileHeader, process_epoch) == 40);
static_assert(offsetof(AsyncPNBProbeFileHeader, producer_sequence) == 64);
static_assert(offsetof(AsyncPNBProbeFileHeader, consumer_ack) == 72);
static_assert(offsetof(AsyncPNBProbeFileHeader, test_gate) == 88);
static_assert(offsetof(AsyncPNBProbeFileHeader, test_gate_peer) == 104);
static_assert(std::atomic<uint32_t>::is_always_lock_free);
static_assert(std::atomic<uint64_t>::is_always_lock_free);
static_assert(sizeof(std::atomic<uint32_t>) == sizeof(uint32_t));
static_assert(sizeof(std::atomic<uint64_t>) == sizeof(uint64_t));

/**
 * Optional nonblocking recorder for the async-PNB experiment.
 *
 * Creation, mapping, and teardown may perform I/O. Record() performs one
 * atomic reservation, fixed POD writes, a checksum, and release publication;
 * it never allocates, locks, formats, or issues a system call.
 */
class AsyncPNBPeerServiceProbe final : public CValidationInterface
{
public:
    static std::shared_ptr<AsyncPNBPeerServiceProbe> Create(
        const fs::path& directory, bool test_gates);

    ~AsyncPNBPeerServiceProbe();

    void Record(AsyncPNBProbeEvent event,
                std::chrono::steady_clock::time_point time,
                std::initializer_list<int64_t> values = {},
                std::string_view text1 = {},
                std::string_view text2 = {},
                const uint256* hash = nullptr) noexcept;

    bool TestGatesEnabled() const noexcept;
    void SetActiveJob(uint64_t job) noexcept;
    void SetActiveSource(int64_t source) noexcept;
    bool IsActiveSource(int64_t source) const noexcept;
    /** Hold a published result uncollected at the quick-test boundary. */
    bool ResultReadyCollectionDeferred() const noexcept;
    bool TestGate(AsyncPNBProbeTestGate gate, uint64_t job,
                  int64_t peer, const uint256* hash) noexcept;
    /** Quick-test hook in the existing kernel header-tip notification. */
    bool TestHeaderTipGate(int64_t height, int64_t timestamp) noexcept;
    /** Record target-side fDisconnect/removal authority for an active test gate. */
    void RecordTargetDisconnect(int64_t peer) noexcept;

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>& block,
                      const BlockValidationState& state) override;

private:
    bool WaitTestGate(AsyncPNBProbeTestGate gate, uint64_t job,
                      int64_t peer, const uint256* hash,
                      int64_t detail1 = 0, int64_t detail2 = 0) noexcept;
    class Impl;
    explicit AsyncPNBPeerServiceProbe(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> m_impl;
};

} // namespace node

#endif // BITCOIN_NODE_ASYNC_PNB_PEER_SERVICE_PROBE_H

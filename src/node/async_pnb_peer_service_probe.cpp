// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/async_pnb_peer_service_probe.h>

#include <primitives/block.h>
#include <uint256.h>
#include <util/fs.h>

#include <algorithm>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#ifndef WIN32
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace node {
namespace {

constexpr std::array<char, 8> PROBE_MAGIC{'A', 'P', 'N', 'B', 'P', 'R', 'B', '\0'};
constexpr auto TEST_GATE_TIMEOUT{std::chrono::seconds{60}};

uint64_t Checksum(const AsyncPNBProbeEventRecord& record) noexcept
{
    constexpr uint64_t OFFSET{1469598103934665603ULL};
    constexpr uint64_t PRIME{1099511628211ULL};
    uint64_t result{OFFSET};
    const auto* bytes{reinterpret_cast<const unsigned char*>(&record)};
    for (size_t index{0}; index < sizeof(record); ++index) {
        result ^= bytes[index];
        result *= PRIME;
    }
    return result;
}

template <size_t Size>
void CopyText(std::array<char, Size>& destination, std::string_view source) noexcept
{
    const size_t count{std::min(source.size(), Size - 1)};
    if (count != 0) std::memcpy(destination.data(), source.data(), count);
}

} // namespace

class AsyncPNBPeerServiceProbe::Impl
{
public:
#ifndef WIN32
    int fd{-1};
    void* mapping{MAP_FAILED};
#endif
    size_t mapping_size{sizeof(AsyncPNBProbeFileHeader) +
                        ASYNC_PNB_PROBE_CAPACITY * sizeof(AsyncPNBProbeSlot)};
    AsyncPNBProbeFileHeader* header{nullptr};
    AsyncPNBProbeSlot* slots{nullptr};
    const bool test_gates;
    std::atomic<uint64_t> active_job{0};
    std::atomic<int64_t> active_source{-1};

    explicit Impl(bool enable_test_gates) : test_gates{enable_test_gates} {}
};

std::shared_ptr<AsyncPNBPeerServiceProbe> AsyncPNBPeerServiceProbe::Create(
    const fs::path& directory, bool test_gates)
{
#ifdef WIN32
    throw std::runtime_error{"-asyncpnbpeerserviceprobedir is unsupported on Windows"};
#else
    if constexpr (std::endian::native != std::endian::little) {
        throw std::runtime_error{
            "-asyncpnbpeerserviceprobedir requires a little-endian host"};
    }
    auto impl{std::make_unique<Impl>(test_gates)};
    const std::string directory_string{fs::PathToString(directory)};
    const int directory_fd{open(directory_string.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (directory_fd < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "opening async-PNB probe directory");
    }
    struct stat directory_stat{};
    if (fstat(directory_fd, &directory_stat) != 0) {
        const int saved_errno{errno};
        close(directory_fd);
        throw std::system_error(saved_errno, std::generic_category(),
                                "validating async-PNB probe directory");
    }
    if (!S_ISDIR(directory_stat.st_mode)) {
        close(directory_fd);
        throw std::system_error(ENOTDIR, std::generic_category(),
                                "validating async-PNB probe directory");
    }

    const std::string filename{"async-pnb-probe-" + std::to_string(getpid()) + ".bin"};
    const std::string output_path{directory_string + "/" + filename};
    impl->fd = openat(directory_fd, filename.c_str(),
                      O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    const int open_errno{errno};
    close(directory_fd);
    if (impl->fd < 0) {
        throw std::system_error(open_errno, std::generic_category(),
                                "creating async-PNB probe file without overwrite " + output_path);
    }
    if (ftruncate(impl->fd, impl->mapping_size) != 0) {
        const int saved_errno{errno};
        close(impl->fd);
        throw std::system_error(saved_errno, std::generic_category(),
                                "sizing async-PNB probe file " + output_path);
    }
    impl->mapping = mmap(nullptr, impl->mapping_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, impl->fd, 0);
    if (impl->mapping == MAP_FAILED) {
        const int saved_errno{errno};
        close(impl->fd);
        throw std::system_error(saved_errno, std::generic_category(),
                                "mapping async-PNB probe file " + output_path);
    }

    std::memset(impl->mapping, 0, impl->mapping_size);
    impl->header = ::new (impl->mapping) AsyncPNBProbeFileHeader{};
    const auto creation_wall{std::chrono::system_clock::now()};
    const auto creation_steady{std::chrono::steady_clock::now()};
    const int64_t wall_ns{std::chrono::duration_cast<std::chrono::nanoseconds>(
        creation_wall.time_since_epoch()).count()};
    const int64_t steady_ns{std::chrono::duration_cast<std::chrono::nanoseconds>(
        creation_steady.time_since_epoch()).count()};
    uint64_t process_epoch{1469598103934665603ULL};
    for (const uint64_t value : {static_cast<uint64_t>(wall_ns),
                                 static_cast<uint64_t>(steady_ns),
                                 static_cast<uint64_t>(getpid())}) {
        process_epoch ^= value;
        process_epoch *= 1099511628211ULL;
    }
    if (process_epoch == 0) process_epoch = 1;
    impl->header->magic = PROBE_MAGIC;
    impl->header->schema = ASYNC_PNB_PROBE_SCHEMA;
    impl->header->header_size = sizeof(AsyncPNBProbeFileHeader);
    impl->header->record_size = sizeof(AsyncPNBProbeSlot);
    impl->header->capacity = ASYNC_PNB_PROBE_CAPACITY;
    impl->header->endian = ASYNC_PNB_PROBE_ENDIAN;
    impl->header->pid = getpid();
    impl->header->process_epoch = process_epoch;
    impl->header->creation_wall_ns = wall_ns;
    impl->header->creation_steady_ns = steady_ns;
    impl->header->status.store(
        test_gates ? ASYNC_PNB_PROBE_FLAG_TEST_GATES : 0,
        std::memory_order_relaxed);
    impl->header->test_gate_peer.store(-1, std::memory_order_relaxed);
    impl->slots = reinterpret_cast<AsyncPNBProbeSlot*>(
        static_cast<unsigned char*>(impl->mapping) + sizeof(AsyncPNBProbeFileHeader));
    for (uint32_t index{0}; index < ASYNC_PNB_PROBE_CAPACITY; ++index) {
        ::new (&impl->slots[index]) AsyncPNBProbeSlot{};
    }
    if (msync(impl->mapping, impl->mapping_size, MS_SYNC) != 0) {
        const int saved_errno{errno};
        munmap(impl->mapping, impl->mapping_size);
        close(impl->fd);
        throw std::system_error(saved_errno, std::generic_category(),
                                "initializing async-PNB probe file " + output_path);
    }
    return std::shared_ptr<AsyncPNBPeerServiceProbe>{
        new AsyncPNBPeerServiceProbe{std::move(impl)}};
#endif
}

AsyncPNBPeerServiceProbe::AsyncPNBPeerServiceProbe(std::unique_ptr<Impl> impl)
    : m_impl{std::move(impl)}
{
}

AsyncPNBPeerServiceProbe::~AsyncPNBPeerServiceProbe()
{
#ifndef WIN32
    if (m_impl->mapping != MAP_FAILED) {
        m_impl->header->status.fetch_or(
            ASYNC_PNB_PROBE_FLAG_CLOSED, std::memory_order_release);
        (void)msync(m_impl->mapping, m_impl->mapping_size, MS_SYNC);
        (void)munmap(m_impl->mapping, m_impl->mapping_size);
    }
    if (m_impl->fd >= 0) (void)close(m_impl->fd);
#endif
}

void AsyncPNBPeerServiceProbe::Record(
    AsyncPNBProbeEvent event,
    std::chrono::steady_clock::time_point time,
    std::initializer_list<int64_t> values,
    std::string_view text1,
    std::string_view text2,
    const uint256* hash) noexcept
{
    const uint64_t sequence{
        m_impl->header->producer_sequence.fetch_add(1, std::memory_order_relaxed) + 1};
    const auto mark_loss{[&] {
        m_impl->header->loss_count.fetch_add(1, std::memory_order_relaxed);
        m_impl->header->status.fetch_or(
            ASYNC_PNB_PROBE_FLAG_LOSS, std::memory_order_release);
    }};
    const uint64_t consumer_ack{
        m_impl->header->consumer_ack.load(std::memory_order_acquire)};
    if ((sequence & ASYNC_PNB_PROBE_SLOT_CLAIM) != 0 ||
        sequence > consumer_ack + ASYNC_PNB_PROBE_CAPACITY) {
        mark_loss();
        return;
    }
    AsyncPNBProbeSlot& slot{
        m_impl->slots[(sequence - 1) & (ASYNC_PNB_PROBE_CAPACITY - 1)]};
    uint64_t expected_publication{
        sequence > ASYNC_PNB_PROBE_CAPACITY
            ? sequence - ASYNC_PNB_PROBE_CAPACITY
            : 0};
    if (!slot.published_sequence.compare_exchange_strong(
            expected_publication, sequence | ASYNC_PNB_PROBE_SLOT_CLAIM,
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        // Never wait for or race a delayed writer. The reserved sequence is a
        // permanent gap, and the collector will reject the retained run.
        mark_loss();
        return;
    }

    AsyncPNBProbeEventRecord record{};
    record.sequence = sequence;
    record.process_epoch = m_impl->header->process_epoch;
    record.event = static_cast<uint32_t>(event);
    record.steady_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        time.time_since_epoch()).count();
    size_t index{0};
    for (const int64_t value : values) {
        if (index == record.values.size()) break;
        record.values[index++] = value;
    }
    CopyText(record.text1, text1);
    CopyText(record.text2, text2);
    if (hash != nullptr) std::memcpy(record.hash.data(), hash->data(), record.hash.size());

    slot.record = record;
    slot.checksum = Checksum(record);
    slot.published_sequence.store(sequence, std::memory_order_release);
}

bool AsyncPNBPeerServiceProbe::TestGatesEnabled() const noexcept
{
    return m_impl->test_gates;
}

void AsyncPNBPeerServiceProbe::SetActiveJob(uint64_t job) noexcept
{
    m_impl->active_job.store(job, std::memory_order_release);
}

void AsyncPNBPeerServiceProbe::SetActiveSource(int64_t source) noexcept
{
    m_impl->active_source.store(source, std::memory_order_release);
}

bool AsyncPNBPeerServiceProbe::IsActiveSource(int64_t source) const noexcept
{
    return m_impl->active_source.load(std::memory_order_acquire) == source;
}

bool AsyncPNBPeerServiceProbe::ResultReadyCollectionDeferred() const noexcept
{
    if (!m_impl->test_gates) return false;
    const uint32_t generation{
        m_impl->header->test_gate_generation.load(std::memory_order_acquire)};
    return generation != 0 &&
           m_impl->header->test_gate.load(std::memory_order_acquire) ==
               static_cast<uint32_t>(AsyncPNBProbeTestGate::RESULT_READY) &&
           m_impl->header->test_gate_release.load(std::memory_order_acquire) < generation;
}

bool AsyncPNBPeerServiceProbe::TestGate(AsyncPNBProbeTestGate gate, uint64_t job,
                                       int64_t peer, const uint256* hash) noexcept
{
    return WaitTestGate(gate, job, peer, hash);
}

bool AsyncPNBPeerServiceProbe::WaitTestGate(AsyncPNBProbeTestGate gate, uint64_t job,
                                           int64_t peer, const uint256* hash,
                                           int64_t detail1, int64_t detail2) noexcept
{
    if (!m_impl->test_gates) return false;
    const uint32_t generation{
        m_impl->header->test_gate_generation.load(std::memory_order_acquire)};
    if (generation == 0 ||
        m_impl->header->test_gate.load(std::memory_order_acquire) != static_cast<uint32_t>(gate) ||
        m_impl->header->test_gate_release.load(std::memory_order_acquire) >= generation) {
        return false;
    }
    const int32_t expected_peer{
        m_impl->header->test_gate_peer.load(std::memory_order_acquire)};
    if (expected_peer != -1 && expected_peer != peer) return false;

    Record(AsyncPNBProbeEvent::TEST_GATE_ENTERED, std::chrono::steady_clock::now(),
           {static_cast<int64_t>(gate), generation, static_cast<int64_t>(job), peer,
            detail1, detail2},
           {}, {}, hash);
    const auto deadline{std::chrono::steady_clock::now() + TEST_GATE_TIMEOUT};
    while (m_impl->header->test_gate_release.load(std::memory_order_acquire) < generation) {
        if (std::chrono::steady_clock::now() >= deadline) {
            m_impl->header->test_gate_error.store(generation, std::memory_order_release);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return false;
}

bool AsyncPNBPeerServiceProbe::TestHeaderTipGate(int64_t height,
                                                int64_t timestamp) noexcept
{
    const uint64_t active_job{m_impl->active_job.load(std::memory_order_acquire)};
    if (active_job == 0) return false;
    return WaitTestGate(AsyncPNBProbeTestGate::PNB_HEADER_TIP,
                        active_job,
                        /*peer=*/-1, /*hash=*/nullptr, height, timestamp);
}

void AsyncPNBPeerServiceProbe::RecordTargetDisconnect(int64_t peer) noexcept
{
    if (!m_impl->test_gates) return;
    const uint32_t generation{
        m_impl->header->test_gate_generation.load(std::memory_order_acquire)};
    const uint32_t gate{m_impl->header->test_gate.load(std::memory_order_acquire)};
    if (generation == 0 || gate == static_cast<uint32_t>(AsyncPNBProbeTestGate::NONE) ||
        m_impl->header->test_gate_release.load(std::memory_order_acquire) >= generation) {
        return;
    }
    Record(AsyncPNBProbeEvent::TEST_TARGET_DISCONNECTED,
           std::chrono::steady_clock::now(),
           {peer, gate, generation,
            static_cast<int64_t>(m_impl->active_job.load(std::memory_order_acquire))});
}

void AsyncPNBPeerServiceProbe::BlockChecked(
    const std::shared_ptr<const CBlock>& block, const BlockValidationState&)
{
    if (!m_impl->test_gates) return;
    const uint256 hash{block->GetHash()};
    (void)TestGate(AsyncPNBProbeTestGate::VALIDATION_RUNNING,
                   m_impl->active_job.load(std::memory_order_acquire),
                   /*peer=*/-1, &hash);
}

} // namespace node

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
    std::atomic<uint32_t> deferred_handler_generation{0};
    std::atomic<int64_t> deferred_handler_peer{-1};

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
    impl->header->magic = PROBE_MAGIC;
    impl->header->schema = ASYNC_PNB_PROBE_SCHEMA;
    impl->header->header_size = sizeof(AsyncPNBProbeFileHeader);
    impl->header->record_size = sizeof(AsyncPNBProbeSlot);
    impl->header->capacity = ASYNC_PNB_PROBE_CAPACITY;
    impl->header->endian = ASYNC_PNB_PROBE_ENDIAN;
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
        m_impl->header->next_sequence.fetch_add(1, std::memory_order_relaxed) + 1};
    if (sequence > ASYNC_PNB_PROBE_CAPACITY) {
        m_impl->header->overflow_count.fetch_add(1, std::memory_order_relaxed);
        m_impl->header->status.fetch_or(
            ASYNC_PNB_PROBE_FLAG_OVERFLOW, std::memory_order_release);
        return;
    }
    AsyncPNBProbeSlot& slot{m_impl->slots[sequence - 1]};
    slot.published_sequence.store(0, std::memory_order_release);

    AsyncPNBProbeEventRecord record{};
    record.sequence = sequence;
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

bool AsyncPNBPeerServiceProbe::HandlerPrePollDeferred(int64_t peer) const noexcept
{
    if (!m_impl->test_gates) return false;
    const uint32_t generation{
        m_impl->deferred_handler_generation.load(std::memory_order_acquire)};
    return generation != 0 &&
           m_impl->deferred_handler_peer.load(std::memory_order_acquire) == peer;
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

bool AsyncPNBPeerServiceProbe::ResumeHandlerPrePoll(int64_t peer) noexcept
{
    if (!m_impl->test_gates) return false;
    uint32_t generation{
        m_impl->deferred_handler_generation.load(std::memory_order_acquire)};
    if (generation == 0 ||
        m_impl->deferred_handler_peer.load(std::memory_order_acquire) != peer ||
        m_impl->header->test_gate_release.load(std::memory_order_acquire) < generation) {
        return false;
    }
    if (!m_impl->deferred_handler_generation.compare_exchange_strong(
            generation, 0, std::memory_order_acq_rel)) {
        return false;
    }
    m_impl->deferred_handler_peer.store(-1, std::memory_order_release);
    return true;
}

bool AsyncPNBPeerServiceProbe::TestGate(AsyncPNBProbeTestGate gate, uint64_t job,
                                       int64_t peer, const uint256* hash) noexcept
{
    if (!m_impl->test_gates) return false;
    if (gate == AsyncPNBProbeTestGate::HANDLER_PRE_POLL) {
        const uint32_t deferred_generation{
            m_impl->deferred_handler_generation.load(std::memory_order_acquire)};
        const uint32_t released{
            m_impl->header->test_gate_release.load(std::memory_order_acquire)};
        if (deferred_generation > released &&
            m_impl->deferred_handler_peer.load(std::memory_order_acquire) == peer) {
            return true;
        }
    }
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
           {static_cast<int64_t>(gate), generation, static_cast<int64_t>(job), peer},
           {}, {}, hash);
    if (gate == AsyncPNBProbeTestGate::HANDLER_PRE_POLL) {
        m_impl->deferred_handler_peer.store(peer, std::memory_order_release);
        m_impl->deferred_handler_generation.store(generation, std::memory_order_release);
        return true;
    }
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

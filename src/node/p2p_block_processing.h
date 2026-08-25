// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_P2P_BLOCK_PROCESSING_H
#define BITCOIN_NODE_P2P_BLOCK_PROCESSING_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

class CBlock;

namespace node {

inline constexpr size_t P2P_BLOCK_PROCESSING_MAX_JOBS{8};
inline constexpr uint32_t P2P_BLOCK_PROCESSING_MAX_BYTES{32U * 1024U * 1024U};

//! Immutable inputs retained for one asynchronous P2P ProcessNewBlock call.
struct P2PBlockProcessingJob {
    int64_t source;
    std::shared_ptr<const CBlock> block;
    uint32_t serialized_size;
    bool force_processing;
};

enum class P2PBlockProcessingSubmit {
    ACCEPTED,
    INTERRUPTED,
};

//! Allocation-free ownership handoff for queued jobs canceled by Stop().
struct P2PBlockProcessingCanceled {
    std::array<P2PBlockProcessingJob, P2P_BLOCK_PROCESSING_MAX_JOBS> jobs{};
    size_t count{0};

    [[nodiscard]] bool empty() const noexcept { return count == 0; }
    [[nodiscard]] size_t size() const noexcept { return count; }
    P2PBlockProcessingJob& operator[](size_t index) { return jobs.at(index); }
    const P2PBlockProcessingJob& operator[](size_t index) const { return jobs.at(index); }
    auto begin() noexcept { return jobs.begin(); }
    auto end() noexcept { return jobs.begin() + count; }
    auto begin() const noexcept { return jobs.begin(); }
    auto end() const noexcept { return jobs.begin() + count; }
};

/**
 * Bounded, single-consumer FIFO for P2P block processing.
 *
 * Capacity includes the active job and queued jobs. Admission queries and
 * submission never wait. Concrete implementation destruction is equivalent to
 * Interrupt followed by Stop.
 */
class P2PBlockProcessing
{
public:
    virtual ~P2PBlockProcessing() = default;

    //! Return whether a job of `serialized_size` can be submitted now.
    [[nodiscard]] virtual bool CanSubmit(uint32_t serialized_size) const noexcept = 0;

    //! Return whether there is no active or queued job.
    [[nodiscard]] virtual bool IsIdle() const noexcept = 0;

    /**
     * Submit a job without waiting.
     *
     * The sole producer must call CanSubmit first. Submitting without capacity
     * is a fatal invariant violation. Returns INTERRUPTED after Interrupt.
     * Job movement and fixed-capacity storage make submission noexcept.
     */
    [[nodiscard]] virtual P2PBlockProcessingSubmit Submit(P2PBlockProcessingJob job) noexcept = 0;

    //! Idempotently reject new jobs and wake the worker.
    virtual void Interrupt() = 0;

    /**
     * Finish at most the active job, join the worker, and return queued jobs
     * without processing them. Repeated calls return no additional jobs.
     */
    [[nodiscard]] virtual P2PBlockProcessingCanceled Stop() = 0;
};

//! Called outside the component mutex to process exactly one job.
using P2PBlockProcessor = std::function<void(const P2PBlockProcessingJob&)>;

//! Called outside the component mutex after an active job releases capacity.
using P2PBlockProcessingStateChanged = std::function<void()>;

/** Construct and start the bounded one-worker component. Callbacks must not throw. */
std::unique_ptr<P2PBlockProcessing> MakeP2PBlockProcessing(
    P2PBlockProcessor processor,
    P2PBlockProcessingStateChanged state_changed);

} // namespace node

#endif // BITCOIN_NODE_P2P_BLOCK_PROCESSING_H

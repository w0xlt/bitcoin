// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_P2P_BLOCK_VALIDATION_H
#define BITCOIN_NODE_P2P_BLOCK_VALIDATION_H

#include <functional>
#include <memory>
#include <optional>

class CBlock;
class ChainstateManager;

namespace node {

//! Result of a nonblocking P2P block validation submission.
enum class P2PBlockValidationSubmit {
    ACCEPTED,
    INTERRUPTED,
};

//! Inputs retained for one asynchronous ProcessNewBlock call.
struct P2PBlockValidationRequest {
    std::shared_ptr<const CBlock> block;
    bool force_processing;
    bool min_pow_checked;
};

//! Result needed by the P2P continuation. The ProcessNewBlock return is discarded.
struct P2PBlockValidationResult {
    bool new_block;
};

/**
 * Single-slot adapter for asynchronous P2P block validation.
 *
 * At most one request may be queued, running, or awaiting collection. The
 * caller must not submit again until it has collected the preceding result.
 * Accepted work is never canceled.
 */
class P2PBlockValidation
{
public:
    virtual ~P2PBlockValidation() = default;

    /**
     * Submit one request without waiting.
     *
     * Returns INTERRUPTED after Interrupt and ACCEPTED otherwise. Submitting
     * while the single slot is occupied is a fatal invariant violation.
     */
    [[nodiscard]] virtual P2PBlockValidationSubmit
    Submit(P2PBlockValidationRequest request) = 0;

    //! Return and clear the retained result, or nullopt without waiting.
    [[nodiscard]] virtual std::optional<P2PBlockValidationResult>
    TakeResult() = 0;

    //! Idempotently reject new work without canceling an accepted request.
    virtual void Interrupt() = 0;

    //! Idempotently interrupt and join the worker, preserving any result for collection.
    virtual void Stop() = 0;
};

//! Called once after each accepted result is visible, outside the adapter lock.
using P2PBlockValidationResultReady = std::function<void()>;

/**
 * Construct the one-worker production adapter.
 *
 * The result-ready callback must be non-empty and must not throw.
 */
std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidation(
    ChainstateManager& chainman,
    P2PBlockValidationResultReady result_ready);

} // namespace node

#endif // BITCOIN_NODE_P2P_BLOCK_VALIDATION_H

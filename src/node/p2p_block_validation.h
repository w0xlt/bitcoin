// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_P2P_BLOCK_VALIDATION_H
#define BITCOIN_NODE_P2P_BLOCK_VALIDATION_H

#include <exception>
#include <functional>
#include <memory>
#include <optional>

class CBlock;

namespace node {

//! Result of a nonblocking P2P block-validation submission.
enum class P2PBlockValidationSubmit {
    ACCEPTED,
    FULL,
    STOPPING,
};

//! Immutable inputs retained for one ProcessNewBlock call.
struct P2PBlockValidationRequest {
    std::shared_ptr<const CBlock> block;
    bool force_processing;
    bool min_pow_checked;
};

//! Terminal result needed by the P2P owner-domain continuation.
struct P2PBlockValidationResult {
    bool new_block{false};
    std::exception_ptr error;
};

/**
 * Single-slot adapter for asynchronous P2P block validation.
 *
 * At most one request may be queued, running, or awaiting collection. Accepted
 * work is never canceled. Stop and destruction require one non-worker control
 * context; Stop calls must not overlap, and neither callback may call Stop.
 * Idempotence covers sequential calls.
 */
class P2PBlockValidation
{
public:
    virtual ~P2PBlockValidation() = default;

    //! Start the sole worker after its owner is fully constructed.
    virtual void Start() = 0;

    //! Submit without waiting for validation.
    [[nodiscard]] virtual P2PBlockValidationSubmit Submit(P2PBlockValidationRequest request) = 0;

    //! Take a ready result without waiting for validation.
    [[nodiscard]] virtual std::optional<P2PBlockValidationResult> TakeResult() = 0;

    //! Idempotently reject new work without canceling accepted work.
    virtual void Interrupt() = 0;

    //! Sequentially idempotent interrupt and join, preserving any result.
    virtual void Stop() = 0;
};

//! Process one request and report whether it was a new block.
using P2PBlockValidationProcessor = std::function<bool(
    const std::shared_ptr<const CBlock>& block,
    bool force_processing,
    bool min_pow_checked)>;

//! Called after a terminal result is visible, without the component mutex held.
using P2PBlockValidationResultReady = std::function<void()>;

std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidation(
    P2PBlockValidationProcessor processor,
    P2PBlockValidationResultReady result_ready);

} // namespace node

#endif // BITCOIN_NODE_P2P_BLOCK_VALIDATION_H

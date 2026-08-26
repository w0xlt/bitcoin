// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_P2P_BLOCK_VALIDATION_H
#define BITCOIN_NODE_P2P_BLOCK_VALIDATION_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

class CBlock;
class ChainstateManager;

namespace node {

enum class P2PBlockValidationSubmit {
    ACCEPTED,
    FULL,
    STOPPING,
};

//! Immutable inputs retained for one asynchronous ProcessNewBlock call.
struct P2PBlockValidationRequest {
    std::shared_ptr<const CBlock> block;
    bool force_processing;
    bool min_pow_checked;
    uint64_t job_id{0}; //!< Inert measurement correlation only.
};

//! Minimal result needed by the existing P2P continuation.
struct P2PBlockValidationResult {
    bool new_block;
};

using P2PBlockValidationFn = std::function<bool(
    const std::shared_ptr<const CBlock>& block,
    bool force_processing,
    bool min_pow_checked,
    bool* new_block)>;

/**
 * One-slot adapter for serial asynchronous P2P block validation.
 *
 * The slot is occupied while a request is queued, running, or awaiting result
 * collection. Submission and result collection never wait for validation.
 * Accepted work is never canceled.
 */
class P2PBlockValidation
{
public:
    virtual ~P2PBlockValidation() = default;

    //! Start the sole worker after its owner is fully constructed.
    virtual void Start() = 0;

    [[nodiscard]] virtual P2PBlockValidationSubmit
    Submit(P2PBlockValidationRequest request) = 0;

    [[nodiscard]] virtual std::optional<P2PBlockValidationResult>
    TakeResult() = 0;

    //! Idempotently reject new work, drain accepted work, and join.
    virtual void StopAndJoin() = 0;
};

//! Called outside the component mutex after the result has been published.
using P2PBlockValidationResultReady = std::function<void()>;

std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidation(
    ChainstateManager& chainman,
    P2PBlockValidationResultReady result_ready);

//! Unit-test factory for deterministic state and invocation accounting.
std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidationForTest(
    P2PBlockValidationFn process_new_block,
    P2PBlockValidationResultReady result_ready);

} // namespace node

#endif // BITCOIN_NODE_P2P_BLOCK_VALIDATION_H

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

class AsyncPNBPeerServiceProbe;

enum class P2PBlockValidationSubmit {
    ACCEPTED,
    FULL,
    STOPPING,
};

enum class P2PBlockDeliveryRoute : uint8_t {
    UNKNOWN = 0,
    FULL_BLOCK,
    COMPACT_BLOCK,
    BLOCKTXN,
};

//! Immutable inputs retained for one asynchronous ProcessNewBlock call.
struct P2PBlockValidationRequest {
    std::shared_ptr<const CBlock> block;
    bool force_processing;
    bool min_pow_checked;
    uint64_t job_id{0}; //!< Inert measurement correlation only.
    int64_t source{-1};
    P2PBlockDeliveryRoute delivery_route{P2PBlockDeliveryRoute::UNKNOWN};
    bool initial_block_download{false};
    int32_t active_height{-1};
};

//! Minimal result needed by the existing P2P continuation.
struct P2PBlockValidationResult {
    bool process_new_block;
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

//! Deterministic component phases exposed only by the unit-test factory.
enum class P2PBlockValidationTestState {
    QUEUED,
    RUNNING,
    RESULT_READY,
};
using P2PBlockValidationTestStateHook =
    std::function<void(P2PBlockValidationTestState)>;

std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidation(
    ChainstateManager& chainman,
    P2PBlockValidationResultReady result_ready,
    std::shared_ptr<AsyncPNBPeerServiceProbe> probe = {});

//! Unit-test factory for deterministic state and invocation accounting.
std::unique_ptr<P2PBlockValidation> MakeP2PBlockValidationForTest(
    P2PBlockValidationFn process_new_block,
    P2PBlockValidationResultReady result_ready,
    P2PBlockValidationTestStateHook state_hook = {});

} // namespace node

#endif // BITCOIN_NODE_P2P_BLOCK_VALIDATION_H

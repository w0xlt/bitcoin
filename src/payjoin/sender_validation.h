// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_SENDER_VALIDATION_H
#define BITCOIN_PAYJOIN_SENDER_VALIDATION_H

#include <psbt.h>

#include <optional>
#include <string>

namespace wallet {
class CWallet;
} // namespace wallet

namespace payjoin::detail {

struct SenderProposalValidationContext {
    CScript payee_script;
    bool disable_output_substitution{false};
};

/** Build the sender-side validation context from the original PSBT and wallet state. */
std::optional<SenderProposalValidationContext> BuildSenderProposalValidationContext(
    wallet::CWallet& wallet,
    const PartiallySignedTransaction& original,
    bool disable_output_substitution);

/** Validate a Proposal PSBT against the BIP 78 sender checklist used by BIP 77. */
std::optional<std::string> ValidateSenderProposal(
    const PartiallySignedTransaction& original,
    const PartiallySignedTransaction& proposal,
    const SenderProposalValidationContext& context);

/** Restore original sender-owned PSBT metadata that a receiver may have stripped. */
void RestoreOriginalSenderData(
    const PartiallySignedTransaction& original,
    PartiallySignedTransaction& proposal);

} // namespace payjoin::detail

#endif // BITCOIN_PAYJOIN_SENDER_VALIDATION_H

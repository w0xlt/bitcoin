// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/sender_validation.h>

#include <script/script.h>
#include <wallet/wallet.h>

namespace payjoin::detail {
namespace {

bool InputHasKeypaths(const PSBTInput& input)
{
    return !input.hd_keypaths.empty() || !input.m_tap_bip32_paths.empty();
}

bool InputHasPartialSignatures(const PSBTInput& input)
{
    return !input.partial_sigs.empty() || !input.m_tap_key_sig.empty() ||
           !input.m_tap_script_sigs.empty() || !input.m_musig2_partial_sigs.empty();
}

bool OutputHasKeypaths(const PSBTOutput& output)
{
    return !output.hd_keypaths.empty() || !output.m_tap_bip32_paths.empty();
}

bool GetInputUTXOWithOriginalFallback(
    const PartiallySignedTransaction& original,
    const PartiallySignedTransaction& proposal,
    size_t proposal_index,
    CTxOut& utxo)
{
    if (proposal.GetInputUTXO(utxo, proposal_index)) return true;
    if (!original.tx || !proposal.tx) return false;

    const COutPoint& prevout = proposal.tx->vin.at(proposal_index).prevout;
    for (size_t i = 0; i < original.tx->vin.size(); ++i) {
        if (original.tx->vin[i].prevout == prevout) {
            return original.GetInputUTXO(utxo, i);
        }
    }
    return false;
}

std::optional<CAmount> ComputeFee(
    const PartiallySignedTransaction& original,
    const PartiallySignedTransaction& proposal)
{
    if (!proposal.tx) return std::nullopt;

    CAmount total_in{0};
    for (size_t i = 0; i < proposal.tx->vin.size(); ++i) {
        CTxOut utxo;
        if (!GetInputUTXOWithOriginalFallback(original, proposal, i, utxo)) return std::nullopt;
        total_in += utxo.nValue;
    }

    CAmount total_out{0};
    for (const auto& txout : proposal.tx->vout) {
        total_out += txout.nValue;
    }

    return total_in - total_out;
}

} // namespace

std::optional<SenderProposalValidationContext> BuildSenderProposalValidationContext(
    wallet::CWallet& wallet,
    const PartiallySignedTransaction& original,
    bool disable_output_substitution)
{
    if (!original.tx) return std::nullopt;

    LOCK(wallet.cs_wallet);
    for (const auto& txout : original.tx->vout) {
        if (!wallet.IsMine(txout.scriptPubKey)) {
            return SenderProposalValidationContext{
                .payee_script = txout.scriptPubKey,
                .disable_output_substitution = disable_output_substitution,
            };
        }
    }

    return std::nullopt;
}

std::optional<std::string> ValidateSenderProposal(
    const PartiallySignedTransaction& original,
    const PartiallySignedTransaction& proposal,
    const SenderProposalValidationContext& context)
{
    if (!original.tx) return "Original PSBT missing transaction";
    if (!proposal.tx) return "Proposal PSBT missing transaction";
    if (proposal.inputs.size() != proposal.tx->vin.size()) return "Proposal PSBT input count mismatch";
    if (proposal.outputs.size() != proposal.tx->vout.size()) return "Proposal PSBT output count mismatch";
    if (original.tx->vin.empty()) return "Original PSBT has no inputs";

    if (proposal.tx->version != original.tx->version) {
        return "Proposal changed transaction version";
    }
    if (proposal.tx->nLockTime != original.tx->nLockTime) {
        return "Proposal changed transaction locktime";
    }

    size_t next_original_input{0};
    for (size_t i = 0; i < proposal.tx->vin.size(); ++i) {
        const auto& proposed_txin = proposal.tx->vin[i];
        const auto& proposed_input = proposal.inputs[i];

        if (InputHasKeypaths(proposed_input)) return "Proposal input contains keypaths";
        if (InputHasPartialSignatures(proposed_input)) return "Proposal input contains partial signatures";

        const bool matches_next_original =
            next_original_input < original.tx->vin.size() &&
            proposed_txin.prevout == original.tx->vin[next_original_input].prevout;

        if (matches_next_original) {
            if (proposed_txin.nSequence != original.tx->vin[next_original_input].nSequence) {
                return "Proposal changed sender input sequence";
            }
            if (!proposed_input.final_script_sig.empty() || !proposed_input.final_script_witness.IsNull()) {
                return "Proposal finalizes sender input";
            }
            ++next_original_input;
            continue;
        }

        if (proposed_input.final_script_sig.empty() && proposed_input.final_script_witness.IsNull()) {
            return "Proposal added input is not finalized";
        }
        if (proposed_txin.nSequence != original.tx->vin.front().nSequence) {
            return "Proposal mixes input sequences";
        }
        if (proposed_input.non_witness_utxo == nullptr && proposed_input.witness_utxo.IsNull()) {
            return "Proposal added input missing UTXO information";
        }
    }

    if (next_original_input != original.tx->vin.size()) {
        return "Proposal missing or shuffles original inputs";
    }

    size_t next_original_output{0};
    for (size_t i = 0; i < proposal.tx->vout.size(); ++i) {
        const auto& proposed_txout = proposal.tx->vout[i];
        const auto& proposed_output = proposal.outputs[i];

        if (OutputHasKeypaths(proposed_output)) return "Proposal output contains keypaths";

        if (next_original_output >= original.tx->vout.size()) continue;

        const auto& original_txout = original.tx->vout[next_original_output];

        if (original_txout.scriptPubKey == context.payee_script) {
            if (context.disable_output_substitution &&
                (proposed_txout.scriptPubKey != original_txout.scriptPubKey ||
                 proposed_txout.nValue < original_txout.nValue)) {
                return "Proposal violates output substitution rules";
            }
            ++next_original_output;
            continue;
        }

        if (proposed_txout.scriptPubKey == original_txout.scriptPubKey) {
            if (proposed_txout.nValue < original_txout.nValue) {
                return "Proposal reduces sender-owned output";
            }
            ++next_original_output;
        }
    }

    if (next_original_output != original.tx->vout.size()) {
        return "Proposal missing or shuffles original outputs";
    }

    const auto original_fee = ComputeFee(original, original);
    const auto proposal_fee = ComputeFee(original, proposal);
    if (!original_fee || !proposal_fee) return "Proposal fee could not be computed";
    if (*proposal_fee < *original_fee) return "Proposal decreases absolute fee";

    return std::nullopt;
}

void RestoreOriginalSenderData(
    const PartiallySignedTransaction& original,
    PartiallySignedTransaction& proposal)
{
    if (!original.tx || !proposal.tx) return;

    size_t next_original_input{0};
    for (size_t i = 0; i < proposal.tx->vin.size(); ++i) {
        if (next_original_input >= original.tx->vin.size()) break;
        if (proposal.tx->vin[i].prevout != original.tx->vin[next_original_input].prevout) continue;

        const auto& original_input = original.inputs[next_original_input];
        auto& proposal_input = proposal.inputs[i];
        proposal_input.non_witness_utxo = original_input.non_witness_utxo;
        proposal_input.witness_utxo = original_input.witness_utxo;
        proposal_input.redeem_script = original_input.redeem_script;
        proposal_input.witness_script = original_input.witness_script;
        proposal_input.hd_keypaths = original_input.hd_keypaths;
        proposal_input.m_tap_scripts = original_input.m_tap_scripts;
        proposal_input.m_tap_bip32_paths = original_input.m_tap_bip32_paths;
        proposal_input.m_tap_internal_key = original_input.m_tap_internal_key;
        proposal_input.m_tap_merkle_root = original_input.m_tap_merkle_root;
        ++next_original_input;
    }

    size_t next_original_output{0};
    for (size_t i = 0; i < proposal.tx->vout.size(); ++i) {
        if (next_original_output >= original.tx->vout.size()) break;
        if (proposal.tx->vout[i] != original.tx->vout[next_original_output]) continue;

        proposal.outputs[i] = original.outputs[next_original_output];
        ++next_original_output;
    }
}

} // namespace payjoin::detail

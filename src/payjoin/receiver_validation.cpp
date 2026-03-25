// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/receiver_validation.h>

#include <algorithm>

namespace payjoin::detail {

bool GetInputUTXO(const PartiallySignedTransaction& psbt, size_t input_index, CTxOut& utxo)
{
    if (input_index >= psbt.inputs.size() || !psbt.tx || input_index >= psbt.tx->vin.size()) return false;

    if (psbt.GetInputUTXO(utxo, input_index)) return true;

    const auto& input = psbt.inputs[input_index];
    if (!input.non_witness_utxo) return false;

    const COutPoint& prevout = psbt.tx->vin[input_index].prevout;
    if (prevout.n >= input.non_witness_utxo->vout.size()) return false;

    utxo = input.non_witness_utxo->vout[prevout.n];
    return true;
}

std::optional<CAmount> ComputePSBTFee(const PartiallySignedTransaction& psbt)
{
    if (!psbt.tx) return std::nullopt;

    CAmount total_in{0};
    for (size_t i = 0; i < psbt.tx->vin.size(); ++i) {
        CTxOut utxo;
        if (!GetInputUTXO(psbt, i, utxo)) return std::nullopt;
        total_in += utxo.nValue;
    }

    CAmount total_out{0};
    for (const auto& txout : psbt.tx->vout) {
        total_out += txout.nValue;
    }

    return total_in - total_out;
}

OriginalPayloadParams SanitizeReceiverOriginalParams(const CTransaction& original_tx,
                                                    const OriginalPayloadParams& params,
                                                    const std::vector<size_t>& receiver_output_indexes)
{
    OriginalPayloadParams sanitized = params;
    if (!sanitized.additional_fee_contribution) return sanitized;

    const size_t output_index = sanitized.additional_fee_contribution->additional_fee_output_index;
    if (output_index >= original_tx.vout.size() ||
        std::find(receiver_output_indexes.begin(), receiver_output_indexes.end(), output_index) != receiver_output_indexes.end()) {
        sanitized.additional_fee_contribution.reset();
    }
    return sanitized;
}

std::optional<std::string> ApplyReceiverFeeContribution(const PartiallySignedTransaction& original,
                                                        PartiallySignedTransaction& proposal,
                                                        const OriginalPayloadParams& params,
                                                        size_t receiver_output_index,
                                                        const std::vector<size_t>& original_receiver_output_indexes,
                                                        int original_tx_vsize,
                                                        int receiver_input_vsize)
{
    if (!original.tx) return "Original PSBT has no transaction";
    if (!proposal.tx) return "Proposal PSBT has no transaction";
    if (receiver_output_index >= proposal.tx->vout.size()) return "Receiver output missing from proposal";

    CAmount receiver_additional_fee = params.min_fee_rate.GetFee(receiver_input_vsize);
    CAmount sender_additional_fee{0};

    if (params.additional_fee_contribution) {
        const size_t output_index = params.additional_fee_contribution->additional_fee_output_index;
        if (output_index < proposal.tx->vout.size()) {
            auto& sender_fee_output = proposal.tx->vout[output_index];
            sender_additional_fee = std::min({
                receiver_additional_fee,
                params.additional_fee_contribution->max_additional_fee_contribution,
                sender_fee_output.nValue,
            });
            sender_fee_output.nValue -= sender_additional_fee;
            receiver_additional_fee -= sender_additional_fee;
        }
    }

    if (receiver_additional_fee > 0) {
        const bool drains_original_receiver_output =
            std::find(original_receiver_output_indexes.begin(),
                      original_receiver_output_indexes.end(),
                      receiver_output_index) != original_receiver_output_indexes.end();
        if (params.disable_output_substitution && drains_original_receiver_output) {
            return "Receiver cannot pay additional fee from the original receiver output when output substitution is disabled";
        }
        auto& receiver_output = proposal.tx->vout[receiver_output_index];
        if (receiver_output.nValue <= receiver_additional_fee) {
            return "Receiver output cannot cover additional fee";
        }
        receiver_output.nValue -= receiver_additional_fee;
    }

    const auto proposal_fee = ComputePSBTFee(proposal);
    if (!proposal_fee) return "Proposal fee could not be computed";

    const int proposal_vsize = original_tx_vsize + receiver_input_vsize;
    if (*proposal_fee < params.min_fee_rate.GetFee(proposal_vsize)) {
        return "Proposal fee rate below sender minimum";
    }

    return std::nullopt;
}

} // namespace payjoin::detail

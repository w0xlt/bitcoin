// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_RECEIVER_VALIDATION_H
#define BITCOIN_PAYJOIN_RECEIVER_VALIDATION_H

#include <payjoin/original.h>
#include <policy/feerate.h>
#include <psbt.h>

#include <optional>
#include <string>
#include <vector>

namespace payjoin::detail {

bool GetInputUTXO(const PartiallySignedTransaction& psbt, size_t input_index, CTxOut& utxo);

std::optional<CAmount> ComputePSBTFee(const PartiallySignedTransaction& psbt);

OriginalPayloadParams SanitizeReceiverOriginalParams(const CTransaction& original_tx,
                                                    const OriginalPayloadParams& params,
                                                    const std::vector<size_t>& receiver_output_indexes);

std::optional<std::string> ApplyReceiverFeeContribution(const PartiallySignedTransaction& original,
                                                        PartiallySignedTransaction& proposal,
                                                        const OriginalPayloadParams& params,
                                                        size_t receiver_output_index,
                                                        const std::vector<size_t>& original_receiver_output_indexes,
                                                        int original_tx_vsize,
                                                        int receiver_input_vsize);

} // namespace payjoin::detail

#endif // BITCOIN_PAYJOIN_RECEIVER_VALIDATION_H

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/original.h>
#include <payjoin/receiver_validation.h>

#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>

namespace {

Txid MakeTxid(unsigned char seed)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(seed);
    return Txid::FromUint256(uint256{std::span<const unsigned char>(bytes)});
}

CScript SenderScript()
{
    return CScript() << OP_1;
}

CScript ReceiverScript()
{
    return CScript() << OP_2;
}

CScript SenderChangeScript()
{
    return CScript() << OP_3;
}

PartiallySignedTransaction MakeOriginalPsbt()
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(MakeTxid(0x01), 0), CScript(), /*nSequence=*/42);
    tx.vout.emplace_back(1000, ReceiverScript());
    tx.vout.emplace_back(8900, SenderChangeScript());

    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = CTxOut(10000, SenderScript());
    return psbt;
}

PartiallySignedTransaction MakeProposalPsbt()
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(MakeTxid(0x01), 0), CScript(), /*nSequence=*/42);
    tx.vin.emplace_back(COutPoint(MakeTxid(0x02), 1), CScript(), /*nSequence=*/42);
    tx.vout.emplace_back(6000, ReceiverScript());
    tx.vout.emplace_back(8900, SenderChangeScript());

    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = CTxOut(10000, SenderScript());
    psbt.inputs[1].witness_utxo = CTxOut(5000, ReceiverScript());
    return psbt;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(payjoin_receiver_validation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(get_input_utxo_falls_back_to_non_witness)
{
    CMutableTransaction prevtx;
    prevtx.vout.emplace_back(1234, SenderScript());

    CMutableTransaction spend;
    spend.vin.emplace_back(COutPoint(prevtx.GetHash(), 0), CScript(), /*nSequence=*/0);
    spend.vout.emplace_back(1000, ReceiverScript());

    PartiallySignedTransaction psbt(spend);
    psbt.inputs[0].non_witness_utxo = MakeTransactionRef(prevtx);

    CTxOut utxo;
    BOOST_REQUIRE(payjoin::detail::GetInputUTXO(psbt, 0, utxo));
    BOOST_CHECK_EQUAL(utxo.nValue, 1234);
    BOOST_CHECK(utxo.scriptPubKey == SenderScript());
}

BOOST_AUTO_TEST_CASE(sanitize_receiver_original_params_ignores_receiver_fee_claim)
{
    const auto original = MakeOriginalPsbt();

    payjoin::OriginalPayloadParams params;
    params.additional_fee_contribution = payjoin::SenderFeeContribution{
        .max_additional_fee_contribution = 250,
        .additional_fee_output_index = 0,
    };

    const auto sanitized =
        payjoin::detail::SanitizeReceiverOriginalParams(CTransaction{*original.tx}, params, /*receiver_output_indexes=*/{0});
    BOOST_CHECK(!sanitized.additional_fee_contribution.has_value());
}

BOOST_AUTO_TEST_CASE(apply_receiver_fee_contribution_uses_sender_change_when_available)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeProposalPsbt();

    payjoin::OriginalPayloadParams params;
    params.min_fee_rate = CFeeRate{1000};
    params.additional_fee_contribution = payjoin::SenderFeeContribution{
        .max_additional_fee_contribution = 60,
        .additional_fee_output_index = 1,
    };

    const auto error = payjoin::detail::ApplyReceiverFeeContribution(
        original, proposal, params, /*receiver_output_index=*/0, /*original_tx_vsize=*/100, /*receiver_input_vsize=*/100);
    BOOST_CHECK(!error.has_value());
    BOOST_CHECK_EQUAL(proposal.tx->vout[0].nValue, 5960);
    BOOST_CHECK_EQUAL(proposal.tx->vout[1].nValue, 8840);
    BOOST_CHECK_EQUAL(*payjoin::detail::ComputePSBTFee(proposal), 200);
}

BOOST_AUTO_TEST_CASE(apply_receiver_fee_contribution_rejects_receiver_fee_when_disabled)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeProposalPsbt();

    payjoin::OriginalPayloadParams params;
    params.disable_output_substitution = true;
    params.min_fee_rate = CFeeRate{1000};

    const auto error = payjoin::detail::ApplyReceiverFeeContribution(
        original, proposal, params, /*receiver_output_index=*/0, /*original_tx_vsize=*/100, /*receiver_input_vsize=*/25);
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Receiver cannot pay additional fee with output substitution disabled");
}

BOOST_AUTO_TEST_CASE(apply_receiver_fee_contribution_enforces_min_fee_rate)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeProposalPsbt();

    payjoin::OriginalPayloadParams params;
    params.min_fee_rate = CFeeRate{1000};

    const auto error = payjoin::detail::ApplyReceiverFeeContribution(
        original, proposal, params, /*receiver_output_index=*/0, /*original_tx_vsize=*/300, /*receiver_input_vsize=*/50);
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal fee rate below sender minimum");
}

BOOST_AUTO_TEST_SUITE_END()

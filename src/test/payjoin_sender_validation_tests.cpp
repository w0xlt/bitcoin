// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/sender_validation.h>

#include <key.h>
#include <psbt.h>
#include <script/script.h>
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

CScript SenderInputScript()
{
    return CScript() << OP_1;
}

CScript ReceiverInputScript()
{
    return CScript() << OP_2;
}

CScript PayeeScript()
{
    return CScript() << OP_3;
}

CScript SenderChangeScript()
{
    return CScript() << OP_4;
}

CScript SubstitutePayeeScript()
{
    return CScript() << OP_5;
}

PartiallySignedTransaction MakeOriginalPsbt()
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 123;
    tx.vin.emplace_back(COutPoint(MakeTxid(0x01), 0), CScript(), /*nSequence=*/42);
    tx.vout.emplace_back(1000, PayeeScript());
    tx.vout.emplace_back(8900, SenderChangeScript());

    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = CTxOut(10000, SenderInputScript());
    psbt.outputs[1].witness_script = CScript() << OP_TRUE;
    return psbt;
}

PartiallySignedTransaction MakeValidProposal(const PartiallySignedTransaction& original)
{
    CMutableTransaction tx(*original.tx);
    tx.vin.insert(tx.vin.begin(), CTxIn(COutPoint(MakeTxid(0x02), 1), CScript(), /*nSequence=*/42));
    tx.vout[0].nValue = 6000;

    PartiallySignedTransaction proposal(tx);
    proposal.inputs[0].witness_utxo = CTxOut(5000, ReceiverInputScript());
    proposal.inputs[0].final_script_witness.stack = {{0x01}};
    proposal.inputs[1].witness_utxo = original.inputs[0].witness_utxo;
    return proposal;
}

payjoin::detail::SenderProposalValidationContext MakeContext(bool disable_output_substitution = true)
{
    return {
        .payee_script = PayeeScript(),
        .disable_output_substitution = disable_output_substitution,
    };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(payjoin_sender_validation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(valid_proposal_passes_validation)
{
    const auto original = MakeOriginalPsbt();
    const auto proposal = MakeValidProposal(original);

    BOOST_CHECK(!payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext()).has_value());
}

BOOST_AUTO_TEST_CASE(missing_original_input_is_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);
    proposal.tx->vin.erase(proposal.tx->vin.begin() + 1);
    proposal.inputs.erase(proposal.inputs.begin() + 1);

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext());
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal missing or shuffles original inputs");
}

BOOST_AUTO_TEST_CASE(changed_sender_sequence_is_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);
    proposal.tx->vin[1].nSequence = 41;

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext());
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal changed sender input sequence");
}

BOOST_AUTO_TEST_CASE(added_input_without_utxo_info_is_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);
    proposal.inputs[0].witness_utxo = CTxOut();

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext());
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal added input missing UTXO information");
}

BOOST_AUTO_TEST_CASE(unfinalized_added_input_is_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);
    proposal.inputs[0].final_script_witness.SetNull();

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext());
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal added input is not finalized");
}

BOOST_AUTO_TEST_CASE(partial_signatures_are_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);

    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    CPubKey pubkey = key.GetPubKey();
    proposal.inputs[0].partial_sigs.emplace(pubkey.GetID(), SigPair(pubkey, {0x30, 0x01}));

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext());
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal input contains partial signatures");
}

BOOST_AUTO_TEST_CASE(output_keypaths_are_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);

    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    proposal.outputs[0].hd_keypaths.emplace(key.GetPubKey().GetID(), KeyOriginInfo{});

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext());
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal output contains keypaths");
}

BOOST_AUTO_TEST_CASE(sender_output_reduction_is_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);
    proposal.tx->vout[1].nValue = 8899;

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext());
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal reduces sender-owned output");
}

BOOST_AUTO_TEST_CASE(disallowed_output_substitution_is_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);
    proposal.tx->vout[0].scriptPubKey = SubstitutePayeeScript();

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext(/*disable_output_substitution=*/true));
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal violates output substitution rules");
}

BOOST_AUTO_TEST_CASE(decreased_absolute_fee_is_rejected)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = MakeValidProposal(original);
    proposal.tx->vout[0].nValue = 6001;

    const auto error = payjoin::detail::ValidateSenderProposal(original, proposal, MakeContext());
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, "Proposal decreases absolute fee");
}

BOOST_AUTO_TEST_CASE(restore_original_sender_data_restores_sender_metadata)
{
    const auto original = MakeOriginalPsbt();
    auto proposal = original;

    proposal.inputs[0].witness_utxo = CTxOut();
    proposal.outputs[1].witness_script = CScript();

    payjoin::detail::RestoreOriginalSenderData(original, proposal);

    BOOST_CHECK(!proposal.inputs[0].witness_utxo.IsNull());
    BOOST_CHECK(proposal.outputs[1].witness_script == original.outputs[1].witness_script);
}

BOOST_AUTO_TEST_SUITE_END()

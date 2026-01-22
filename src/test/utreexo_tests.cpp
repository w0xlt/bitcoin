// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <streams.h>
#include <test/util/setup_common.h>
#include <utreexo/utreexo.h>
#include <utreexo/util.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(utreexo_tests, BasicTestingSetup)

// Test utility functions
BOOST_AUTO_TEST_CASE(tree_rows_test)
{
    using namespace utreexo;

    BOOST_CHECK_EQUAL(TreeRows(0), 0);
    BOOST_CHECK_EQUAL(TreeRows(1), 0);
    BOOST_CHECK_EQUAL(TreeRows(2), 1);
    BOOST_CHECK_EQUAL(TreeRows(3), 2);
    BOOST_CHECK_EQUAL(TreeRows(4), 2);
    BOOST_CHECK_EQUAL(TreeRows(5), 3);
    BOOST_CHECK_EQUAL(TreeRows(8), 3);
    BOOST_CHECK_EQUAL(TreeRows(9), 4);
    BOOST_CHECK_EQUAL(TreeRows(16), 4);
    BOOST_CHECK_EQUAL(TreeRows(17), 5);
}

BOOST_AUTO_TEST_CASE(row_offset_test)
{
    using namespace utreexo;

    // For 8 leaves: positions 0-7 are row 0, 8-11 are row 1, 12-13 are row 2, 14 is row 3.
    BOOST_CHECK_EQUAL(RowOffset(8, 0), 0);
    BOOST_CHECK_EQUAL(RowOffset(8, 1), 8);
    BOOST_CHECK_EQUAL(RowOffset(8, 2), 12);
    BOOST_CHECK_EQUAL(RowOffset(8, 3), 14);

    // For 5 leaves: positions 0-4 are row 0, 5-6 are row 1, 7 is row 2.
    BOOST_CHECK_EQUAL(RowOffset(5, 0), 0);
    BOOST_CHECK_EQUAL(RowOffset(5, 1), 5);
    BOOST_CHECK_EQUAL(RowOffset(5, 2), 7);
}

BOOST_AUTO_TEST_CASE(detect_row_test)
{
    using namespace utreexo;

    // For 8 leaves.
    BOOST_CHECK_EQUAL(DetectRow(0, 8), 0);
    BOOST_CHECK_EQUAL(DetectRow(7, 8), 0);
    BOOST_CHECK_EQUAL(DetectRow(8, 8), 1);
    BOOST_CHECK_EQUAL(DetectRow(11, 8), 1);
    BOOST_CHECK_EQUAL(DetectRow(12, 8), 2);
    BOOST_CHECK_EQUAL(DetectRow(13, 8), 2);
    BOOST_CHECK_EQUAL(DetectRow(14, 8), 3);
}

BOOST_AUTO_TEST_CASE(sibling_and_parent_test)
{
    using namespace utreexo;

    // For 8 leaves, leaf 0's sibling is 1, parent is 8.
    BOOST_CHECK_EQUAL(GetSiblingPosition(0, 8), 1);
    BOOST_CHECK_EQUAL(GetSiblingPosition(1, 8), 0);
    BOOST_CHECK_EQUAL(GetParentPosition(0, 8), 8);
    BOOST_CHECK_EQUAL(GetParentPosition(1, 8), 8);

    // Leaf 2's sibling is 3, parent is 9.
    BOOST_CHECK_EQUAL(GetSiblingPosition(2, 8), 3);
    BOOST_CHECK_EQUAL(GetParentPosition(2, 8), 9);

    // Node 8's sibling is 9, parent is 12.
    BOOST_CHECK_EQUAL(GetSiblingPosition(8, 8), 9);
    BOOST_CHECK_EQUAL(GetParentPosition(8, 8), 12);
}

BOOST_AUTO_TEST_CASE(is_left_child_test)
{
    using namespace utreexo;

    BOOST_CHECK(IsLeftChild(0, 8));
    BOOST_CHECK(!IsLeftChild(1, 8));
    BOOST_CHECK(IsLeftChild(2, 8));
    BOOST_CHECK(!IsLeftChild(3, 8));
    BOOST_CHECK(IsLeftChild(8, 8));
    BOOST_CHECK(!IsLeftChild(9, 8));
}

BOOST_AUTO_TEST_CASE(is_root_test)
{
    using namespace utreexo;

    // 8 leaves: single root at position 14.
    BOOST_CHECK(!IsRoot(0, 8));
    BOOST_CHECK(!IsRoot(7, 8));
    BOOST_CHECK(IsRoot(14, 8));

    // 5 leaves: roots at positions 4 (row 0), 7 (row 2).
    // Actually for 5 leaves (binary 101): roots at row 0 and row 2.
    BOOST_CHECK(IsRoot(4, 5)); // Row 0, position 4 (the 5th leaf is alone).
    BOOST_CHECK(IsRoot(7, 5)); // Row 2, position 7.
    BOOST_CHECK(!IsRoot(0, 5));
    BOOST_CHECK(!IsRoot(5, 5));
}

BOOST_AUTO_TEST_CASE(num_roots_test)
{
    using namespace utreexo;

    BOOST_CHECK_EQUAL(NumRoots(0), 0);
    BOOST_CHECK_EQUAL(NumRoots(1), 1);  // binary: 1
    BOOST_CHECK_EQUAL(NumRoots(2), 1);  // binary: 10
    BOOST_CHECK_EQUAL(NumRoots(3), 2);  // binary: 11
    BOOST_CHECK_EQUAL(NumRoots(4), 1);  // binary: 100
    BOOST_CHECK_EQUAL(NumRoots(5), 2);  // binary: 101
    BOOST_CHECK_EQUAL(NumRoots(7), 3);  // binary: 111
    BOOST_CHECK_EQUAL(NumRoots(8), 1);  // binary: 1000
}

// Test parent hash calculation
BOOST_AUTO_TEST_CASE(parent_hash_test)
{
    using namespace utreexo;

    uint256 left, right;
    left.SetNull();
    right.SetNull();

    // Hash of two zero hashes should be deterministic.
    uint256 parent = CalculateParentHash(left, right);
    BOOST_CHECK(!parent.IsNull());

    // Same inputs should give same output.
    uint256 parent2 = CalculateParentHash(left, right);
    BOOST_CHECK(parent == parent2);

    // Different order should give different result.
    right = uint256(uint8_t{1});
    uint256 parent3 = CalculateParentHash(left, right);
    uint256 parent4 = CalculateParentHash(right, left);
    BOOST_CHECK(parent3 != parent4);
}

// Test Stump::Add
BOOST_AUTO_TEST_CASE(stump_add_single_test)
{
    using namespace utreexo;

    Stump stump;
    BOOST_CHECK_EQUAL(stump.GetNumLeaves(), 0);
    BOOST_CHECK_EQUAL(stump.GetRoots().size(), 0);

    // Add single leaf.
    uint256 leaf1;
    leaf1.SetNull();
    std::vector<uint256> leaves = {leaf1};
    stump.Add(leaves);

    BOOST_CHECK_EQUAL(stump.GetNumLeaves(), 1);
    BOOST_CHECK_EQUAL(stump.GetRoots().size(), 1);
    BOOST_CHECK(stump.GetRoots()[0] == leaf1);
}

BOOST_AUTO_TEST_CASE(stump_add_two_test)
{
    using namespace utreexo;

    Stump stump;

    uint256 leaf1, leaf2;
    leaf1.SetNull();
    leaf2 = uint256(uint8_t{1});

    std::vector<uint256> leaves = {leaf1, leaf2};
    stump.Add(leaves);

    BOOST_CHECK_EQUAL(stump.GetNumLeaves(), 2);
    BOOST_CHECK_EQUAL(stump.GetRoots().size(), 1);

    // Root should be hash of the two leaves.
    uint256 expected_root = CalculateParentHash(leaf1, leaf2);
    BOOST_CHECK(stump.GetRoots()[0] == expected_root);
}

BOOST_AUTO_TEST_CASE(stump_add_three_test)
{
    using namespace utreexo;

    Stump stump;

    uint256 leaf1, leaf2, leaf3;
    leaf1.SetNull();
    leaf2 = uint256(uint8_t{1});
    leaf3 = uint256(uint8_t{2});

    std::vector<uint256> leaves = {leaf1, leaf2, leaf3};
    stump.Add(leaves);

    BOOST_CHECK_EQUAL(stump.GetNumLeaves(), 3);
    BOOST_CHECK_EQUAL(stump.GetRoots().size(), 2); // 3 = 11 binary, 2 roots.

    // First root (higher row): hash of first two leaves.
    uint256 expected_root1 = CalculateParentHash(leaf1, leaf2);
    // Second root (lower row): third leaf.
    BOOST_CHECK(stump.GetRoots()[0] == expected_root1);
    BOOST_CHECK(stump.GetRoots()[1] == leaf3);
}

BOOST_AUTO_TEST_CASE(stump_add_power_of_two_test)
{
    using namespace utreexo;

    Stump stump;

    // Add 8 leaves.
    std::vector<uint256> leaves;
    for (int i = 0; i < 8; i++) {
        leaves.push_back(uint256(uint8_t(i)));
    }
    stump.Add(leaves);

    BOOST_CHECK_EQUAL(stump.GetNumLeaves(), 8);
    BOOST_CHECK_EQUAL(stump.GetRoots().size(), 1);
}

// Test Stump::Verify
BOOST_AUTO_TEST_CASE(stump_verify_single_leaf_test)
{
    using namespace utreexo;

    Stump stump;
    uint256 leaf1 = uint256(uint8_t{42});
    stump.Add(std::vector<uint256>{leaf1});

    // Proof for single leaf in single-leaf tree is empty.
    Proof proof({0}, {});
    BOOST_CHECK(stump.Verify(proof, std::vector<uint256>{leaf1}));

    // Wrong leaf hash should fail.
    uint256 wrong_leaf = uint256(uint8_t{99});
    BOOST_CHECK(!stump.Verify(proof, std::vector<uint256>{wrong_leaf}));
}

BOOST_AUTO_TEST_CASE(stump_verify_two_leaves_test)
{
    using namespace utreexo;

    Stump stump;
    uint256 leaf1 = uint256(uint8_t{1});
    uint256 leaf2 = uint256(uint8_t{2});
    stump.Add(std::vector<uint256>{leaf1, leaf2});

    // Proof for leaf 0 needs sibling (leaf 1).
    Proof proof0({0}, {leaf2});
    BOOST_CHECK(stump.Verify(proof0, std::vector<uint256>{leaf1}));

    // Proof for leaf 1 needs sibling (leaf 0).
    Proof proof1({1}, {leaf1});
    BOOST_CHECK(stump.Verify(proof1, std::vector<uint256>{leaf2}));

    // Proof for both leaves needs no siblings (they are siblings).
    Proof proof_both({0, 1}, {});
    BOOST_CHECK(stump.Verify(proof_both, std::vector<uint256>{leaf1, leaf2}));
}

BOOST_AUTO_TEST_CASE(stump_verify_four_leaves_test)
{
    using namespace utreexo;

    Stump stump;
    uint256 leaf0 = uint256(uint8_t{0});
    uint256 leaf1 = uint256(uint8_t{1});
    uint256 leaf2 = uint256(uint8_t{2});
    uint256 leaf3 = uint256(uint8_t{3});
    stump.Add(std::vector<uint256>{leaf0, leaf1, leaf2, leaf3});

    // Tree structure:
    //       6
    //     /   \
    //    4     5
    //   / \   / \
    //  0   1 2   3

    uint256 hash4 = CalculateParentHash(leaf0, leaf1);
    uint256 hash5 = CalculateParentHash(leaf2, leaf3);

    // Proof for leaf 0: needs sibling 1 and uncle 5.
    Proof proof0({0}, {leaf1, hash5});
    BOOST_CHECK(stump.Verify(proof0, std::vector<uint256>{leaf0}));

    // Proof for leaf 2: needs sibling 3 and uncle 4.
    Proof proof2({2}, {leaf3, hash4});
    BOOST_CHECK(stump.Verify(proof2, std::vector<uint256>{leaf2}));
}

BOOST_AUTO_TEST_CASE(stump_verify_invalid_proof_test)
{
    using namespace utreexo;

    Stump stump;
    uint256 leaf0 = uint256(uint8_t{0});
    uint256 leaf1 = uint256(uint8_t{1});
    stump.Add(std::vector<uint256>{leaf0, leaf1});

    // Wrong sibling hash.
    uint256 wrong_sibling = uint256(uint8_t{99});
    Proof bad_proof({0}, {wrong_sibling});
    BOOST_CHECK(!stump.Verify(bad_proof, std::vector<uint256>{leaf0}));

    // Target out of bounds.
    Proof oob_proof({5}, {leaf1});
    BOOST_CHECK(!stump.Verify(oob_proof, std::vector<uint256>{leaf0}));

    // Mismatched sizes.
    Proof mismatch_proof({0, 1}, {});
    BOOST_CHECK(!stump.Verify(mismatch_proof, std::vector<uint256>{leaf0})); // Only one hash provided.
}

BOOST_AUTO_TEST_CASE(stump_verify_empty_test)
{
    using namespace utreexo;

    Stump stump;
    stump.Add(std::vector<uint256>{uint256(uint8_t{1})});

    // Empty proof is valid for empty targets.
    Proof empty_proof({}, {});
    BOOST_CHECK(stump.Verify(empty_proof, std::vector<uint256>{}));
}

// Test Stump::Modify
BOOST_AUTO_TEST_CASE(stump_modify_add_only_test)
{
    using namespace utreexo;

    Stump stump;
    uint256 leaf1 = uint256(uint8_t{1});
    stump.Add(std::vector<uint256>{leaf1});

    // Modify with no deletions, just additions.
    Proof empty_proof({}, {});
    uint256 leaf2 = uint256(uint8_t{2});
    BOOST_CHECK(stump.Modify(empty_proof, {}, std::vector<uint256>{leaf2}));

    BOOST_CHECK_EQUAL(stump.GetNumLeaves(), 2);
    BOOST_CHECK_EQUAL(stump.GetRoots().size(), 1);
}

// Test serialization
BOOST_AUTO_TEST_CASE(proof_serialization_test)
{
    using namespace utreexo;

    Proof original({0, 2, 5}, {uint256(uint8_t{1}), uint256(uint8_t{2})});

    DataStream ss{};
    ss << original;

    Proof deserialized;
    ss >> deserialized;

    BOOST_CHECK(original.GetTargets() == deserialized.GetTargets());
    BOOST_CHECK(original.GetHashes() == deserialized.GetHashes());
}

BOOST_AUTO_TEST_CASE(stump_serialization_test)
{
    using namespace utreexo;

    Stump original;
    original.Add(std::vector<uint256>{uint256(uint8_t{1}), uint256(uint8_t{2}), uint256(uint8_t{3})});

    DataStream ss{};
    ss << original;

    Stump deserialized;
    ss >> deserialized;

    BOOST_CHECK_EQUAL(original.GetNumLeaves(), deserialized.GetNumLeaves());
    BOOST_CHECK(original.GetRoots() == deserialized.GetRoots());
}

// Test larger tree
BOOST_AUTO_TEST_CASE(stump_large_tree_test)
{
    using namespace utreexo;

    Stump stump;

    // Add 100 leaves.
    std::vector<uint256> leaves;
    for (int i = 0; i < 100; i++) {
        uint256 leaf;
        std::memset(leaf.data(), 0, 32);
        leaf.data()[0] = static_cast<unsigned char>(i & 0xFF);
        leaf.data()[1] = static_cast<unsigned char>((i >> 8) & 0xFF);
        leaves.push_back(leaf);
    }
    stump.Add(leaves);

    BOOST_CHECK_EQUAL(stump.GetNumLeaves(), 100);
    // 100 = 0b1100100, popcount = 3 roots.
    BOOST_CHECK_EQUAL(stump.GetRoots().size(), 3);
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <utreexo/utreexo.h>
#include <utreexo/util.h>

#include <crypto/sha512_256.h>

#include <algorithm>
#include <map>
#include <set>

namespace utreexo {

uint256 CalculateParentHash(const uint256& left, const uint256& right)
{
    uint256 result;
    CSHA512_256()
        .Write(left.data(), 32)
        .Write(right.data(), 32)
        .Finalize(result.data());
    return result;
}

void Stump::Add(std::span<const uint256> leaves)
{
    for (const auto& leaf : leaves) {
        uint256 current = leaf;
        uint8_t row = 0;

        // While there's a root at this row, merge with it and move up.
        while ((m_num_leaves >> row) & 1) {
            // Pop the root at this row (it's the last one in the vector).
            uint256 existing_root = m_roots.back();
            m_roots.pop_back();
            // Merge: existing root becomes left child, current becomes right.
            current = CalculateParentHash(existing_root, current);
            row++;
        }

        // Place the result as the new root at this row.
        m_roots.push_back(current);
        m_num_leaves++;
    }
}

bool Stump::Verify(const Proof& proof, std::span<const uint256> leaf_hashes) const
{
    const auto& targets = proof.GetTargets();
    const auto& proof_hashes = proof.GetHashes();

    // Number of leaf hashes must match number of targets.
    if (leaf_hashes.size() != targets.size()) {
        return false;
    }

    // Empty proof is valid for empty inputs.
    if (targets.empty()) {
        return true;
    }

    // Verify targets are within bounds and sorted.
    for (size_t i = 0; i < targets.size(); i++) {
        if (targets[i] >= m_num_leaves) {
            return false;
        }
        if (i > 0 && targets[i] <= targets[i - 1]) {
            return false; // Must be strictly ascending.
        }
    }

    // Map from position to hash, for computing up the tree.
    std::map<uint64_t, uint256> computed;
    for (size_t i = 0; i < targets.size(); i++) {
        computed[targets[i]] = leaf_hashes[i];
    }

    size_t proof_idx = 0;
    uint8_t max_row = TreeRows(m_num_leaves);

    // Process row by row, from leaves up to roots.
    for (uint8_t row = 0; row <= max_row; row++) {
        uint64_t row_start = RowOffset(m_num_leaves, row);
        uint64_t row_end = RowOffset(m_num_leaves, row + 1);

        // Collect positions at this row.
        std::vector<uint64_t> positions_at_row;
        for (const auto& [pos, hash] : computed) {
            if (pos >= row_start && pos < row_end) {
                positions_at_row.push_back(pos);
            }
        }

        // Process positions from left to right.
        for (uint64_t pos : positions_at_row) {
            // Check if this position still exists (might have been processed as sibling).
            if (computed.find(pos) == computed.end()) continue;

            // If this is a root, don't process further.
            if (IsRoot(pos, m_num_leaves)) {
                continue;
            }

            uint64_t sibling_pos = GetSiblingPosition(pos, m_num_leaves);
            uint64_t parent_pos = GetParentPosition(pos, m_num_leaves);

            // Get sibling hash: either from computed or from proof.
            uint256 sibling_hash;
            auto sibling_it = computed.find(sibling_pos);
            if (sibling_it != computed.end()) {
                sibling_hash = sibling_it->second;
            } else {
                if (proof_idx >= proof_hashes.size()) {
                    return false;
                }
                sibling_hash = proof_hashes[proof_idx++];
            }

            // Compute parent hash.
            uint256 left_hash, right_hash;
            if (IsLeftChild(pos, m_num_leaves)) {
                left_hash = computed[pos];
                right_hash = sibling_hash;
            } else {
                left_hash = sibling_hash;
                right_hash = computed[pos];
            }
            uint256 parent_hash = CalculateParentHash(left_hash, right_hash);

            // Update map: add parent, remove children.
            computed.erase(pos);
            if (sibling_it != computed.end()) {
                computed.erase(sibling_pos);
            }
            computed[parent_pos] = parent_hash;
        }
    }

    // All proof hashes should have been used.
    if (proof_idx != proof_hashes.size()) {
        return false;
    }

    // All remaining entries should be roots with matching hashes.
    for (const auto& [pos, hash] : computed) {
        if (!IsRoot(pos, m_num_leaves)) {
            return false;
        }
        uint8_t row = DetectRow(pos, m_num_leaves);
        uint8_t root_idx = RootIndex(m_num_leaves, row);
        if (root_idx >= m_roots.size() || m_roots[root_idx] != hash) {
            return false;
        }
    }

    return true;
}

bool Stump::Modify(const Proof& proof, std::span<const uint256> del_hashes,
                   std::span<const uint256> add_hashes)
{
    const auto& targets = proof.GetTargets();
    const auto& proof_hashes = proof.GetHashes();

    // Validate inputs.
    if (del_hashes.size() != targets.size()) {
        return false;
    }

    // No deletions: just verify empty and add.
    if (targets.empty()) {
        Add(add_hashes);
        return true;
    }

    // Verify targets are sorted and in bounds.
    for (size_t i = 0; i < targets.size(); i++) {
        if (targets[i] >= m_num_leaves) {
            return false;
        }
        if (i > 0 && targets[i] <= targets[i - 1]) {
            return false;
        }
    }

    // Build position -> hash map for targets (to be deleted).
    std::map<uint64_t, uint256> computed;
    for (size_t i = 0; i < targets.size(); i++) {
        computed[targets[i]] = del_hashes[i];
    }

    size_t proof_idx = 0;
    uint8_t max_row = TreeRows(m_num_leaves);

    // Track which positions are deleted (including propagated deletions).
    std::set<uint64_t> deleted(targets.begin(), targets.end());

    // Track surviving hashes that will form new roots.
    // These are sibling hashes from the proof that aren't deleted.
    std::vector<std::pair<uint8_t, uint256>> survivors;

    // Track which root rows are affected by deletions.
    std::set<uint8_t> affected_root_rows;

    // Process row by row.
    for (uint8_t row = 0; row <= max_row; row++) {
        uint64_t row_start = RowOffset(m_num_leaves, row);
        uint64_t row_end = RowOffset(m_num_leaves, row + 1);

        // Collect deleted positions at this row.
        std::vector<uint64_t> del_at_row;
        for (uint64_t pos : deleted) {
            if (pos >= row_start && pos < row_end) {
                del_at_row.push_back(pos);
            }
        }
        std::sort(del_at_row.begin(), del_at_row.end());

        for (uint64_t pos : del_at_row) {
            if (deleted.find(pos) == deleted.end()) continue;

            // If this is a root position, mark the row as affected.
            if (IsRoot(pos, m_num_leaves)) {
                uint8_t root_row = DetectRow(pos, m_num_leaves);
                affected_root_rows.insert(root_row);

                // Verify hash matches before deleting this root.
                auto it = computed.find(pos);
                if (it != computed.end()) {
                    uint8_t idx = RootIndex(m_num_leaves, root_row);
                    if (idx >= m_roots.size() || m_roots[idx] != it->second) {
                        return false;
                    }
                }
                deleted.erase(pos);
                continue;
            }

            uint64_t sibling_pos = GetSiblingPosition(pos, m_num_leaves);
            uint64_t parent_pos = GetParentPosition(pos, m_num_leaves);

            // Is sibling also deleted?
            if (deleted.count(sibling_pos)) {
                // Both deleted -> parent is deleted.
                // First verify we can compute parent hash.
                auto pos_it = computed.find(pos);
                auto sib_it = computed.find(sibling_pos);
                if (pos_it != computed.end() && sib_it != computed.end()) {
                    uint256 left = IsLeftChild(pos, m_num_leaves) ? pos_it->second : sib_it->second;
                    uint256 right = IsLeftChild(pos, m_num_leaves) ? sib_it->second : pos_it->second;
                    computed[parent_pos] = CalculateParentHash(left, right);
                }
                deleted.erase(pos);
                deleted.erase(sibling_pos);
                deleted.insert(parent_pos);
            } else {
                // Sibling survives. Get hash from proof.
                if (proof_idx >= proof_hashes.size()) {
                    return false;
                }
                uint256 sibling_hash = proof_hashes[proof_idx++];

                // Verify we can compute parent to check proof validity.
                auto pos_it = computed.find(pos);
                if (pos_it != computed.end()) {
                    uint256 left = IsLeftChild(pos, m_num_leaves) ? pos_it->second : sibling_hash;
                    uint256 right = IsLeftChild(pos, m_num_leaves) ? sibling_hash : pos_it->second;
                    computed[parent_pos] = CalculateParentHash(left, right);
                }

                // Sibling becomes a survivor.
                survivors.emplace_back(row, sibling_hash);
                deleted.erase(pos);
            }
        }
    }

    // Verify all proof hashes were used.
    if (proof_idx != proof_hashes.size()) {
        return false;
    }

    // Verify computed roots match actual roots.
    for (const auto& [pos, hash] : computed) {
        if (IsRoot(pos, m_num_leaves)) {
            uint8_t row = DetectRow(pos, m_num_leaves);
            uint8_t idx = RootIndex(m_num_leaves, row);
            if (idx >= m_roots.size() || m_roots[idx] != hash) {
                return false;
            }
        }
    }

    // Now rebuild the accumulator.
    // Sort survivors by row (ascending).
    std::sort(survivors.begin(), survivors.end());

    // Collect unaffected roots.
    std::vector<std::pair<uint8_t, uint256>> unaffected_roots;
    for (uint8_t row = 0; row <= max_row; row++) {
        if ((m_num_leaves >> row) & 1) {
            if (affected_root_rows.find(row) == affected_root_rows.end()) {
                uint8_t idx = RootIndex(m_num_leaves, row);
                unaffected_roots.emplace_back(row, m_roots[idx]);
            }
        }
    }

    // Rebuild accumulator from survivors and unaffected roots.
    m_roots.clear();
    m_num_leaves = 0;

    // Add survivors.
    for (const auto& [row, hash] : survivors) {
        AddAtRow(row, hash);
    }

    // Add unaffected roots.
    for (const auto& [row, hash] : unaffected_roots) {
        AddAtRow(row, hash);
    }

    // Add new leaves.
    Add(add_hashes);

    return true;
}

// Helper function to add a hash at a specific row.
void Stump::AddAtRow(uint8_t row, const uint256& hash)
{
    uint64_t leaves_represented = 1ULL << row;
    uint256 current = hash;
    uint8_t current_row = row;

    // Merge with existing roots if needed.
    while ((m_num_leaves >> current_row) & 1) {
        uint256 existing_root = m_roots.back();
        m_roots.pop_back();
        current = CalculateParentHash(existing_root, current);
        current_row++;
    }

    m_roots.push_back(current);
    m_num_leaves += leaves_represented;
}

} // namespace utreexo

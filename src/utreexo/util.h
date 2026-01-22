// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTREEXO_UTIL_H
#define BITCOIN_UTREEXO_UTIL_H

#include <bit>
#include <cstdint>

namespace utreexo {

/** Return the number of rows in a tree with num_leaves leaves. */
inline uint8_t TreeRows(uint64_t num_leaves)
{
    if (num_leaves == 0) return 0;
    // std::bit_width returns the number of bits needed to represent num_leaves,
    // which equals floor(log2(num_leaves)) + 1.
    return static_cast<uint8_t>(std::bit_width(num_leaves - 1));
}

/** Return the offset to the start of a given row in the forest.
 *  The offset is the sum of nodes at all previous rows.
 */
inline uint64_t RowOffset(uint64_t num_leaves, uint8_t row)
{
    // offset(r) = sum_{i=0}^{r-1} floor(num_leaves / 2^i)
    // = num_leaves + floor(num_leaves/2) + floor(num_leaves/4) + ...
    uint64_t offset = 0;
    for (uint8_t i = 0; i < row && (num_leaves >> i) > 0; i++) {
        offset += num_leaves >> i;
    }
    return offset;
}

/** Return the number of nodes at a given row. */
inline uint64_t NodesAtRow(uint64_t num_leaves, uint8_t row)
{
    return num_leaves >> row;
}

/** Return the row that a position is at in the tree. */
inline uint8_t DetectRow(uint64_t pos, uint64_t num_leaves)
{
    if (num_leaves == 0) return 0;
    uint8_t max_row = TreeRows(num_leaves);
    for (uint8_t row = 0; row <= max_row; row++) {
        uint64_t next_offset = RowOffset(num_leaves, row + 1);
        if (pos < next_offset) {
            return row;
        }
    }
    return max_row;
}

/** Return whether the position is a left child (even position within its row). */
inline bool IsLeftChild(uint64_t pos, uint64_t num_leaves)
{
    uint8_t row = DetectRow(pos, num_leaves);
    uint64_t offset = RowOffset(num_leaves, row);
    uint64_t relative_pos = pos - offset;
    return (relative_pos & 1) == 0;
}

/** Return the position of the sibling. */
inline uint64_t GetSiblingPosition(uint64_t pos, uint64_t num_leaves)
{
    uint8_t row = DetectRow(pos, num_leaves);
    uint64_t offset = RowOffset(num_leaves, row);
    uint64_t relative_pos = pos - offset;
    // XOR with 1 flips the last bit, giving the sibling position within the row.
    return offset + (relative_pos ^ 1);
}

/** Return the position of the parent. */
inline uint64_t GetParentPosition(uint64_t pos, uint64_t num_leaves)
{
    uint8_t row = DetectRow(pos, num_leaves);
    uint64_t offset = RowOffset(num_leaves, row);
    uint64_t relative_pos = pos - offset;
    uint64_t parent_offset = RowOffset(num_leaves, row + 1);
    return parent_offset + (relative_pos >> 1);
}

/** Count the number of roots (same as popcount of num_leaves). */
inline uint8_t NumRoots(uint64_t num_leaves)
{
    return static_cast<uint8_t>(std::popcount(num_leaves));
}

/** Return whether a position is a root in the current forest.
 *  A position is a root if:
 *  1. Its row bit is set in num_leaves (meaning there's a tree of that height)
 *  2. It's at the last position in its row (the rightmost node at that row)
 */
inline bool IsRoot(uint64_t pos, uint64_t num_leaves)
{
    if (num_leaves == 0) return false;

    uint8_t row = DetectRow(pos, num_leaves);
    uint64_t offset = RowOffset(num_leaves, row);
    uint64_t relative_pos = pos - offset;
    uint64_t nodes_at_row = num_leaves >> row;

    if (nodes_at_row == 0) return false;

    // A position is a root if:
    // 1. The bit at position 'row' is set in num_leaves
    // 2. The relative position is the last one in the row
    if ((num_leaves >> row) & 1) {
        // There's a root at this row. The root is at the last position.
        return relative_pos == (nodes_at_row - 1);
    }
    return false;
}

/** Return the root position for a given row, or UINT64_MAX if no root at this row. */
inline uint64_t GetRootPosition(uint64_t num_leaves, uint8_t row)
{
    // Check if there's a root at this row (bit at position 'row' is set).
    if (!((num_leaves >> row) & 1)) {
        return UINT64_MAX;
    }
    uint64_t offset = RowOffset(num_leaves, row);
    uint64_t nodes_at_row = num_leaves >> row;
    return offset + nodes_at_row - 1;
}

/** Return the index of a root within the roots vector for a given row.
 *  Roots are ordered from highest row to lowest (largest subtree first).
 */
inline uint8_t RootIndex(uint64_t num_leaves, uint8_t row)
{
    // Count how many roots are at rows > row.
    uint8_t index = 0;
    uint8_t max_row = TreeRows(num_leaves);
    for (uint8_t r = max_row; r > row; r--) {
        if ((num_leaves >> r) & 1) {
            index++;
        }
    }
    return index;
}

} // namespace utreexo

#endif // BITCOIN_UTREEXO_UTIL_H

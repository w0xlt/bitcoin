// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTREEXO_UTREEXO_H
#define BITCOIN_UTREEXO_UTREEXO_H

#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace utreexo {

/** Compute the parent hash from two children using SHA-512/256. */
uint256 CalculateParentHash(const uint256& left, const uint256& right);

/**
 * Utreexo inclusion proof.
 * Contains the leaf positions being proved and the sibling hashes needed
 * for verification.
 */
class Proof
{
private:
    std::vector<uint64_t> m_targets;  //!< Leaf positions being proved
    std::vector<uint256> m_hashes;    //!< Sibling hashes for verification path

public:
    Proof() = default;
    Proof(std::vector<uint64_t> targets, std::vector<uint256> hashes)
        : m_targets(std::move(targets)), m_hashes(std::move(hashes)) {}

    /** Get the target positions. */
    const std::vector<uint64_t>& GetTargets() const { return m_targets; }

    /** Get the proof hashes. */
    const std::vector<uint256>& GetHashes() const { return m_hashes; }

    SERIALIZE_METHODS(Proof, obj)
    {
        READWRITE(obj.m_targets, obj.m_hashes);
    }
};

/**
 * Utreexo Stump - a lightweight accumulator that stores only roots.
 *
 * The Stump can:
 * - Add new leaves (updating the roots)
 * - Verify inclusion proofs
 * - Modify the accumulator state (delete old leaves and add new ones)
 *
 * It cannot produce proofs; for that, use a Pollard (not implemented here).
 */
class Stump
{
private:
    uint64_t m_num_leaves{0};        //!< Total number of leaves ever added
    std::vector<uint256> m_roots;    //!< Current roots, from highest row to lowest

public:
    Stump() = default;

    /** Get the number of leaves in the accumulator. */
    uint64_t GetNumLeaves() const { return m_num_leaves; }

    /** Get the current roots. */
    const std::vector<uint256>& GetRoots() const { return m_roots; }

    /** Add leaves to the accumulator. */
    void Add(std::span<const uint256> leaves);

    /**
     * Verify an inclusion proof against this stump.
     * @param proof The proof to verify.
     * @param leaf_hashes The leaf hashes being proved, in the same order as proof targets.
     * @return true if the proof is valid.
     */
    bool Verify(const Proof& proof, std::span<const uint256> leaf_hashes) const;

    /**
     * Modify the accumulator: verify deletions and apply additions.
     * @param proof Proof for the leaves being deleted.
     * @param del_hashes The leaf hashes being deleted (must match proof targets).
     * @param add_hashes The new leaf hashes to add.
     * @return true if verification succeeded and the state was updated.
     */
    bool Modify(const Proof& proof, std::span<const uint256> del_hashes,
                std::span<const uint256> add_hashes);

private:
    /** Helper to add a hash representing 2^row leaves at a specific row. */
    void AddAtRow(uint8_t row, const uint256& hash);

public:
    SERIALIZE_METHODS(Stump, obj)
    {
        READWRITE(obj.m_num_leaves, obj.m_roots);
    }
};

} // namespace utreexo

#endif // BITCOIN_UTREEXO_UTREEXO_H

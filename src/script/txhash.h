// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_TXHASH_H
#define BITCOIN_SCRIPT_TXHASH_H

#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <span.h>
#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

class CTxOut;

// ===== Byte 0: Global field flags (BIP 346) =====
static const unsigned char TXFS_VERSION = 1 << 0;
static const unsigned char TXFS_LOCKTIME = 1 << 1;
static const unsigned char TXFS_CURRENT_INPUT_IDX = 1 << 2;
static const unsigned char TXFS_CURRENT_INPUT_CONTROL_BLOCK = 1 << 3;
static const unsigned char TXFS_CURRENT_INPUT_SPENTSCRIPT = 1 << 4;
static const unsigned char TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS = 1 << 5;
static const unsigned char TXFS_CURRENT_INPUT_TAPROOT_ANNEX = 1 << 6;
static const unsigned char TXFS_CONTROL = 1 << 7;

// ===== Byte 1: Input/output field flags =====
static const unsigned char TXFS_INPUTS_PREVOUTS = 1 << 0;
static const unsigned char TXFS_INPUTS_SEQUENCES = 1 << 1;
static const unsigned char TXFS_INPUTS_SCRIPTSIGS = 1 << 2;
static const unsigned char TXFS_INPUTS_PREV_SCRIPTPUBKEYS = 1 << 3;
static const unsigned char TXFS_INPUTS_PREV_VALUES = 1 << 4;
static const unsigned char TXFS_INPUTS_TAPROOT_ANNEXES = 1 << 5;
static const unsigned char TXFS_OUTPUTS_SCRIPTPUBKEYS = 1 << 6;
static const unsigned char TXFS_OUTPUTS_VALUES = 1 << 7;

// ===== Composite constants =====
static const unsigned char TXFS_INPUTS_ALL = TXFS_INPUTS_PREVOUTS
    | TXFS_INPUTS_SEQUENCES
    | TXFS_INPUTS_SCRIPTSIGS
    | TXFS_INPUTS_PREV_SCRIPTPUBKEYS
    | TXFS_INPUTS_PREV_VALUES
    | TXFS_INPUTS_TAPROOT_ANNEXES;
static const unsigned char TXFS_OUTPUTS_ALL = TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES;

// ===== In/out selector byte flags =====
static const unsigned char TXFS_INOUT_NUMBER = 1 << 7;
static const unsigned char TXFS_INOUT_SELECTION_NONE = 0x00;
static const unsigned char TXFS_INOUT_SELECTION_CURRENT = 0x40;
static const unsigned char TXFS_INOUT_SELECTION_ALL = 0x3f;
static const unsigned char TXFS_INOUT_SELECTION_MODE = 1 << 6;
static const unsigned char TXFS_INOUT_LEADING_SIZE = 1 << 5;
static const unsigned char TXFS_INOUT_INDIVIDUAL_MODE = 1 << 5;
static const unsigned char TXFS_INOUT_SELECTION_MASK = 0xff ^ (1 << 7) ^ (1 << 6) ^ (1 << 5);

// ===== Special TxFieldSelector values (BIP 346) =====
static const std::vector<unsigned char> TXFS_SPECIAL_TEMPLATE = {
    TXFS_VERSION | TXFS_LOCKTIME | TXFS_CURRENT_INPUT_IDX,
    TXFS_INPUTS_SEQUENCES | TXFS_INPUTS_SCRIPTSIGS | TXFS_OUTPUTS_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
};

static const unsigned int LEADING_CACHE_INTERVAL = 10;

struct TxHashCache
{
    Mutex mtx;

    // Individual hashes for variable-size input fields
    std::vector<uint256> hashed_script_sigs GUARDED_BY(mtx);
    std::vector<uint256> hashed_prevout_spks GUARDED_BY(mtx);
    std::vector<uint256> hashed_annexes GUARDED_BY(mtx);

    // Individual hashes for variable-size output fields
    std::vector<uint256> hashed_script_pubkeys GUARDED_BY(mtx);

    // Leading hash caches for input fields
    std::vector<CSHA256> leading_prevouts GUARDED_BY(mtx);
    std::vector<CSHA256> leading_sequences GUARDED_BY(mtx);
    std::vector<CSHA256> leading_script_sigs GUARDED_BY(mtx);
    std::vector<CSHA256> leading_prevout_spks GUARDED_BY(mtx);
    std::vector<CSHA256> leading_prevout_amounts GUARDED_BY(mtx);
    std::vector<CSHA256> leading_annexes GUARDED_BY(mtx);

    // Leading hash caches for output fields
    std::vector<CSHA256> leading_script_pubkeys GUARDED_BY(mtx);
    std::vector<CSHA256> leading_amounts GUARDED_BY(mtx);

    // All-items hash caches for input fields
    uint256 all_prevouts GUARDED_BY(mtx);
    uint256 all_sequences GUARDED_BY(mtx);
    uint256 all_script_sigs GUARDED_BY(mtx);
    uint256 all_prevout_spks GUARDED_BY(mtx);
    uint256 all_prevout_amounts GUARDED_BY(mtx);
    uint256 all_annexes GUARDED_BY(mtx);

    // All-items hash caches for output fields
    uint256 all_script_pubkeys GUARDED_BY(mtx);
    uint256 all_amounts GUARDED_BY(mtx);

    // Per-input caches
    std::vector<uint256> hashed_spentscripts GUARDED_BY(mtx);
    std::vector<uint256> hashed_control_blocks GUARDED_BY(mtx);

    TxHashCache() = default;
};

template <class T>
bool calculate_txhash(
    uint256& hash_out,
    std::span<const unsigned char> field_selector,
    TxHashCache& cache,
    const T& tx,
    const std::vector<CTxOut>& prevout_outputs,
    uint32_t codeseparator_pos,
    uint32_t in_pos
) EXCLUSIVE_LOCKS_REQUIRED(!cache.mtx);

#endif // BITCOIN_SCRIPT_TXHASH_H

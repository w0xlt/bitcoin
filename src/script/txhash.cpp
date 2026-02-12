// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/txhash.h>

#include <crypto/sha256.h>
#include <script/script.h>
#include <uint256.h>

#include <memory>
#include <type_traits>

static constexpr uint8_t TAPROOT_LEAF_MASK = 0xfe;
static constexpr size_t TAPROOT_CONTROL_BASE_SIZE = 33;
static constexpr size_t TAPROOT_CONTROL_NODE_SIZE = 32;

static const uint256 SHA256_EMPTY = (HashWriter{}).GetSHA256();

static int8_t read_i7(uint8_t input) {
    uint8_t masked = input & 0x7f;
    if ((masked & 0x40) == 0) {
        return static_cast<int8_t>(masked);
    } else {
        uint8_t neg = (~(masked - 1)) & 0x7f;
        return 0 - static_cast<int8_t>(neg);
    }
}

static int16_t read_i15(uint16_t input) {
    uint16_t masked = input & 0x7fff;
    if ((masked & 0x4000) == 0) {
        return static_cast<int16_t>(masked);
    } else {
        uint16_t neg = (~(masked - 1)) & 0x7fff;
        return 0 - static_cast<int16_t>(neg);
    }
}

static bool convert_short_txfs(uint8_t txfs, std::vector<unsigned char>& out) {
    unsigned char base = TXFS_VERSION | TXFS_LOCKTIME | TXFS_CONTROL | TXFS_CURRENT_INPUT_TAPROOT_ANNEX;
    unsigned char inout_fields = TXFS_OUTPUTS_ALL | TXFS_INPUTS_SEQUENCES | TXFS_INPUTS_SCRIPTSIGS;

    unsigned char input_selection;
    switch (txfs & 0x03) {
        case 0x00: input_selection = TXFS_INOUT_SELECTION_NONE; break;
        case 0x01: input_selection = TXFS_INOUT_SELECTION_CURRENT; break;
        case 0x03: input_selection = TXFS_INOUT_SELECTION_ALL; break;
        default: return false; // 0b10 is invalid
    }

    unsigned char output_selection;
    switch (txfs & 0x0c) {
        case 0x00: output_selection = TXFS_INOUT_SELECTION_NONE; break;
        case 0x04: output_selection = TXFS_INOUT_SELECTION_CURRENT; break;
        case 0x0c: output_selection = TXFS_INOUT_SELECTION_ALL; break;
        default: return false; // 0b10 is invalid
    }

    if (txfs & 0x10) {
        inout_fields |= TXFS_INPUTS_PREVOUTS;
    }
    if (txfs & 0x20) {
        inout_fields |= TXFS_INPUTS_PREV_SCRIPTPUBKEYS | TXFS_INPUTS_PREV_VALUES;
    }
    if (txfs & 0x40) {
        base |= TXFS_CURRENT_INPUT_CONTROL_BLOCK | TXFS_CURRENT_INPUT_SPENTSCRIPT
            | TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS;
    }
    if (txfs & 0x80) {
        base |= TXFS_CURRENT_INPUT_IDX;
    }

    out = {base, inout_fields, input_selection, output_selection};
    return true;
}

static bool parse_inout_selector(
    std::span<const unsigned char>& bytes,
    unsigned int nb_items,
    bool& out_count,
    std::vector<unsigned int>& out_selected,
    uint32_t in_pos
) {
    out_count = false;
    out_selected.clear();

    if (bytes.empty()) {
        return false;
    }
    unsigned char first = SpanPopFront(bytes);
    out_count = (first & TXFS_INOUT_NUMBER) != 0;

    unsigned char selection = first & (0xff ^ TXFS_INOUT_NUMBER);
    if (selection == TXFS_INOUT_SELECTION_NONE) {
        return true;
    } else if (selection == TXFS_INOUT_SELECTION_ALL) {
        out_selected.resize(nb_items);
        for (unsigned int i = 0; i < nb_items; i++) out_selected[i] = i;
        return true;
    } else if (selection == TXFS_INOUT_SELECTION_CURRENT) {
        if (in_pos >= nb_items) return false;
        out_selected = {in_pos};
        return true;
    } else if ((selection & TXFS_INOUT_SELECTION_MODE) == 0) {
        // leading mode
        unsigned int count;
        if ((selection & TXFS_INOUT_LEADING_SIZE) == 0) {
            count = selection & TXFS_INOUT_SELECTION_MASK;
        } else {
            if (bytes.empty()) return false;
            unsigned int next_byte = SpanPopFront(bytes);
            count = ((selection & TXFS_INOUT_SELECTION_MASK) << 8) + next_byte;
        }
        if (count == 0 || count > nb_items) return false;
        out_selected.resize(count);
        for (unsigned int i = 0; i < count; i++) out_selected[i] = i;
        return true;
    } else {
        // individual mode
        bool absolute = (selection & TXFS_INOUT_INDIVIDUAL_MODE) == 0;
        unsigned int count = selection & TXFS_INOUT_SELECTION_MASK;

        int cur = static_cast<int>(in_pos);
        for (unsigned int i = 0; i < count; i++) {
            if (bytes.empty()) return false;
            unsigned int first_byte = SpanPopFront(bytes);
            bool single_byte = (first_byte & (1 << 7)) == 0;

            unsigned int number = first_byte;
            if (!single_byte) {
                if (bytes.empty()) return false;
                unsigned int second_byte = SpanPopFront(bytes);
                number = ((first_byte & ~(1u << 7)) << 8) + second_byte;
            }

            unsigned int idx;
            if (absolute) {
                idx = number;
            } else {
                int rel;
                if (single_byte) {
                    rel = read_i7(static_cast<uint8_t>(number));
                } else {
                    rel = read_i15(static_cast<uint16_t>(number));
                }
                if (rel < 0 && (-rel) > cur) return false;
                idx = static_cast<unsigned int>(cur + rel);
            }

            if (idx >= nb_items) return false;
            if (!out_selected.empty() && idx <= out_selected.back()) return false;
            out_selected.push_back(idx);
        }
        return true;
    }
}

// Individual hash helpers — caller must hold cache.mtx

static uint256 sha256_bytes(const std::vector<unsigned char>& bytes) {
    uint256 out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(out.begin());
    return out;
}

static uint256 sha256_script(const CScript& script) {
    uint256 out;
    CSHA256().Write(script.data(), script.size()).Finalize(out.begin());
    return out;
}

static uint256 hash_prevouts_content(const std::vector<CTxOut>& prev_outputs)
{
    HashWriter ss{};
    for (const auto& prevout : prev_outputs) {
        ss << prevout;
    }
    return ss.GetSHA256();
}

static uint256 tx_content_fingerprint(const CMutableTransaction& tx)
{
    return (HashWriter{} << TX_WITH_WITNESS(tx)).GetSHA256();
}

static void clear_cached_hashes(TxHashCache& cache) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx)
{
    AssertLockHeld(cache.mtx);

    cache.context_initialized = false;
    cache.cached_tx_ref = nullptr;
    cache.cached_prevouts_ref = nullptr;
    cache.cached_num_inputs = 0;
    cache.cached_num_outputs = 0;
    cache.cached_tx_content_fingerprint.SetNull();
    cache.cached_prevouts_content_fingerprint.SetNull();

    cache.hashed_script_sigs.clear();
    cache.hashed_prevout_spks.clear();
    cache.hashed_annexes.clear();
    cache.hashed_script_pubkeys.clear();

    cache.leading_prevouts.clear();
    cache.leading_sequences.clear();
    cache.leading_script_sigs.clear();
    cache.leading_prevout_spks.clear();
    cache.leading_prevout_amounts.clear();
    cache.leading_annexes.clear();
    cache.leading_script_pubkeys.clear();
    cache.leading_amounts.clear();

    cache.all_prevouts.SetNull();
    cache.all_sequences.SetNull();
    cache.all_script_sigs.SetNull();
    cache.all_prevout_spks.SetNull();
    cache.all_prevout_amounts.SetNull();
    cache.all_annexes.SetNull();
    cache.all_script_pubkeys.SetNull();
    cache.all_amounts.SetNull();

    cache.hashed_spentscripts.clear();
    cache.hashed_control_blocks.clear();
}

template <class T>
static void ensure_cache_context_compatible(TxHashCache& cache, const T& tx, const std::vector<CTxOut>& prev_outputs) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx)
{
    AssertLockHeld(cache.mtx);

    const size_t num_inputs = tx.vin.size();
    const size_t num_outputs = tx.vout.size();
    const void* tx_ref = std::addressof(tx);
    const void* prevouts_ref = std::addressof(prev_outputs);

    bool content_matches = true;
    if constexpr (std::is_same_v<T, CMutableTransaction>) {
        const uint256 tx_fingerprint = tx_content_fingerprint(tx);
        const uint256 prevouts_fingerprint = hash_prevouts_content(prev_outputs);
        content_matches = cache.cached_tx_content_fingerprint == tx_fingerprint &&
            cache.cached_prevouts_content_fingerprint == prevouts_fingerprint;
        if (!content_matches) {
            clear_cached_hashes(cache);
            cache.context_initialized = true;
            cache.cached_tx_ref = tx_ref;
            cache.cached_prevouts_ref = prevouts_ref;
            cache.cached_num_inputs = num_inputs;
            cache.cached_num_outputs = num_outputs;
            cache.cached_tx_content_fingerprint = tx_fingerprint;
            cache.cached_prevouts_content_fingerprint = prevouts_fingerprint;
            return;
        }
    }

    if (cache.context_initialized &&
        cache.cached_tx_ref == tx_ref &&
        cache.cached_prevouts_ref == prevouts_ref &&
        cache.cached_num_inputs == num_inputs &&
        cache.cached_num_outputs == num_outputs &&
        content_matches) {
        return;
    }

    clear_cached_hashes(cache);
    cache.context_initialized = true;
    cache.cached_tx_ref = tx_ref;
    cache.cached_prevouts_ref = prevouts_ref;
    cache.cached_num_inputs = num_inputs;
    cache.cached_num_outputs = num_outputs;
    if constexpr (std::is_same_v<T, CMutableTransaction>) {
        cache.cached_tx_content_fingerprint = tx_content_fingerprint(tx);
        cache.cached_prevouts_content_fingerprint = hash_prevouts_content(prev_outputs);
    }
}

static uint256 script_sig_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, unsigned int idx) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx) {
    AssertLockHeld(cache.mtx);
    if (idx >= cache.hashed_script_sigs.size() || cache.hashed_script_sigs[idx].IsNull()) {
        cache.hashed_script_sigs.resize(inputs.size());
        cache.hashed_script_sigs[idx] = sha256_script(inputs[idx].scriptSig);
    }
    return cache.hashed_script_sigs[idx];
}

static uint256 prevout_spk_hash(TxHashCache& cache, const std::vector<CTxOut>& prev_outputs, unsigned int idx) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx) {
    AssertLockHeld(cache.mtx);
    if (idx >= cache.hashed_prevout_spks.size() || cache.hashed_prevout_spks[idx].IsNull()) {
        cache.hashed_prevout_spks.resize(prev_outputs.size());
        cache.hashed_prevout_spks[idx] = sha256_script(prev_outputs[idx].scriptPubKey);
    }
    return cache.hashed_prevout_spks[idx];
}

static uint256 annex_hash(TxHashCache& cache, const std::vector<CTxIn>& inputs, const std::vector<CTxOut>& prev_outputs, unsigned int idx) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx) {
    AssertLockHeld(cache.mtx);
    if (idx >= cache.hashed_annexes.size() || cache.hashed_annexes[idx].IsNull()) {
        cache.hashed_annexes.resize(inputs.size());

        uint256 h = SHA256_EMPTY;
        // Only check for annex on p2tr prevouts
        if (prev_outputs[idx].scriptPubKey.IsPayToTaproot()) {
            const auto& stack = inputs[idx].scriptWitness.stack;
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                h = sha256_bytes(stack.back());
            }
        }
        cache.hashed_annexes[idx] = h;
    }
    return cache.hashed_annexes[idx];
}

static uint256 script_pubkey_hash(TxHashCache& cache, const std::vector<CTxOut>& outputs, unsigned int idx) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx) {
    AssertLockHeld(cache.mtx);
    if (idx >= cache.hashed_script_pubkeys.size() || cache.hashed_script_pubkeys[idx].IsNull()) {
        cache.hashed_script_pubkeys.resize(outputs.size());
        cache.hashed_script_pubkeys[idx] = sha256_script(outputs[idx].scriptPubKey);
    }
    return cache.hashed_script_pubkeys[idx];
}

// Generic leading-hash helper with LEADING_CACHE_INTERVAL context caching.
// hash_item(ss, idx) must serialize item idx into HashWriter ss.
// Caller must hold cache.mtx for the context_cache vector passed in.
template <typename F>
static uint256 leading_hash(
    std::vector<CSHA256>& context_cache,
    size_t total_items,
    unsigned int nb,
    F hash_item
) {
    if (context_cache.empty()) {
        context_cache.reserve(total_items / LEADING_CACHE_INTERVAL);
    }
    unsigned int cached_count = context_cache.size();
    unsigned int cursor = cached_count * LEADING_CACHE_INTERVAL;
    if (cursor > nb) cursor = (nb / LEADING_CACHE_INTERVAL) * LEADING_CACHE_INTERVAL;

    HashWriter ss;
    if (cursor > 0 && cached_count > 0) {
        unsigned int cache_idx = (cursor / LEADING_CACHE_INTERVAL) - 1;
        if (cache_idx < cached_count) {
            ss = HashWriter(context_cache[cache_idx]);
        }
    }

    while (cursor < nb) {
        hash_item(ss, cursor);
        cursor++;
        if (cursor % LEADING_CACHE_INTERVAL == 0) {
            if (cursor / LEADING_CACHE_INTERVAL > context_cache.size()) {
                context_cache.push_back(ss.GetHashCtx());
            }
        }
    }
    return ss.GetSHA256();
}

// Hash selected items for each field — caller must hold cache.mtx for variants that use cache

static uint256 hash_selected_prevouts(const std::vector<CTxIn>& inputs, const std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int idx : indices) ss << inputs[idx].prevout;
    return ss.GetSHA256();
}

static uint256 hash_selected_sequences(const std::vector<CTxIn>& inputs, const std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int idx : indices) ss << inputs[idx].nSequence;
    return ss.GetSHA256();
}

static uint256 hash_selected_script_sigs(TxHashCache& cache, const std::vector<CTxIn>& inputs, const std::vector<unsigned int>& indices) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx) {
    AssertLockHeld(cache.mtx);
    HashWriter ss{};
    for (unsigned int idx : indices) ss << script_sig_hash(cache, inputs, idx);
    return ss.GetSHA256();
}

static uint256 hash_selected_prevout_spks(TxHashCache& cache, const std::vector<CTxOut>& prev_outputs, const std::vector<unsigned int>& indices) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx) {
    AssertLockHeld(cache.mtx);
    HashWriter ss{};
    for (unsigned int idx : indices) ss << prevout_spk_hash(cache, prev_outputs, idx);
    return ss.GetSHA256();
}

static uint256 hash_selected_prevout_amounts(const std::vector<CTxOut>& prev_outputs, const std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int idx : indices) ss << prev_outputs[idx].nValue;
    return ss.GetSHA256();
}

static uint256 hash_selected_annexes(TxHashCache& cache, const std::vector<CTxIn>& inputs, const std::vector<CTxOut>& prev_outputs, const std::vector<unsigned int>& indices) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx) {
    AssertLockHeld(cache.mtx);
    HashWriter ss{};
    for (unsigned int idx : indices) ss << annex_hash(cache, inputs, prev_outputs, idx);
    return ss.GetSHA256();
}

static uint256 hash_selected_script_pubkeys(TxHashCache& cache, const std::vector<CTxOut>& outputs, const std::vector<unsigned int>& indices) EXCLUSIVE_LOCKS_REQUIRED(cache.mtx) {
    AssertLockHeld(cache.mtx);
    HashWriter ss{};
    for (unsigned int idx : indices) ss << script_pubkey_hash(cache, outputs, idx);
    return ss.GetSHA256();
}

static uint256 hash_selected_amounts(const std::vector<CTxOut>& outputs, const std::vector<unsigned int>& indices) {
    HashWriter ss{};
    for (unsigned int idx : indices) ss << outputs[idx].nValue;
    return ss.GetSHA256();
}

// Check if a selection covers ALL items (used for caching)
static bool is_all_selection(const std::vector<unsigned int>& selected, unsigned int nb_items) {
    return selected.size() == nb_items;
}

// Check if selection is exactly a leading prefix
static bool is_leading_selection(const std::vector<unsigned int>& selected) {
    if (selected.empty()) return false;
    for (unsigned int i = 0; i < selected.size(); i++) {
        if (selected[i] != i) return false;
    }
    return true;
}

template <class T>
bool calculate_txhash(
    uint256& hash_out,
    std::span<const unsigned char> field_selector,
    TxHashCache& cache,
    const T& tx,
    const std::vector<CTxOut>& prev_outputs,
    uint32_t codeseparator_pos,
    uint32_t in_pos
) {
    if (tx.vin.size() != prev_outputs.size()) return false;
    if (in_pos >= tx.vin.size()) return false;

    {
        LOCK(cache.mtx);
        ensure_cache_context_compatible(cache, tx, prev_outputs);
    }

    // Handle special cases
    std::vector<unsigned char> resolved_txfs;
    if (field_selector.empty()) {
        resolved_txfs = TXFS_SPECIAL_TEMPLATE;
    } else if (field_selector.size() == 1) {
        if (!convert_short_txfs(field_selector[0], resolved_txfs)) return false;
    } else {
        resolved_txfs.assign(field_selector.begin(), field_selector.end());
    }

    std::span<const unsigned char> txfs_span{resolved_txfs};
    HashWriter ss{};

    unsigned char global = txfs_span[0];

    // 1. Control (include the TxFieldSelector itself in the hash)
    if ((global & TXFS_CONTROL) != 0) {
        ss.write(std::as_bytes(txfs_span));
    }

    // 2. Version
    if ((global & TXFS_VERSION) != 0) {
        ss << tx.version;
    }

    // 3. Locktime
    if ((global & TXFS_LOCKTIME) != 0) {
        ss << tx.nLockTime;
    }

    // 4. Current input index
    if ((global & TXFS_CURRENT_INPUT_IDX) != 0) {
        ss << in_pos;
    }

    // 5. Current input control block (BIP 346: bit 3)
    if ((global & TXFS_CURRENT_INPUT_CONTROL_BLOCK) != 0) {
        LOCK(cache.mtx);
        if (in_pos >= cache.hashed_control_blocks.size() || cache.hashed_control_blocks[in_pos].IsNull()) {
            cache.hashed_control_blocks.resize(tx.vin.size());

            uint256 cb_hash = SHA256_EMPTY;
            if (prev_outputs[in_pos].scriptPubKey.IsPayToTaproot()) {
                const auto& stack = tx.vin[in_pos].scriptWitness.stack;
                if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                    // Has annex: control block is second to last
                    if (stack.size() >= 3) {
                        cb_hash = sha256_bytes(stack[stack.size() - 2]);
                    }
                } else if (stack.size() >= 2) {
                    // No annex: control block is last element
                    cb_hash = sha256_bytes(stack.back());
                }
                // If stack.size() < 2, it's a keyspend => SHA256_EMPTY
            }
            cache.hashed_control_blocks[in_pos] = cb_hash;
        }
        ss << cache.hashed_control_blocks[in_pos];
    }

    // 6. Current input spent script (BIP 346: bit 4)
    // Hash = SHA256(leaf_version || script) for tapscript, SHA256_EMPTY for keyspend
    if ((global & TXFS_CURRENT_INPUT_SPENTSCRIPT) != 0) {
        LOCK(cache.mtx);
        if (in_pos >= cache.hashed_spentscripts.size() || cache.hashed_spentscripts[in_pos].IsNull()) {
            cache.hashed_spentscripts.resize(tx.vin.size());

            uint256 ss_hash = SHA256_EMPTY;
            if (prev_outputs[in_pos].scriptPubKey.IsPayToTaproot()) {
                const auto& stack = tx.vin[in_pos].scriptWitness.stack;
                // Determine script index: if annex present, script is at stack.size()-3,
                // control block at stack.size()-2. Without annex, script at stack.size()-2.
                bool has_annex = stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG;
                size_t control_idx = has_annex ? stack.size() - 2 : stack.size() - 1;

                // Script path: need at least script + control_block (+ optional annex)
                // Control block must be valid: >= 33 bytes and (size-33) % 32 == 0
                if (control_idx >= 1 && stack.size() >= 2) {
                    const auto& control_block = stack[control_idx];
                    if (control_block.size() >= TAPROOT_CONTROL_BASE_SIZE &&
                        ((control_block.size() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE) == 0) {
                        uint8_t leaf_version = control_block[0] & TAPROOT_LEAF_MASK;
                        const auto& script = stack[control_idx - 1];

                        // Hash leaf_version byte followed by the script (with compact size prefix)
                        CSHA256 eng;
                        eng.Write(&leaf_version, 1);
                        // Write compact size of script length
                        std::vector<unsigned char> len_bytes;
                        if (script.size() < 253) {
                            len_bytes.push_back(static_cast<unsigned char>(script.size()));
                        } else if (script.size() <= 0xffff) {
                            len_bytes.push_back(253);
                            len_bytes.push_back(script.size() & 0xff);
                            len_bytes.push_back((script.size() >> 8) & 0xff);
                        } else {
                            len_bytes.push_back(254);
                            len_bytes.push_back(script.size() & 0xff);
                            len_bytes.push_back((script.size() >> 8) & 0xff);
                            len_bytes.push_back((script.size() >> 16) & 0xff);
                            len_bytes.push_back((script.size() >> 24) & 0xff);
                        }
                        eng.Write(len_bytes.data(), len_bytes.size());
                        eng.Write(script.data(), script.size());
                        uint256 tmp;
                        eng.Finalize(tmp.begin());
                        ss_hash = tmp;
                    }
                }
            }
            cache.hashed_spentscripts[in_pos] = ss_hash;
        }
        ss << cache.hashed_spentscripts[in_pos];
    }

    // 7. Codeseparator position
    if ((global & TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS) != 0) {
        ss << codeseparator_pos;
    }

    // 8. Current input taproot annex (BIP 346: bit 6)
    if ((global & TXFS_CURRENT_INPUT_TAPROOT_ANNEX) != 0) {
        // Hash the annex (including 0x50 prefix) or SHA256_EMPTY if none
        const auto& stack = tx.vin[in_pos].scriptWitness.stack;
        if (prev_outputs[in_pos].scriptPubKey.IsPayToTaproot() &&
            stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
            ss << sha256_bytes(stack.back());
        } else {
            ss << SHA256_EMPTY;
        }
    }

    // Parse remaining bytes
    std::span<const unsigned char> bytes = txfs_span.subspan(1);

    unsigned char inout_fields = 0;
    if (!bytes.empty()) {
        inout_fields = SpanPopFront(bytes);
    }

    // === INPUTS ===
    std::vector<unsigned int> input_selected;
    bool commit_number_inputs = false;
    if (!bytes.empty()) {
        if (!parse_inout_selector(bytes, tx.vin.size(), commit_number_inputs, input_selected, in_pos)) {
            return false;
        }
    }

    if (commit_number_inputs) {
        uint32_t len32 = tx.vin.size();
        ss << len32;
    }

    if (!input_selected.empty()) {
        bool all = is_all_selection(input_selected, tx.vin.size());
        bool leading = !all && is_leading_selection(input_selected);
        unsigned int nb = input_selected.size();

        LOCK(cache.mtx);

        if ((inout_fields & TXFS_INPUTS_PREVOUTS) != 0) {
            auto hash_item = [&](HashWriter& h, unsigned int i) { h << tx.vin[i].prevout; };
            if (all) {
                if (cache.all_prevouts.IsNull()) cache.all_prevouts = leading_hash(cache.leading_prevouts, tx.vin.size(), tx.vin.size(), hash_item);
                ss << cache.all_prevouts;
            } else if (leading) {
                ss << leading_hash(cache.leading_prevouts, tx.vin.size(), nb, hash_item);
            } else {
                ss << hash_selected_prevouts(tx.vin, input_selected);
            }
        }

        if ((inout_fields & TXFS_INPUTS_SEQUENCES) != 0) {
            auto hash_item = [&](HashWriter& h, unsigned int i) { h << tx.vin[i].nSequence; };
            if (all) {
                if (cache.all_sequences.IsNull()) cache.all_sequences = leading_hash(cache.leading_sequences, tx.vin.size(), tx.vin.size(), hash_item);
                ss << cache.all_sequences;
            } else if (leading) {
                ss << leading_hash(cache.leading_sequences, tx.vin.size(), nb, hash_item);
            } else {
                ss << hash_selected_sequences(tx.vin, input_selected);
            }
        }

        if ((inout_fields & TXFS_INPUTS_SCRIPTSIGS) != 0) {
            auto hash_item = [&](HashWriter& h, unsigned int i) { h << script_sig_hash(cache, tx.vin, i); };
            if (all) {
                if (cache.all_script_sigs.IsNull()) cache.all_script_sigs = leading_hash(cache.leading_script_sigs, tx.vin.size(), tx.vin.size(), hash_item);
                ss << cache.all_script_sigs;
            } else if (leading) {
                ss << leading_hash(cache.leading_script_sigs, tx.vin.size(), nb, hash_item);
            } else {
                ss << hash_selected_script_sigs(cache, tx.vin, input_selected);
            }
        }

        if ((inout_fields & TXFS_INPUTS_PREV_SCRIPTPUBKEYS) != 0) {
            auto hash_item = [&](HashWriter& h, unsigned int i) { h << prevout_spk_hash(cache, prev_outputs, i); };
            if (all) {
                if (cache.all_prevout_spks.IsNull()) cache.all_prevout_spks = leading_hash(cache.leading_prevout_spks, prev_outputs.size(), prev_outputs.size(), hash_item);
                ss << cache.all_prevout_spks;
            } else if (leading) {
                ss << leading_hash(cache.leading_prevout_spks, prev_outputs.size(), nb, hash_item);
            } else {
                ss << hash_selected_prevout_spks(cache, prev_outputs, input_selected);
            }
        }

        if ((inout_fields & TXFS_INPUTS_PREV_VALUES) != 0) {
            auto hash_item = [&](HashWriter& h, unsigned int i) { h << prev_outputs[i].nValue; };
            if (all) {
                if (cache.all_prevout_amounts.IsNull()) cache.all_prevout_amounts = leading_hash(cache.leading_prevout_amounts, prev_outputs.size(), prev_outputs.size(), hash_item);
                ss << cache.all_prevout_amounts;
            } else if (leading) {
                ss << leading_hash(cache.leading_prevout_amounts, prev_outputs.size(), nb, hash_item);
            } else {
                ss << hash_selected_prevout_amounts(prev_outputs, input_selected);
            }
        }

        if ((inout_fields & TXFS_INPUTS_TAPROOT_ANNEXES) != 0) {
            auto hash_item = [&](HashWriter& h, unsigned int i) { h << annex_hash(cache, tx.vin, prev_outputs, i); };
            if (all) {
                if (cache.all_annexes.IsNull()) cache.all_annexes = leading_hash(cache.leading_annexes, tx.vin.size(), tx.vin.size(), hash_item);
                ss << cache.all_annexes;
            } else if (leading) {
                ss << leading_hash(cache.leading_annexes, tx.vin.size(), nb, hash_item);
            } else {
                ss << hash_selected_annexes(cache, tx.vin, prev_outputs, input_selected);
            }
        }
    }

    // === OUTPUTS ===
    std::vector<unsigned int> output_selected;
    bool commit_number_outputs = false;
    if (!bytes.empty()) {
        if (!parse_inout_selector(bytes, tx.vout.size(), commit_number_outputs, output_selected, in_pos)) {
            return false;
        }
    }

    if (commit_number_outputs) {
        uint32_t len32 = tx.vout.size();
        ss << len32;
    }

    if (!output_selected.empty()) {
        bool all = is_all_selection(output_selected, tx.vout.size());
        bool leading = !all && is_leading_selection(output_selected);
        unsigned int nb = output_selected.size();

        LOCK(cache.mtx);

        if ((inout_fields & TXFS_OUTPUTS_SCRIPTPUBKEYS) != 0) {
            auto hash_item = [&](HashWriter& h, unsigned int i) { h << script_pubkey_hash(cache, tx.vout, i); };
            if (all) {
                if (cache.all_script_pubkeys.IsNull()) cache.all_script_pubkeys = leading_hash(cache.leading_script_pubkeys, tx.vout.size(), tx.vout.size(), hash_item);
                ss << cache.all_script_pubkeys;
            } else if (leading) {
                ss << leading_hash(cache.leading_script_pubkeys, tx.vout.size(), nb, hash_item);
            } else {
                ss << hash_selected_script_pubkeys(cache, tx.vout, output_selected);
            }
        }

        if ((inout_fields & TXFS_OUTPUTS_VALUES) != 0) {
            auto hash_item = [&](HashWriter& h, unsigned int i) { h << tx.vout[i].nValue; };
            if (all) {
                if (cache.all_amounts.IsNull()) cache.all_amounts = leading_hash(cache.leading_amounts, tx.vout.size(), tx.vout.size(), hash_item);
                ss << cache.all_amounts;
            } else if (leading) {
                ss << leading_hash(cache.leading_amounts, tx.vout.size(), nb, hash_item);
            } else {
                ss << hash_selected_amounts(tx.vout, output_selected);
            }
        }
    }

    // Check no extra bytes remain
    if (!bytes.empty()) return false;

    hash_out = ss.GetSHA256();
    return true;
}

// Explicit template instantiations
template
bool calculate_txhash(
    uint256&,
    std::span<const unsigned char>,
    TxHashCache&,
    const CTransaction&,
    const std::vector<CTxOut>&,
    uint32_t,
    uint32_t
);

template
bool calculate_txhash(
    uint256&,
    std::span<const unsigned char>,
    TxHashCache&,
    const CMutableTransaction&,
    const std::vector<CTxOut>&,
    uint32_t,
    uint32_t
);

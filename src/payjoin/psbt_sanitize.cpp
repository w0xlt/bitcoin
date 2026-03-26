// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <payjoin/psbt_sanitize.h>

namespace payjoin {

void StripUnneededPSBTFields(PartiallySignedTransaction& psbt)
{
    psbt.m_xpubs.clear();
    psbt.unknown.clear();
    psbt.m_proprietary.clear();

    for (auto& input : psbt.inputs) {
        input.hd_keypaths.clear();
        input.m_tap_internal_key = XOnlyPubKey{};
        input.m_tap_bip32_paths.clear();
        input.m_tap_key_sig.clear();
        input.m_tap_script_sigs.clear();
        input.m_tap_merkle_root.SetNull();
        input.unknown.clear();
        input.m_proprietary.clear();
    }

    for (auto& output : psbt.outputs) {
        output.hd_keypaths.clear();
        output.m_tap_internal_key = XOnlyPubKey{};
        output.m_tap_bip32_paths.clear();
        output.unknown.clear();
        output.m_proprietary.clear();
    }
}

} // namespace payjoin

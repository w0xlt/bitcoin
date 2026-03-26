// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PAYJOIN_PSBT_SANITIZE_H
#define BITCOIN_PAYJOIN_PSBT_SANITIZE_H

#include <psbt.h>

namespace payjoin {

void StripUnneededPSBTFields(PartiallySignedTransaction& psbt);

} // namespace payjoin

#endif // BITCOIN_PAYJOIN_PSBT_SANITIZE_H

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PAYJOIN_H
#define BITCOIN_WALLET_PAYJOIN_H

#include <payjoin/session.h>

#include <memory>

namespace wallet {
struct WalletContext;
class CWallet;

/** Advance a payjoin session one protocol step.
 *  Returns true if session state changed.
 *  Throws std::runtime_error on missing proxy. */
bool AdvancePayjoinSession(CWallet& wallet,
                           std::shared_ptr<payjoin::PayjoinSession> session);

/** Background callback: advance all active sessions across all wallets.
 *  Registered on CScheduler, called every 30 seconds. */
void MaybeAdvancePayjoinSessions(WalletContext& context);
} // namespace wallet

#endif // BITCOIN_WALLET_PAYJOIN_H

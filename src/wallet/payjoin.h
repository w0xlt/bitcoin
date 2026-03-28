// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PAYJOIN_H
#define BITCOIN_WALLET_PAYJOIN_H

#include <consensus/amount.h>
#include <netbase.h>
#include <payjoin/session.h>
#include <wallet/transaction.h>

#include <memory>
#include <optional>
#include <string_view>

namespace wallet {
struct WalletContext;
class CWallet;

enum class PayjoinTxRole {
    Sender,
    Receiver,
};

struct PayjoinTxMetadata {
    PayjoinTxRole role;
    CAmount amount;
};

/**
 * Copy a SOCKS proxy configuration for payjoin transport and force stream
 * isolation on the copy. This keeps payjoin requests on distinct Tor proxy
 * identities even if the user disabled credential randomization for other
 * wallet or P2P traffic.
 */
Proxy HardenPayjoinTransportProxy(Proxy proxy);

/** Return the SOCKS proxy used for payjoin transport with stream isolation enabled. */
Proxy GetPayjoinTransportProxy();

/** Advance a payjoin session one protocol step.
 *  Returns true if session state changed.
 *  Throws std::runtime_error on missing proxy. */
bool AdvancePayjoinSession(CWallet& wallet,
                           std::shared_ptr<payjoin::PayjoinSession> session);

/** Background callback: advance all active sessions across all wallets.
 *  Registered on CScheduler, called every 30 seconds. */
void MaybeAdvancePayjoinSessions(WalletContext& context);

std::optional<PayjoinTxMetadata> GetPayjoinTxMetadata(const mapValue_t& map_value);
std::optional<PayjoinTxMetadata> GetPayjoinTxMetadata(const CWalletTx& wtx);
void SetPayjoinTxMetadata(mapValue_t& map_value, PayjoinTxRole role, CAmount amount);
bool IsPayjoinTxMetadataKey(std::string_view key);
} // namespace wallet

#endif // BITCOIN_WALLET_PAYJOIN_H

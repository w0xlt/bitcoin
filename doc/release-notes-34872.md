Wallet
------

- Transactions that spend a mix of wallet-owned and non-wallet inputs are now
  reported correctly by the `gettransaction`, `listtransactions`, and
  `listsinceblock` RPCs. Previously such transactions reported a misleading fee
  and attributed non-wallet outputs as wallet sends (see issue #14136).

  When every non-wallet input has a known zero value (for example a
  pay-to-anchor output), the wallet can still attribute the full fee and all
  sent outputs, so these transactions continue to be reported with the usual
  `send`/`receive` entries. Otherwise the transaction is now reported with a new
  `mixed` category entry carrying the negative total of wallet-owned inputs
  spent, because the wallet cannot attribute foreign outputs or the fee share
  without additional input metadata. Wallet-owned outputs are still reported as
  `receive` entries alongside the `mixed` entry, so deposit detection based on
  the `receive` category keeps working, and the amounts of a transaction's
  entries sum to the wallet's net change.

  Affected entries additionally expose the new `involves_mixed_inputs`,
  `wallet_debit`, and `wallet_credit` fields. Note that the `vout` field is no
  longer present on `mixed` summary entries, and the `fee` field is omitted
  when the wallet cannot determine the fee. (#34872)

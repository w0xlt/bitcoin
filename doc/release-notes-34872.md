Wallet
------

- The `gettransaction`, `listtransactions`, and `listsinceblock` RPCs now report
  transactions that spend a mix of wallet-owned and non-wallet inputs using
  wallet-specific debit and credit accounting. Previously such transactions
  reported a misleading fee and considered all non-wallet outputs to be wallet
  sends (see issue #14136).

  When the wallet has the parent transaction for every non-wallet input and each
  spent output has zero value (for example a pay-to-anchor output), the wallet
  supplied the transaction's entire input value. These transactions therefore
  continue to be reported with the usual per-output `send`/`receive` entries and
  the full fee.
  A transaction input does not contain the spent output's value, so the wallet
  cannot retrieve it when the parent transaction is absent. If a parent is
  absent or any non-wallet input has nonzero value, the non-wallet inputs may
  pay for some outputs or fees. The wallet cannot tell which non-wallet outputs
  are payments made by this wallet or how much of the fee it paid. It reports
  one mixed-input `send` summary whose amount is the total value of wallet-owned
  inputs with its sign reversed. It does not report specific recipients or a
  fee. Wallet-owned outputs are still reported as `receive` entries alongside
  that send summary, so deposit detection based on the `receive` category keeps
  working. The amounts of a transaction's entries sum to the wallet's net
  change.

  Affected entries additionally expose the new `involves_mixed_inputs`,
  `wallet_debit`, and `wallet_credit` fields, which let consumers detect the
  conservative case without depending on the `category` value. The `vout` field
  is now optional in the result schema: it is omitted from mixed-input
  send summaries, which do not correspond to a single output. The `fee` field is
  likewise omitted when the wallet cannot determine its share of the fee.
  (#34872)

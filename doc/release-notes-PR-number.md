P2P and network changes
-----------------------

- A new `setpeerhighbandwidth` RPC can enable or disable BIP152
  high-bandwidth compact block announcements from a currently connected peer.
  The RPC selection applies only to the current connection and is not persisted.

- Persistent manual peers configured with `-addnode` can now be selected for
  BIP152 high-bandwidth compact block announcements by appending the
  `=bip152-hb` tag, for example:

  ```ini
  addnode=203.0.113.10:8333=bip152-hb
  ```

  This configuration records operator intent rather than negotiated connection
  state. The request is reapplied after each reconnect once the peer negotiates
  version 2 compact block support. Tagged entries are incompatible with
  `-blocksonly`.

- `getpeerinfo` now reports the live manual selection source in
  `bip152_hb_to_manual`, while the existing `bip152_hb_to` field continues to
  report the effective state. `getaddednodeinfo` reports configured intent in
  `bip152_hb_to_configured`.

- Manual selections are independent of the existing automatic selector and do
  not consume its three slots. Consequently, operators can configure more than
  three effective high-bandwidth peers, exceeding BIP152's recommended limit
  and potentially increasing bandwidth usage.

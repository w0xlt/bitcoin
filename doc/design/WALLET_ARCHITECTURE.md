# Bitcoin Core Wallet Architecture Guide

> A didactic guide for new developers to understand the classes, attributes,
> and relationships in `src/wallet/wallet.{h,cpp}` and surrounding files.

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [Class-by-Class Deep Dive](#2-class-by-class-deep-dive)
3. [UML Class Diagram](#3-uml-class-diagram)
4. [Transaction Lifecycle Diagram](#4-transaction-lifecycle-diagram)
5. [How Key Management Works (ScriptPubKeyMan)](#5-how-key-management-works-scriptpubkeyman)
6. [The Transaction State Machine](#6-the-transaction-state-machine)
7. [Thread Safety & Locking Model](#7-thread-safety--locking-model)
8. [Signal / Observer System](#8-signal--observer-system)
9. [Data Flow: From RPC to Disk](#9-data-flow-from-rpc-to-disk)
10. [Improvement Proposals](#10-improvement-proposals)

---

## 1. The Big Picture

Think of `CWallet` as the **central hub** of Bitcoin Core's wallet subsystem.
It connects three major concerns:

```
┌──────────────────────────────────────────────────────────────┐
│                        The Node                              │
│  (blockchain, mempool, P2P network)                          │
└─────────────────────┬────────────────────────────────────────┘
                      │  interfaces::Chain  (abstract boundary)
                      │  + Chain::Notifications (events)
                      ▼
┌──────────────────────────────────────────────────────────────┐
│                       CWallet                                │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Transactions  │  │ Address Book │  │ Key Management    │  │
│  │ (mapWallet)   │  │(m_address_   │  │ (ScriptPubKey-    │  │
│  │               │  │  book)       │  │  Mans)            │  │
│  └──────────────┘  └──────────────┘  └───────────────────┘  │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Coin Locking │  │  Fee Config  │  │ Encryption        │  │
│  │(m_locked_    │  │ (m_pay_tx_   │  │ (CMasterKey,      │  │
│  │  coins)      │  │  fee, etc.)  │  │  vMasterKey)      │  │
│  └──────────────┘  └──────────────┘  └───────────────────┘  │
└─────────────────────┬────────────────────────────────────────┘
                      │  WalletDatabase (abstract boundary)
                      ▼
┌──────────────────────────────────────────────────────────────┐
│                  SQLite / BDB Storage                         │
└──────────────────────────────────────────────────────────────┘
```

**Key idea**: `CWallet` doesn't talk to the blockchain directly. It goes
through `interfaces::Chain`, an abstraction layer. This allows the wallet
to be compiled and tested independently from the node.

---

## 2. Class-by-Class Deep Dive

### 2.1 `WalletContext` — The Global Container

**File**: `context.h`

```
WalletContext is NOT a wallet. It's the "world" that wallets live in.
```

| Field               | Type                              | Purpose |
|---------------------|-----------------------------------|---------|
| `chain`             | `interfaces::Chain*`              | Access to blockchain state (blocks, mempool, fees) |
| `scheduler`         | `CScheduler*`                     | Periodic task runner (e.g., rebroadcast timer) |
| `args`              | `ArgsManager*`                    | Command-line / config file arguments |
| `wallets`           | `vector<shared_ptr<CWallet>>`     | All currently loaded wallets |
| `wallet_load_fns`   | `list<LoadWalletFn>`              | Callbacks invoked when a new wallet loads |
| `wallets_mutex`     | `Mutex`                           | Protects the wallets vector |

**Analogy**: If `CWallet` is a person, `WalletContext` is the city they
live in — it provides shared infrastructure (chain, scheduler, args)
that all wallets need.

**Important rule**: You must NEVER lock `wallets_mutex` while already holding
`CWallet::cs_wallet`, or you risk deadlocks.

---

### 2.2 `CWallet` — The Heart of the Wallet

**File**: `wallet.h` (line 311)

`CWallet` inherits from two base classes:

```
                    ┌───────────────┐     ┌─────────────────────────┐
                    │ WalletStorage │     │ Chain::Notifications    │
                    │ (interface)   │     │ (interface)             │
                    └───────┬───────┘     └────────────┬────────────┘
                            │                          │
                            └─────────┬────────────────┘
                                      │
                               ┌──────▼──────┐
                               │   CWallet   │
                               └─────────────┘
```

- **`WalletStorage`**: Allows `ScriptPubKeyMan` objects to call back into the
  wallet for encryption keys, database access, and wallet flags — without
  creating a circular dependency on `CWallet`.

- **`Chain::Notifications`**: Makes `CWallet` an *observer* of blockchain
  events. The node calls methods like `blockConnected()` and
  `transactionAddedToMempool()` on the wallet.

#### Core Data Structures Inside CWallet

| Field | Type | What It Stores |
|-------|------|---------------|
| `mapWallet` | `unordered_map<Txid, CWalletTx>` | Every transaction the wallet cares about (sent or received) |
| `wtxOrdered` | `multimap<int64_t, CWalletTx*>` | Same transactions, but ordered by time (for listing) |
| `m_address_book` | `map<CTxDestination, CAddressBookData>` | Labels, purposes, and metadata for known addresses |
| `m_locked_coins` | `map<COutPoint, bool>` | Coins we won't spend (e.g., already used in an unconfirmed tx). `bool` = persisted to disk? |
| `m_txos` | `unordered_map<COutPoint, WalletTXO>` | Cache of all transaction outputs owned by this wallet |
| `mapTxSpends` | `unordered_multimap<COutPoint, Txid>` | Reverse index: "which transactions spend this outpoint?" — used for conflict detection |
| `m_spk_managers` | `map<uint256, unique_ptr<ScriptPubKeyMan>>` | All key/script managers, indexed by their unique ID |
| `m_external_spk_managers` | `map<OutputType, ScriptPubKeyMan*>` | Active managers for receiving addresses (one per output type) |
| `m_internal_spk_managers` | `map<OutputType, ScriptPubKeyMan*>` | Active managers for change addresses |
| `m_cached_spks` | `unordered_map<CScript, vector<ScriptPubKeyMan*>>` | Fast lookup: "which SPKMs own this script?" |
| `mapMasterKeys` | `map<unsigned int, CMasterKey>` | Encryption master keys (usually just one) |
| `vMasterKey` | `CKeyingMaterial` | The *decrypted* master key (only in memory while wallet is unlocked) |

#### Fee Configuration Fields

These are public fields set from command-line arguments at startup:

| Field | Default | Purpose |
|-------|---------|---------|
| `m_pay_tx_fee` | 0 | User-specified fee rate (overrides estimation) |
| `m_fallback_fee` | 0 | Used when fee estimation has insufficient data |
| `m_min_fee` | 1000 sat/kvB | Floor for fee rate |
| `m_discard_rate` | 10000 sat/kvB | If change costs more than this to spend, drop it |
| `m_consolidate_feerate` | 10 sat/vB | Below this rate, consolidate inputs; above, minimize fees |
| `m_default_max_tx_fee` | 0.1 BTC | Safety cap — refuse to create transactions with higher fees |
| `m_confirm_target` | 6 blocks | Target confirmation depth for fee estimation |
| `m_signal_rbf` | true | Whether to signal Replace-By-Fee on new transactions |

#### Chain Sync Tracking

| Field | Purpose |
|-------|---------|
| `m_last_block_processed` | Hash of the last block the wallet has seen |
| `m_last_block_processed_height` | Height of the last block the wallet has seen |
| `m_birth_time` | Timestamp of the wallet's oldest key — blocks before this are skipped during rescan |
| `m_best_block_time` | When the tip block was received (used to schedule rebroadcasts) |

---

### 2.3 `CWalletTx` — A Transaction the Wallet Cares About

**File**: `transaction.h` (line 194)

Every transaction in `mapWallet` is wrapped in `CWalletTx`, which adds
wallet-specific metadata on top of the raw `CTransaction`:

```
┌───────────────────────────────────────────────────────────────┐
│                        CWalletTx                              │
│                                                               │
│  ┌─────────────────────┐                                      │
│  │  tx (CTransactionRef)│ ◄── The actual Bitcoin transaction  │
│  └─────────────────────┘                                      │
│                                                               │
│  ┌─────────────────────┐                                      │
│  │  m_state (TxState)  │ ◄── Where is this tx? (variant type) │
│  │   • Confirmed       │     See state machine below          │
│  │   • InMempool       │                                      │
│  │   • BlockConflicted │                                      │
│  │   • Inactive        │                                      │
│  │   • Unrecognized    │                                      │
│  └─────────────────────┘                                      │
│                                                               │
│  mapValue ─── Key/value metadata persisted to DB              │
│    "comment"           : user comment                         │
│    "to"                : recipient description                │
│    "replaces_txid"     : tx replaced by fee bump              │
│    "replaced_by_txid"  : new tx from fee bump                 │
│                                                               │
│  nTimeReceived ─── When this node first saw the tx            │
│  nTimeSmart    ─── Stable timestamp for ordering              │
│  nOrderPos     ─── Position in wallet's ordered tx list       │
│                                                               │
│  m_amounts[DEBIT]  ─┐                                         │
│  m_amounts[CREDIT] ─┤ Cached balance calculations             │
│  nChangeCached     ─┘ (invalidated by MarkDirty())            │
│                                                               │
│  mempool_conflicts ── Set of txids that conflict in mempool   │
│  truc_child_in_mempool ── v3/TRUC child tx tracking           │
└───────────────────────────────────────────────────────────────┘
```

**Why are balances cached?** Computing "how much did I send/receive" requires
looking up inputs and checking `IsMine()` for each output. This is expensive,
so results are cached in `m_amounts[]` and invalidated via `MarkDirty()`.

**Copy protection**: `CWalletTx` has a *private* copy constructor. You cannot
accidentally copy a wallet transaction. If you need a copy, you must explicitly
call `CopyFrom()`. This prevents bugs where modifications go to the wrong copy.

---

### 2.4 `WalletTXO` — A Single Output Owned by the Wallet

**File**: `transaction.h` (line 389)

```cpp
class WalletTXO {
    const CWalletTx& m_wtx;    // Parent transaction
    const CTxOut& m_output;     // The specific output
};
```

This is a lightweight view/reference type — it doesn't own data, it just
pairs a wallet transaction with one of its outputs. Used in coin selection.

---

### 2.5 `CAddressBookData` — Address Label & Metadata

**File**: `wallet.h` (line 240)

| Field | Type | Purpose |
|-------|------|---------|
| `label` | `optional<string>` | Human-readable label. `nullopt` = change address |
| `purpose` | `optional<AddressPurpose>` | RECEIVE, SEND, or REFUND (mostly legacy from BIP70) |
| `previously_spent` | `bool` | For `avoid_reuse` feature: has this address been spent from? |
| `receive_requests` | `map<string, string>` | BIP21 payment request data |

**Key insight**: The `label` field does double duty. Its *presence or absence*
distinguishes change addresses from regular addresses. `IsChange()` simply
returns `!label.has_value()`.

---

### 2.6 `CRecipient` — Where to Send Money

**File**: `wallet.h` (line 300)

```cpp
struct CRecipient {
    CTxDestination dest;         // The destination address
    CAmount nAmount;             // How much to send
    bool fSubtractFeeFromAmount; // Should the fee come out of this output?
};
```

This is a pure data struct used as input to `CreateTransaction()`.

---

### 2.7 `ReserveDestination` — RAII Address Reservation

**File**: `wallet.h` (line 199)

```
                    Reserve               Keep
  [ Keypool ] ──────────────► [ Reserved ] ────────► [ Used ]
                                    │
                                    │ ReturnDestination() or destructor
                                    ▼
                              [ Keypool ] (returned)
```

When you need a new address (e.g., for change), you don't just grab one.
You *reserve* it, use it, and then either:
- **Keep it** (`KeepDestination()`) — the address is consumed permanently
- **Return it** (`ReturnDestination()`) — it goes back to the keypool

The destructor automatically returns unreserved addresses, so if
`CreateTransaction` fails, the change address goes back to the pool.

---

### 2.8 `WalletRescanReserver` — RAII Rescan Lock

**File**: `wallet.h` (line 1087)

Ensures only one blockchain rescan runs at a time. Uses an atomic
`fScanningWallet` flag (not a mutex) so that other threads can check
"is a scan running?" without blocking.

```
    WalletRescanReserver reserver(wallet);
    if (!reserver.reserve()) {
        // Another scan is already in progress
        return;
    }
    // ... scan happens ...
    // ~WalletRescanReserver() automatically releases
```

---

### 2.9 `WalletDescriptor` — A Descriptor + Wallet Metadata

**File**: `walletutil.h` (line 63)

```
┌──────────────────────────────────────┐
│          WalletDescriptor            │
│                                      │
│  descriptor ──► shared_ptr<Descriptor>│  The actual output descriptor
│  id         ──► uint256              │  Unique ID (hash of descriptor)
│  creation_time ──► uint64_t          │  When it was created
│  range_start ──► int32_t             │  First index [inclusive]
│  range_end   ──► int32_t             │  Last index [exclusive]
│  next_index  ──► int32_t             │  Next index to generate
│  cache       ──► DescriptorCache     │  Pre-computed derived keys
└──────────────────────────────────────┘
```

Range-based descriptors (like `wpkh(xpub.../0/*)`) generate addresses by
incrementing `next_index`. The `range_start..range_end` window defines the
"look-ahead" — addresses pre-generated to detect incoming payments.

---

### 2.10 `CMasterKey` — Wallet Encryption Key

**File**: `crypter.h` (line 34)

```
User Passphrase
       │
       ▼ PBKDF2 (EVP_sha512, nDeriveIterations rounds, vchSalt)
       │
       ▼
  Derived Key + IV
       │
       ▼ AES-256-CBC decrypt
       │
       ▼
  vMasterKey (the actual encryption key, held in memory only while unlocked)
       │
       ▼ AES-256-CBC encrypt (with double-SHA256 of pubkey as IV)
       │
       ▼
  Encrypted Private Keys (stored on disk)
```

`CMasterKey` stores the *encrypted* form of the master key plus the
parameters needed to re-derive the decryption key from the passphrase.

---

### 2.11 `MigrationResult` / `MigrationData` — Legacy → Descriptor Migration

**File**: `wallet.h` (line 1135), `scriptpubkeyman.h` (line 411)

When migrating from the old legacy key model to descriptors:

```
┌─────────────────┐     MigrateLegacyToDescriptor()     ┌──────────────────┐
│  Legacy Wallet  │ ──────────────────────────────────► │ Descriptor Wallet │
│  (BDB, mixed    │                                     │ (SQLite, clean    │
│   key types)    │                                     │  descriptor sets) │
└─────────────────┘                                     └──────────────────┘
                                                               │
                                                               ├── watchonly_wallet (optional)
                                                               └── solvables_wallet (optional)
```

`MigrationData` holds the intermediate state: new descriptor SPKMs,
plus any watch-only or solvable scripts that need their own wallets.

---

## 3. UML Class Diagram

```
┌─────────────────────┐          ┌──────────────────────────┐
│   WalletContext      │          │  interfaces::Chain       │
│─────────────────────│          │──────────────────────────│
│ chain*              │          │ (abstract)               │
│ scheduler*          │          │ findBlock()              │
│ args*               │  ◄─uses──│ isInMempool()            │
│ wallets[]           │          │ broadcastTransaction()   │
│ wallet_load_fns[]   │          │ estimateSmartFee()       │
└────────┬────────────┘          └────────────┬─────────────┘
         │ owns 0..*                          │
         ▼                                    │ implements
┌══════════════════════════════════════════════▼═══════════════════┐
║                          CWallet                                ║
║═════════════════════════════════════════════════════════════════ ║
║                                                                 ║
║  «implements» WalletStorage                                     ║
║  «implements» Chain::Notifications                              ║
║                                                                 ║
║  ── Core Data ──────────────────────────────────────────────    ║
║  - m_chain*          : interfaces::Chain                        ║
║  - m_name            : string                                   ║
║  - m_database        : unique_ptr<WalletDatabase>               ║
║  - m_wallet_flags    : atomic<uint64_t>                         ║
║  - cs_wallet         : RecursiveMutex          (main lock)      ║
║                                                                 ║
║  ── Transaction Storage ────────────────────────────────────    ║
║  - mapWallet         : unordered_map<Txid, CWalletTx>          ║
║  - wtxOrdered        : multimap<int64_t, CWalletTx*>           ║
║  - mapTxSpends       : unordered_multimap<COutPoint, Txid>     ║
║  - m_txos            : unordered_map<COutPoint, WalletTXO>     ║
║                                                                 ║
║  ── Address Book ───────────────────────────────────────────    ║
║  - m_address_book    : map<CTxDestination, CAddressBookData>    ║
║                                                                 ║
║  ── Key Management ─────────────────────────────────────────    ║
║  - m_spk_managers    : map<uint256, unique_ptr<ScriptPubKeyMan>>║
║  - m_external_spk_managers : map<OutputType, ScriptPubKeyMan*>  ║
║  - m_internal_spk_managers : map<OutputType, ScriptPubKeyMan*>  ║
║  - m_cached_spks     : unordered_map<CScript, vector<SPKM*>>   ║
║                                                                 ║
║  ── Encryption ─────────────────────────────────────────────    ║
║  - vMasterKey        : CKeyingMaterial                          ║
║  - mapMasterKeys     : map<uint, CMasterKey>                    ║
║                                                                 ║
║  ── Chain Sync ─────────────────────────────────────────────    ║
║  - m_last_block_processed        : uint256                      ║
║  - m_last_block_processed_height : int                          ║
║  - m_birth_time      : atomic<int64_t>                          ║
║                                                                 ║
║  ── Signals (boost::signals2) ──────────────────────────────    ║
║  + NotifyUnload                                                 ║
║  + NotifyAddressBookChanged                                     ║
║  + NotifyTransactionChanged                                     ║
║  + ShowProgress                                                 ║
║  + NotifyCanGetAddressesChanged                                 ║
║  + NotifyStatusChanged                                          ║
║                                                                 ║
║  ── Key Methods ────────────────────────────────────────────    ║
║  + AddToWallet()             + CommitTransaction()              ║
║  + ScanForWalletTransactions()  + SignTransaction()             ║
║  + IsMine()                  + GetDebit() / GetCredit()         ║
║  + blockConnected()          + transactionAddedToMempool()      ║
║  + ResubmitWalletTransactions()                                 ║
╚═════════════════════════════════════════════════════════════════╝
         │                    │                     │
         │ owns 0..*         │ owns 0..*           │ owns 1
         ▼                   ▼                     ▼
┌─────────────────┐  ┌───────────────┐  ┌──────────────────────┐
│   CWalletTx     │  │CAddressBook-  │  │   WalletDatabase     │
│─────────────────│  │ Data          │  │──────────────────────│
│ tx              │  │───────────────│  │ (abstract)           │
│ m_state         │  │ label         │  │ MakeBatch()          │
│ mapValue        │  │ purpose       │  │ Rewrite()            │
│ nTimeReceived   │  │ previously_   │  │ Backup()             │
│ nTimeSmart      │  │  spent        │  │ Close()              │
│ nOrderPos       │  │ receive_      │  └──────────────────────┘
│ m_amounts[]     │  │  requests     │
│ mempool_conflicts│  └───────────────┘
│ truc_child_in_  │
│  mempool        │
└─────────────────┘
         │
         │ contains 1
         ▼
┌──────────────────┐
│ CTransactionRef  │
│──────────────────│
│ (shared_ptr to   │
│  CTransaction)   │
└──────────────────┘


┌───────────────────┐
│  WalletStorage    │ ◄──── Abstract interface (defined in scriptpubkeyman.h)
│  (interface)      │
│───────────────────│
│ GetDatabase()     │
│ IsWalletFlagSet() │
│ WithEncryptionKey()│
│ HasEncryptionKeys()│
│ IsLocked()        │
│ TopUpCallback()   │
└────────┬──────────┘
         │ implemented by CWallet
         │
         │ referenced by ▼
┌══════════════════════════════════════════════════════┐
║              ScriptPubKeyMan (abstract)              ║
║══════════════════════════════════════════════════════║
║ # m_storage : WalletStorage&                        ║
║ + GetNewDestination()     + IsMine()                ║
║ + Encrypt()               + TopUp()                 ║
║ + SignTransaction()       + FillPSBT()              ║
║ + GetID()                 + GetScriptPubKeys()      ║
╚══════════════════════════════════════════════════════╝
              ▲                         ▲
              │                         │
  ┌───────────┴──────────┐   ┌─────────┴──────────────────┐
  │   LegacyDataSPKM     │   │ DescriptorScriptPubKeyMan  │
  │ (legacy wallets,     │   │ (modern descriptor wallets) │
  │  migration only)     │   │                             │
  │──────────────────────│   │─────────────────────────────│
  │ mapCryptedKeys       │   │ m_wallet_descriptor         │
  │ setWatchOnly         │   │ m_map_script_pub_keys       │
  │ m_hd_chain           │   │ m_map_keys                  │
  │ mapKeyMetadata       │   │ m_map_crypted_keys          │
  └──────────────────────┘   │ m_map_signing_providers     │
                             │ m_musig2_secnonces          │
                             └─────────────────────────────┘
```

---

## 4. Transaction Lifecycle Diagram

This shows what happens when you send bitcoin, from the user's perspective:

```
  User calls "sendtoaddress" RPC
              │
              ▼
  ┌───────────────────────┐
  │  CreateTransaction()  │  ← coin selection, fee calculation,
  │  (in spend.cpp)       │    change address generation
  └───────────┬───────────┘
              │ Returns CTransactionRef
              ▼
  ┌───────────────────────┐
  │  CommitTransaction()  │  ← Adds CWalletTx to mapWallet,
  │  (wallet.cpp)         │    persists to DB
  └───────────┬───────────┘
              │
              ▼
  ┌─────────────────────────────┐
  │  SubmitTxMemoryPoolAndRelay │  ← Submits to local mempool
  │  (wallet.cpp)               │    and broadcasts to peers
  └───────────┬─────────────────┘
              │
              ▼
  ┌───────────────────────┐
  │  BroadcastTransaction │  ← Central entry point in
  │  (node/transaction.cpp)│    node/transaction.cpp
  └───────────┬───────────┘
              │
              │  ... time passes, tx gets mined ...
              ▼
  ┌───────────────────────┐
  │  blockConnected()     │  ← Chain::Notifications callback
  │  (wallet.cpp)         │    updates CWalletTx state to
  │                       │    TxStateConfirmed
  └───────────────────────┘
```

### Incoming Transaction Flow

```
  New block arrives from P2P network
              │
              ▼
  ┌───────────────────────────┐
  │  blockConnected()         │  ← Called by the node for each block
  └───────────┬───────────────┘
              │ For each tx in block:
              ▼
  ┌───────────────────────────┐
  │  AddToWalletIfInvolvingMe │  ← Checks IsMine() for all outputs
  └───────────┬───────────────┘
              │ If relevant:
              ▼
  ┌───────────────────────────┐
  │  AddToWallet()            │  ← Creates/updates CWalletTx,
  │                           │    writes to DB, fires signals
  └───────────────────────────┘
```

---

## 5. How Key Management Works (ScriptPubKeyMan)

The wallet delegates *all* key and script operations to `ScriptPubKeyMan`
objects. This is the **Strategy Pattern** — `CWallet` doesn't know *how*
keys are generated, it just asks the right SPKM.

```
                         CWallet
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    m_external_spk_    m_internal_spk_   m_spk_managers
    managers           managers          (all SPKMs)
           │               │
           ▼               ▼
    ┌──────────┐    ┌──────────┐
    │ BECH32   │    │ BECH32   │    These are pointers into
    │ (recv)   │    │ (change) │    m_spk_managers
    ├──────────┤    ├──────────┤
    │ BECH32M  │    │ BECH32M  │
    │ (recv)   │    │ (change) │
    └──────────┘    └──────────┘

    Each points to a DescriptorScriptPubKeyMan that wraps
    a descriptor like:
      wpkh([fingerprint/84h/0h/0h]xpub.../0/*)  ← external
      wpkh([fingerprint/84h/0h/0h]xpub.../1/*)  ← internal (change)
```

### How `IsMine()` Works

```
  CWallet::IsMine(script)
       │
       ▼
  Look up script in m_cached_spks
       │
       ├── Found? → return true
       │
       └── Not found? → return false
           (The cache is populated when SPKMs do TopUp())
```

The cache (`m_cached_spks`) is critical for performance. Without it, every
`IsMine()` check would need to iterate all descriptors and try to match.

---

## 6. The Transaction State Machine

`CWalletTx::m_state` uses a `std::variant` to represent where a transaction
currently lives. Here's how states transition:

```
                        ┌─────────────────────┐
                        │    TxStateInactive   │
                        │    (abandoned=false)  │
                        └──────────┬──────────┘
                                   │
              ┌────────────────────┼──────────────────┐
              │ addedToMempool()   │ blockConnected()  │ AbandonTransaction()
              ▼                    │                    ▼
   ┌────────────────────┐         │         ┌─────────────────────┐
   │  TxStateInMempool  │         │         │    TxStateInactive   │
   │                    │         │         │    (abandoned=true)   │
   └────────┬───────────┘         │         └──────────────────────┘
            │                     │
            │ blockConnected()    │
            ▼                     ▼
   ┌─────────────────────────────────┐
   │       TxStateConfirmed          │
   │  (block_hash, height, index)    │
   └─────────────┬───────────────────┘
                 │
                 │ blockDisconnected()  (reorg)
                 ▼
   ┌─────────────────────────────────┐
   │       TxStateInactive           │
   │       (back to unconfirmed)     │
   └─────────────────────────────────┘

   Conflict path:
   ┌─────────────────────────────────┐
   │     TxStateBlockConflicted      │  ← A different tx spending the same
   │  (conflicting_block_hash,       │     inputs was confirmed
   │   conflicting_block_height)     │
   └─────────────────────────────────┘
```

**Why `std::variant` instead of an enum?** Because each state carries
different data. `Confirmed` needs a block hash and height. `BlockConflicted`
needs the conflicting block's hash. Using a variant makes illegal states
unrepresentable — you can't have a "confirmed" transaction without block info.

---

## 7. Thread Safety & Locking Model

```
  Lock Ordering (must always be acquired in this order):

  1. cs_main          (node's main lock, coarsest)
  2. cs_wallet        (wallet's main lock)
  3. cs_KeyStore      (ScriptPubKeyMan's key lock)
  4. cs_desc_man      (DescriptorScriptPubKeyMan's lock)

  NEVER: cs_wallet → wallets_mutex  (deadlock risk!)
  NEVER: cs_wallet → cs_main        (deadlock risk!)
```

The codebase uses Clang's thread safety annotations (`GUARDED_BY`,
`EXCLUSIVE_LOCKS_REQUIRED`) to catch violations at compile time.

Notable patterns:
- `cs_wallet` is a **RecursiveMutex** — the same thread can lock it multiple
  times without deadlocking. This is needed because many wallet operations
  call each other internally.
- Rescan uses **atomic bools** (`fScanningWallet`, `fAbortRescan`) instead
  of mutexes, allowing non-blocking status checks from RPC threads.
- `m_wallet_flags` is `std::atomic<uint64_t>` — can be read without holding
  any lock.

---

## 8. Signal / Observer System

CWallet uses **Boost.Signals2** to notify external code (GUI, RPC) of changes
without coupling to them:

```
  CWallet                              GUI / RPC
  ───────                              ─────────
  NotifyTransactionChanged ──────────► Update transaction list
  NotifyAddressBookChanged ──────────► Update address book display
  NotifyCanGetAddressesChanged ──────► Enable/disable "New Address" button
  NotifyStatusChanged ───────────────► Update lock icon
  ShowProgress ──────────────────────► Update rescan progress bar
  NotifyUnload ──────────────────────► Release wallet references
```

Signals are fired from within wallet methods (e.g., `AddToWallet()` emits
`NotifyTransactionChanged`). Any number of observers can connect.

---

## 9. Data Flow: From RPC to Disk

Here's the full path when a user calls `getnewaddress`:

```
  RPC: getnewaddress(label="savings", address_type="bech32m")
       │
       ▼
  CWallet::GetNewDestination(BECH32M, "savings")
       │
       ├── Look up m_external_spk_managers[BECH32M]
       │          │
       │          ▼
       │   DescriptorScriptPubKeyMan::GetNewDestination()
       │          │
       │          ├── Derive key at next_index from descriptor
       │          ├── Increment next_index
       │          ├── Add to m_map_script_pub_keys cache
       │          ├── Write updated descriptor to DB
       │          └── Return CTxDestination
       │
       ├── CWallet::SetAddressBook(dest, "savings", RECEIVE)
       │          │
       │          ├── Update m_address_book[dest]
       │          ├── Write to DB via WalletBatch
       │          └── Emit NotifyAddressBookChanged signal
       │
       └── Return address string to RPC caller
```

---

## 10. Improvement Proposals

### 10.1 Break Up the God Class (`CWallet`)

**Problem**: `CWallet` has ~80 public methods and ~30 data members. It manages
transactions, addresses, keys, encryption, fee configuration, chain sync,
rescan, and rebroadcast — all in one class. This is a classic
[God Object](https://en.wikipedia.org/wiki/God_object) anti-pattern.

**Suggestion**: Extract cohesive groups of functionality into dedicated classes:

```
  Current CWallet (monolithic)
       │
       ├──► WalletTxManager       — mapWallet, AddToWallet, conflict tracking
       ├──► WalletAddressBook     — m_address_book, labels, address purposes
       ├──► WalletFeeConfig       — all fee-related fields and estimation logic
       ├──► WalletChainSync       — block processing, rescan, rebroadcast
       ├──► WalletEncryption      — Lock/Unlock, master key management
       └──► CWallet (coordinator) — thin facade delegating to the above
```

**Benefit**: Each class would be independently testable and have a clear
single responsibility. New developers would know exactly where to look for
fee-related code vs. transaction management code.

### 10.2 Replace Public Data Members with Accessors

**Problem**: Many critical fields are public (`mapWallet`, `m_address_book`,
`m_locked_coins`, `wtxOrdered`, `mapMasterKeys`, and all fee configuration
fields). External code can bypass the wallet's internal invariants.

**Suggestion**: Make data members private and expose them through accessor
methods. For example:

```cpp
// Instead of:
wallet.m_pay_tx_fee = CFeeRate(10000);  // Anyone can set this anytime

// Prefer:
wallet.SetPayTxFee(CFeeRate(10000));    // Can validate, log, persist
```

For read-only access to collections, return `const` references or ranges.

### 10.3 Decouple Fee Configuration

**Problem**: Fee-related fields (`m_pay_tx_fee`, `m_fallback_fee`,
`m_min_fee`, `m_discard_rate`, `m_consolidate_feerate`,
`m_max_aps_fee`, `m_default_max_tx_fee`, `m_confirm_target`,
`m_signal_rbf`, etc.) are scattered as public members of `CWallet`.
They are read by coin selection code in `spend.cpp` and have no
validation logic.

**Suggestion**: Group into a `WalletFeePolicy` struct/class:

```cpp
struct WalletFeePolicy {
    CFeeRate pay_tx_fee{DEFAULT_PAY_TX_FEE};
    CFeeRate fallback_fee{DEFAULT_FALLBACK_FEE};
    CFeeRate min_fee{DEFAULT_TRANSACTION_MINFEE};
    CFeeRate discard_rate{DEFAULT_DISCARD_FEE};
    CFeeRate consolidate_feerate{DEFAULT_CONSOLIDATE_FEERATE};
    CAmount max_aps_fee{DEFAULT_MAX_AVOIDPARTIALSPEND_FEE};
    CAmount max_tx_fee{DEFAULT_TRANSACTION_MAXFEE};
    unsigned int confirm_target{DEFAULT_TX_CONFIRM_TARGET};
    bool signal_rbf{DEFAULT_WALLET_RBF};
    bool allow_fallback_fee{true};

    // Parse from ArgsManager, with validation
    static WalletFeePolicy FromArgs(const ArgsManager& args);
};
```

### 10.4 Formalize the Transaction State Machine

**Problem**: Transaction state transitions are implicit — they happen
deep inside methods like `SyncTransaction`, `MarkConflicted`,
`AbandonTransaction`, and `blockConnected`. There's no single place
to understand all valid transitions.

**Suggestion**: Create an explicit state transition function:

```cpp
// Returns the new state, or nullopt if the transition is invalid
std::optional<TxState> TransitionState(
    const TxState& current,
    TxStateEvent event,    // enum: BLOCK_CONNECTED, BLOCK_DISCONNECTED,
                           //       MEMPOOL_ADDED, MEMPOOL_REMOVED,
                           //       USER_ABANDON, CONFLICT_DETECTED
    const TxStateEventData& data
);
```

This would make the state machine testable in isolation and serve as
living documentation.

### 10.5 Replace `mapValue` with Typed Fields

**Problem**: `CWalletTx::mapValue` is a `map<string, string>` used to
store metadata like `"comment"`, `"replaces_txid"`, and
`"replaced_by_txid"`. This is a "stringly-typed" design that is:
- Easy to typo (no compile-time checking of key names)
- Inefficient (string lookups, no type safety)
- Hard to discover (you must grep the codebase for key names)

**Suggestion**: Replace with dedicated typed fields where possible:

```cpp
class CWalletTx {
    // Instead of mapValue["comment"] and mapValue["to"]:
    std::string m_comment;
    std::string m_comment_to;

    // Instead of mapValue["replaces_txid"]:
    std::optional<Txid> m_replaces_txid;

    // Instead of mapValue["replaced_by_txid"]:
    std::optional<Txid> m_replaced_by_txid;

    // Keep mapValue only for truly extensible/unknown fields
    mapValue_t mapValue;  // for forward compatibility only
};
```

Keep backward-compatible serialization by reading from/writing to
`mapValue` during (de)serialization, but use typed fields internally.

### 10.6 Reduce Boost.Signals2 Usage

**Problem**: Boost.Signals2 is the only remaining Boost dependency used
at runtime (beyond Boost.Process for external signers). It adds compile
time and complexity.

**Suggestion**: Replace with a lightweight `std::function`-based callback
system or a simple observer interface. The wallet's signals are not
heavily used — most have 0–2 connected slots.

### 10.7 `WalletStorage` Interface Is Too Thin

**Problem**: `WalletStorage` was designed to break the circular dependency
between `CWallet` and `ScriptPubKeyMan`. But it exposes low-level details
(raw encryption keys, database reference) instead of providing
higher-level operations.

**Suggestion**: Redesign the interface to expose *capabilities* instead of
*implementation details*:

```cpp
class WalletStorage {
public:
    // Instead of exposing raw encryption keys:
    virtual bool EncryptKey(const CKey& key, std::vector<unsigned char>& crypted) = 0;
    virtual bool DecryptKey(const std::vector<unsigned char>& crypted, CKey& key) = 0;

    // Instead of exposing the raw database:
    virtual bool PersistDescriptor(const WalletDescriptor& desc) = 0;
    virtual bool PersistKey(const CKeyID& id, const CPubKey& pub,
                           const std::vector<unsigned char>& crypted) = 0;
};
```

This would make `ScriptPubKeyMan` more testable (easier to mock the
storage interface) and reduce coupling to the database layer.

---

## Summary: Relationship Map (Simplified)

```
                    ┌─────────────┐
                    │WalletContext │ 1
                    └──────┬──────┘
                           │ owns 0..*
                           ▼
                    ┌─────────────┐ 1        1 ┌────────────────┐
                    │   CWallet   │────────────│ WalletDatabase │
                    └──────┬──────┘            └────────────────┘
                           │
          ┌────────────────┼──────────────────┐
          │ owns 0..*      │ owns 0..*        │ owns 0..*
          ▼                ▼                  ▼
  ┌──────────────┐ ┌──────────────┐  ┌──────────────────┐
  │  CWalletTx   │ │CAddressBook- │  │ScriptPubKeyMan   │
  │              │ │ Data         │  │  (abstract)       │
  └──────┬───────┘ └──────────────┘  └────────┬──────────┘
         │                                     │
         │ contains 1                          │ specialized as
         ▼                                     ▼
  ┌──────────────┐                    ┌────────────────────────┐
  │CTransactionRef│                    │DescriptorScriptPubKey- │
  └──────────────┘                    │ Man                     │
                                      │                        │
                                      │ contains 1             │
                                      ▼                        │
                               ┌────────────────┐              │
                               │WalletDescriptor │              │
                               └────────────────┘              │
                                                               │
                                                    ┌──────────┘
                                                    │ uses
                                                    ▼
                                             ┌─────────────┐
                                             │WalletStorage │
                                             │ (interface)  │
                                             └─────────────┘
                                               ▲ implemented by CWallet
```

---

*This document reflects the state of Bitcoin Core's wallet code as of early
2026 (8f0e1f6540). The wallet subsystem is under active development —
some of the improvement suggestions here may already be in progress.*

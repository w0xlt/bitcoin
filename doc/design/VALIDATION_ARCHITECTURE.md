# Bitcoin Core Validation Architecture Guide

> A didactic guide for new developers to understand the consensus validation
> engine in `src/validation.{h,cpp}` — the code that decides whether blocks
> and transactions are valid.

---

## Table of Contents

1. [Where Validation Sits](#1-where-validation-sits)
2. [The Two Pillars: ChainstateManager and Chainstate](#2-the-two-pillars-chainstatemanager-and-chainstate)
3. [Class-by-Class Deep Dive](#3-class-by-class-deep-dive)
4. [UML Class Diagram](#4-uml-class-diagram)
5. [The Block Validation Pipeline](#5-the-block-validation-pipeline)
6. [Chain Activation — How the Tip Moves Forward](#6-chain-activation--how-the-tip-moves-forward)
7. [Reorganizations — When the Chain Switches](#7-reorganizations--when-the-chain-switches)
8. [Transaction Validation — The Mempool Gate](#8-transaction-validation--the-mempool-gate)
9. [The UTXO Set — A Layered Cache Architecture](#9-the-utxo-set--a-layered-cache-architecture)
10. [Script Verification — Parallel Cryptographic Checks](#10-script-verification--parallel-cryptographic-checks)
11. [AssumeUTXO — Fast Sync via Snapshots](#11-assumeutxo--fast-sync-via-snapshots)
12. [Flushing to Disk — Persistence Strategy](#12-flushing-to-disk--persistence-strategy)
13. [Thread Safety & Locking Model](#13-thread-safety--locking-model)
14. [Block Index Status Flags — The Validity Ladder](#14-block-index-status-flags--the-validity-ladder)
15. [Improvement Proposals](#15-improvement-proposals)

---

## 1. Where Validation Sits

```
┌─────────────────────────────────────────────────────────────────┐
│  P2P Layer (net_processing.cpp)                                 │
│  PeerManagerImpl: receives blocks/txs from peers                │
└─────────────────────────┬───────────────────────────────────────┘
                          │ ProcessNewBlock(), ProcessNewBlockHeaders(),
                          │ ProcessTransaction()
                          │
┌═════════════════════════▼═══════════════════════════════════════┐
║  Validation Layer (validation.cpp)        ◄── THIS DOCUMENT    ║
║  ChainstateManager: orchestrates validation                     ║
║  Chainstate: manages one chain + UTXO set                       ║
║  MemPoolAccept: transaction validation engine                   ║
╚═════════════════════════╤═══════════════════════════════════════╝
                          │
          ┌───────────────┼──────────────────────┐
          │               │                      │
          ▼               ▼                      ▼
┌──────────────┐  ┌──────────────┐    ┌──────────────────────┐
│  Block Files │  │  UTXO DB     │    │  CValidationInterface│
│  (blk*.dat)  │  │  (LevelDB)   │    │  (signals to wallet, │
│              │  │              │    │   GUI, indexes)       │
└──────────────┘  └──────────────┘    └──────────────────────┘
```

**Key insight**: Validation is the **gatekeeper**. Every block and every
transaction must pass through this code before the node accepts it.
Nothing enters the UTXO set or mempool without validation's approval.
This is the most security-critical code in Bitcoin Core.

---

## 2. The Two Pillars: ChainstateManager and Chainstate

```
  ┌─────────────────────────────────────────────────────────────┐
  │                   ChainstateManager                         │
  │  "The Coordinator"                                          │
  │                                                             │
  │  Owns 1–2 Chainstate objects.                               │
  │  Routes blocks and txs to the right chainstate.             │
  │  Manages script verification thread pool.                   │
  │  Tracks best header across all chainstates.                 │
  │  Handles IBD detection, snapshot activation, block storage. │
  └──────────────────────┬──────────────────────────────────────┘
                         │ owns
           ┌─────────────┴────────────────┐
           │                              │
           ▼                              ▼
  ┌──────────────────┐         ┌──────────────────────┐
  │  Chainstate      │         │  Chainstate          │
  │  "Current"       │         │  "Historical"        │
  │  (active tip)    │         │  (snapshot validation)│
  │                  │         │                      │
  │  Has mempool     │         │  No mempool          │
  │  Serves wallet   │         │  Background sync     │
  │  Serves RPCs     │         │  Validates snapshot   │
  └──────────────────┘         └──────────────────────┘
    (always present)             (only during AssumeUTXO)
```

**Normal operation**: One Chainstate. It represents the best-known valid
chain from genesis to the current tip.

**During AssumeUTXO**: Two Chainstates exist temporarily. The "current"
one starts from a UTXO snapshot (fast sync). The "historical" one
validates from genesis in the background to verify the snapshot was
correct.

---

## 3. Class-by-Class Deep Dive

### 3.1 `ChainstateManager` — The Coordinator

**File**: `validation.h` (line ~934)

This is the main entry point for all validation operations.

#### External Dependencies

| Field | Type | Purpose |
|-------|------|---------|
| `m_blockman` | `node::BlockManager` | Block file storage and block index |
| `m_options` | `Options` | Consensus params, notification callbacks, script threads |
| `m_interrupt` | `SignalInterrupt&` | Shutdown signal |
| `m_validation_cache` | `ValidationCache` | Script execution + signature caches |

#### Chainstate Management

| Field | Type | Purpose |
|-------|------|---------|
| `m_chainstates` | `vector<unique_ptr<Chainstate>>` | All chainstates (1 normally, 2 during AssumeUTXO) |
| `m_best_header` | `CBlockIndex*` | Best header known across all chainstates |
| `m_best_invalid` | `CBlockIndex*` | Most-work invalid block (debugging) |
| `m_versionbitscache` | `VersionBitsCache` | Softfork deployment status cache |

#### IBD Tracking

| Field | Type | Purpose |
|-------|------|---------|
| `m_cached_is_ibd` | `atomic_bool` | Latched: once false, stays false forever |
| `m_total_coinstip_cache` | `size_t` | Total in-memory UTXO cache budget |
| `m_total_coinsdb_cache` | `size_t` | Total LevelDB cache budget |

#### Script Verification

| Field | Type | Purpose |
|-------|------|---------|
| `m_script_check_queue` | `CCheckQueue<CScriptCheck>` | Thread pool for parallel script verification |

#### Performance Counters

| Field | Purpose |
|-------|---------|
| `time_check` | Time spent in CheckBlock() |
| `time_connect` | Time in ConnectBlock() |
| `time_verify` | Time in script verification |
| `time_undo` | Time writing undo data |
| `time_flush` | Time flushing to disk |
| `num_blocks_total` | Total blocks validated |

#### Key Methods

```
  Block Processing:
    ProcessNewBlock(block)           — Full pipeline: check → store → activate
    ProcessNewBlockHeaders(headers)  — Validate and index headers only
    AcceptBlock(block, state)        — Validate and write to disk
    ProcessTransaction(tx)           — Submit tx to mempool

  Chain Navigation:
    ActiveChainstate()  — The best-work chainstate
    ActiveChain()       — The active CChain (list of block indexes)
    ActiveTip()         — Current chain tip
    ActiveHeight()      — Current chain height

  Snapshot:
    ActivateSnapshot(coins_file)     — Load UTXO snapshot from file
    MaybeValidateSnapshot()          — Check snapshot hash against historical chain

  State:
    IsInitialBlockDownload()         — Are we still syncing?
    LoadBlockIndex()                 — Load block tree from disk on startup
    CheckBlockIndex()                — Paranoid consistency check of all blocks
```

### 3.2 `Chainstate` — One Chain + Its UTXO Set

**File**: `validation.h` (line ~549)

Each `Chainstate` manages a single chain from some starting point
(genesis or a UTXO snapshot) to its current tip, plus the UTXO set
for that tip.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Chainstate                              │
│                                                                 │
│  ── Identity ───────────────────────────────────────────────── │
│  m_chainman           : ChainstateManager& (parent)            │
│  m_blockman           : BlockManager& (shared block storage)    │
│  m_from_snapshot_blockhash : optional<uint256> (snapshot origin)│
│  m_assumeutxo         : enum {VALIDATED, UNVALIDATED, INVALID} │
│                                                                 │
│  ── The Chain ──────────────────────────────────────────────── │
│  m_chain              : CChain (vector of CBlockIndex*)         │
│  setBlockIndexCandidates : set<CBlockIndex*>                    │
│                         (blocks with work >= our tip)           │
│                                                                 │
│  ── The UTXO Set ───────────────────────────────────────────── │
│  m_coins_views        : unique_ptr<CoinsViews>                  │
│    ├─ m_dbview         : CCoinsViewDB (LevelDB)                 │
│    ├─ m_catcherview    : CCoinsViewErrorCatcher                  │
│    ├─ m_cacheview      : CCoinsViewCache (in-memory, ~300 MB)   │
│    └─ m_connect_block_view : CCoinsViewCache (temporary)        │
│                                                                 │
│  ── Cache Sizing ───────────────────────────────────────────── │
│  m_coinsdb_cache_size_bytes  : size_t                           │
│  m_coinstip_cache_size_bytes : size_t                           │
│  m_next_write         : time_point (next scheduled flush)       │
│                                                                 │
│  ── Mempool ────────────────────────────────────────────────── │
│  m_mempool            : CTxMemPool* (only for active chainstate)│
│                                                                 │
│  ── Snapshot Validation ────────────────────────────────────── │
│  m_target_blockhash   : optional<uint256>                       │
│  m_target_utxohash    : optional<AssumeutxoHash>                 │
│                                                                 │
│  ── Key Methods ────────────────────────────────────────────── │
│  ActivateBestChain()    ConnectBlock()     DisconnectBlock()    │
│  ConnectTip()           DisconnectTip()    FlushStateToDisk()   │
│  CoinsTip()             CoinsDB()          FindMostWorkChain()  │
│  InvalidateBlock()      PreciousBlock()    LoadChainTip()       │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 `CoinsViews` — The UTXO Cache Hierarchy

**File**: `validation.h` (line ~478)

The UTXO set is managed through a **layered cache** architecture. Each
layer wraps the one below it, adding functionality:

```
  ┌───────────────────────────────────────────────────────────┐
  │ Layer 4: m_connect_block_view (CCoinsViewCache)           │
  │ Purpose: Temporary scratch space for ConnectBlock()        │
  │ Lifetime: Created per-block, discarded on validation fail  │
  │ Backend: Layer 3                                           │
  └──────────────────────────┬────────────────────────────────┘
                             │ reads from / flushes to
  ┌──────────────────────────▼────────────────────────────────┐
  │ Layer 3: m_cacheview (CCoinsViewCache)                    │
  │ Purpose: Main in-memory UTXO cache (~300 MB typical)       │
  │ Lifetime: Entire chainstate lifetime                       │
  │ Backend: Layer 2                                           │
  │ This is what CoinsTip() returns.                           │
  └──────────────────────────┬────────────────────────────────┘
                             │ reads from / flushes to
  ┌──────────────────────────▼────────────────────────────────┐
  │ Layer 2: m_catcherview (CCoinsViewErrorCatcher)           │
  │ Purpose: Catches LevelDB read errors gracefully            │
  │ Lifetime: Entire chainstate lifetime                       │
  │ Backend: Layer 1                                           │
  └──────────────────────────┬────────────────────────────────┘
                             │ reads from / writes to
  ┌──────────────────────────▼────────────────────────────────┐
  │ Layer 1: m_dbview (CCoinsViewDB)                          │
  │ Purpose: LevelDB persistent storage on disk                │
  │ Lifetime: Entire chainstate lifetime                       │
  │ This is the ground truth — survives restarts.              │
  └───────────────────────────────────────────────────────────┘
```

**Why the temporary layer?** When `ConnectBlock()` validates a block, it
applies all transactions to `m_connect_block_view`. If the block turns
out to be invalid (bad script, overspend, etc.), this temporary layer
is simply discarded — the real UTXO set (`CoinsTip()`) is untouched.
Only on success is the temporary layer flushed down.

### 3.4 `MempoolAcceptResult` — Transaction Validation Outcome

**File**: `validation.h` (line ~130)

```
┌─────────────────────────────────────────────────────────────────┐
│                    MempoolAcceptResult                          │
│                                                                 │
│  ResultType:                                                    │
│    VALID             — Accepted into mempool                    │
│    INVALID           — Rejected                                 │
│    MEMPOOL_ENTRY     — Already in mempool (idempotent)          │
│    DIFFERENT_WITNESS — Same txid, different witness already in  │
│                                                                 │
│  Fields (all optional, present based on ResultType):            │
│    m_state           — TxValidationState (error details)        │
│    m_replaced_transactions — Txs evicted by RBF                 │
│    m_vsize            — Virtual size in bytes                   │
│    m_base_fees        — Raw fees in satoshis                    │
│    m_effective_feerate — Including package/priority context     │
│    m_wtxids_fee_calculations — Which txs contributed to feerate │
│    m_other_wtxid      — The other witness version (if swap)     │
│                                                                 │
│  Static Factories:                                              │
│    Failure(state)     Success(replaced, vsize, fees, ...)       │
│    MempoolTx(vsize)   MempoolTxDifferentWitness(other_wtxid)    │
└─────────────────────────────────────────────────────────────────┘
```

### 3.5 `CScriptCheck` — A Verifiable Script Operation

**File**: `validation.h` (line ~337)

```
┌─────────────────────────────────────────────────────────────────┐
│                       CScriptCheck                              │
│                                                                 │
│  Encapsulates verification of ONE input's script:               │
│                                                                 │
│  m_tx_out    : CTxOut (the output being spent)                  │
│  ptxTo       : CTransaction* (the spending transaction)         │
│  nIn         : unsigned int (which input)                       │
│  m_flags     : script_verify_flags (consensus + policy rules)   │
│  txdata      : PrecomputedTransactionData* (optimization cache) │
│  m_signature_cache : SignatureCache* (sig verification cache)   │
│                                                                 │
│  operator()() → optional<pair<ScriptError, string>>             │
│    Returns nullopt on success, error+debug info on failure.     │
│                                                                 │
│  Move-only (no copies) — designed for CCheckQueue threading.    │
└─────────────────────────────────────────────────────────────────┘
```

### 3.6 `ValidationCache` — Shared Cryptographic Caches

**File**: `validation.h` (line ~369)

```
┌─────────────────────────────────────────────────────────────────┐
│                      ValidationCache                            │
│                                                                 │
│  m_script_execution_cache : CuckooCache                         │
│    Key: SHA256(wtxid + flags + spent_outputs)                   │
│    Value: "this script combination is valid"                    │
│    Hit rate: Very high for mempool txs (already verified)       │
│                                                                 │
│  m_signature_cache : SignatureCache                              │
│    Caches individual ECDSA/Schnorr signature verifications      │
│    Shared across all threads                                    │
│                                                                 │
│  m_script_execution_cache_hasher : CSHA256                      │
│    Pre-initialized with random nonce (prevents cache poisoning) │
└─────────────────────────────────────────────────────────────────┘
```

**Why two caches?** Signature verification (~100μs per ECDSA) is the
most expensive single operation. The signature cache prevents re-verifying
signatures seen in the mempool when the transaction appears in a block.
The script execution cache goes further — it caches the entire
`VerifyScript()` result, covering all script operations.

### 3.7 `CVerifyDB` — RAII Database Consistency Check

**File**: `validation.h` (line ~434)

Used during startup to verify the coins database is consistent:

```
  Verification Levels (0-4):
    Level 0: Read all coins from DB (just check readability)
    Level 1: Verify block file integrity
    Level 2: Verify block data can be read from disk
    Level 3: Apply ConnectBlock() for recent blocks
    Level 4: Apply DisconnectBlock() + reconnect (full roundtrip)
```

Default: level 3, last 6 blocks. Higher levels are slower but catch
more corruption.

---

## 4. UML Class Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                  CValidationInterface                           │
│                  (signal interface)                              │
│─────────────────────────────────────────────────────────────────│
│ BlockConnected(block, role)                                     │
│ BlockDisconnected(block, role)                                  │
│ UpdatedBlockTip(tip, fork, is_ibd)                              │
│ ActiveTipChange(tip, is_ibd)                                    │
│ TransactionAddedToMempool(tx)                                   │
│ TransactionRemovedFromMempool(tx, reason)                       │
│ NewPoWValidBlock(index, block)                                  │
│ BlockChecked(block, state)                                      │
└─────────────────────────────────────────────────────────────────┘
                           ▲ signals fired by
                           │
┌══════════════════════════╪══════════════════════════════════════┐
║                  ChainstateManager                             ║
║════════════════════════════════════════════════════════════════ ║
║                                                                ║
║  ── Configuration ────────────────────────────────────────── ║
║  m_options         : Options (consensus, notifications)        ║
║  m_interrupt       : SignalInterrupt&                           ║
║                                                                ║
║  ── Block Management ─────────────────────────────────────── ║
║  m_blockman        : BlockManager (block files + index)        ║
║  m_best_header     : CBlockIndex* (best known header)          ║
║  m_best_invalid    : CBlockIndex* (most-work invalid block)    ║
║                                                                ║
║  ── Chainstates ──────────────────────────────────────────── ║
║  m_chainstates     : vector<unique_ptr<Chainstate>>            ║
║                      (1 normally, 2 during snapshot)           ║
║                                                                ║
║  ── Script Verification ──────────────────────────────────── ║
║  m_script_check_queue : CCheckQueue<CScriptCheck>              ║
║  m_validation_cache   : ValidationCache                        ║
║                                                                ║
║  ── IBD ──────────────────────────────────────────────────── ║
║  m_cached_is_ibd   : atomic_bool (latched)                     ║
║                                                                ║
║  ── Key Methods ──────────────────────────────────────────── ║
║  ProcessNewBlock()    ProcessNewBlockHeaders()                  ║
║  ProcessTransaction() ActivateSnapshot()                       ║
║  ActiveChainstate()   IsInitialBlockDownload()                  ║
║  LoadBlockIndex()     CheckBlockIndex()                         ║
╚════════════════════╤═══════════════════════════════════════════╝
                     │ owns 1-2
                     ▼
┌══════════════════════════════════════════════════════════════════┐
║                        Chainstate                               ║
║════════════════════════════════════════════════════════════════ ║
║                                                                 ║
║  m_chain              : CChain (active chain of CBlockIndex*)   ║
║  m_coins_views        : unique_ptr<CoinsViews>  ────────┐       ║
║  m_mempool            : CTxMemPool* (optional)          │       ║
║  m_assumeutxo         : enum (VALIDATED/UNVALIDATED)    │       ║
║  setBlockIndexCandidates : set<CBlockIndex*>            │       ║
║                                                         │       ║
║  ActivateBestChain()  ConnectBlock()                    │       ║
║  DisconnectBlock()    ConnectTip()    DisconnectTip()   │       ║
║  FlushStateToDisk()   InvalidateBlock()                 │       ║
║  FindMostWorkChain()  CoinsTip()     CoinsDB()         │       ║
╚════════════════════════════════════════════════════════╤═╝
                                                        │ owns 1
                                                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                        CoinsViews                               │
│─────────────────────────────────────────────────────────────────│
│                                                                 │
│  m_connect_block_view ─► CCoinsViewCache (temporary per-block)  │
│         │ backed by                                              │
│  m_cacheview ──────────► CCoinsViewCache (main in-memory cache) │
│         │ backed by                                              │
│  m_catcherview ────────► CCoinsViewErrorCatcher                  │
│         │ backed by                                              │
│  m_dbview ─────────────► CCoinsViewDB (LevelDB on disk)         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘


Transaction Validation Result Types:
┌──────────────────────┐           ┌─────────────────────────────┐
│ MempoolAcceptResult  │           │ PackageMempoolAcceptResult  │
│──────────────────────│           │─────────────────────────────│
│ m_result_type:       │           │ m_state:                    │
│  VALID               │           │  PackageValidationState     │
│  INVALID             │           │ m_tx_results:               │
│  MEMPOOL_ENTRY       │           │  map<Wtxid, MempoolAccept-  │
│  DIFFERENT_WITNESS   │           │       Result>               │
│                      │           │                             │
│ m_state              │           │ (wraps individual results   │
│ m_vsize              │           │  for multi-tx packages)     │
│ m_base_fees          │           └─────────────────────────────┘
│ m_effective_feerate  │
│ m_replaced_txs       │
└──────────────────────┘

Block Status Flags (on CBlockIndex):
┌────────────────────────────────────────────────────────────────┐
│  BLOCK_VALID_TREE         ← Header structure valid             │
│  BLOCK_VALID_TRANSACTIONS ← All txs parseable and unique       │
│  BLOCK_VALID_CHAIN        ← Context checks pass (timestamps)   │
│  BLOCK_VALID_SCRIPTS      ← All scripts verified  ← FULL      │
│                                                      VALIDITY  │
│  BLOCK_HAVE_DATA          ← Block data on disk                 │
│  BLOCK_HAVE_UNDO          ← Undo data on disk                  │
│                                                                │
│  BLOCK_FAILED_VALID       ← Known to be invalid                │
│  BLOCK_FAILED_CHILD       ← Descendant of invalid block        │
└────────────────────────────────────────────────────────────────┘
```

---

## 5. The Block Validation Pipeline

When a new block arrives from a peer, it goes through a multi-stage
pipeline. Each stage adds confidence:

```
  Block arrives from P2P (via ProcessNewBlock)
       │
       ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Stage 1: CheckBlock()  — "Is this block structurally sane?" │
  │ Context-free, stateless. Can run without any chain data.     │
  │                                                              │
  │  ✓ Proof of work matches nBits difficulty                    │
  │  ✓ Merkle root matches transactions                          │
  │  ✓ No duplicate transactions (CVE-2012-2459)                 │
  │  ✓ First tx is coinbase, rest are not                        │
  │  ✓ Block weight ≤ MAX_BLOCK_WEIGHT (4M weight units)         │
  │  ✓ Each transaction passes CheckTransaction()                │
  │  ✓ Total legacy sigops ≤ MAX_BLOCK_SIGOPS_COST               │
  │  ✓ Witness commitment valid (if SegWit)                      │
  └──────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Stage 2: ContextualCheckBlockHeader()  — "Does the header   │
  │           fit in the chain?"                                 │
  │                                                              │
  │  ✓ PoW matches GetNextWorkRequired() for this height         │
  │  ✓ Timestamp > median of previous 11 blocks                  │
  │  ✓ Timestamp not too far in the future (2 hours)             │
  │  ✓ No timewarp attacks on difficulty adjustments (BIP94)     │
  │  ✓ Block version not outdated per deployment rules           │
  └──────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Stage 3: ContextualCheckBlock()  — "Do the transactions      │
  │           make sense at this height?"                         │
  │                                                              │
  │  ✓ All transactions are final (nLockTime, BIP113)            │
  │  ✓ Coinbase height commitment correct (BIP34)                │
  │  ✓ Witness commitment valid                                  │
  │  ✓ Block weight within limit                                 │
  └──────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Stage 4: AcceptBlock()  — "Store it on disk."                │
  │                                                              │
  │  ✓ Write block data to blk*.dat file                         │
  │  ✓ Record position in block index                            │
  │  ✓ Mark as BLOCK_HAVE_DATA                                   │
  │  ✓ Add to setBlockIndexCandidates if enough work             │
  └──────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Stage 5: ActivateBestChain() → ConnectBlock()                │
  │          "Apply it to the UTXO set."                         │
  │                                                              │
  │  For each transaction:                                       │
  │    ✓ All inputs exist in UTXO set (no double-spend)          │
  │    ✓ Input values ≥ output values (no inflation)             │
  │    ✓ All scripts verify (signatures valid)                   │
  │    ✓ Sequence locks satisfied (BIP68)                        │
  │    ✓ Sigop count within limits                               │
  │  Coinbase:                                                   │
  │    ✓ Block reward ≤ subsidy + fees                           │
  │  On success:                                                 │
  │    ✓ Flush UTXO changes to CoinsTip()                        │
  │    ✓ Write undo data (for potential future disconnection)     │
  │    ✓ Mark as BLOCK_VALID_SCRIPTS (fully validated)            │
  │    ✓ Update chain tip                                        │
  └─────────────────────────────────────────────────────────────┘
```

---

## 6. Chain Activation — How the Tip Moves Forward

`ActivateBestChain()` is the engine that advances the chain to the
best-known tip. It's designed to work in **steps** to avoid holding
`cs_main` for too long:

```
  ActivateBestChain()
       │
       │  LOCK(m_chainstate_mutex)  — only one activation at a time
       │
       │  Outer loop (keeps trying until tip == best candidate):
       │       │
       │       ├─ LOCK(cs_main)
       │       │
       │       ├─ FindMostWorkChain()
       │       │    Scans setBlockIndexCandidates for most total work
       │       │    Validates all blocks on the path have data
       │       │    Removes invalid candidates
       │       │
       │       ├─ Already at best? → break
       │       │
       │       ├─ ActivateBestChainStep()  ◄── processes up to 32 blocks
       │       │       │
       │       │       ├─ DISCONNECT: Walk back to fork point
       │       │       │    DisconnectTip() for each block
       │       │       │    Save disconnected txs for mempool resurrection
       │       │       │
       │       │       └─ CONNECT: Walk forward to new tip
       │       │            ConnectTip() for each block
       │       │            On invalid: mark failed, try again
       │       │
       │       ├─ UNLOCK(cs_main)  — let other threads run
       │       │
       │       ├─ Fire BlockConnected signals (without cs_main!)
       │       │
       │       ├─ FlushStateToDisk(PERIODIC)
       │       │
       │       └─ Continue loop
       │
       └─ Fire UpdatedBlockTip + ActiveTipChange signals
```

**Why 32 blocks per step?** During IBD, connecting blocks is fast
(~50ms each). But we can't hold `cs_main` for minutes — RPC calls,
wallet operations, and P2P message processing would all stall. By
processing in chunks and releasing the lock between iterations, we
keep the node responsive.

### ConnectTip() — The Single-Block Worker

```
  ConnectTip(pindexNew)
       │
       ├─ Read block from disk (if not already in memory)
       │
       ├─ ConnectBlock(block, pindexNew, m_connect_block_view)
       │       │
       │       ├─ For each non-coinbase tx:
       │       │    ├─ Check inputs exist in UTXO
       │       │    ├─ Accumulate fees
       │       │    ├─ Create CScriptCheck for each input
       │       │    └─ Queue checks to thread pool (or verify inline)
       │       │
       │       ├─ Wait for all script checks to complete
       │       │
       │       ├─ Verify coinbase reward ≤ subsidy + fees
       │       │
       │       ├─ UpdateCoins(): apply all tx effects to view
       │       │    ├─ Spend all inputs (remove from UTXO set)
       │       │    └─ Add all outputs (add to UTXO set)
       │       │
       │       └─ Write undo data to rev*.dat file
       │
       ├─ Flush m_connect_block_view → CoinsTip()
       │  (temporary view → permanent UTXO cache)
       │
       ├─ FlushStateToDisk(IF_NEEDED)
       │
       ├─ Remove block's txs from mempool
       │
       └─ Set m_chain.Tip() = pindexNew
```

---

## 7. Reorganizations — When the Chain Switches

A "reorg" happens when a competing chain has more cumulative work:

```
  Before reorg:            After reorg:

  ... → A → B → C  (tip)  ... → A → B'→ C'→ D' (new tip)
             \                        \
              B'→ C'→ D'               B → C  (now stale)

  The reorg requires:
  1. DISCONNECT C (undo its UTXO changes)
  2. DISCONNECT B (undo its UTXO changes)
  3. CONNECT B' (apply its UTXO changes)
  4. CONNECT C' (apply its UTXO changes)
  5. CONNECT D' (apply its UTXO changes)
```

### DisconnectBlock() — Undoing a Block

```
  DisconnectBlock(block, pindex, view)
       │
       ├─ Read undo data from rev*.dat
       │  (CBlockUndo: for each tx, the coins it spent)
       │
       ├─ Process transactions in REVERSE order:
       │       │
       │       ├─ For non-coinbase txs:
       │       │    ├─ Remove outputs (delete coins created by this tx)
       │       │    └─ Restore inputs from undo data (re-create spent coins)
       │       │
       │       └─ For coinbase:
       │            └─ Remove coinbase outputs
       │
       └─ Return DISCONNECT_OK or DISCONNECT_UNCLEAN
```

**Why reverse order?** If tx B spends an output created by tx A (both in
the same block), we must undo B before A. Otherwise, when we try to
restore B's input, the coin doesn't exist yet.

### Mempool Recovery After Reorg

```
  MaybeUpdateMempoolForReorg()
       │
       ├─ For each disconnected tx (FIFO order):
       │    ├─ Try AcceptToMemoryPool(tx, bypass_limits=true)
       │    └─ If fails: remove from mempool entirely
       │
       ├─ For each remaining mempool tx:
       │    ├─ Recalculate lock points (sequence locks may have changed)
       │    ├─ If no longer final: remove
       │    └─ If spends immature coinbase: remove
       │
       └─ LimitMempoolSize() — trim if over limit
```

---

## 8. Transaction Validation — The Mempool Gate

### The MemPoolAccept Pipeline

When a transaction is submitted (from RPC or P2P), it goes through a
multi-stage validation inside the `MemPoolAccept` class:

```
  AcceptToMemoryPool(tx)
       │
       ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Stage 1: PreChecks()  — "Is this transaction worth looking   │
  │           at?"                                                │
  │                                                              │
  │  ✓ Not a coinbase                                            │
  │  ✓ Passes CheckTransaction() (basic structure)               │
  │  ✓ Standard tx (IsStandardTx — policy, not consensus)        │
  │  ✓ Not too small (MIN_STANDARD_TX_NONWITNESS_SIZE)           │
  │  ✓ Final at current tip (nLockTime, nSequence)               │
  │  ✓ Not already in mempool (dedup by txid and wtxid)          │
  │  ✓ All inputs exist in UTXO set                              │
  │  ✓ Sequence locks satisfied (BIP68)                          │
  │  ✓ Fee meets mempool minimum and relay minimum               │
  │  ✓ Inputs are standard (AreInputsStandard)                   │
  │  ✓ Witness is standard (IsWitnessStandard)                   │
  │  ✓ Sigops within limits                                      │
  │  ✓ TRUC policy rules pass (if v3 transaction)                │
  └──────────────────────────┬───────────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Stage 2: ReplacementChecks()  — "Can this replace existing   │
  │           transactions?" (BIP125 RBF)                         │
  │                                                              │
  │  ✓ Conflict count within limits (prevent DoS)                │
  │  ✓ New tx pays more total fees (Rule #3)                     │
  │  ✓ New tx feerate > old tx feerate (Rule #4)                 │
  │  ✓ Replacement doesn't exceed cluster size limits            │
  │  ✓ Fee-rate diagram improves (incentive compatibility)       │
  └──────────────────────────┬───────────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Stage 3: PolicyScriptChecks()  — "Do scripts pass policy?"   │
  │                                                              │
  │  ✓ All scripts verify with STANDARD_SCRIPT_VERIFY_FLAGS      │
  │  ✓ Signatures cached for later consensus check               │
  │  ✓ No witness stripping attack detected                      │
  └──────────────────────────┬───────────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Stage 4: ConsensusScriptChecks()  — "Do scripts pass         │
  │           consensus at the current tip?"                      │
  │                                                              │
  │  ✓ All scripts verify with GetBlockScriptFlags(tip)          │
  │  ✓ Results cached (script execution cache)                   │
  │  NOTE: This is slightly different from policy — script flags  │
  │  depend on which softforks are active at the current height.  │
  └──────────────────────────┬───────────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Stage 5: FinalizeSubpackage()  — "Add it to the mempool."    │
  │                                                              │
  │  ✓ Remove conflicting transactions (RBF evictions)           │
  │  ✓ Add transaction to mempool                                │
  │  ✓ Update ancestor/descendant relationships                  │
  └──────────────────────────────────────────────────────────────┘
```

### Why Two Script Checks?

**PolicyScriptChecks** uses the strictest possible flags (`STANDARD_SCRIPT_VERIFY_FLAGS`).
**ConsensusScriptChecks** uses the flags active at the current chain tip.

These can differ when a new softfork is defined but not yet active.
Policy is forward-looking (prepares for activation); consensus matches
the current chain state. Running both ensures the transaction is valid
now AND will remain valid after activation.

### Package Validation

When a child transaction is too low fee on its own but valid when
bundled with its parent (CPFP):

```
  ProcessNewPackage(parent, child)
       │
       ├─ Validate parent (AcceptSingleTransaction)
       │    If fails on fee: mark as "reconsiderable"
       │
       ├─ Validate child (AcceptSingleTransaction)
       │    If fails because parent missing:
       │       Try package validation (parent + child together)
       │
       └─ Submit package: child's fees cover parent's relay cost
```

---

## 9. The UTXO Set — A Layered Cache Architecture

### How a Transaction Modifies the UTXO Set

```
  Transaction: Alice pays Bob 0.5 BTC

  BEFORE (UTXO set contains):
    (txid_prev, vout=0) → {scriptPubKey: Alice's, amount: 1.0 BTC}

  UpdateCoins(tx, view, undo_data):

  AFTER (UTXO set contains):
    (txid_prev, vout=0) → SPENT (removed from UTXO set)
    (txid_new, vout=0)  → {scriptPubKey: Bob's, amount: 0.5 BTC}
    (txid_new, vout=1)  → {scriptPubKey: Alice's, amount: 0.4999 BTC}
                            (change, 0.0001 BTC is the fee)

  Undo data saved:
    (txid_prev, vout=0) → {scriptPubKey: Alice's, amount: 1.0 BTC}
    (needed to restore this coin if block is disconnected)
```

### Cache Size Management

```
  ┌───────────────────────────────────────────────────────────────┐
  │  CoinsCacheSizeState                                          │
  │                                                               │
  │  OK (0)       Cache usage is comfortable                      │
  │               → No action needed                              │
  │                                                               │
  │  LARGE (1)    Cache at ≥90% of budget (or <10 MiB free)      │
  │               → FlushStateToDisk(IF_NEEDED) during periodic   │
  │                 check in ActivateBestChain()                  │
  │                                                               │
  │  CRITICAL (2) Cache at 100% of budget                         │
  │               → Immediate flush required                      │
  │               → ConnectTip() forces flush before proceeding   │
  └───────────────────────────────────────────────────────────────┘

  Typical sizes:
    Default -dbcache=450 → ~450 MiB for CoinsTip()
    Plus LevelDB overhead (~32 MiB)
    Plus mempool usage (subtracted from coin cache budget)
```

---

## 10. Script Verification — Parallel Cryptographic Checks

Script verification is the most CPU-intensive part of block validation.
Bitcoin Core parallelizes it across multiple threads:

```
  ConnectBlock() is processing a block with 2500 transactions:
       │
       │  For each transaction with N inputs:
       │    Create N CScriptCheck objects
       │    (each encapsulates one input's script verification)
       │
       │  If thread pool available (m_script_check_queue.HasThreads()):
       │       │
       │       ├─ Queue all CScriptChecks to thread pool
       │       │    Worker threads pick up checks and run VerifyScript()
       │       │
       │       └─ Meanwhile, ConnectBlock continues:
       │            - Processing more transactions
       │            - Creating more CScriptCheck objects
       │            - Accumulating fees
       │
       │  After all transactions processed:
       │       │
       │       └─ control.Complete()  — wait for all threads to finish
       │            │
       │            └─ Any failure? → Return error (block invalid)
       │
       │  No thread pool (single-threaded):
       │       └─ Verify each CScriptCheck inline (slower)
       │
       │  Script verification uses two levels of caching:
       │
       │  1. Signature cache (per-signature):
       │       ├─ Cache hit: skip ECDSA/Schnorr verify (~100μs saved)
       │       └─ Cache miss: verify and cache result
       │
       │  2. Script execution cache (per-input):
       │       ├─ Cache hit: skip entire VerifyScript() call
       │       │  (common for mempool txs → already verified)
       │       └─ Cache miss: run full script, cache result
```

**Cache effectiveness during normal operation**: Most transactions in a
block were already verified when they entered the mempool. The script
execution cache gives near-100% hit rate for these. Only new transactions
(e.g., from compact block reconstruction) need full verification.

---

## 11. AssumeUTXO — Fast Sync via Snapshots

AssumeUTXO lets a node start using the wallet and RPCs within minutes
instead of hours, by loading a pre-generated UTXO snapshot:

```
  ═══════════════════════════════════════════════════════════════
  PHASE 1: Snapshot Activation
  ═══════════════════════════════════════════════════════════════

  User calls loadtxoutset(snapshot_file)
       │
       ▼
  ChainstateManager::ActivateSnapshot()
       │
       ├─ Verify snapshot file hash matches hardcoded assumeutxo value
       │
       ├─ Deserialize UTXO set from file
       │  (PopulateAndValidateSnapshot: millions of coins)
       │
       ├─ Create "snapshot" Chainstate at snapshot height
       │  m_assumeutxo = UNVALIDATED
       │
       └─ Demote existing chainstate to "historical" (background sync)

  State after Phase 1:

  ┌────────────────────────┐   ┌────────────────────────────┐
  │ Snapshot Chainstate    │   │ Historical Chainstate      │
  │ (ACTIVE — serves RPCs) │   │ (BACKGROUND — validating)  │
  │                        │   │                            │
  │ height: 800,000        │   │ height: 0 (genesis)        │
  │ has mempool: YES       │   │ has mempool: NO            │
  │ assumeutxo: UNVALIDATED│   │ assumeutxo: VALIDATED      │
  └────────────────────────┘   └────────────────────────────┘


  ═══════════════════════════════════════════════════════════════
  PHASE 2: Background Validation (hours/days)
  ═══════════════════════════════════════════════════════════════

  While the snapshot chainstate serves the user normally,
  the historical chainstate syncs from genesis to the snapshot
  height, validating every block:

  Historical chainstate: 0 → 100k → 200k → ... → 800,000
                                                      │
                                                      ▼
  At height 800,000: compute UTXO set hash
       │
       ├─ Hash matches hardcoded value? → VALIDATED ✓
       │    Snapshot chainstate m_assumeutxo = VALIDATED
       │
       └─ Hash doesn't match? → INVALID ✗
            Fatal error: snapshot was wrong


  ═══════════════════════════════════════════════════════════════
  PHASE 3: Cleanup
  ═══════════════════════════════════════════════════════════════

  ValidatedSnapshotCleanup():
    ├─ Move snapshot chainstate's data to main chainstate location
    ├─ Delete historical chainstate (no longer needed)
    └─ Back to 1 chainstate, fully validated
```

---

## 12. Flushing to Disk — Persistence Strategy

The UTXO cache is flushed to LevelDB periodically to balance performance
(batch writes are faster) with crash safety (unflushed data is lost):

```
  FlushStateToDisk(mode)
       │
       ├─ Evaluate cache pressure:
       │    GetCoinsCacheSizeState() → OK / LARGE / CRITICAL
       │
       ├─ Determine if flush is needed:
       │    ┌────────────────┬────────────────────────────────┐
       │    │ Mode           │ When to flush                  │
       │    ├────────────────┼────────────────────────────────┤
       │    │ NONE           │ Never (just check pruning)     │
       │    │ IF_NEEDED      │ If cache is CRITICAL           │
       │    │ PERIODIC       │ Cache LARGE, or timer expired  │
       │    │                │ (50-70 min, randomized)        │
       │    │ FORCE_FLUSH    │ Always                         │
       │    │ FORCE_SYNC     │ Always, plus fsync()           │
       │    └────────────────┴────────────────────────────────┘
       │
       ├─ If flushing:
       │    1. Flush block/undo file buffers to disk
       │    2. Write block index changes to LevelDB
       │    3. Delete pruned block files (if pruning)
       │    4. Flush CoinsTip() → CCoinsViewDB (LevelDB)
       │    5. Write best block hash to DB
       │    6. If FORCE_SYNC: fsync() LevelDB WAL
       │
       └─ Update m_next_write timestamp
```

**Crash recovery**: If the node crashes between flushes, `ReplayBlocks()`
on startup detects the inconsistency and replays blocks from the last
flushed tip to restore the UTXO set.

---

## 13. Thread Safety & Locking Model

### Lock Hierarchy

```
  Coarsest (acquire first)
  ────────────────────────
  cs_main                   ← Global. Protects block index, chain tip,
  │                            CNodeState, UTXO set, and most of
  │                            validation state.
  │
  ├─ m_chainstate_mutex     ← Per-Chainstate. Protects ActivateBestChain
  │                            and InvalidateBlock from concurrent entry.
  │                            MUST NOT hold cs_main when acquiring.
  │
  └─ CTxMemPool::cs         ← Mempool lock. Acquired AFTER cs_main.
                               Used within ConnectTip, DisconnectTip,
                               and MaybeUpdateMempoolForReorg.
  ────────────────────────
  Finest (acquire last)
```

### Critical Patterns

1. **`cs_main` is released between chain activation steps**: This is why
   `ActivateBestChain()` loops — it processes 32 blocks, releases
   `cs_main`, fires signals, then re-acquires.

2. **Signals fire without `cs_main`**: `BlockConnected`, `UpdatedBlockTip`,
   etc. are fired after releasing `cs_main`. Handlers (wallet, indexes)
   must not assume chain state is unchanged.

3. **`m_chainstate_mutex` prevents concurrent activation**: Two threads
   can't both run `ActivateBestChain()` simultaneously. But they CAN
   read chain state via `cs_main` while activation is paused between
   steps.

4. **`LOCKS_EXCLUDED(cs_main)`**: Some methods (like `ActivateBestChain`)
   cannot be called while holding `cs_main`, because they need to
   acquire and release it internally.

---

## 14. Block Index Status Flags — The Validity Ladder

Every `CBlockIndex` tracks how much validation the block has passed.
These flags form a **ladder** — each level includes all below it:

```
  BLOCK_VALID_UNKNOWN     (0)
       │
       ▼
  BLOCK_VALID_TREE        (1)
    "Header is valid, parent link exists"
    Set by: AcceptBlockHeader()
       │
       ▼
  BLOCK_VALID_TRANSACTIONS (2)
    "All transactions are parseable and unique"
    Set by: ReceivedBlockTransactions()
       │
       ▼
  BLOCK_VALID_CHAIN       (3)
    "Context checks pass (timestamps, BIP34, etc.)"
    Set by: ContextualCheckBlock() inside ConnectBlock()
       │
       ▼
  BLOCK_VALID_SCRIPTS     (4)
    "All scripts verified — FULLY VALIDATED"
    Set by: ConnectBlock() after all CScriptChecks pass

  ─── Orthogonal flags ───

  BLOCK_HAVE_DATA         Block data stored in blk*.dat
  BLOCK_HAVE_UNDO         Undo data stored in rev*.dat
  BLOCK_FAILED_VALID      This block is known invalid
  BLOCK_FAILED_CHILD      A parent of this block is invalid
```

**Why a ladder?** It allows the node to track partial progress. During
IBD, headers arrive before block data. The block index can store the
header (VALID_TREE) and later upgrade when the full block arrives
(VALID_TRANSACTIONS → VALID_SCRIPTS).

**`BLOCK_FAILED_CHILD`**: When a block is marked invalid, ALL its
descendants are automatically marked `BLOCK_FAILED_CHILD`. This prevents
wasting time validating blocks on a known-bad chain.

---

## 15. Improvement Proposals

### 15.1 Break Up `validation.cpp` by Responsibility

**Problem**: `validation.cpp` is ~6400 lines covering block validation,
transaction validation, chain activation, UTXO management, disk flushing,
reorg handling, mempool maintenance, and AssumeUTXO. It's the largest
single file in Bitcoin Core.

**Suggestion**: Split along natural boundaries:

```
  Current validation.cpp (monolithic, ~6400 lines)
       │
       ├──► block_validation.cpp       — CheckBlock, ContextualCheckBlock,
       │                                  ConnectBlock, DisconnectBlock
       │
       ├──► chain_activation.cpp       — ActivateBestChain, ConnectTip,
       │                                  DisconnectTip, FindMostWorkChain,
       │                                  reorg handling
       │
       ├──► mempool_accept.cpp         — MemPoolAccept class (already ~800
       │                                  lines), PreChecks, ReplacementChecks,
       │                                  script checks, package validation
       │
       ├──► chainstate.cpp             — Chainstate methods: flush, cache
       │                                  management, initialization, loading
       │
       ├──► chainstate_manager.cpp     — ChainstateManager methods: block
       │                                  processing entry points, IBD,
       │                                  snapshot management
       │
       └──► validation.cpp (residual)  — Shared helpers, constants
```

**Benefit**: Each file would be under 1500 lines. `MemPoolAccept` is
already a logically separate class — it could be its own file today
with minimal effort.

### 15.2 Extract `MemPoolAccept` Into Its Own File

**Problem**: `MemPoolAccept` is a ~350-line class declaration plus ~800
lines of implementation, nested inside `validation.cpp`. It's
conceptually independent (it validates transactions, not blocks) but
physically coupled to the rest of validation.

**Suggestion**: Move to `mempool_accept.{h,cpp}`. This is the lowest-risk
first step of proposal 15.1, and would immediately improve navigability.

### 15.3 Formalize the Block Status Ladder as a Type

**Problem**: Block validity levels are bare integer flags combined with
bitwise OR. Code checks validity with manual comparisons like
`nStatus & BLOCK_VALID_MASK >= BLOCK_VALID_SCRIPTS`. It's easy to
get the comparison wrong.

**Suggestion**: Use an enum class with comparison operators:

```cpp
enum class BlockValidity : uint8_t {
    UNKNOWN      = 0,
    TREE         = 1,  // header valid
    TRANSACTIONS = 2,  // txs parseable
    CHAIN        = 3,  // context valid
    SCRIPTS      = 4,  // scripts verified (fully valid)
};

// Now instead of:
if (pindex->nStatus & BLOCK_VALID_MASK >= BLOCK_VALID_SCRIPTS)

// You write:
if (pindex->GetValidity() >= BlockValidity::SCRIPTS)
```

The failed/data flags would remain separate. This makes the validity
ladder explicit and prevents comparison bugs.

### 15.4 Make `ConnectBlock` Return a Structured Result

**Problem**: `ConnectBlock()` returns `bool` and communicates failure
details via `BlockValidationState` (an output parameter). This is a
C-style error reporting pattern that makes it hard to understand all
possible outcomes.

**Suggestion**: Return a result type:

```cpp
struct ConnectBlockResult {
    bool success;
    CAmount total_fees;           // Needed by caller for coinbase check
    int sigop_count;              // For monitoring
    std::vector<CTxUndo> undo;    // Undo data for future disconnection
    // On failure:
    BlockValidationState state;
};
```

This makes all outputs explicit and eliminates the need for callers to
separately track fees and undo data.

### 15.5 Reduce `cs_main` Scope in Transaction Validation

**Problem**: `AcceptToMemoryPool` holds `cs_main` for the entire
validation pipeline, including expensive script verification. This blocks
all other chain state access (block processing, RPC, etc.) for the
duration of each transaction's validation.

**Suggestion**: Script verification doesn't actually need `cs_main` —
it only needs the coins view (which could be snapshot-copied) and the
transaction data. Restructure to:

```
  LOCK(cs_main):
    PreChecks()           — needs UTXO set
    ReplacementChecks()   — needs mempool state
    Snapshot coins view   — copy the few coins we need
  UNLOCK(cs_main)

  PolicyScriptChecks()    — only needs tx + coins (snapshot)
  ConsensusScriptChecks() — only needs tx + coins (snapshot)

  LOCK(cs_main):
    FinalizeSubpackage()  — needs mempool state
  UNLOCK(cs_main)
```

This is a complex refactor but would significantly reduce `cs_main`
contention on transaction-heavy workloads.

### 15.6 Decouple Chain Activation from Block Validation

**Problem**: `ConnectBlock()` does both UTXO-level validation (checking
inputs exist, scripts verify) and chain-level bookkeeping (writing undo
data, updating indexes, flushing). These are different concerns with
different testing needs.

**Suggestion**: Split into:

```cpp
// Pure validation — no side effects, easy to test
ValidateBlockResult ValidateBlock(
    const CBlock& block,
    const CBlockIndex& pindex,
    const CCoinsViewCache& view  // read-only
);

// Side effects — applies validated block to state
void ApplyValidatedBlock(
    const CBlock& block,
    const CBlockIndex& pindex,
    CCoinsViewCache& view,       // modified
    const ValidateBlockResult& validation
);
```

The validation half would be a pure function — given a block and a UTXO
snapshot, return whether it's valid. This is vastly easier to test and
reason about than the current `ConnectBlock` which does both.

### 15.7 Replace Performance Counters with Structured Metrics

**Problem**: ChainstateManager tracks 10+ timing fields (`time_check`,
`time_connect`, `time_verify`, `time_flush`, etc.) as bare `Stopwatch`
or `int64_t` members. They're only accessible via log output.

**Suggestion**: Collect into a metrics struct with clear semantics:

```cpp
struct ValidationMetrics {
    struct BlockTiming {
        Duration check;        // CheckBlock
        Duration context;      // ContextualCheckBlock
        Duration connect;      // ConnectBlock (total)
        Duration scripts;      // Script verification subset
        Duration undo_write;   // Writing undo data
        Duration flush;        // Flushing to disk
    };

    std::atomic<uint64_t> blocks_validated{0};
    std::atomic<uint64_t> blocks_connected{0};
    std::atomic<uint64_t> reorgs{0};
    std::atomic<uint64_t> reorg_depth_total{0};

    // Expose via RPC (getblockchaininfo or new getvalidationmetrics)
    UniValue ToJSON() const;
};
```

---

## Appendix A: Important Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MIN_BLOCKS_TO_KEEP` | 288 | Minimum blocks retained when pruning (~2 days) |
| `DEFAULT_CHECKBLOCKS` | 6 | Blocks to verify on startup |
| `DEFAULT_CHECKLEVEL` | 3 | Verification depth (0-4) |
| `MAX_SCRIPTCHECK_THREADS` | 15 | Max parallel script verification threads |
| `MAX_BLOCK_WEIGHT` | 4,000,000 | Maximum block weight (weight units) |
| `MAX_BLOCK_SIGOPS_COST` | 80,000 | Maximum signature operations per block |
| `COINBASE_MATURITY` | 100 | Blocks before coinbase can be spent |
| `MAX_FUTURE_BLOCK_TIME` | 7200 | Max seconds a block timestamp can be ahead |

## Appendix B: Key Entry Points for New Contributors

| If you want to... | Start reading at... |
|---|---|
| Understand block validation | `CheckBlock()` → `ConnectBlock()` |
| Understand tx validation | `MemPoolAccept::PreChecks()` |
| Understand chain activation | `ActivateBestChain()` → `ConnectTip()` |
| Understand reorgs | `ActivateBestChainStep()` → `DisconnectTip()` |
| Understand UTXO management | `CoinsViews`, `UpdateCoins()` |
| Understand script caching | `CheckInputScripts()`, `ValidationCache` |
| Understand AssumeUTXO | `ActivateSnapshot()`, `MaybeValidateSnapshot()` |
| Understand disk flushing | `FlushStateToDisk()` |
| Understand IBD | `IsInitialBlockDownload()`, `ActivateBestChain()` |

---

*This document reflects the state of Bitcoin Core's validation code as of
early 2026 (8f0e1f6540). The validation engine is under active development —
AssumeUTXO, package relay, and cluster mempool are ongoing areas of work.*

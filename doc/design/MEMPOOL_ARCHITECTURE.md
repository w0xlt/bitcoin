# Bitcoin Core Memory Pool Architecture Guide

> A didactic guide for new developers to understand the transaction memory pool
> in `src/txmempool.{h,cpp}` and its supporting files — the holding area for
> unconfirmed transactions waiting to be mined.

---

## Table of Contents

1. [Where the Mempool Sits](#1-where-the-mempool-sits)
2. [The Core Mental Model](#2-the-core-mental-model)
3. [Class-by-Class Deep Dive](#3-class-by-class-deep-dive)
4. [UML Class Diagram](#4-uml-class-diagram)
5. [The Multi-Index Container — How Transactions Are Stored](#5-the-multi-index-container--how-transactions-are-stored)
6. [Transaction Lifecycle — From Arrival to Departure](#6-transaction-lifecycle--from-arrival-to-departure)
7. [The ChangeSet — Atomic Batch Operations](#7-the-changeset--atomic-batch-operations)
8. [Ancestor & Descendant Tracking via TxGraph](#8-ancestor--descendant-tracking-via-txgraph)
9. [Eviction & Fee Management](#9-eviction--fee-management)
10. [Block Connection & Disconnection](#10-block-connection--disconnection)
11. [CCoinsViewMemPool — The UTXO Bridge](#11-ccoinsviewmempool--the-utxo-bridge)
12. [Block Building — Mining Transaction Selection](#12-block-building--mining-transaction-selection)
13. [Thread Safety & Locking Model](#13-thread-safety--locking-model)
14. [Key Invariants & Consistency Checks](#14-key-invariants--consistency-checks)
15. [Improvement Proposals](#15-improvement-proposals)

---

## 1. Where the Mempool Sits

```
┌─────────────────────────────────────────────────────────────────────┐
│  P2P Layer (net_processing.cpp)                                     │
│  PeerManagerImpl: receives transactions from peers                  │
└────────────────────────────┬────────────────────────────────────────┘
                             │ ProcessMessage("tx") / ProcessOrphanTx()
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│  Validation Layer (validation.cpp)                                   │
│  MemPoolAccept: validates tx against consensus + policy rules       │
│  See VALIDATION_ARCHITECTURE.md §8 for the 5-stage pipeline         │
└────────────────────────────┬────────────────────────────────────────┘
                             │ ChangeSet::Apply()
                             │
┌════════════════════════════▼════════════════════════════════════════┐
║  Memory Pool (txmempool.cpp)              ◄── THIS DOCUMENT         ║
║  CTxMemPool: stores validated unconfirmed transactions              ║
║  TxGraph: manages dependency graph, clustering, linearization       ║
╚════════════════╤═══════════════╤═══════════════╤════════════════════╝
                 │               │               │
                 ▼               ▼               ▼
        ┌──────────────┐ ┌───────────┐  ┌────────────────────────┐
        │ Block Builder│ │  Wallet   │  │ CValidationInterface   │
        │ (miner.cpp)  │ │(wallet.h) │  │ (fee estimation, GUI,  │
        │              │ │           │  │  ZMQ notifications)     │
        └──────────────┘ └───────────┘  └────────────────────────┘
```

**Key insight**: The mempool is a **waiting room**. Transactions that have passed
validation sit here until a miner includes them in a block (or they're evicted).
It's not just a flat list — it's a sophisticated data structure that maintains
dependency graphs, fee-based ordering, and cluster linearizations for optimal
mining.

**Files involved**:

| File | Role |
|------|------|
| `src/txmempool.h` | CTxMemPool class, ChangeSet, CCoinsViewMemPool |
| `src/txmempool.cpp` | All method implementations |
| `src/kernel/mempool_entry.h` | CTxMemPoolEntry (individual tx wrapper) |
| `src/kernel/mempool_options.h` | MemPoolOptions configuration |
| `src/kernel/mempool_limits.h` | Cluster / ancestor / descendant limits |
| `src/kernel/mempool_removal_reason.h` | MemPoolRemovalReason enum |
| `src/txgraph.h` | TxGraph interface (dependency graph engine) |

---

## 2. The Core Mental Model

Think of the mempool as a **directed acyclic graph (DAG)** of transactions,
overlaid with three conceptual layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                  Layer 3: Mining Order                           │
│  TxGraph linearizes clusters into chunks for optimal mining     │
│  BlockBuilder iterates chunks in fee-rate-descending order      │
├─────────────────────────────────────────────────────────────────┤
│                  Layer 2: Dependency Graph                       │
│  TxGraph tracks parent→child relationships                      │
│  Clusters = connected components of the DAG                     │
│  Each cluster is linearized (topological + fee-optimal order)   │
├─────────────────────────────────────────────────────────────────┤
│                  Layer 1: Transaction Storage                   │
│  boost::multi_index_container (mapTx) with 3 indices            │
│  mapNextTx: reverse spending map (COutPoint → txiter)           │
│  mapDeltas: fee priority adjustments                            │
└─────────────────────────────────────────────────────────────────┘
```

**Separation of concerns**: CTxMemPool handles Bitcoin-specific logic (fees, RPC,
notifications, UTXO tracking), while TxGraph handles pure graph algorithms
(clustering, linearization, eviction ordering). This decoupling was a major
refactoring — previously, ancestor/descendant state was tracked directly inside
CTxMemPoolEntry.

---

## 3. Class-by-Class Deep Dive

### 3.1 CTxMemPoolEntry (`kernel/mempool_entry.h`)

The fundamental unit — wraps a single transaction with cached metadata.

```
CTxMemPoolEntry ──inherits──▶ TxGraph::Ref
```

The inheritance from `TxGraph::Ref` is crucial: it means **destroying a
CTxMemPoolEntry automatically removes it from TxGraph**. The Ref destructor
notifies TxGraph via `UnlinkRef()`.

| Field | Type | Mutable? | Purpose |
|-------|------|----------|---------|
| `tx` | `CTransactionRef` | const | The actual transaction |
| `nFee` | `CAmount` | const | Base fee in satoshis |
| `nTxWeight` | `int32_t` | const | Cached weight (WU) |
| `nUsageSize` | `size_t` | const | Dynamic memory usage |
| `nTime` | `int64_t` | const | Timestamp when added |
| `entry_sequence` | `uint64_t` | const | Monotonic ordering for relay |
| `entryHeight` | `unsigned int` | const | Chain height when added |
| `spendsCoinbase` | `bool` | const | Whether it spends a coinbase |
| `sigOpCost` | `int64_t` | const | Signature operation cost |
| `m_modified_fee` | `CAmount` | **mutable** | Fee + prioritization delta |
| `lockPoints` | `LockPoints` | **mutable** | BIP68 locktime tracking |
| `idx_randomized` | `size_t` | **mutable** | Position in random-order vector |

**Why const fields?** Once a transaction enters the mempool, its fundamental
properties (fee, size, weight) never change. Only the *modified fee* (via
`prioritisetransaction` RPC) and *lock points* (after reorg) can be updated.

**Why inherit from TxGraph::Ref?** This is RAII for graph membership. When
`mapTx.erase(it)` is called, the entry's destructor fires, which calls
`TxGraph::Ref::~Ref()`, which tells TxGraph to remove the transaction. No
separate "remove from graph" call is needed.

**Virtual size**: `GetTxSize()` computes the *virtual* size, which accounts
for both weight and sigop cost:
```cpp
GetVirtualTransactionSize(nTxWeight, sigOpCost, ::nBytesPerSigOp)
```

### 3.2 LockPoints (`kernel/mempool_entry.h`)

Caches BIP68 (relative lock-time) evaluation results to avoid recomputation:

| Field | Type | Purpose |
|-------|------|---------|
| `height` | `int` | Block height at which tx becomes final |
| `time` | `int64_t` | Median time past for time-based locks |
| `maxInputBlock` | `CBlockIndex*` | Highest block containing a referenced input |

`maxInputBlock` enables efficient reorg detection: if a reorg doesn't go deeper
than this block, the cached LockPoints are still valid.

### 3.3 CTxMemPool (`txmempool.h`)

The main container. Let's break its ~90 member variables and methods into
logical groups.

#### Configuration (immutable after construction)

| Field | Type | Purpose |
|-------|------|---------|
| `m_opts` | `Options` | All mempool settings |
| `ROLLING_FEE_HALFLIFE` | `static const int` | 12 hours (43200s) — decay rate for min fee |

`Options` (= `kernel::MemPoolOptions`) bundles together:
- `max_size_bytes`: Default 300 MB
- `expiry`: Default 336 hours (2 weeks)
- `incremental_relay_feerate`, `min_relay_feerate`, `dust_relay_feerate`
- `limits`: Cluster/ancestor/descendant caps
- `signals`: Pointer to `ValidationSignals` for notifications
- `check_ratio`: Probability of running consistency checks

#### Transaction Storage

| Field | Type | Purpose |
|-------|------|---------|
| `mapTx` | `indexed_transaction_set` | Main multi-index container (§5) |
| `txns_randomized` | `vector<pair<Wtxid,txiter>>` | Random-order access for relay |
| `mapNextTx` | `indirectmap<COutPoint,txiter>` | Outpoint → spending tx |
| `mapDeltas` | `map<Txid,CAmount>` | Manual fee adjustments |

#### Graph Engine

| Field | Type | Purpose |
|-------|------|---------|
| `m_txgraph` | `unique_ptr<TxGraph>` | Dependency graph + linearization |
| `m_builder` | `unique_ptr<TxGraph::BlockBuilder>` | Active block construction session |
| `m_have_changeset` | `bool` | Guard: at most one ChangeSet at a time |

#### Accounting

| Field | Type | Purpose |
|-------|------|---------|
| `totalTxSize` | `uint64_t` | Sum of all virtual sizes |
| `m_total_fee` | `CAmount` | Sum of all base fees |
| `cachedInnerUsage` | `uint64_t` | Sum of all `DynamicMemoryUsage()` |
| `nTransactionsUpdated` | `unsigned int` (atomic) | External change counter (for `getblocktemplate`) |
| `m_sequence_number` | `uint64_t` | Monotonic event counter |

#### Fee Floor Management

| Field | Type | Purpose |
|-------|------|---------|
| `rollingMinimumFeeRate` | `double` | Current minimum fee to enter the pool |
| `lastRollingFeeUpdate` | `int64_t` | Timestamp of last fee update |
| `blockSinceLastRollingFeeBump` | `bool` | Reset flag: allow fee decay after block |

#### Tracking

| Field | Type | Purpose |
|-------|------|---------|
| `m_unbroadcast_txids` | `set<Txid>` | Locally-submitted txs needing rebroadcast |
| `m_load_tried` | `bool` | Whether mempool persistence load was attempted |

### 3.4 ChangeSet (nested in CTxMemPool)

The transactional interface for batched modifications — see §7 for details.

### 3.5 CCoinsViewMemPool (`txmempool.h`)

A UTXO view that overlays mempool outputs on top of the chain — see §11.

### 3.6 TxMempoolInfo (`txmempool.h`)

A lightweight snapshot of a mempool entry for RPC/relay:

| Field | Type | Purpose |
|-------|------|---------|
| `tx` | `CTransactionRef` | The transaction |
| `m_time` | `chrono::seconds` | Entry time |
| `fee` | `CAmount` | Base fee |
| `vsize` | `int32_t` | Virtual size |
| `nFeeDelta` | `int64_t` | Prioritization delta |

### 3.7 Notification Structs (`kernel/mempool_entry.h`)

| Struct | Used For | Extra Fields |
|--------|----------|--------------|
| `TransactionInfo` | Base: tx + fee + vsize + height | — |
| `RemovedMempoolTransactionInfo` | Removal notifications | Wraps `TransactionInfo` |
| `NewMempoolTransactionInfo` | Addition notifications | `m_mempool_limit_bypassed`, `m_submitted_in_package`, `m_chainstate_is_current`, `m_has_no_mempool_parents` |

### 3.8 MemPoolRemovalReason (`kernel/mempool_removal_reason.h`)

```
┌─────────────┬───────────────────────────────────────────┐
│ BLOCK       │ Confirmed in a block                      │
│ CONFLICT    │ Inputs spent by an in-block transaction   │
│ REPLACED    │ Replaced via RBF                          │
│ SIZELIMIT   │ Evicted due to mempool size limit         │
│ EXPIRY      │ Exceeded max age (default: 2 weeks)       │
│ REORG       │ Invalidated by chain reorganization       │
└─────────────┴───────────────────────────────────────────┘
```

### 3.9 TxGraph (`txgraph.h`)

A pure graph abstraction, deliberately Bitcoin-unaware. Key characteristics:

- **Two-level model**: Maintains a `MAIN` graph and optionally a `STAGING`
  graph (copy-on-write semantics for evaluating changes before committing)
- **Cluster-based**: Connected components are called *clusters*; each is
  independently linearized for mining optimality
- **Chunk-based**: Linearizations are partitioned into *chunks* — groups of
  transactions that should be mined together (each chunk is the
  highest-feerate prefix of the remaining linearization)
- **Lazy computation**: `DoWork(iters)` performs background optimization;
  callers explicitly request computation via queries

| Method | Purpose |
|--------|---------|
| `AddTransaction(feerate)` | Create node, return Ref |
| `RemoveTransaction(ref)` | Remove node |
| `AddDependency(parent, child)` | Add edge |
| `SetTransactionFee(ref, fee)` | Update fee |
| `GetAncestors(ref, level)` | All ancestors (transitive) |
| `GetDescendants(ref, level)` | All descendants (transitive) |
| `GetCluster(ref, level)` | Connected component |
| `GetWorstMainChunk()` | Lowest-feerate chunk (for eviction) |
| `GetBlockBuilder()` | Mining iterator |
| `CompareMainOrder(a, b)` | Compare mining priority |
| `StartStaging() / CommitStaging() / AbortStaging()` | Transaction semantics |
| `Trim()` | Evict to satisfy limits |
| `IsOversized(level)` | Cluster limit exceeded? |
| `GetMainStagingDiagrams()` | Old vs new fee diagrams (for RBF) |

**Cluster size limit**: `MAX_CLUSTER_COUNT_LIMIT = 64` transactions per cluster
(configurable down from this maximum).

---

## 4. UML Class Diagram

```
┌───────────────────────────────────────────────────────────┐
│                      CTxMemPool                            │
├───────────────────────────────────────────────────────────┤
│ - mapTx: indexed_transaction_set                          │
│ - mapNextTx: indirectmap<COutPoint, txiter>               │
│ - mapDeltas: map<Txid, CAmount>                           │
│ - txns_randomized: vector<pair<Wtxid,txiter>>             │
│ - m_txgraph: unique_ptr<TxGraph>                          │
│ - m_builder: unique_ptr<BlockBuilder>   (mutable)         │
│ - totalTxSize, m_total_fee, cachedInnerUsage              │
│ - rollingMinimumFeeRate: double                           │
│ - m_unbroadcast_txids: set<Txid>                          │
│ - m_opts: Options                                         │
│ + cs: RecursiveMutex                                      │
├───────────────────────────────────────────────────────────┤
│ + addNewTransaction(txiter)                               │
│ + removeUnchecked(txiter, reason)                         │
│ + removeRecursive(tx, reason)                             │
│ + removeForBlock(vtx, height)                             │
│ + removeForReorg(chain, filter)                           │
│ + TrimToSize(sizelimit)                                   │
│ + Expire(time)                                            │
│ + PrioritiseTransaction(txid, delta)                      │
│ + GetIter(txid/wtxid) → optional<txiter>                  │
│ + CalculateMemPoolAncestors(entry) → setEntries           │
│ + CalculateDescendants(it, set)                           │
│ + GetChangeSet() → unique_ptr<ChangeSet>                  │
│ + StartBlockBuilding()                                    │
│ + GetBlockBuilderChunk(entries) → FeePerWeight            │
│ + check(coins, height)                                    │
└──────────────┬────────────────────────────────────────────┘
               │ contains
               │
    ┌──────────▼──────────┐        ┌───────────────────────┐
    │    ChangeSet         │        │    TxGraph             │
    ├─────────────────────┤        ├───────────────────────┤
    │ - m_to_add          │        │ + AddTransaction()     │
    │ - m_to_remove       │        │ + RemoveTransaction()  │
    │ - m_entry_vec       │        │ + AddDependency()      │
    │ - m_ancestors       │◄───────│ + GetAncestors()       │
    │ - m_pool: CTxMemPool│uses    │ + GetDescendants()     │
    ├─────────────────────┤        │ + GetWorstMainChunk()  │
    │ + StageAddition()   │        │ + GetBlockBuilder()    │
    │ + StageRemoval()    │        │ + StartStaging()       │
    │ + Apply()           │        │ + CommitStaging()      │
    │ + CalculateChunks.. │        │ + AbortStaging()       │
    │ + CheckPolicyLimits │        │ + Trim()               │
    └─────────────────────┘        └───────────────────────┘

    ┌─────────────────────────────────────────────────────────┐
    │              CTxMemPoolEntry : TxGraph::Ref              │
    ├─────────────────────────────────────────────────────────┤
    │ - tx: CTransactionRef           (const)                 │
    │ - nFee: CAmount                 (const)                 │
    │ - nTxWeight: int32_t            (const)                 │
    │ - nTime: int64_t                (const)                 │
    │ - entryHeight: unsigned int     (const)                 │
    │ - spendsCoinbase: bool          (const)                 │
    │ - sigOpCost: int64_t            (const)                 │
    │ - m_modified_fee: CAmount       (mutable)               │
    │ - lockPoints: LockPoints        (mutable)               │
    │ - idx_randomized: size_t        (mutable)               │
    ├─────────────────────────────────────────────────────────┤
    │ + GetTx(), GetSharedTx(), GetFee()                      │
    │ + GetTxSize(), GetModifiedFee()                         │
    │ + UpdateModifiedFee(diff), UpdateLockPoints(lp)         │
    └─────────────────────────────────────────────────────────┘

    ┌───────────────────────────────────────────────┐
    │           CCoinsViewMemPool                    │
    │             : CCoinsViewBacked                 │
    ├───────────────────────────────────────────────┤
    │ - mempool: const CTxMemPool&                  │
    │ - m_temp_added: map<COutPoint, Coin>          │
    │ - m_non_base_coins: set<COutPoint>            │
    ├───────────────────────────────────────────────┤
    │ + GetCoin(outpoint) → optional<Coin>          │
    │ + PackageAddTransaction(tx)                   │
    │ + Reset()                                     │
    └───────────────────────────────────────────────┘

    ┌───────────────────────────────────────────────┐
    │          kernel::MemPoolOptions                │
    ├───────────────────────────────────────────────┤
    │ check_ratio: int           = 0                │
    │ max_size_bytes: int64_t    = 300 MB           │
    │ expiry: seconds            = 336 hours        │
    │ incremental_relay_feerate  = 1000 sat/kvB     │
    │ min_relay_feerate          = 1000 sat/kvB     │
    │ dust_relay_feerate         = 3000 sat/kvB     │
    │ max_datacarrier_bytes      = 83 bytes         │
    │ permit_bare_multisig: bool = true             │
    │ require_standard: bool     = true             │
    │ limits: MemPoolLimits                         │
    │ signals: ValidationSignals*                   │
    └───────────────────────────────────────────────┘

    ┌───────────────────────────────────────────────┐
    │          kernel::MemPoolLimits                 │
    ├───────────────────────────────────────────────┤
    │ cluster_count: unsigned                       │
    │ cluster_size_vbytes: int64_t                  │
    │ ancestor_count: int64_t                       │
    │ descendant_count: int64_t                     │
    ├───────────────────────────────────────────────┤
    │ + NoLimits() → MemPoolLimits [static]         │
    └───────────────────────────────────────────────┘
```

---

## 5. The Multi-Index Container — How Transactions Are Stored

The heart of CTxMemPool is `mapTx`, a Boost Multi-Index Container that provides
three simultaneous views of the same transaction set:

```
                    mapTx: indexed_transaction_set
                    ┌────────────────────────────┐
                    │    CTxMemPoolEntry[]         │
                    │    (all mempool txs live     │
                    │     here, once)              │
                    └──┬──────────┬──────────┬────┘
                       │          │          │
              Index 0  │  Index 1 │  Index 2 │
              ─────────┘  ────────┘  ────────┘
              hashed by   hashed by  ordered by
              txid        wtxid      entry time
              (primary)   (tag:      (tag:
                          index_by_  entry_time)
                          wtxid)
              ─────────   ─────────  ──────────
              O(1)        O(1)       O(log n)
              lookup      lookup     iteration
```

### Why three indices?

| Index | Tag | Use Case |
|-------|-----|----------|
| 0 (primary) | — | Most lookups: `GetIter(txid)`, `exists(txid)` |
| 1 | `index_by_wtxid` | Segwit-aware lookups: `exists(wtxid)`, relay by wtxid |
| 2 | `entry_time` | Expiration: `Expire()` iterates oldest-first |

**Important**: There is no fee-rate index. Mining order comes from TxGraph's
linearization, not from a direct sort in mapTx.

### Extractors

Two functors extract keys from entries:

```cpp
struct mempoolentry_txid {
    Txid operator()(const CTxMemPoolEntry& entry) const;
    Txid operator()(const CTransactionRef& tx) const;
};

struct mempoolentry_wtxid {
    Wtxid operator()(const CTxMemPoolEntry& entry) const;
    Wtxid operator()(const CTransactionRef& tx) const;
};
```

The dual overloads allow searching by either an entry or a bare `CTransactionRef`.

### The mapNextTx Reverse Index

Separate from mapTx, `mapNextTx` is an `indirectmap<COutPoint, txiter>` that
maps each spent outpoint to the mempool transaction spending it:

```
  mapNextTx:
  ┌──────────────────────┬──────────────────────────┐
  │ COutPoint            │ txiter (→ spending tx)    │
  ├──────────────────────┼──────────────────────────┤
  │ txA:0                │ → entry for txB           │
  │ txA:1                │ → entry for txC           │
  │ txD:0                │ → entry for txE           │
  └──────────────────────┴──────────────────────────┘
```

**Purpose**: Conflict detection. When checking if a new transaction spends the
same input as an existing one (RBF), `mapNextTx.find(prevout)` answers in O(1).
Also used for computing children: scan `mapNextTx` for all entries with the same
parent txid.

### The Randomization Vector

`txns_randomized` stores `(Wtxid, txiter)` pairs in arbitrary order. This is used
for efficient random transaction selection (e.g., for `getrawmempool`). Each
entry has an `idx_randomized` field pointing to its slot, enabling O(1)
swap-with-back removal.

---

## 6. Transaction Lifecycle — From Arrival to Departure

```
   New tx from         RPC
   peer (P2P)      sendrawtx
       │               │
       ▼               ▼
  ┌─────────────────────────────┐
  │  MemPoolAccept              │ ← Validation layer
  │  (PreChecks → PolicyScript  │
  │   → ConsensusScript → ...)  │
  └──────────────┬──────────────┘
                 │ Creates ChangeSet
                 ▼
  ┌──────────────────────────────────────────┐
  │  ChangeSet::StageAddition(tx, fee, ...)  │ ← Staging graph
  │  ChangeSet::StageRemoval(conflicts)      │   (if RBF)
  │  CheckMemPoolPolicyLimits()              │
  │  CalculateChunksForRBF()                 │ ← Diagram check
  └──────────────┬───────────────────────────┘
                 │ All checks pass
                 ▼
  ┌──────────────────────────────────────────┐
  │  ChangeSet::Apply()                      │
  │   ├── ProcessDependencies()              │ ← Find parents
  │   ├── CommitStaging() in TxGraph         │ ← Promote staging → main
  │   ├── RemoveStaged(m_to_remove, REPLACED)│ ← Remove RBF victims
  │   ├── Splice entries from m_to_add       │ ← Transfer into mapTx
  │   │    into CTxMemPool::mapTx            │
  │   └── addNewTransaction(txiter)          │ ← Update mapNextTx, accounting
  └──────────────┬───────────────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────┐
  │  In mempool — waiting to be mined        │
  │  ┌─ Periodic: Expire() removes old txs   │
  │  ├─ TrimToSize() evicts low-fee txs      │
  │  └─ removeForBlock() on new block         │
  └──────────────────────────────────────────┘
```

### Addition: addNewTransaction()

Called once per entry after `Apply()`. This is where the mempool's secondary data
structures are updated:

```
addNewTransaction(newit):
  1. cachedInnerUsage += entry.DynamicMemoryUsage()
  2. For each input in tx.vin:
       mapNextTx[prevout] = newit              ← Reverse spending index
  3. totalTxSize += entry.GetTxSize()
  4. m_total_fee  += entry.GetFee()
  5. nTransactionsUpdated++                    ← Signal for getblocktemplate
  6. txns_randomized.push_back({wtxid, newit}) ← Random access slot
     newit->idx_randomized = index             ← Back-reference
  7. TRACEPOINT(mempool, added, ...)           ← eBPF observability
```

### Removal: removeUnchecked()

The inverse operation, with careful bookkeeping:

```
removeUnchecked(it, reason):
  1. Signal notification (unless BLOCK removal)
     └── TransactionRemovedFromMempool(tx, reason, sequence)
  2. For each input in tx.vin:
       mapNextTx.erase(prevout)               ← Clean reverse index
  3. RemoveUnbroadcastTx(txid)                ← Clean rebroadcast set
  4. Swap-with-back removal from txns_randomized:
     ├── Move last element to this slot
     ├── Update moved element's idx_randomized
     └── Pop back (or shrink if < half capacity)
  5. totalTxSize -= entry.GetTxSize()
  6. m_total_fee  -= entry.GetFee()
  7. cachedInnerUsage -= entry.DynamicMemoryUsage()
  8. mapTx.erase(it)                          ← Triggers ~TxGraph::Ref
  9. nTransactionsUpdated++
```

**Why no TxGraph::RemoveTransaction call?** Because CTxMemPoolEntry inherits from
TxGraph::Ref. When `mapTx.erase(it)` destroys the entry, the Ref destructor
automatically notifies TxGraph. This is RAII at work.

### Removal Cascade: removeRecursive()

When a transaction must be removed (e.g., conflict), all its descendants must go
too. Two variants exist:

1. **By iterator**: Ask TxGraph for all descendants, remove each
2. **By CTransaction**: For txs not in the pool (e.g., confirmed txs during
   reorg), scan mapNextTx for direct children, then get their descendants via
   `GetDescendantsUnion()`

**Critical invariant**: Descendant computation must happen *before* any removals,
because removing entries invalidates iterators and graph references.

---

## 7. The ChangeSet — Atomic Batch Operations

ChangeSet is CTxMemPool's transaction mechanism — it batches additions and
removals so they can be evaluated atomically before committing.

```
┌─────────────────────────────────────────────────────┐
│                    ChangeSet                         │
│                                                     │
│  m_to_add: indexed_transaction_set                  │
│  ┌────┐┌────┐┌────┐                                │
│  │ tx1 ││ tx2 ││ tx3 │   ← Staged additions          │
│  └────┘└────┘└────┘                                │
│                                                     │
│  m_to_remove: setEntries                            │
│  ┌────┐┌────┐                                       │
│  │ old1││ old2│        ← Staged removals (RBF)       │
│  └────┘└────┘                                       │
│                                                     │
│  m_entry_vec: vector<txiter>  ← Insertion order     │
│  m_ancestors: map<txiter, setEntries>  ← Cached     │
│  m_dependencies_processed: bool                     │
│                                                     │
│  TxGraph staging graph ← Parallel graph state       │
└─────────────────────────────────────────────────────┘
```

### Lifecycle

```
1. pool.GetChangeSet()            ← Creates ChangeSet + TxGraph::StartStaging()
2. changeset.StageAddition(...)   ← Adds to m_to_add + TxGraph::AddTransaction()
3. changeset.StageRemoval(iter)   ← Adds to m_to_remove
4. changeset.CheckPolicyLimits()  ← Validates cluster limits on staging graph
5. changeset.CalculateChunksForRBF() ← Compares main vs staging fee diagrams
6. changeset.Apply()              ← CommitStaging + RemoveStaged + splice entries
```

**Guard mechanism**: `m_have_changeset` ensures only one ChangeSet exists at a
time. The ChangeSet constructor sets it to true; the destructor resets it to
false (and calls `AbortStaging()` if Apply was never called).

### StageAddition internals

```cpp
TxHandle StageAddition(tx, fee, time, height, sequence,
                       spends_coinbase, sigops_cost, lp)
{
    // Apply any pre-existing fee prioritization
    CAmount delta{0};
    m_pool->ApplyDelta(tx->GetHash(), delta);

    // Create TxGraph node in staging with sigops-adjusted weight
    TxGraph::Ref ref(m_pool->m_txgraph->AddTransaction(
        FeePerWeight(fee, GetSigOpsAdjustedWeight(weight, sigops, nBytesPerSigOp))));

    // Insert entry into staging container
    auto newit = m_to_add.emplace(std::move(ref), tx, fee, ...);

    // Apply delta if any
    if (delta) {
        newit->UpdateModifiedFee(delta);
        m_pool->m_txgraph->SetTransactionFee(*newit, newit->GetModifiedFee());
    }
    m_entry_vec.push_back(newit);
    return newit;
}
```

### ProcessDependencies

Called lazily (before Apply or CheckPolicyLimits). Scans each staged addition's
inputs to find parent transactions — in either the existing pool or in the
staging set itself (for packages):

```
For each staged entry:
  For each input (txin):
    parent = pool.GetIter(txin.prevout.hash)      ← In existing pool?
    if not found:
      parent = m_to_add.find(txin.prevout.hash)   ← In staging?
    if found:
      m_txgraph->AddDependency(*parent, *entry)   ← Add edge
```

### Apply — The Commit

```
Apply():
  1. ProcessDependencies() if not done
  2. m_txgraph->CommitStaging()        ← Staging becomes main
  3. RemoveStaged(m_to_remove, REPLACED) ← Evict RBF victims
  4. For each entry in m_entry_vec:
       Extract node from m_to_add      ← Boost node-handle extraction
       Insert into pool.mapTx          ← Constant-time splice
       addNewTransaction(it)           ← Update secondary structures
  5. m_txgraph->DoWork(POST_CHANGE_WORK) ← Background optimization
  6. Clear all staging structures
```

**Node-handle extraction** is key: `m_to_add.extract(iter)` detaches the entry
from the staging container without destroying it, and `mapTx.insert(handle)`
re-inserts it into the main container — no copy, no move, no re-allocation of
the CTxMemPoolEntry.

---

## 8. Ancestor & Descendant Tracking via TxGraph

All relationship queries are delegated to TxGraph, which maintains the full
transitive closure of dependencies.

### CalculateMemPoolAncestors

Two paths depending on whether the transaction is already in the graph:

```
CalculateMemPoolAncestors(entry):
  Path A: entry is in TxGraph
    → m_txgraph->GetAncestors(entry, MAIN)
    → Convert Ref* pointers to txiters

  Path B: entry is new (not yet added)
    → Scan entry.tx.vin for parent txids
    → For each parent in mapTx:
        → Get its ancestors from TxGraph
        → Union into result set
    → Return combined set
```

### Cluster Queries

Clusters are the connected components of the dependency graph. They matter
because:

1. **All transactions in a cluster are linearized together** for mining
2. **Cluster size limits** prevent DoS (default: `DEFAULT_CLUSTER_LIMIT` txs)
3. **RBF evaluation** compares fee diagrams at the cluster level

```
GatherClusters(txids):
  For each txid:
    cluster = m_txgraph->GetCluster(entry, MAIN)
    if cluster representative is new:       ← Dedup by cluster
      add all cluster members to result
  if result.size() > 500: return {}         ← DoS protection
  return result
```

---

## 9. Eviction & Fee Management

When the mempool exceeds its size limit (`-maxmempool`, default 300MB),
transactions must be evicted. The strategy is to remove the worst-performing
transactions first.

### TrimToSize

```
TrimToSize(sizelimit):
  while (DynamicMemoryUsage() > sizelimit):
    ┌─────────────────────────────────────────────┐
    │  worst_chunk = m_txgraph->GetWorstMainChunk()│
    │  (lowest feerate chunk in the linearization)  │
    └──────────────────────┬──────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────┐
    │  removed_feerate = chunk_feerate             │
    │  removed_feerate += incremental_relay_feerate│ ← Prevent re-entry
    │  trackPackageRemoved(removed_feerate)        │ ← Bump rolling min fee
    └──────────────────────┬──────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────┐
    │  For each tx in worst_chunk:                 │
    │    removeUnchecked(tx, SIZELIMIT)            │
    └──────────────────────┬──────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────┐
    │  Track orphaned outpoints for wallet:        │
    │  pvNoSpendsRemaining ← inputs no longer      │
    │  spent by any mempool tx                     │
    └─────────────────────────────────────────────┘
```

**Why chunks?** Because transactions within a chunk are connected — they're
dependencies of each other. Removing one without the others would break the
linearization and potentially leave orphan transactions.

### Rolling Minimum Fee

The mempool maintains a fee floor that dynamically adjusts:

```
GetMinFee(sizelimit):
  if no block since last bump: return current fee (no decay)

  Compute elapsed time since last update

  halflife = 12 hours (ROLLING_FEE_HALFLIFE)
  if memory < 25% full:  halflife /= 4    ← Decay 4× faster
  if memory < 50% full:  halflife /= 2    ← Decay 2× faster

  rollingMinimumFeeRate /= 2^(elapsed / halflife)

  if rate < incremental_relay_feerate/2:
    rate = 0                              ← Back to normal

  return max(rate, incremental_relay_feerate)
```

**Intuition**: After evicting transactions, the fee floor rises to prevent them
from immediately re-entering. The floor then decays exponentially — faster when
the mempool is emptier (more room available).

### Expiry

`Expire(time)` uses the `entry_time` index for efficient oldest-first scanning:

```
Expire(time):
  Use mapTx.get<entry_time>() index
  Iterate from beginning (oldest entries)
  while entry.GetTime() < time:
    collect entry + all its descendants (via CalculateDescendants)
  RemoveStaged(collected, EXPIRY)
  return count
```

---

## 10. Block Connection & Disconnection

### Block Connected: removeForBlock()

When a new block arrives, confirmed transactions leave the mempool:

```
removeForBlock(vtx, nBlockHeight):
  For each tx in block:
    ┌──────────────────────────────────────────────┐
    │  if tx is in mempool:                         │
    │    record RemovedMempoolTransactionInfo        │
    │    removeUnchecked(it, BLOCK)                  │
    │                                                │
    │  removeConflicts(tx)                           │
    │    ← For each input of the confirmed tx:       │
    │       if that input is spent by a mempool tx:  │
    │         removeRecursive(spender, CONFLICT)     │
    │                                                │
    │  ClearPrioritisation(tx.hash)                  │
    └──────────────────────────────────────────────┘

  Signal: MempoolTransactionsRemovedForBlock(removed, height)

  lastRollingFeeUpdate = now
  blockSinceLastRollingFeeBump = true      ← Allow fee to decay
  m_txgraph->DoWork(POST_CHANGE_WORK)     ← Re-optimize graph
```

**Why BLOCK vs CONFLICT?** Transactions confirmed in the block get `BLOCK`
reason (they succeeded). But if the block contains a transaction spending the
same input as a mempool transaction, that mempool tx gets `CONFLICT` (it lost
the race).

### Block Disconnected: UpdateTransactionsFromBlock()

During a reorg, previously-confirmed transactions re-enter the mempool. Their
parent-child relationships need to be re-established:

```
UpdateTransactionsFromBlock(vHashesToUpdate):
  For each txid in REVERSE order:        ← Process descendants before ancestors
    if tx is in mempool:
      Scan mapNextTx for children
      For each child spending this tx's outputs:
        m_txgraph->AddDependency(parent=this, child)

  Trim() if graph became oversized
  Remove trimmed entries with SIZELIMIT reason
```

**Why reverse order?** So that when we process a parent transaction, all its
descendant relationships have already been established. This ensures the graph
is fully connected before any trimming occurs.

### Reorg Cleanup: removeForReorg()

After block disconnection, some transactions may be invalid (e.g., spending an
immature coinbase, or non-final under new chain state):

```
removeForReorg(chain, filter_predicate):
  For each entry in mapTx:
    if filter_predicate(entry) is true:     ← Not final or immature
      mark for removal (collect TxGraph::Ref pointers)

  GetDescendantsUnion(marked)               ← Include all descendants
  removeUnchecked(all, REORG)

  For remaining entries:
    assert(TestLockPointValidity(lockPoints)) ← Verify survivors are valid
```

---

## 11. CCoinsViewMemPool — The UTXO Bridge

`CCoinsViewMemPool` is a layered UTXO view that adds mempool outputs on top of
the chain's coin set. It inherits from `CCoinsViewBacked`, forming a chain:

```
            GetCoin(outpoint) lookup order
            ┌──────────────────────────────┐
 Priority 1 │  m_temp_added                 │ ← Package validation:
            │  (manually added coins for    │   intra-package deps
            │   in-flight package members)  │
            ├──────────────────────────────┤
 Priority 2 │  mempool (via mempool.get())  │ ← Unconfirmed outputs
            │  Returns coins at height      │   with MEMPOOL_HEIGHT
            │  MEMPOOL_HEIGHT (0x7FFFFFFF)  │   (= not yet in a block)
            ├──────────────────────────────┤
 Priority 3 │  base view (chain UTXO set)   │ ← Confirmed outputs
            │  (via CCoinsViewBacked)        │
            └──────────────────────────────┘
```

**MEMPOOL_HEIGHT** (`0x7FFFFFFF`) is a sentinel value that marks coins as
coming from the mempool rather than the chain. This allows downstream code to
distinguish confirmed from unconfirmed coins.

**PackageAddTransaction()** temporarily adds a transaction's outputs to
`m_temp_added`. This is how package validation works: when validating tx B that
depends on tx A (both in the same package), A's outputs are added via
`PackageAddTransaction(A)` so that B can find them during input validation,
even though A isn't in the mempool yet.

---

## 12. Block Building — Mining Transaction Selection

The mempool provides a **BlockBuilder** interface for miners to select
transactions in optimal fee-rate order:

```
Block building session:
  ┌─────────────────────────────────────────────────────┐
  │  StartBlockBuilding()                                │
  │  └── m_builder = m_txgraph->GetBlockBuilder()        │
  │                                                      │
  │  Loop:                                               │
  │    chunk = GetBlockBuilderChunk(entries)              │
  │    ├── m_builder->GetCurrentChunk()                   │
  │    ├── Returns {entries[], feerate} or empty           │
  │    │                                                  │
  │    if chunk fits in block:                            │
  │      IncludeBuilderChunk()                            │
  │      └── m_builder->Include()  ← Accept, move to next │
  │    else:                                              │
  │      SkipBuilderChunk()                               │
  │      └── m_builder->Skip()    ← Reject entire cluster │
  │                                                      │
  │  StopBlockBuilding()                                  │
  │  └── m_builder.reset()                                │
  └─────────────────────────────────────────────────────┘
```

**Chunk semantics**: A chunk is a group of transactions from the same cluster
that should be mined together (they form the highest-feerate prefix of their
cluster's linearization). Skip() rejects the current chunk *and all remaining
chunks from that cluster*, because if the best chunk from a cluster doesn't fit,
lower-feerate chunks from the same cluster certainly won't.

### Fee Diagram

`GetFeerateDiagram()` builds a cumulative feerate diagram by iterating through
all chunks:

```
GetFeerateDiagram():
  result = [{fee:0, size:0}]            ← Origin point
  StartBlockBuilding()

  for each chunk (via GetBlockBuilderChunk):
    result.push_back(prev + chunk)      ← Cumulative {fee, size}
    IncludeBuilderChunk()

  StopBlockBuilding()
  return result
```

This diagram is used for RBF evaluation: a replacement is only accepted if it
produces a strictly better feerate diagram than the current mempool state.

---

## 13. Thread Safety & Locking Model

### Lock Hierarchy

```
cs_main (global chain lock)
  └── CTxMemPool::cs (mempool lock)
```

**Rule**: When both locks are needed, `cs_main` must be acquired first.
Violating this order would cause deadlocks.

### When Each Lock Is Needed

| Operation | cs_main | cs | Why both? |
|-----------|---------|-----|-----------|
| Read mempool (RPC query) | | ✓ | Internal consistency only |
| Remove transaction | | ✓ | Mempool-internal |
| Add transaction | ✓ | ✓ | Must be consistent with chain tip |
| removeForReorg | ✓ | ✓ | Accesses chain state |
| UpdateTransactionsFromBlock | ✓ | ✓ | Processes block-related txs |
| check() consistency | ✓ | ✓ | Validates against chain UTXO |

### Consistency Guarantee

From the header comment:

> Holding `cs_main` + `cs` guarantees the mempool is consistent with the
> current chain tip. Holding only `cs` guarantees the mempool is consistent
> with *some* recent chain state.

This means read-only RPC calls (like `getrawmempool`) only need `cs`, but
chain-modifying operations need both locks.

### Mutable Fields

Several fields in CTxMemPoolEntry are `mutable`, allowing modification through
const iterators (required by boost::multi_index_container). This is thread-safe
because:

- `m_modified_fee`: Only modified under `cs` via `PrioritiseTransaction()`
- `lockPoints`: Only modified under `cs` + `cs_main` via `removeForReorg()`
- `idx_randomized`: Only modified under `cs` during add/remove

---

## 14. Key Invariants & Consistency Checks

The `check()` method (running probabilistically when `check_ratio > 0`) verifies
the following invariants:

### Data Structure Consistency

| Invariant | What's Checked |
|-----------|----------------|
| **mapTx ↔ mapNextTx** | Every tx input in mapTx has a corresponding entry in mapNextTx; every mapNextTx entry points to a valid mapTx entry |
| **Memory accounting** | `cachedInnerUsage` == sum of all `DynamicMemoryUsage()` |
| **Size accounting** | `totalTxSize` == sum of all `GetTxSize()` |
| **Fee accounting** | `m_total_fee` == sum of all `GetFee()` (base fee, not modified) |
| **Fee diagram** | Last point matches total modified fee and total adjusted weight |
| **txns_randomized** | Kept in sync with mapTx (same count) |

### Graph Consistency

| Invariant | What's Checked |
|-----------|----------------|
| **Not oversized** | `m_txgraph->IsOversized(MAIN)` is false |
| **TxGraph sanity** | `m_txgraph->SanityCheck()` passes |
| **Mining order** | Sorted order via `CompareMainOrder` is monotonic |
| **Topological validity** | Fee diagram boundaries align with chunk transitions |

### Input Validity

| Invariant | What's Checked |
|-----------|----------------|
| **Inputs exist** | Every input is available in a duplicate coin cache |
| **Consensus rules** | `Consensus::CheckTxInputs()` passes for every transaction |
| **Parent-child** | `GetParents()` matches actual input references |

---

## 15. Improvement Proposals

### 15.1 Replace RecursiveMutex with Mutex

`CTxMemPool::cs` is a `RecursiveMutex`, but recursive locking masks bugs where
a function accidentally re-enters itself while already holding the lock. A
standard `Mutex` would catch these at compile time via `EXCLUSIVE_LOCKS_REQUIRED`
annotations. This requires auditing all call paths to ensure no recursive
acquisition occurs — a large but worthwhile effort.

### 15.2 Extract mapNextTx into TxGraph

`mapNextTx` duplicates information that TxGraph already knows (parent-child
relationships). Currently, CTxMemPool maintains mapNextTx separately by scanning
transaction inputs during add/remove. If TxGraph exposed an efficient
"which-transactions-spend-this-output" query, mapNextTx could be eliminated,
removing a class of inconsistency bugs.

### 15.3 Separate Fee Prioritization from CTxMemPool

`mapDeltas` (fee prioritization via `prioritisetransaction` RPC) can hold entries
for transactions not yet in the mempool. This pre-application pattern makes it
hard to reason about state. Extracting it into a dedicated `FeePrioritizer` class
with a clear interface would improve testability.

### 15.4 Replace Multi-Index Container with Custom Structure

The Boost Multi-Index Container is powerful but heavyweight:
- 9 pointers per entry (for 3 indices) adds significant memory overhead
- Compile times suffer due to heavy template instantiation
- The `entry_time` index is only used by `Expire()`, which runs infrequently

A custom hash map (by txid) + a secondary hash map (by wtxid) + a simple sorted
vector or min-heap (by time) could reduce memory and improve compilation.

### 15.5 Make ChangeSet a First-Class Type

Currently, `ChangeSet` is a nested class of `CTxMemPool` with `friend` access to
the pool's internals. This tight coupling makes it hard to test in isolation.
Moving it to a standalone class with a well-defined interface to CTxMemPool would
improve modularity. The existing `m_have_changeset` guard shows the code is
already thinking in terms of exclusive access — this could be formalized with a
proper RAII token.

### 15.6 Type-Safe Removal Reasons

`MemPoolRemovalReason` is used as a parameter to `removeUnchecked`, but the
function's behavior differs subtly per reason (BLOCK removals skip
notifications). This could be made explicit by having separate removal
functions (e.g., `removeForConfirmation()`, `removeForEviction()`) that
encode the behavioral differences in their implementation rather than a runtime
enum switch.

### 15.7 Unify Accounting Updates

The add/remove paths manually update five counters (`totalTxSize`, `m_total_fee`,
`cachedInnerUsage`, `nTransactionsUpdated`, `m_sequence_number`) plus secondary
structures (`mapNextTx`, `txns_randomized`). This is error-prone — forgetting
one update creates subtle bugs that only `check()` catches. A single
`AccountingUpdate` struct that captures the delta and is applied atomically
would reduce this risk.

---

> **Document scope**: This document describes `src/txmempool.{h,cpp}` and its
> supporting kernel headers as of early 2026 (8f0e1f6540). For the validation
> pipeline that feeds transactions into the mempool, see
> [VALIDATION_ARCHITECTURE.md](VALIDATION_ARCHITECTURE.md) §8. For the network
> layer that receives transactions from peers, see
> [NET_PROCESSING_ARCHITECTURE.md](NET_PROCESSING_ARCHITECTURE.md).

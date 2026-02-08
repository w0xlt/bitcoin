# Bitcoin Core Protocol Processing Architecture Guide

> A didactic guide for new developers to understand how Bitcoin Core
> processes P2P protocol messages in `src/net_processing.{h,cpp}`.
>
> **Companion document**: See [NET_LAYER_ARCHITECTURE.md](NET_LAYER_ARCHITECTURE.md)
> for the transport/connection layer that sits below this one.

---

## Table of Contents

1. [Where This Layer Sits](#1-where-this-layer-sits)
2. [The Two Core Abstractions: Peer vs CNodeState](#2-the-two-core-abstractions-peer-vs-cnodestate)
3. [Class-by-Class Deep Dive](#3-class-by-class-deep-dive)
4. [UML Class Diagram](#4-uml-class-diagram)
5. [The Message Processing Pipeline](#5-the-message-processing-pipeline)
6. [Protocol Handshake — The First 6 Messages](#6-protocol-handshake--the-first-6-messages)
7. [Block Relay — Headers-First Sync](#7-block-relay--headers-first-sync)
8. [Compact Blocks (BIP152)](#8-compact-blocks-bip152)
9. [Transaction Relay](#9-transaction-relay)
10. [Address Relay](#10-address-relay)
11. [Misbehavior Tracking & Punishment](#11-misbehavior-tracking--punishment)
12. [Stale Tip Detection & Peer Eviction](#12-stale-tip-detection--peer-eviction)
13. [Thread Safety & Locking Model](#13-thread-safety--locking-model)
14. [Improvement Proposals](#14-improvement-proposals)

---

## 1. Where This Layer Sits

```
┌─────────────────────────────────────────────────────────────┐
│  Validation Layer (validation.cpp)                          │
│  ChainstateManager: ProcessNewBlock(), ProcessNewBlockHeaders│
│  CTxMemPool: AcceptToMemoryPool()                           │
└──────────────────────┬──────────────────────────────────────┘
                       │ called by ProcessMessage handlers
                       │ CValidationInterface signals (upward)
                       │
┌══════════════════════▼══════════════════════════════════════┐
║  Protocol Layer (net_processing.cpp)  ◄── THIS DOCUMENT    ║
║  PeerManagerImpl: message dispatch, relay logic             ║
║  Peer: per-peer application state                           ║
║  CNodeState: per-peer validation state                      ║
╚══════════════════════╤══════════════════════════════════════╝
                       │ NetEventsInterface (upward callbacks)
                       │ CConnman::PushMessage() (downward sends)
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Transport Layer (net.cpp)                                  │
│  CConnman: threads, sockets       CNode: per-peer buffers   │
└─────────────────────────────────────────────────────────────┘
```

**Key insight**: `net_processing.cpp` is the **brain** of the P2P layer.
It decides what to do with each message, when to request blocks, how to
announce transactions, and when to punish misbehaving peers. The transport
layer below just moves bytes; the validation layer above just validates data.

---

## 2. The Two Core Abstractions: Peer vs CNodeState

This is the most important conceptual split in the codebase. Per-peer
data is divided into two structs based on **which lock protects it**:

```
  ┌──────────────────────────────┐    ┌──────────────────────────────┐
  │          Peer                │    │       CNodeState             │
  │  (guarded by m_peer_mutex   │    │  (guarded by cs_main)        │
  │   or per-field mutexes)     │    │                              │
  │──────────────────────────────│    │──────────────────────────────│
  │                              │    │                              │
  │  "Social" data:              │    │  "Validation" data:          │
  │  • Address relay state       │    │  • Best known block          │
  │  • Tx relay state (TxRelay) │    │  • Common block with us      │
  │  • Fee filter                │    │  • Blocks in flight          │
  │  • Ping latency              │    │  • Stalling timeout          │
  │  • Misbehavior flag          │    │  • Chain sync enforcement    │
  │  • Headers announcement pref │    │  • Preferred download flag   │
  │  • Block inv/headers relay   │    │  • Compact block support     │
  │                              │    │                              │
  │  Accessed WITHOUT cs_main    │    │  Accessed WITH cs_main       │
  └──────────────────────────────┘    └──────────────────────────────┘
```

**Why the split?** `cs_main` is the node's most contended lock. By
keeping "social" peer data (relay preferences, ping, misbehavior) in
`Peer` with its own lighter locks, the code avoids holding `cs_main`
for operations that don't need chain state.

---

## 3. Class-by-Class Deep Dive

### 3.1 `PeerManager` — The Public Interface

**File**: `net_processing.h`

An abstract interface that the rest of the node uses to interact with
the P2P protocol layer.

```
┌─────────────────────────────────────────────────────────────────┐
│                     PeerManager (abstract)                      │
│                                                                 │
│  Inherits: CValidationInterface + NetEventsInterface            │
│                                                                 │
│  ── Block Operations ──────────────────────────────────────── │
│  FetchBlock(block_hash, peer_id)  — manually request a block   │
│                                                                 │
│  ── Transaction Operations ────────────────────────────────── │
│  InitiateTxBroadcastToAll(tx)     — announce tx to all peers   │
│  InitiateTxBroadcastPrivate(tx)   — announce via Tor/I2P       │
│                                                                 │
│  ── Peer Management ──────────────────────────────────────── │
│  GetNodeStateStats(id) → CNodeStateStats                       │
│  CheckForStaleTipAndEvictPeers()                               │
│  SetBestBlock(height, time)                                    │
│  SendPings()                                                   │
│                                                                 │
│  ── Service Flags ────────────────────────────────────────── │
│  GetDesirableServiceFlags()       — what we want peers to have │
│  IgnoresIncomingTxs()             — are we in -blocksonly mode? │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 `PeerManagerImpl` — The Implementation

**File**: `net_processing.cpp` (line ~507, ~600 lines of declarations)

This is the actual implementation — one of the largest classes in
Bitcoin Core. It implements both `NetEventsInterface` (called by
`CConnman`) and `CValidationInterface` (called by validation).

#### External Dependencies

| Field | Type | Purpose |
|-------|------|---------|
| `m_connman` | `CConnman&` | Send messages, query connection info |
| `m_addrman` | `AddrMan&` | Store/retrieve peer addresses |
| `m_banman` | `BanMan*` | Ban/discourage misbehaving peers |
| `m_chainman` | `ChainstateManager&` | Process blocks/headers, query chain |
| `m_mempool` | `CTxMemPool*` | Query mempool, fee info |
| `m_chainparams` | `CChainParams&` | Network rules (mainnet/testnet) |
| `m_opts` | `Options` | Feature flags and limits |

#### Per-Peer State

| Field | Type | Purpose |
|-------|------|---------|
| `m_peer_map` | `map<NodeId, PeerRef>` | All Peer objects, guarded by `m_peer_mutex` |
| `m_node_states` | `map<NodeId, CNodeState>` | Validation state, guarded by `cs_main` |

#### Block Download State

| Field | Type | Purpose |
|-------|------|---------|
| `mapBlocksInFlight` | `multimap<hash, (NodeId, iter)>` | Which blocks are being downloaded from whom |
| `m_block_stalling_timeout` | `seconds` | Dynamic timeout (2s → 64s) |
| `m_last_tip_update` | `time_point` | When our tip last advanced |
| `mapBlockSource` | `map<hash, (NodeId, bool)>` | Where we got each block (for punishment) |

#### Block Announcement

| Field | Type | Purpose |
|-------|------|---------|
| `lNodesAnnouncingHeaderAndIDs` | `list<NodeId>` | Up to 3 peers for high-bandwidth compact blocks |
| `vExtraTxnForCompact` | `ring buffer` | Recent orphans/rejected txs for compact block reconstruction |
| `m_most_recent_block` | `shared_ptr<CBlock>` | Cached for serving to peers |
| `m_most_recent_compact_block` | `shared_ptr<CBlockHeaderAndShortTxIDs>` | Cached compact block |

#### Transaction Download

| Field | Type | Purpose |
|-------|------|---------|
| `m_txdownloadman` | `TxDownloadManager` | Manages tx request scheduling and orphanage |
| `m_txreconciliation` | `TxReconciliationTracker` | Erlay set reconciliation (BIP330) |
| `m_recent_rejects` | `CRollingBloomFilter` | Recently rejected txids (don't re-request) |
| `m_recent_rejects_reconsiderable` | `CRollingBloomFilter` | Rejected but worth retrying (package) |

### 3.3 `Peer` — Per-Peer Application State

**File**: `net_processing.cpp` (line ~227)

```
┌─────────────────────────────────────────────────────────────────┐
│                            Peer                                 │
│                                                                 │
│  m_id              : NodeId (unique identifier)                 │
│  m_our_services    : ServiceFlags (what we offer)               │
│  m_their_services  : atomic<ServiceFlags> (what they offer)     │
│  m_is_inbound      : bool                                       │
│                                                                 │
│  ── Misbehavior ──────────────────── (m_misbehavior_mutex) ──  │
│  m_should_discourage : bool (flag: this peer misbehaved)        │
│                                                                 │
│  ── Block Announcements ──────────── (m_block_inv_mutex) ────  │
│  m_blocks_for_inv_relay     : vector<uint256> (announce via INV)│
│  m_blocks_for_headers_relay : vector<uint256> (announce via HDR)│
│  m_continuation_block       : uint256 (for GETBLOCKS pagination)│
│                                                                 │
│  ── Transaction Relay ─────────────── (nested TxRelay struct) ─│
│  m_relay_txs            : bool (enabled after VERACK)           │
│  m_bloom_filter          : unique_ptr<CBloomFilter> (BIP37)     │
│  m_tx_inventory_known_filter : CRollingBloomFilter (seen txids) │
│  m_tx_inventory_to_send  : set<uint256> (pending tx inv)        │
│  m_next_inv_send_time    : chrono (trickle timer)               │
│  m_last_inv_sequence     : uint64_t (mempool sequence cursor)   │
│  m_fee_filter_received   : CAmount (BIP133 min feerate)         │
│  m_send_mempool          : bool (BIP35 mempool request)         │
│                                                                 │
│  ── Address Relay ────────────────────────────────────────────  │
│  m_addrs_to_send        : vector<CAddress> (pending addr relay) │
│  m_addr_known           : CRollingBloomFilter (already sent)    │
│  m_addr_relay_enabled   : bool                                  │
│  m_next_addr_send       : chrono (rate limit timer)             │
│  m_addr_token_bucket    : double (rate limiter)                 │
│  m_wants_addrv2         : bool (BIP155 format)                  │
│                                                                 │
│  ── Headers Sync ─────────────────── (m_headers_sync_mutex) ── │
│  m_headers_sync         : unique_ptr<HeadersSyncState>          │
│  m_headers_sync_timeout : chrono                                │
│  m_prefers_headers      : bool (BIP130 SENDHEADERS)             │
│                                                                 │
│  ── Ping/Pong ────────────────────────────────────────────────  │
│  m_ping_nonce_sent      : uint64_t (outstanding ping)           │
│  m_ping_start           : chrono (when ping was sent)           │
│                                                                 │
│  ── Feature Flags ────────────────────────────────────────────  │
│  m_wtxid_relay          : bool (BIP339)                         │
│  m_time_offset          : seconds (clock skew from VERSION)     │
│                                                                 │
│  ── Getdata Queue ────────────────── (m_getdata_requests_mutex)│
│  m_getdata_requests     : deque<CInv> (requests to serve)       │
└─────────────────────────────────────────────────────────────────┘
```

**Why `shared_ptr`?** `Peer` objects are reference-counted and shared
between the message processing thread and the validation callback thread.
The `shared_ptr` prevents use-after-free when a peer disconnects while
a validation callback is running.

### 3.4 `CNodeState` — Per-Peer Validation State

**File**: `net_processing.cpp` (line ~443)

All fields are protected by `cs_main`:

```
┌─────────────────────────────────────────────────────────────────┐
│                        CNodeState                               │
│                    (GUARDED_BY cs_main)                          │
│                                                                 │
│  ── Chain Knowledge ──────────────────────────────────────────  │
│  pindexBestKnownBlock  : CBlockIndex* (peer's best header)     │
│  hashLastUnknownBlock  : uint256 (hash we couldn't look up)     │
│  pindexLastCommonBlock : CBlockIndex* (our shared ancestor)     │
│  pindexBestHeaderSent  : CBlockIndex* (best header we sent)     │
│                                                                 │
│  ── Block Download ───────────────────────────────────────────  │
│  fSyncStarted          : bool (we started header sync with peer)│
│  vBlocksInFlight       : list<QueuedBlock>                      │
│  m_downloading_since   : time_point (when download started)     │
│  m_stalling_since      : time_point (when stall detected)       │
│  nBlocksInFlight       : int (count of in-flight blocks)        │
│  fPreferredDownload    : bool (is this a preferred peer?)       │
│                                                                 │
│  ── Compact Blocks ───────────────────────────────────────────  │
│  m_requested_hb_cmpctblocks : bool (high-bandwidth compact)     │
│  m_provides_cmpctblocks     : bool (peer supports compact)      │
│                                                                 │
│  ── Chain Sync Enforcement (ChainSyncTimeoutState) ───────────  │
│  m_timeout             : time_point (deadline for sync)         │
│  m_work_header         : CBlockIndex* (reference for progress)  │
│  m_sent_getheaders     : bool (asked for more headers)          │
│  m_protect             : bool (protected from eviction)         │
│                                                                 │
│  ── Statistics ───────────────────────────────────────────────  │
│  m_last_block_announcement : time_point (for eviction scoring)  │
│  nSyncHeight               : int (peer's claimed tip height)    │
└─────────────────────────────────────────────────────────────────┘
```

### 3.5 `CNodeStateStats` — Statistics for RPC

**File**: `net_processing.h`

A snapshot struct returned by `GetNodeStateStats()` for the `getpeerinfo`
RPC. Contains a mix of data from `Peer` and `CNodeState`.

---

## 4. UML Class Diagram

```
                    ┌────────────────────────────┐
                    │     CValidationInterface   │
                    │     (signals from           │
                    │      validation layer)      │
                    └─────────────┬──────────────┘
                                  │ BlockConnected,
                                  │ NewPoWValidBlock, etc.
                                  │
                    ┌─────────────┴──────────────┐
                    │    NetEventsInterface       │
                    │    (callbacks from           │
                    │     CConnman)               │
                    └─────────────┬──────────────┘
                                  │ ProcessMessages,
                                  │ SendMessages, etc.
                                  │
┌══════════════════════════════════▼══════════════════════════════┐
║                      PeerManagerImpl                           ║
║════════════════════════════════════════════════════════════════ ║
║                                                                ║
║  ── External Dependencies ──────────────────────────────────   ║
║  m_connman      : CConnman&          (send msgs, query peers)  ║
║  m_addrman      : AddrMan&           (peer address DB)         ║
║  m_banman       : BanMan*            (ban/discourage)          ║
║  m_chainman     : ChainstateManager& (validate blocks/txs)    ║
║  m_mempool      : CTxMemPool*        (query tx pool)           ║
║                                                                ║
║  ── Per-Peer Maps ──────────────────────────────────────────   ║
║  m_peer_map     : map<NodeId, shared_ptr<Peer>>                ║
║  m_node_states  : map<NodeId, CNodeState>                      ║
║                                                                ║
║  ── Block Download ─────────────────────────────────────────   ║
║  mapBlocksInFlight     : multimap<hash, (NodeId, QueuedBlock)> ║
║  mapBlockSource        : map<hash, (NodeId, bool)>             ║
║  m_block_stalling_timeout : seconds (2s → 64s)                 ║
║  lNodesAnnouncingHeaderAndIDs : list<NodeId> (max 3)           ║
║                                                                ║
║  ── Transaction Handling ───────────────────────────────────   ║
║  m_txdownloadman       : TxDownloadManager                     ║
║  m_txreconciliation    : TxReconciliationTracker               ║
║  vExtraTxnForCompact   : ring buffer (orphans for CB reconstr.)║
║                                                                ║
║  ── Caches ─────────────────────────────────────────────────   ║
║  m_most_recent_block         : shared_ptr<CBlock>              ║
║  m_most_recent_compact_block : shared_ptr<CBlockHeaderAndShort>║
║                                                                ║
║  ── Key Methods ────────────────────────────────────────────   ║
║  ProcessMessages(node)      : dispatch incoming messages       ║
║  SendMessages(node)         : build outgoing messages          ║
║  ProcessMessage(node, msg)  : handle one message type          ║
║  ProcessHeadersMessage()    : headers-first sync logic         ║
║  ProcessCompactBlockTxns()  : BIP152 reconstruction            ║
║  ProcessValidTx()           : announce accepted tx             ║
║  ProcessInvalidTx()         : handle rejection + maybe package ║
╚════════════════════════╤═══════════════════════════════════════╝
                         │ owns 0..*
           ┌─────────────┴────────────────┐
           │                              │
           ▼                              ▼
┌────────────────────┐       ┌────────────────────────┐
│       Peer         │       │     CNodeState         │
│  (m_peer_mutex)    │       │     (cs_main)          │
│────────────────────│       │────────────────────────│
│ m_id               │       │ pindexBestKnownBlock   │
│ m_should_discourage│       │ pindexLastCommonBlock   │
│                    │       │ vBlocksInFlight        │
│ TxRelay:           │       │ m_stalling_since       │
│  m_relay_txs       │       │ fSyncStarted           │
│  m_bloom_filter    │       │ fPreferredDownload     │
│  m_tx_inv_to_send  │       │                        │
│  m_fee_filter      │       │ ChainSyncTimeoutState: │
│                    │       │  m_timeout             │
│ Addr relay:        │       │  m_work_header         │
│  m_addrs_to_send   │       │  m_protect             │
│  m_addr_known      │       │                        │
│  m_addr_token_bucket│      │ Compact blocks:        │
│                    │       │  m_requested_hb_cmpct  │
│ Headers:           │       │  m_provides_cmpct      │
│  m_headers_sync    │       └────────────────────────┘
│  m_prefers_headers │
│                    │
│ Ping:              │
│  m_ping_nonce_sent │
│  m_ping_start      │
└────────────────────┘
```

---

## 5. The Message Processing Pipeline

### The Main Loop

```
  ThreadMessageHandler (in net.cpp) calls:
       │
       │  For each connected node (random order):
       │
       ├─► PeerManagerImpl::ProcessMessages(node)
       │        │
       │        ├─ Poll one message from node's queue
       │        │
       │        ├─ ProcessMessage(node, msg_type, payload, time)
       │        │       │
       │        │       └─ Giant switch on msg_type (see below)
       │        │
       │        ├─ ProcessOrphanTx() — retry orphaned transactions
       │        │
       │        └─ MaybeDiscourageAndDisconnect() — punish misbehavior
       │
       └─► PeerManagerImpl::SendMessages(node)
                │
                ├─ MaybeSendAddr()      — address gossip
                ├─ MaybeSendPing()      — latency measurement
                ├─ MaybeSendFeefilter() — BIP133 fee filter
                ├─ MaybeSendSendHeaders() — BIP130
                │
                ├─ Sync headers if needed (getheaders)
                ├─ Request blocks (getdata for blocks)
                │
                ├─ Announce new blocks (headers or inv)
                ├─ Announce new transactions (inv, trickled)
                │
                └─ Detect stalling & timeout peers
```

### The Message Dispatch

`ProcessMessage()` handles 20+ message types. Here's every handler:

```
  ┌──────────────┬──────────────────────────────────────────────────┐
  │ Message      │ What happens                                     │
  ├──────────────┼──────────────────────────────────────────────────┤
  │              │ ═══ HANDSHAKE ═══                                │
  │ VERSION      │ Exchange versions, services, heights. Send back  │
  │              │ WTXIDRELAY + SENDADDRV2 + VERACK.                │
  │ VERACK       │ Handshake complete. Send SENDCMPCT. Mark         │
  │              │ fSuccessfullyConnected. Register tx relay.       │
  │ WTXIDRELAY   │ Agree to use wtxid for tx relay (BIP339).       │
  │ SENDADDRV2   │ Agree to use ADDRv2 format (BIP155).            │
  │ SENDHEADERS  │ Prefer headers over inv for blocks (BIP130).    │
  │ SENDCMPCT    │ Negotiate compact block relay (BIP152).         │
  │ SENDTXRCNCL  │ Register for Erlay reconciliation (BIP330).     │
  │              │                                                  │
  │              │ ═══ BLOCK RELAY ═══                              │
  │ INV          │ Peer announces blocks/txs. For blocks: trigger  │
  │              │ headers sync. For txs: add to download queue.    │
  │ GETDATA      │ Peer requests specific blocks/txs. Queue for    │
  │              │ serving in ProcessGetData().                     │
  │ GETBLOCKS    │ Legacy block request (inv-based sync).          │
  │ GETHEADERS   │ Request block headers (headers-first sync).     │
  │ HEADERS      │ Block headers received. Process, validate,      │
  │              │ request full blocks if near tip.                 │
  │ BLOCK        │ Full block received. Forward to validation.     │
  │ CMPCTBLOCK   │ Compact block (BIP152). Reconstruct using       │
  │              │ mempool txs. Request missing via GETBLOCKTXN.   │
  │ GETBLOCKTXN  │ Peer wants missing txs for compact block.      │
  │ BLOCKTXN     │ Missing compact block txs received.            │
  │              │                                                  │
  │              │ ═══ TRANSACTION RELAY ═══                        │
  │ TX           │ Transaction received. Validate via mempool.     │
  │              │ On success: announce to other peers.             │
  │              │ On failure: maybe try package validation.        │
  │ NOTFOUND     │ Peer doesn't have requested item. Update        │
  │              │ download manager.                                │
  │              │                                                  │
  │              │ ═══ ADDRESS RELAY ═══                            │
  │ ADDR/ADDRV2  │ Peer shares known addresses. Rate-limited.     │
  │              │ Add to AddrMan. Relay 1-2 to other peers.       │
  │ GETADDR      │ Peer requests addresses. Send up to 1000.      │
  │              │                                                  │
  │              │ ═══ MEMPOOL ═══                                  │
  │ MEMPOOL      │ BIP35: peer requests full mempool inv.          │
  │ FEEFILTER    │ BIP133: peer's minimum fee rate for relay.      │
  │              │                                                  │
  │              │ ═══ BLOOM FILTERS ═══                            │
  │ FILTERLOAD   │ BIP37: peer sets a bloom filter.                │
  │ FILTERADD    │ BIP37: peer adds to bloom filter.               │
  │ FILTERCLEAR  │ BIP37: peer removes bloom filter.               │
  │              │                                                  │
  │              │ ═══ LATENCY ═══                                  │
  │ PING         │ Echo nonce back as PONG.                        │
  │ PONG         │ Calculate round-trip latency.                   │
  │              │                                                  │
  │              │ ═══ COMPACT FILTERS ═══                          │
  │ GETCFILTERS  │ BIP157: request basic block filters.            │
  │ GETCFHEADERS │ BIP157: request filter header chain.            │
  │ GETCFCHECKPT │ BIP157: request filter checkpoints.            │
  └──────────────┴──────────────────────────────────────────────────┘
```

---

## 6. Protocol Handshake — The First 6 Messages

```
  Outbound Node (us)                    Inbound Node (peer)
  ──────────────────                    ───────────────────

  1. VERSION ────────────────────────►
     (our version, services, height,
      nonce, relay flag)

                                        2. VERSION ◄───────
                                        (their version, services,
                                         height, nonce)

  ┌──────── Feature Negotiation Window ────────────────────┐
  │  Only these messages allowed before VERACK:            │
  │                                                        │
  │  3a. WTXIDRELAY ──────────────────► (if we support it) │
  │  3b. SENDADDRV2 ──────────────────►                    │
  │  3c. SENDTXRCNCL ─────────────────► (if Erlay enabled) │
  │                                                        │
  │                    ◄─── WTXIDRELAY  (if they support)  │
  │                    ◄─── SENDADDRV2                     │
  │                    ◄─── SENDTXRCNCL                    │
  └────────────────────────────────────────────────────────┘

  4. VERACK ─────────────────────────►
     (handshake complete from our side)

                                        5. VERACK ◄────────
                                        (handshake complete from their side)

  6. SENDCMPCT ──────────────────────►
     (BIP152 compact block negotiation)

  ═══ Connection is now fully established ═══
  Both sides can send any message type.
```

**Key rules**:
- WTXIDRELAY, SENDADDRV2, SENDTXRCNCL **must** come before VERACK.
  Sending them after VERACK causes disconnection.
- VERSION must be the first message. Anything else before VERSION
  is silently ignored.
- Self-connections are detected by nonce comparison and disconnected.

---

## 7. Block Relay — Headers-First Sync

### Initial Block Download (IBD)

```
  Our node starts up with genesis block only.
  We need to download ~850,000 blocks.

  Step 1: Send GETHEADERS with our tip (genesis)
          ┌──────────┐         ┌──────────┐
          │    Us     │ ──────► │   Peer   │
          │ height=0  │ GETHDR  │ height=  │
          │           │         │  850000  │
          └──────────┘         └──────────┘

  Step 2: Receive up to 2000 headers
          ◄───────── HEADERS (2000 block headers)

  Step 3: Validate headers, update chain tip
          Request blocks for validated headers
          ──────────► GETDATA (block hashes)

  Step 4: Receive blocks, validate, connect
          ◄───────── BLOCK (full block data)

  Step 5: Repeat steps 1-4 until caught up

  During IBD:
    • Only one peer syncs headers (fSyncStarted)
    • Up to MAX_BLOCKS_IN_TRANSIT_PER_PEER (16) blocks in flight
    • Stalling detection: if no block arrives in timeout, try another peer
    • Dynamic timeout: starts at 2s, doubles up to 64s
```

### Near-Tip Block Announcement

Once synced, new blocks are announced differently:

```
  Miner finds block
       │
       ▼
  Our node receives it via validation
       │
       ▼
  PeerManagerImpl::NewPoWValidBlock()
       │
       ├─ Cache compact block representation
       │
       └─ For each high-bandwidth compact block peer (up to 3):
            Push CMPCTBLOCK immediately
       │
       ▼
  SendMessages() for each other peer:
       │
       ├─ Peer prefers headers (BIP130)?
       │    └─ Send HEADERS message
       │
       └─ Otherwise?
            └─ Send INV message
```

---

## 8. Compact Blocks (BIP152)

Compact blocks reduce block relay bandwidth by ~99% — sending short
transaction IDs instead of full transactions:

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Full block:    ~1.5 MB (header + ~2500 full transactions)   │
  │  Compact block: ~15 KB  (header + ~2500 short IDs of 6 bytes)│
  └──────────────────────────────────────────────────────────────┘

  HIGH-BANDWIDTH mode (unsolicited push):
  ─────────────────────────────────────────

  Peer (miner) ───── CMPCTBLOCK ──────► Us
                                         │
                                    Match short IDs
                                    against mempool
                                         │
                                    ┌────┴────┐
                                    │ Missing │
                                    │  2 txs  │
                                    └────┬────┘
                                         │
  Peer ◄────────── GETBLOCKTXN ────────  │
  (request the 2                         │
   missing txs)                          │
                                         │
  Peer ──────────── BLOCKTXN ──────────► │
  (provide missing txs)                  │
                                         ▼
                                    Full block
                                    reconstructed!
                                    → ProcessBlock()

  LOW-BANDWIDTH mode (request after INV):
  ────────────────────────────────────────

  Peer ──── INV ────► Us
                       │
  Peer ◄── GETDATA ─── │ (with MSG_CMPCT_BLOCK flag)
                       │
  Peer ── CMPCTBLOCK ► │ (same flow as above)
```

**Optimization**: `vExtraTxnForCompact` is a ring buffer of recent
orphans and rejected transactions. Even if a tx was rejected from our
mempool, we keep it cached so compact block reconstruction still works.

---

## 9. Transaction Relay

### Announcement (Outbound)

```
  New valid tx enters our mempool
       │
       ▼
  ProcessValidTx() → InitiateTxBroadcastToAll()
       │
       ├─ Add (w)txid to each peer's m_tx_inventory_to_send
       │
       └─ (won't be sent immediately — trickled)

  SendMessages() for each peer (called periodically):
       │
       ├─ Is it time? (m_next_inv_send_time, Poisson timer)
       │
       ├─ Sort pending txs by mining score (fee rate)
       │
       ├─ Filter:
       │    ├─ Skip if peer already knows (m_tx_inventory_known_filter)
       │    ├─ Skip if below peer's feefilter (BIP133)
       │    └─ Skip if filtered by bloom filter (BIP37)
       │
       ├─ Build INV message (up to 1000 items per batch)
       │    Use wtxid if peer supports WTXIDRELAY, txid otherwise
       │
       └─ Send INV
```

**Trickle timing**: Transaction announcements are deliberately delayed
using Poisson-distributed intervals (~5 seconds average). This prevents
a spy node from determining which node created a transaction by timing
when the announcement arrives.

### Reception (Inbound)

```
  Peer sends INV(tx_hash)
       │
       ▼
  ProcessMessage("INV"):
    m_txdownloadman.AddTxAnnouncement(peer, txid, now)
       │
       ▼
  SendMessages():
    m_txdownloadman.GetRequestsToSend(now) → getdata items
    Send GETDATA(tx_hash) to peer
       │
       ▼
  Peer sends TX(raw_transaction)
       │
       ▼
  ProcessMessage("TX"):
    m_txdownloadman.ReceivedTx(txid)
         │
         ├─ Validate: m_chainman.ProcessTransaction(tx)
         │
         ├─ If VALID:
         │    ProcessValidTx() → announce to all other peers
         │
         └─ If INVALID:
              ProcessInvalidTx()
                   │
                   ├─ Missing inputs? → Add to orphanage
                   │    (will retry when parent arrives)
                   │
                   ├─ Reconsiderable? → Try package validation
                   │    (child-pays-for-parent)
                   │
                   └─ Hard failure? → Add to reject filter
                        (won't re-request)
```

### Package Validation (1-parent-1-child)

When a child transaction is too low fee on its own but valid if
considered with its parent:

```
  Child tx arrives, fails validation (too low fee)
       │
       ▼
  ProcessInvalidTx() determines: "reconsiderable"
       │
       ▼
  m_txdownloadman returns PackageToValidate{child, parent}
       │
       ▼
  Submit both to mempool as a package
  (child's fee pays for parent's relay)
```

---

## 10. Address Relay

### How Addresses Propagate

```
  Node A learns Node B's address (from VERSION or ADDR message)
       │
       ▼
  Add to AddrMan (if address is reachable for us)
       │
       ▼
  RelayAddress(addr):
       │
       ├─ Select 1-2 peers deterministically:
       │    hash = SipHash(peer_id, addr, time_bucket)
       │    Rotate every 24 hours (privacy: different relayers daily)
       │
       └─ Add addr to selected peers' m_addrs_to_send
              │
              ▼
         SendMessages() → MaybeSendAddr():
              │
              ├─ Batch up to 1000 addresses per message
              ├─ Use ADDR or ADDRv2 format based on negotiation
              └─ Update m_addr_known bloom filter
```

### Rate Limiting (Anti-Scraping)

```
  m_addr_token_bucket: starts at 1.0
  Refill rate: MAX_ADDR_RATE_PER_SECOND (0.1)

  Each address received costs 1.0 token.
  Excess addresses → silently ignored.

  Exception: First response to GETADDR gets a 1000-token bonus
  (allows initial address exchange).
```

---

## 11. Misbehavior Tracking & Punishment

### The Punishment Flow

```
  Peer sends invalid data (bad checksum, invalid block, etc.)
       │
       ▼
  Misbehaving(peer, message):
    peer.m_should_discourage = true
       │
       ▼
  MaybeDiscourageAndDisconnect() [called every ProcessMessages]:
       │
       ├─ Check exemptions:
       │    ├─ NoBan permission? → skip punishment
       │    ├─ MANUAL connection? → skip (user chose this peer)
       │    └─ Localhost? → skip
       │
       └─ Not exempt:
            ├─ m_banman->Discourage(addr) → add to discouraged list
            └─ node.fDisconnect = true → will be cleaned up
```

### Block-Specific Punishment

```
  MaybePunishNodeForBlock(node, state):
       │
       ├─ BLOCK_RESULT_VALID → no punishment
       │
       ├─ BLOCK_CONSENSUS (invalid PoW, bad merkle, etc.)
       │    └─ Misbehaving()
       │
       ├─ BLOCK_CACHED_INVALID (we already know this block is bad)
       │    └─ Misbehaving() ONLY for outbound non-compact-block peers
       │       (compact block peers may have been tricked by short IDs)
       │
       ├─ BLOCK_MUTATED (witness data tampered)
       │    └─ Misbehaving() for outbound only
       │       (inbound could be honest relay)
       │
       └─ BLOCK_TIME_FUTURE (timestamp too far ahead)
            └─ No punishment (clocks differ)
```

**Design principle**: Punishment is conservative. The wallet only punishes
when it's confident the peer is malicious, not just buggy or unlucky.
Inbound peers get more leniency because we don't choose them.

---

## 12. Stale Tip Detection & Peer Eviction

### Detecting a Stale Tip

```
  Every 10 minutes (STALE_CHECK_INTERVAL):
       │
       ▼
  TipMayBeStale():
    Is our tip older than 3 × block interval (30 min)?
    AND are there zero blocks in flight?
       │
       ├─ No → tip is fresh, do nothing
       │
       └─ Yes → tip may be stale
            │
            └─ SetTryNewOutboundPeer(true)
                 → ThreadOpenConnections will make an extra connection
                 → Hopefully the new peer has a better chain
```

### Evicting Underperforming Peers

```
  EvictExtraOutboundPeers() [called periodically]:
       │
       ├─ Check block-relay-only peers:
       │    Sort by time of last block announcement
       │    If youngest hasn't given us a block recently → evict it
       │    (replace with a fresh connection)
       │
       └─ Check full outbound peers:
            Sort by time of last block announcement
            Protect up to 4 peers with sufficient chain work
            Evict the one with the oldest announcement
            (but only if it's older than our current tip)
```

### Chain Sync Enforcement (Per-Peer)

```
  ConsiderEviction(peer):
       │
       ├─ Is peer's best known block behind our tip?
       │    └─ Set timeout: CHAIN_SYNC_TIMEOUT (20 minutes)
       │
       ├─ Timeout expired?
       │    ├─ Did we already send GETHEADERS?
       │    │    └─ Yes, and still no progress?
       │    │         → Disconnect peer (they're stuck)
       │    │
       │    └─ No? Send GETHEADERS, wait HEADERS_RESPONSE_TIME (2 min)
       │
       └─ Peer caught up? → Reset timeout
```

---

## 13. Thread Safety & Locking Model

### Lock Hierarchy

```
  Coarsest (acquire first)
  ────────────────────────
  cs_main                 ← node-wide, protects CNodeState and chain state
  g_msgproc_mutex         ← serializes ProcessMessages + SendMessages
  m_peer_mutex            ← protects m_peer_map
  m_tx_download_mutex     ← protects TxDownloadManager
  m_most_recent_block_mutex ← protects cached block/compact block
  m_headers_presync_mutex ← protects presync stats
  Peer::m_block_inv_mutex ← per-peer block announcement
  Peer::m_misbehavior_mutex ← per-peer misbehavior flag
  Peer::m_headers_sync_mutex ← per-peer headers state
  Peer::m_getdata_requests_mutex ← per-peer request queue
  Peer::TxRelay::m_bloom_filter_mutex ← per-peer bloom filter
  Peer::TxRelay::m_tx_inventory_mutex ← per-peer tx inventory
  ────────────────────────
  Finest (acquire last)
```

### Common Patterns

1. **`cs_main` is held briefly**: Most message handlers acquire `cs_main`
   only for the validation calls, not for the entire message processing.

2. **`Peer` is accessed via `shared_ptr`**: Prevents use-after-free
   if a peer disconnects during processing.

3. **`LOCK2(cs_main, m_peer_mutex)`**: Used when both chain state and
   peer data are needed simultaneously (e.g., `GetNodeStateStats`).

4. **Atomic reads for hot-path checks**: `m_their_services` on `Peer`
   is atomic — read without locks in tight loops.

---

## 14. Improvement Proposals

### 14.1 Break Up `ProcessMessage()` Into Handler Classes

**Problem**: `ProcessMessage()` is a ~1600-line function with a giant
if-else chain for message types. Each handler has different locking
needs, different state access patterns, and different validation logic —
yet they're all crammed into one function.

**Suggestion**: Use a handler registration pattern:

```cpp
class MessageHandler {
public:
    virtual std::string_view MessageType() const = 0;
    virtual void Handle(CNode& node, Peer& peer,
                       DataStream& recv, TimePoint time) = 0;
};

class VersionHandler : public MessageHandler {
    std::string_view MessageType() const override { return "version"; }
    void Handle(...) override { /* version-specific logic */ }
};

// In PeerManagerImpl:
std::map<std::string, unique_ptr<MessageHandler>> m_handlers;

void ProcessMessage(CNode& node, const std::string& type, ...) {
    auto it = m_handlers.find(type);
    if (it != m_handlers.end()) {
        it->second->Handle(node, peer, recv, time);
    }
}
```

**Benefit**: Each handler is independently testable, has clear
dependencies, and can be reviewed in isolation.

### 14.2 Separate the `Peer` Struct Into Cohesive Components

**Problem**: `Peer` has ~40 fields covering tx relay, address relay,
headers sync, ping, misbehavior, and block announcements. It's protected
by 6+ different mutexes. Adding any new per-peer feature means growing
this already-large struct.

**Suggestion**: Decompose into focused components:

```cpp
struct Peer {
    NodeId m_id;
    ServiceFlags m_our_services, m_their_services;
    bool m_is_inbound;

    // Owned sub-components
    PeerTxRelay m_tx_relay;
    PeerAddrRelay m_addr_relay;
    PeerHeadersSync m_headers_sync;
    PeerBlockAnnouncement m_block_announce;
    PeerMisbehavior m_misbehavior;
    PeerLatency m_latency;   // ping/pong
};
```

Each component owns its own mutex and provides a clean interface.

### 14.3 Formalize the Block Download State Machine

**Problem**: Block download state transitions happen across multiple
methods (`SendMessages`, `ProcessMessage("HEADERS")`,
`ProcessMessage("BLOCK")`, `CheckForStaleTipAndEvictPeers`). The states
are implicit in combinations of fields (`fSyncStarted`,
`vBlocksInFlight`, `m_stalling_since`, `m_downloading_since`).

**Suggestion**: Create an explicit state machine:

```
  States:
    IDLE          — no block download activity
    SYNCING_HEADERS — sent GETHEADERS, waiting for HEADERS
    DOWNLOADING_BLOCKS — blocks in flight from this peer
    STALLING      — peer hasn't delivered in timeout
    TIMED_OUT     — peer exceeded patience, will disconnect

  Transitions:
    IDLE → SYNCING_HEADERS : on SendMessages() if peer has more work
    SYNCING_HEADERS → DOWNLOADING_BLOCKS : on HEADERS received
    DOWNLOADING_BLOCKS → IDLE : all blocks delivered
    DOWNLOADING_BLOCKS → STALLING : timeout exceeded
    STALLING → TIMED_OUT : second timeout exceeded
    STALLING → DOWNLOADING_BLOCKS : block finally arrives
```

Making this explicit would make the download logic auditable and
testable in isolation.

### 14.4 Reduce `cs_main` Contention in Message Processing

**Problem**: `cs_main` is the most contended lock in Bitcoin Core.
Several message handlers hold it for significant durations (e.g.,
HEADERS processing, BLOCK validation). This blocks all other threads
that need chain state.

**Suggestion**: Where possible, copy the data needed under `cs_main`,
release the lock, then do the expensive work:

```cpp
// Instead of:
LOCK(cs_main);
auto result = chainman.ProcessNewBlockHeaders(headers);  // holds cs_main!

// Prefer:
CBlockIndex* tip;
{
    LOCK(cs_main);
    tip = chainman.ActiveTip();  // quick snapshot
}
// Validate headers against snapshot (no lock needed)
auto pre_result = ValidateHeadersLocally(headers, tip);
if (pre_result.ok) {
    LOCK(cs_main);
    chainman.ProcessNewBlockHeaders(headers);  // shorter hold
}
```

### 14.5 Extract Transaction Relay Into Its Own Module

**Problem**: Transaction relay logic (announcement, download, orphanage,
package validation, fee filtering, trickle timing, bloom filters) is
scattered across `ProcessMessage("TX")`, `ProcessMessage("INV")`,
`SendMessages()`, `ProcessValidTx()`, `ProcessInvalidTx()`, and
`ProcessOrphanTx()`. It's the most complex subsystem within
net_processing and the hardest to reason about.

**Suggestion**: Extract a `TxRelayManager` class that encapsulates:
- Announcement scheduling (trickle timer, Poisson intervals)
- Fee filtering (BIP133)
- Bloom filtering (BIP37)
- Orphan management (already partially extracted to `TxDownloadManager`)
- Package validation decisions
- Private broadcast coordination

### 14.6 Make `CNodeState` Part of `Peer`

**Problem**: The split between `Peer` (guarded by `m_peer_mutex`) and
`CNodeState` (guarded by `cs_main`) means per-peer data lives in two
separate maps (`m_peer_map` and `m_node_states`). Code frequently needs
to look up both, requiring two separate map lookups and careful lock
ordering.

**Suggestion**: Make `CNodeState` a member of `Peer`, but clearly
annotate which fields require `cs_main`:

```cpp
struct Peer {
    // ... existing fields (guarded by m_peer_mutex or per-field mutexes)

    // Validation state (GUARDED_BY cs_main)
    struct ValidationState {
        CBlockIndex* pindexBestKnownBlock GUARDED_BY(::cs_main);
        CBlockIndex* pindexLastCommonBlock GUARDED_BY(::cs_main);
        std::list<QueuedBlock> vBlocksInFlight GUARDED_BY(::cs_main);
        // ...
    } m_validation_state;
};
```

This eliminates the double-lookup and makes it obvious that `Peer` is
the single source of truth for all per-peer data.

### 14.7 Improve Message Validation Error Reporting

**Problem**: When a message is malformed, the code often silently
returns or disconnects with a generic log line. Developers debugging
P2P issues must add their own logging to figure out which validation
check failed.

**Suggestion**: Return structured validation results:

```cpp
struct MessageValidationResult {
    bool valid;
    std::string rejection_reason;  // "duplicate-version", "headers-too-long"
    bool should_punish;
    bool should_disconnect;
};
```

This would improve debugging, testing, and monitoring (via tracepoints).

---

## Appendix: Message Size & Timing Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_HEADERS_RESULTS` | 2000 | Max headers per HEADERS message |
| `MAX_INV_SZ` | 50,000 | Max items per INV message |
| `MAX_GETDATA_SZ` | 1,000 | Max items per GETDATA message |
| `MAX_BLOCKS_IN_TRANSIT_PER_PEER` | 16 | Max concurrent block downloads per peer |
| `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK` | 3 | Max peers we ask for same compact block |
| `MAX_ADDR_TO_SEND` | 1,000 | Max addresses per ADDR message |
| `MAX_ADDR_RATE_PER_SECOND` | 0.1 | Address relay rate limit |
| `INVENTORY_BROADCAST_TARGET` | 70 | Tx inv target per trickle interval |
| `INVENTORY_BROADCAST_MAX` | 1,000 | Max tx inv per SendMessages() call |
| `BLOCK_STALLING_TIMEOUT_DEFAULT` | 2 sec | Initial block download timeout |
| `BLOCK_STALLING_TIMEOUT_MAX` | 64 sec | Maximum block download timeout |
| `HEADERS_DOWNLOAD_TIMEOUT_BASE` | 15 min | Base timeout for header sync |
| `HEADERS_RESPONSE_TIME` | 2 min | Time to respond to GETHEADERS |
| `CHAIN_SYNC_TIMEOUT` | 20 min | Time before evicting stale peer |
| `STALE_CHECK_INTERVAL` | 10 min | How often to check for stale tip |
| `PING_INTERVAL` | 2 min | How often to send PING |

---

*This document reflects the state of Bitcoin Core's protocol processing
code as of early 2026 (8f0e1f6540). See [NET_LAYER_ARCHITECTURE.md](NET_LAYER_ARCHITECTURE.md)
for the transport and connection management layer below this one.*

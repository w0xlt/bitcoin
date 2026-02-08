# Bitcoin Core Network Layer Architecture Guide

> A didactic guide for new developers to understand the transport and
> connection management code in `src/net.{h,cpp}`.
>
> **Companion document**: See [NET_PROCESSING_ARCHITECTURE.md](NET_PROCESSING_ARCHITECTURE.md)
> for the protocol/message layer that sits on top of this one.

---

## Table of Contents

1. [Where This Layer Sits](#1-where-this-layer-sits)
2. [The Thread Model — 7 Threads Working Together](#2-the-thread-model--7-threads-working-together)
3. [Class-by-Class Deep Dive](#3-class-by-class-deep-dive)
4. [UML Class Diagram](#4-uml-class-diagram)
5. [Connection Lifecycle](#5-connection-lifecycle)
6. [The Transport Layer — V1 vs V2 (BIP324)](#6-the-transport-layer--v1-vs-v2-bip324)
7. [Peer Discovery — How Nodes Find Each Other](#7-peer-discovery--how-nodes-find-each-other)
8. [Peer Eviction — Who Gets Kicked](#8-peer-eviction--who-gets-kicked)
9. [Send/Receive Data Flow](#9-sendreceive-data-flow)
10. [Thread Safety & Locking Model](#10-thread-safety--locking-model)
11. [Bandwidth Management](#11-bandwidth-management)
12. [Improvement Proposals](#12-improvement-proposals)

---

## 1. Where This Layer Sits

```
┌─────────────────────────────────────────────────────────────┐
│  Application Layer (net_processing.cpp)                     │
│  PeerManagerImpl: ProcessMessages(), SendMessages()         │
│  Knows about: blocks, txs, headers, inv, addr              │
└───────────────────────┬─────────────────────────────────────┘
                        │ NetEventsInterface (upward callbacks)
                        │ CConnman::PushMessage() (downward sends)
                        │
┌═══════════════════════▼═════════════════════════════════════┐
║  Transport/Connection Layer (net.cpp)     ◄── THIS DOCUMENT ║
║  CConnman: threads, sockets, connections                    ║
║  CNode: per-peer state, send/recv queues                    ║
║  V1Transport / V2Transport: serialization + encryption      ║
╚═══════════════════════╤═════════════════════════════════════╝
                        │ TCP sockets, Tor/I2P/CJDNS proxies
                        │
┌───────────────────────▼─────────────────────────────────────┐
│  Operating System                                           │
│  TCP/IP stack, SOCKS5 proxies, I2P SAM                      │
└─────────────────────────────────────────────────────────────┘
```

**Key separation**: This layer knows nothing about Bitcoin protocol
semantics. It moves bytes between peers. It doesn't know what a "block"
or "transaction" is — that's `net_processing`'s job.

---

## 2. The Thread Model — 7 Threads Working Together

Bitcoin Core's networking runs on **7 dedicated threads** (some optional).
Understanding which thread does what is essential to working on this code.

```
┌───────────────────────────────────────────────────────────────────────┐
│                        CConnman Threads                               │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ 1. ThreadSocketHandler          (always running)                │  │
│  │    • poll() sockets for readability/writability                 │  │
│  │    • Read bytes from sockets → CNode receive queue              │  │
│  │    • Write bytes from CNode send queue → sockets                │  │
│  │    • Accept inbound connections                                 │  │
│  │    • Detect timeouts (20 min inactivity)                        │  │
│  │    • Clean up disconnected nodes                                │  │
│  │    Loop interval: ~50ms (SELECT_TIMEOUT_MILLISECONDS)           │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ 2. ThreadMessageHandler         (always running)                │  │
│  │    • For each peer: call ProcessMessages() (reads from queue)   │  │
│  │    • For each peer: call SendMessages() (fills send queue)      │  │
│  │    • Randomizes peer order each iteration (privacy)             │  │
│  │    • Wakes via condition variable or 100ms timeout              │  │
│  │    NOTE: Holds g_msgproc_mutex — serializes all message work    │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ 3. ThreadOpenConnections        (always running)                │  │
│  │    • Main connection strategy engine                            │  │
│  │    • Decides WHEN and WHERE to connect                          │  │
│  │    • Manages: full-relay, block-relay, feeler connections       │  │
│  │    • Uses AddrMan to select peers                               │  │
│  │    • Enforces netgroup diversity                                │  │
│  │    • Restores anchor connections on startup                     │  │
│  │    • Loads fixed seeds as last resort                           │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ 4. ThreadOpenAddedConnections   (always running)                │  │
│  │    • Maintains connections from -addnode / addnode RPC           │  │
│  │    • Retries every 60s (or 2s if no connections at all)         │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ 5. ThreadDNSAddressSeed         (runs once, then exits)         │  │
│  │    • Queries DNS seeds for initial peer addresses               │  │
│  │    • Delays: 11s if AddrMan sparse, 5min if rich                │  │
│  │    • Falls back to hardcoded fixed seeds                        │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ 6. ThreadI2PAcceptIncoming      (optional: if I2P configured)   │  │
│  │    • Listens for incoming I2P connections via SAM proxy          │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ 7. ThreadPrivateBroadcast       (optional: if -privatebroadcast)│  │
│  │    • Opens short-lived Tor/I2P connections for tx privacy       │  │
│  │    • Sends one tx per connection, then disconnects              │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
```

**Critical insight**: Thread 1 (SocketHandler) and Thread 2
(MessageHandler) are the core loop. SocketHandler moves raw bytes.
MessageHandler interprets them. They communicate through CNode's
message queues.

---

## 3. Class-by-Class Deep Dive

### 3.1 `CConnman` — The Connection Manager

**File**: `net.h` (line ~1071), `net.cpp`

This is the largest and most important class in the networking layer.
It owns all connections, all threads, and all connection policy.

#### Core Data

| Field | Type | Purpose |
|-------|------|---------|
| `m_nodes` | `vector<CNode*>` | All currently connected peers |
| `m_nodes_disconnected` | `list<CNode*>` | Peers being cleaned up (refcount > 0) |
| `m_added_nodes` | `vector<AddedNodeParams>` | Peers from `-addnode` / RPC |
| `vhListenSocket` | `vector<ListenSocket>` | Sockets accepting inbound connections |
| `m_addr_fetches` | `deque<string>` | DNS names to fetch addresses from |
| `addrman` | `AddrMan&` | Peer address database |
| `nSeed` | `uint256` | Random seed for peer selection |
| `semOutbound` | `CSemaphore*` | Limits total outbound connections |
| `semAddnode` | `CSemaphore*` | Limits addnode connections |

#### Connection Slot Tracking

| Field | Purpose |
|-------|---------|
| `m_max_outbound_full_relay` | Max full-relay outbound (default 8) |
| `m_max_outbound_block_relay` | Max block-only outbound (default 2) |
| `m_max_outbound` | Total outbound limit |
| `nMaxConnections` | Hard cap on all connections (default 125) |
| `m_max_automatic_connections` | = nMaxConnections - m_max_addnode |
| `m_use_addrman_outgoing` | Use AddrMan for peer selection (false for `-connect=`) |

#### Bandwidth Tracking

| Field | Purpose |
|-------|---------|
| `nMaxOutboundLimit` | Max upload bytes per 24h cycle |
| `nMaxOutboundTotalBytesSentInCycle` | Bytes sent this cycle |
| `nMaxOutboundCycleStartTime` | Start of current cycle |
| `nTotalBytesRecv` / `nTotalBytesSent` | Lifetime counters |

#### Key Methods

```
  Connection Management:
    Start() / Stop()                  — Thread lifecycle
    ConnectNode()                     — Establish TCP connection
    CreateNodeFromAcceptedSocket()    — Handle inbound connection
    DisconnectNodes()                 — Clean up marked nodes
    AttemptToEvictConnection()        — Evict inbound if full
    OpenNetworkConnection()           — Open outbound connection

  Message Passing:
    PushMessage(CNode&, msg)          — Queue message for sending
    ForEachNode(func)                 — Iterate all connected nodes

  Discovery:
    AddAddrFetch(addr)                — Schedule address fetch
    SetTryNewOutboundPeer(bool)       — Request extra connection

  Statistics:
    GetNodeCount(type)                — Count by connection type
    GetNodeStats()                    — Snapshot all peer stats
    GetTotalBytesRecv/Sent()          — Bandwidth counters
```

### 3.2 `CNode` — A Single Peer Connection

**File**: `net.h` (line ~679)

One `CNode` exists per connected peer. It's a container for:
- The socket
- The transport protocol handler
- Send and receive message queues
- Per-peer metadata

```
┌─────────────────────────────────────────────────────────────────┐
│                            CNode                                │
│                                                                 │
│  ── Identity ─────────────────────────────────────────────────  │
│  m_id           : NodeId (unique, assigned sequentially)        │
│  addr           : CService (peer's IP:port)                     │
│  addrBind       : CService (our side of the connection)         │
│  m_addr_name    : string (resolved hostname)                    │
│  m_conn_type    : ConnectionType (INBOUND, FULL_RELAY, etc.)    │
│  m_inbound_onion: bool (came through Tor)                       │
│                                                                 │
│  ── Transport ────────────────────────────────────────────────  │
│  m_transport    : unique_ptr<Transport> (V1 or V2)              │
│                                                                 │
│  ── Socket ───────────────────────────────────────────────────  │
│  m_sock         : shared_ptr<Sock> (the TCP socket)             │
│  m_connected    : time_point (when connected)                   │
│                                                                 │
│  ── Send Queue ───────────────────────────────────────────────  │
│  cs_vSend       : Mutex                                         │
│  vSendMsg       : deque<vector<byte>> (outgoing message bytes)  │
│  nSendMsgSize   : size_t (total queued bytes)                   │
│  fPauseSend     : bool (back-pressure: send buffer full)        │
│                                                                 │
│  ── Receive Queue ────────────────────────────────────────────  │
│  cs_vRecv       : Mutex                                         │
│  vRecvMsg       : list<CNetMessage> (parsed incoming messages)  │
│  m_msg_process_queue : list<CNetMessage> (ready for processing) │
│  fPauseRecv     : bool (back-pressure: recv buffer full)        │
│                                                                 │
│  ── Protocol State ───────────────────────────────────────────  │
│  nVersion        : int (negotiated protocol version)            │
│  cleanSubVer     : string (user agent, e.g., "/Satoshi:27.0/") │
│  fSuccessfullyConnected : bool (VERACK received)                │
│  fDisconnect     : bool (marked for disconnection)              │
│  m_permission_flags : NetPermissionFlags (whitelist perms)      │
│                                                                 │
│  ── Statistics ───────────────────────────────────────────────  │
│  m_last_send     : atomic<seconds> (last data sent)             │
│  m_last_recv     : atomic<seconds> (last data received)         │
│  nSendBytes      : uint64_t (lifetime bytes sent)               │
│  nRecvBytes      : uint64_t (lifetime bytes received)           │
│  mapSendBytesPerMsgType  : map<string, uint64_t>                │
│  mapRecvBytesPerMsgType  : map<string, uint64_t>                │
│                                                                 │
│  ── Reference Counting ───────────────────────────────────────  │
│  nRefCount       : atomic<int> (prevents premature deletion)    │
│  AddRef() / Release()                                           │
└─────────────────────────────────────────────────────────────────┘
```

#### Connection Types

```
  ┌─────────────────────────────┬────────┬────────┬──────────────┐
  │ ConnectionType              │ Relays │ Relays │ Who          │
  │                             │ Blocks │ Txs    │ Initiates    │
  ├─────────────────────────────┼────────┼────────┼──────────────┤
  │ INBOUND                     │  Yes   │  Yes   │ Remote peer  │
  │ OUTBOUND_FULL_RELAY         │  Yes   │  Yes   │ Us (AddrMan) │
  │ BLOCK_RELAY                 │  Yes   │  No    │ Us (AddrMan) │
  │ MANUAL                      │  Yes   │  Yes   │ Us (-addnode)│
  │ FEELER                      │  —     │  —     │ Us (probe)   │
  │ ADDR_FETCH                  │  —     │  —     │ Us (seeds)   │
  │ PRIVATE_BROADCAST           │  No    │  1 tx  │ Us (Tor/I2P) │
  └─────────────────────────────┴────────┴────────┴──────────────┘

  Default slot allocation (125 total):

  ┌──────────────────────────────────────────────────────────────┐
  │ 8 full-relay │ 2 block │ 1 feeler │ 8 addnode │ ~106 inbound│
  └──────────────────────────────────────────────────────────────┘
```

**BLOCK_RELAY** connections exist for network topology diversity
without the bandwidth cost of transaction relay. They are invisible
to spy nodes that probe transaction propagation patterns.

**FEELER** connections are ephemeral — connect, verify the peer is
alive, then immediately disconnect. They keep AddrMan's "tried" table
accurate.

### 3.3 `Transport` — The Wire Protocol Interface

**File**: `net.h` (line ~261)

```
                     ┌─────────────┐
                     │  Transport  │  (abstract interface)
                     │─────────────│
                     │ ReceivedBytes()               │
                     │ GetReceivedMessage()           │
                     │ SetMessageToSend()             │
                     │ GetBytesToSend()               │
                     │ ReceivedMessageComplete()      │
                     └──────┬──────┘
                            │
              ┌─────────────┴──────────────┐
              │                            │
       ┌──────▼──────┐            ┌────────▼────────┐
       │ V1Transport │            │  V2Transport    │
       │ (legacy)    │            │  (BIP324)       │
       │─────────────│            │─────────────────│
       │ SHA256      │            │ ChaCha20Poly1305│
       │ checksum    │            │ encryption      │
       │ 24-byte     │            │ 3-byte header   │
       │ header      │            │ key exchange     │
       └─────────────┘            └─────────────────┘
```

The `Transport` interface cleanly separates "how bytes become messages"
from "what messages mean." `CConnman` calls `Transport` methods to
serialize/deserialize; it never knows whether encryption is involved.

### 3.4 `V1Transport` — Legacy Bitcoin Protocol

```
  V1 Wire Format:
  ┌──────────┬──────────────┬──────────┬──────────┬─────────────┐
  │  Magic   │ Command Name │ Payload  │ Checksum │   Payload   │
  │ (4 bytes)│ (12 bytes)   │ Size (4) │ (4 bytes)│  (variable) │
  └──────────┴──────────────┴──────────┴──────────┴─────────────┘
  ◄─────────────── 24-byte header ───────────────►

  Receive State Machine:
    ┌──────────┐  got 24 bytes   ┌──────────┐  got payload   ┌──────────┐
    │ READING  │ ──────────────► │ READING  │ ─────────────► │ COMPLETE │
    │ HEADER   │                 │ DATA     │                │          │
    └──────────┘                 └──────────┘                └──────────┘
```

**Checksum**: First 4 bytes of `SHA256(SHA256(payload))`. Protects against
accidental corruption but not against active attackers (no encryption or
authentication).

### 3.5 `V2Transport` — BIP324 Encrypted Protocol

```
  V2 Handshake:
  ┌──────────────┐                    ┌──────────────┐
  │   Initiator  │                    │  Responder   │
  │              │ ── 64-byte key ──► │              │
  │              │    + garbage        │              │
  │              │                    │              │
  │              │ ◄── 64-byte key ── │              │
  │              │    + garbage        │              │
  │              │    + garbage term   │              │
  │              │                    │              │
  │              │ ── garbage term ──► │              │
  │              │ ── encrypted ver ─► │              │
  │              │                    │              │
  │              │ ◄── encrypted ver ─│              │
  │              │                    │              │
  │   ═══ Encrypted channel established ═══         │
  └──────────────┘                    └──────────────┘

  V2 Encrypted Packet:
  ┌──────────────┬──────────────────────┬──────────┐
  │ Length (3 B) │ Encrypted Payload    │ MAC (16) │
  │ (encrypted)  │ (1-byte type + data) │          │
  └──────────────┴──────────────────────┴──────────┘
```

**Receive State Machine** (more complex than V1):

```
  ┌───────────────┐                ┌──────────┐
  │ KEY_MAYBE_V1  │ ─ V1 magic? ─►│ V1       │ (fallback)
  │ (detect v1/v2)│                │ FALLBACK │
  └───────┬───────┘                └──────────┘
          │ not V1
          ▼
  ┌───────────────┐  64 bytes  ┌──────────────────┐
  │     KEY       │ ─────────► │ GARB_GARBTERM    │
  │ (recv pubkey) │            │ (recv garbage +   │
  └───────────────┘            │  16-byte termin.) │
                               └────────┬─────────┘
                                        │ found terminator
                                        ▼
                               ┌──────────────────┐
                               │    VERSION       │
                               │ (decrypt version │
                               │  packet)         │
                               └────────┬─────────┘
                                        │
                                        ▼
                               ┌──────────────────┐
                               │      APP         │ ◄─── Steady state:
                               │ (decrypt app     │      decrypt packets
                               │  packets)        │      in a loop
                               └──────────────────┘
```

**Why the complexity?** V2 must:
1. Look indistinguishable from random bytes (censorship resistance)
2. Support graceful fallback to V1 (for mixed networks)
3. Authenticate the session (via garbage terminator as AAD)
4. Use short message type IDs (1 byte vs 12 bytes in V1)

### 3.6 `CNetMessage` — A Parsed Incoming Message

```
┌─────────────────────────────────────────────────┐
│                  CNetMessage                    │
│                                                 │
│  m_type           : string ("tx", "block", ...) │
│  m_recv           : DataStream (payload bytes)  │
│  m_time           : microseconds (arrival time) │
│  m_message_size   : uint32_t (payload size)     │
│  m_raw_message_size: uint32_t (wire size incl.  │
│                      headers/encryption)        │
└─────────────────────────────────────────────────┘
```

### 3.7 `CSerializedNetMsg` — An Outgoing Message

```
┌─────────────────────────────────────────────────┐
│               CSerializedNetMsg                 │
│                                                 │
│  data    : vector<byte> (serialized payload)    │
│  m_type  : string ("tx", "block", ...)          │
│                                                 │
│  Move-only (no copying — prevents accidental    │
│  double-sends)                                  │
│                                                 │
│  Created via: CNetMsgMaker(version).Make(type, args...)  │
└─────────────────────────────────────────────────┘
```

### 3.8 `NetEventsInterface` — The Upward Callback Interface

This is how `CConnman` talks to `PeerManagerImpl` without depending on it:

```
  class NetEventsInterface {
      InitializeNode(CNode&)       — new peer connected
      FinalizeNode(CNode&)         — peer disconnected
      ProcessMessages(CNode&)      — "process this peer's messages"
      SendMessages(CNode&)         — "fill this peer's send queue"
  };
```

`CConnman` holds a `NetEventsInterface*` and calls these from
`ThreadMessageHandler`. The implementation lives in `net_processing.cpp`.

### 3.9 `CNodeStats` — A Snapshot for RPC/GUI

A copyable, thread-safe snapshot of `CNode` state. Created by
`CNode::CopyStats()` and used by RPCs like `getpeerinfo`. This avoids
holding locks while rendering JSON.

---

## 4. UML Class Diagram

```
┌──────────────────────────────┐           ┌────────────────────────┐
│      NetEventsInterface      │           │       AddrMan          │
│      (abstract)              │           │  (address database)    │
│──────────────────────────────│           └──────────┬─────────────┘
│ InitializeNode()             │                      │ used by
│ FinalizeNode()               │                      │
│ ProcessMessages()            │                      │
│ SendMessages()               │                      │
└──────────────┬───────────────┘                      │
               │ implemented by                       │
               │ PeerManagerImpl                      │
               │ (in net_processing.cpp)              │
               │                                      │
               │ called by ▼                          │
┌══════════════▼══════════════════════════════════════▼════════════┐
║                          CConnman                               ║
║═════════════════════════════════════════════════════════════════ ║
║                                                                 ║
║  ── Threads ─────────────────────────────────────────────────   ║
║  threadSocketHandler          threadMessageHandler              ║
║  threadOpenConnections        threadOpenAddedConnections        ║
║  threadDNSAddressSeed         threadI2PAcceptIncoming           ║
║  threadPrivateBroadcast                                         ║
║                                                                 ║
║  ── Connections ─────────────────────────────────────────────   ║
║  m_nodes              : vector<CNode*>                          ║
║  m_nodes_disconnected : list<CNode*>                            ║
║  vhListenSocket       : vector<ListenSocket>                    ║
║                                                                 ║
║  ── Limits ──────────────────────────────────────────────────   ║
║  m_max_outbound_full_relay  (8)                                 ║
║  m_max_outbound_block_relay (2)                                 ║
║  nMaxConnections            (125)                               ║
║                                                                 ║
║  ── Key Methods ─────────────────────────────────────────────   ║
║  Start() / Stop()                                               ║
║  PushMessage(node, msg)                                         ║
║  ConnectNode() / DisconnectNodes()                              ║
║  ForEachNode(func)                                              ║
║  AttemptToEvictConnection()                                     ║
╚═══════════════╤═════════════════════════════════════════════════╝
                │ owns 0..*
                ▼
┌═══════════════════════════════════════════════════════════════════┐
║                           CNode                                  ║
║═════════════════════════════════════════════════════════════════ ║
║  m_id          : NodeId                                          ║
║  addr          : CService                                        ║
║  m_conn_type   : ConnectionType                                  ║
║  m_sock        : shared_ptr<Sock>                                ║
║  m_transport   : unique_ptr<Transport>  ──────────┐              ║
║                                                   │              ║
║  vSendMsg[]    : deque<vector<byte>>              │              ║
║  vRecvMsg[]    : list<CNetMessage>                │              ║
║  m_msg_process_queue : list<CNetMessage>          │              ║
║                                                   │              ║
║  nVersion, cleanSubVer                            │              ║
║  fSuccessfullyConnected                           │              ║
║  fDisconnect                                      │              ║
║  m_permission_flags                               │              ║
╚═══════════════════════════════════════════════════╤══════════════╝
                                                    │ owns 1
                                                    ▼
                              ┌─────────────────────────────────┐
                              │  Transport (abstract interface) │
                              └─────────────┬───────────────────┘
                                            │
                              ┌─────────────┴──────────────┐
                              │                            │
                       ┌──────▼──────┐            ┌────────▼────────┐
                       │ V1Transport │            │  V2Transport    │
                       │ (plain)     │            │  (encrypted)    │
                       │ Magic+Cmd+  │            │  BIP324 cipher  │
                       │ Size+Cksum  │            │  AEAD packets   │
                       └─────────────┘            └─────────────────┘

┌──────────────────────────┐          ┌───────────────────────────┐
│      CNetMessage         │          │   CSerializedNetMsg       │
│ (parsed incoming message)│          │ (outgoing message)        │
│──────────────────────────│          │───────────────────────────│
│ m_type                   │          │ data : vector<byte>       │
│ m_recv : DataStream      │          │ m_type : string           │
│ m_time                   │          │ (move-only)               │
│ m_message_size           │          └───────────────────────────┘
│ m_raw_message_size       │
└──────────────────────────┘

Connection Type Enum:
┌──────────────────────────────────────────────┐
│  INBOUND             ← they connected to us  │
│  OUTBOUND_FULL_RELAY ← we connected (full)   │
│  BLOCK_RELAY         ← we connected (blocks) │
│  MANUAL              ← -addnode / RPC         │
│  FEELER              ← short probe            │
│  ADDR_FETCH          ← seed address fetch     │
│  PRIVATE_BROADCAST   ← Tor/I2P tx broadcast  │
└──────────────────────────────────────────────┘
```

---

## 5. Connection Lifecycle

### 5.1 Outbound Connection

```
  ThreadOpenConnections()
       │
       ├─ Decide what kind of connection to make
       │  (full-relay? block-relay? feeler?)
       │
       ├─ Pick peer from AddrMan (or anchors, or fixed seeds)
       │
       ▼
  OpenNetworkConnection(addr, conn_type)
       │
       ├─ Check: already connected? banned? self-connection?
       │
       ▼
  ConnectNode(addr)
       │
       ├─ Create TCP socket (or SOCKS5 proxy, or I2P SAM)
       ├─ Negotiate V2 if -v2transport=1:
       │    Send ElligatorSwift public key + garbage
       │    (V1 fallback: detect magic bytes)
       │
       ▼
  new CNode(id, sock, addr, conn_type, transport)
       │
       ├─ CConnman adds to m_nodes[]
       │
       ▼
  NetEventsInterface::InitializeNode(node)
       │ (PeerManagerImpl creates Peer + CNodeState)
       │
       ▼
  ThreadMessageHandler picks up new node
       │
       ├─ SendMessages(): sends VERSION message
       │
       ▼
  ... VERSION/VERACK handshake (see net_processing doc) ...
       │
  node.fSuccessfullyConnected = true
```

### 5.2 Inbound Connection

```
  ThreadSocketHandler()
       │
       ▼
  SocketHandlerListening()
       │
       ├─ poll() reports a listening socket is readable
       │
       ▼
  AcceptConnection(listen_socket)
       │
       ├─ accept() → new socket fd
       │
       ▼
  CreateNodeFromAcceptedSocket(sock, addr, ...)
       │
       ├─ Check: banned? too many inbounds? AttemptToEvictConnection()?
       ├─ Detect: Tor onion? I2P? CJDNS?
       │
       ▼
  new CNode(id, sock, addr, INBOUND, transport)
       │
       ├─ Add to m_nodes[]
       │
       ▼
  InitializeNode() → ... same as outbound from here ...
```

### 5.3 Disconnection

```
  fDisconnect flag set by:
    • Misbehavior/ban
    • Inactivity timeout (20 minutes)
    • Handshake timeout
    • Eviction
    • User request (disconnectnode RPC)
    • Transport error
    • V2 handshake failure

  DisconnectNodes() [called by ThreadSocketHandler]:
       │
       ├─ Lock m_nodes_mutex
       ├─ Remove nodes with fDisconnect from m_nodes
       ├─ Move to m_nodes_disconnected
       │
       └─ For nodes in m_nodes_disconnected:
            ├─ If refcount == 0:
            │    ├─ FinalizeNode() callback
            │    └─ delete node
            └─ Else: wait (someone still has a reference)
```

---

## 6. The Transport Layer — V1 vs V2 (BIP324)

### Feature Comparison

```
  ┌─────────────────────┬──────────────────┬──────────────────────┐
  │ Feature             │ V1 Transport     │ V2 Transport (BIP324)│
  ├─────────────────────┼──────────────────┼──────────────────────┤
  │ Header size         │ 24 bytes         │ 3 bytes (encrypted)  │
  │ Msg type encoding   │ 12 bytes (ASCII) │ 1 byte (numeric)     │
  │ Encryption          │ None             │ ChaCha20Poly1305     │
  │ Authentication      │ None             │ AEAD (per packet)    │
  │ Integrity           │ SHA256 checksum  │ Poly1305 MAC         │
  │ Handshake           │ None (cleartext) │ ECDH key exchange    │
  │ Censorship resist.  │ Magic bytes      │ Random-looking bytes │
  │ Overhead per msg    │ 24 bytes         │ 19 bytes (3+16)      │
  │ Connection detect.  │ Easy (magic)     │ Hard (looks random)  │
  └─────────────────────┴──────────────────┴──────────────────────┘
```

### V2 Fallback Mechanism

```
  Initiator sends 64-byte public key (looks random)
       │
       ▼
  Responder checks first byte:
       │
       ├─ Matches V1 magic byte? → Create V1Transport as fallback
       │  (The 64-byte key was never going to start with the
       │   V1 magic, so if we see magic, it's really a V1 peer)
       │
       └─ Doesn't match? → Proceed with V2 handshake
```

This allows a V2-capable node to accept both V1 and V2 inbound
connections on the same port.

---

## 7. Peer Discovery — How Nodes Find Each Other

```
  ┌────────────────────────────────────────────────────────────────┐
  │                    Discovery Priority                          │
  │                                                                │
  │  1. Anchor connections (anchors.dat)                           │
  │     Block-relay peers from last session, reconnect first       │
  │                                                                │
  │  2. AddrMan (peers.dat)                                        │
  │     Persistent database of known peer addresses                │
  │     Populated by: addr relay, DNS seeds, manual additions      │
  │                                                                │
  │  3. DNS Seeds (ThreadDNSAddressSeed)                           │
  │     Queried if AddrMan has few peers                           │
  │     Delay: 11s if <1000 peers, 5min if ≥1000 peers            │
  │     x{flags}.seed.bitcoin.sipa.be, etc.                       │
  │                                                                │
  │  4. Seed Nodes (-seednode=)                                    │
  │     Connect briefly to fetch addresses, then disconnect        │
  │                                                                │
  │  5. Fixed Seeds (chainparamsseeds.h)                           │
  │     Hardcoded IP list compiled into the binary                 │
  │     Last resort — only used if all above fail                  │
  └────────────────────────────────────────────────────────────────┘
```

### Connection Strategy (ThreadOpenConnections)

```
  Every ~500ms:
       │
       ├─ Need anchor connections? → Try anchors first
       │
       ├─ Need feeler? (every 2 min)
       │    └─ Pick random addr from AddrMan "new" or "tried"
       │       Connect, verify alive, disconnect
       │
       ├─ Need full-relay? (<8 connected)
       │    └─ Pick addr from AddrMan, check netgroup diversity
       │
       ├─ Need block-relay? (<2 connected)
       │    └─ Pick addr, prefer different netgroups from full-relay
       │
       └─ Need extra block-relay? (every 5 min, if tip stale)
              └─ Try to rotate: evict worst block-relay peer,
                 replace with fresh connection
```

### Netgroup Diversity

The wallet avoids connecting multiple peers in the same "netgroup"
(usually a /16 for IPv4). This protects against eclipse attacks where
an attacker fills all your connections from one ASN.

With `-asmap=` configured, AS numbers are used instead of /16 prefixes,
providing much better diversity.

---

## 8. Peer Eviction — Who Gets Kicked

When all inbound slots are full and a new peer connects:

```
  AttemptToEvictConnection()
       │
       ▼
  Collect NodeEvictionCandidate for each inbound peer:
    • network, connection time, min ping time
    • last block time, last tx time
    • bytes sent/received
    • relay capability, services
    • netgroup, permission flags
       │
       ▼
  SelectNodeToEvict() [in node/eviction.cpp]:
       │
       ├─ Protect the 4 peers with lowest ping time
       ├─ Protect the 4 peers that most recently sent us blocks
       ├─ Protect the 4 peers that most recently sent us txs
       ├─ Protect the 8 peers connected longest
       ├─ Protect peers from underrepresented networks
       │  (at least 1 each from Tor, I2P, CJDNS, localhost)
       ├─ Protect peers with Noban permission
       │
       └─ From remaining: evict the peer with the most
          connections from the same netgroup (break ties by
          most recent connection = youngest evicted first)
```

**Key insight**: The eviction algorithm is designed to resist eclipse
attacks. An attacker can't fill your slots by being fast (ping-protected),
by being old (tenure-protected), or by having many IPs in one ASN
(netgroup-protected).

---

## 9. Send/Receive Data Flow

### Sending a Message

```
  PeerManagerImpl calls:
    m_connman.PushMessage(node, CNetMsgMaker(ver).Make("inv", inv_vec));
         │
         ▼
  CConnman::PushMessage(CNode& node, CSerializedNetMsg&& msg)
         │
         ├─ Lock node.cs_vSend
         ├─ node.m_transport->SetMessageToSend(msg)
         │       │
         │       └─ V1: Prepend 24-byte header (magic+cmd+size+checksum)
         │          V2: Encrypt payload, prepend 3-byte encrypted length
         │
         ├─ Attempt immediate send (optimization):
         │    GetBytesToSend() → sock->Send() → MarkBytesSent()
         │
         └─ If not fully sent: bytes remain in transport buffer,
            ThreadSocketHandler will finish sending on next poll()
```

### Receiving a Message

```
  ThreadSocketHandler:
    poll() reports socket readable
         │
         ▼
  SocketHandlerConnected(node):
    sock->Recv(buffer)
         │
         ▼
  node.ReceiveMsgBytes(buffer):
    Lock cs_vRecv
    node.m_transport->ReceivedBytes(buffer)
         │
         ├─ V1: Parse header, verify checksum, extract payload
         │  V2: Decrypt AEAD packet, decompress message type
         │
         ├─ If message complete:
         │    GetReceivedMessage() → CNetMessage
         │    Add to node.vRecvMsg
         │
         └─ Return (more bytes may follow)
         │
         ▼
  node.MarkReceivedMsgsForProcessing():
    Lock m_msg_process_queue_mutex
    Move vRecvMsg → m_msg_process_queue
    If queue too large: set fPauseRecv = true (back-pressure)
         │
         ▼
  ThreadMessageHandler (next iteration):
    node.PollMessage() → get one CNetMessage
    m_msgproc->ProcessMessages(node)
    (handled by PeerManagerImpl — see companion document)
```

---

## 10. Thread Safety & Locking Model

### Lock Hierarchy

```
  Coarsest (acquire first)
  ────────────────────────
  g_msgproc_mutex         ← serializes all message processing
  m_nodes_mutex           ← protects m_nodes vector (RecursiveMutex)
  CNode::cs_vSend         ← per-node send queue
  CNode::cs_vRecv         ← per-node receive queue
  CNode::m_sock_mutex     ← per-node socket pointer
  Transport::m_recv_mutex ← V2 receive state
  Transport::m_send_mutex ← V2 send state
  ────────────────────────
  Finest (acquire last)
```

### Key Rules

1. **Never hold `m_nodes_mutex` when calling `PushMessage()`** — it
   acquires `cs_vSend` internally.

2. **V2Transport**: `m_recv_mutex` before `m_send_mutex` (never reverse).

3. **`g_msgproc_mutex`** serializes `ProcessMessages` + `SendMessages`
   for all peers. This is a bottleneck but simplifies reasoning.

4. **Atomic fields** on CNode (`m_last_send`, `m_last_recv`, etc.)
   can be read without locks — used for timeout checks from
   ThreadSocketHandler.

5. **Reference counting** (`nRefCount`) prevents `CNode` deletion while
   other code holds pointers. `AddRef()`/`Release()` are called via
   RAII `CNodeRef` wrappers.

---

## 11. Bandwidth Management

```
  ┌──────────────────────────────────────────────────────────┐
  │              Upload Limit (-maxuploadtarget)             │
  │                                                          │
  │  24-hour rolling window                                  │
  │                                                          │
  │  OutboundTargetReached(msg_size):                        │
  │    if (bytes_sent_this_cycle + msg_size > limit):        │
  │      return true → don't serve historical blocks         │
  │                                                          │
  │  Note: only limits BLOCK serving. Control messages       │
  │  (version, ping, addr) are always sent.                  │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │              Per-Node Flow Control                        │
  │                                                          │
  │  fPauseSend:  set when send buffer exceeds               │
  │              nSendBufferMaxSize (1 MB default)            │
  │              ThreadSocketHandler skips writing to peer    │
  │                                                          │
  │  fPauseRecv: set when process queue exceeds              │
  │              nReceiveFloodSize (5 MB default)             │
  │              ThreadSocketHandler stops reading from peer  │
  │              (back-pressure prevents memory exhaustion)   │
  └──────────────────────────────────────────────────────────┘
```

---

## 12. Improvement Proposals

### 12.1 Decompose `CConnman` Into Focused Components

**Problem**: `CConnman` is ~800 lines of header declarations managing
7 threads, connection lifecycle, bandwidth tracking, peer discovery
strategy, and socket I/O. It's Bitcoin Core's largest God Object after
`CWallet`.

**Suggestion**: Split responsibilities:

```
  Current CConnman (monolithic)
       │
       ├──► ConnectionManager     — m_nodes, Connect/Disconnect, eviction
       ├──► SocketEngine          — poll(), read/write, accept
       ├──► ConnectionStrategy    — ThreadOpenConnections logic,
       │                            anchor/feeler/diversity policy
       ├──► BandwidthTracker      — upload limits, per-node flow control
       └──► CConnman (facade)     — thin coordinator, thread lifecycle
```

Each component would be independently testable. The connection strategy
(which peers to connect to) is particularly ripe for extraction — it has
complex logic with no inherent dependency on sockets.

### 12.2 Extract `CNode` Data Into Layers

**Problem**: `CNode` mixes transport state (socket, buffers), protocol
state (version, subversion), application state (permission flags, stats),
and lifecycle state (refcount, disconnect flag). External code accesses
fields it shouldn't need.

**Suggestion**: Layer the data:

```cpp
// Transport-layer data (only SocketEngine needs this)
struct NodeTransport {
    shared_ptr<Sock> sock;
    unique_ptr<Transport> transport;
    deque<vector<byte>> send_queue;
    list<CNetMessage> recv_queue;
};

// Protocol-layer data (only PeerManager needs this)
struct NodeProtocol {
    int version;
    string subversion;
    bool successfully_connected;
    NetPermissionFlags permissions;
};

// Public identity (anyone can read)
struct NodeIdentity {
    NodeId id;
    CService addr;
    ConnectionType conn_type;
    chrono::seconds connected_time;
};
```

### 12.3 Remove Recursive Mutex for `m_nodes_mutex`

**Problem**: `m_nodes_mutex` is a `RecursiveMutex`, which is generally
considered a code smell — it means code can accidentally re-enter locked
sections without noticing. The Bitcoin Core coding guidelines discourage
recursive mutexes.

**Suggestion**: Audit all paths that lock `m_nodes_mutex`, refactor to
eliminate re-entrancy, and convert to a plain `Mutex`. This may require
splitting some methods into a locked inner function and an unlocked
public wrapper.

### 12.4 Decouple Peer Selection Policy from Socket Code

**Problem**: `ThreadOpenConnections()` is a ~370-line function that
interleaves high-level policy decisions ("should I make a feeler
connection?") with low-level operations ("create a socket to this IP").
Testing connection strategy requires running actual sockets.

**Suggestion**: Extract a pure `ConnectionPolicy` class:

```cpp
struct ConnectionDecision {
    CAddress target;
    ConnectionType type;
    // metadata: why this peer was chosen
};

class ConnectionPolicy {
public:
    // Given current state, decide what to do next
    std::optional<ConnectionDecision> NextConnection(
        const ConnectionSnapshot& current_state,
        AddrMan& addrman,
        FastRandomContext& rng
    ) const;
};
```

This would be testable with mock state — no sockets, no threads.

### 12.5 Formalize the V2 Transport State Machine

**Problem**: V2Transport has two interleaved state machines (send and
receive) with 6+ states each. The states are enum values with transitions
buried in method implementations. It's correct but hard to audit.

**Suggestion**: Use a state-transition table or diagram-driven approach:

```cpp
// Explicit transition table
static const TransitionTable RECV_TRANSITIONS = {
    {RecvState::KEY_MAYBE_V1, Event::V1_DETECTED, RecvState::V1},
    {RecvState::KEY_MAYBE_V1, Event::GOT_BYTE,    RecvState::KEY},
    {RecvState::KEY,          Event::GOT_64_BYTES, RecvState::GARB_GARBTERM},
    {RecvState::GARB_GARBTERM,Event::FOUND_TERM,   RecvState::VERSION},
    // ...
};
```

This makes the state machine self-documenting and auditable — critical
for security-sensitive code like encrypted transport.

### 12.6 Reduce Thread Count with an Event Loop

**Problem**: 7 threads is a lot. Each thread wakes periodically, holds
locks, and does work. The interaction between `ThreadSocketHandler` and
`ThreadMessageHandler` requires careful synchronization via queues and
condition variables.

**Suggestion**: Consolidate I/O and message handling into a single
event loop (similar to `libuv` or `boost::asio`), with the connection
strategy and DNS threads as separate background tasks:

```
  Main event loop (1 thread):
    poll() for sockets
    Read/write bytes
    Parse messages (transport)
    Dispatch to ProcessMessages()
    Call SendMessages()

  Background threads:
    ConnectionStrategy (opens new connections periodically)
    DNSResolver (one-shot address fetch)
```

This would reduce lock contention and make the code flow easier to
follow. It's a major refactor but aligns with modern networking practice.

### 12.7 Address the `CNode` Public Field Exposure

**Problem**: Many `CNode` fields are public and directly accessed by
`net_processing.cpp`. This creates tight coupling between the two
layers. For example, `nVersion`, `fSuccessfullyConnected`, and
`cleanSubVer` are read directly.

**Suggestion**: Provide a narrow, read-only interface for the protocol
layer:

```cpp
class PeerConnection {
public:
    NodeId GetId() const;
    ConnectionType GetConnectionType() const;
    bool IsSuccessfullyConnected() const;
    int GetVersion() const;
    bool HasPermission(NetPermissionFlags flag) const;
    // ... only what PeerManager actually needs
};
```

`CNode` would implement `PeerConnection`, and `PeerManagerImpl` would
only hold `PeerConnection&` references.

---

*This document reflects the state of Bitcoin Core's networking code as of
early 2026 (8f0e1f6540). See [NET_PROCESSING_ARCHITECTURE.md](NET_PROCESSING_ARCHITECTURE.md)
for the protocol layer that processes messages on top of this transport layer.*

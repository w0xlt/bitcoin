# Bitcoin Core Script Interpreter Architecture Guide

> A didactic guide for new developers to understand the Script execution engine
> in `src/script/interpreter.{h,cpp}` — the code that evaluates whether a
> transaction is authorized to spend its inputs.

---

## Table of Contents

1. [Where the Script Interpreter Sits](#1-where-the-script-interpreter-sits)
2. [The Core Mental Model](#2-the-core-mental-model)
3. [Script Versions — Four Eras of Bitcoin Scripting](#3-script-versions--four-eras-of-bitcoin-scripting)
4. [Class-by-Class Deep Dive](#4-class-by-class-deep-dive)
5. [UML Class Diagram](#5-uml-class-diagram)
6. [The Verification Entry Point — VerifyScript()](#6-the-verification-entry-point--verifyscript)
7. [The Evaluation Engine — EvalScript()](#7-the-evaluation-engine--evalscript)
8. [Opcode Reference by Category](#8-opcode-reference-by-category)
9. [Signature Hashing — What Gets Signed](#9-signature-hashing--what-gets-signed)
10. [Witness Program Dispatch — VerifyWitnessProgram()](#10-witness-program-dispatch--verifywitnessprogram)
11. [Taproot Deep Dive — Key-Path vs Script-Path](#11-taproot-deep-dive--key-path-vs-script-path)
12. [Verification Flags — Consensus vs Policy](#12-verification-flags--consensus-vs-policy)
13. [Caching & Performance Optimizations](#13-caching--performance-optimizations)
14. [Security Model & Consensus Limits](#14-security-model--consensus-limits)
15. [Improvement Proposals](#15-improvement-proposals)

---

## 1. Where the Script Interpreter Sits

```
┌─────────────────────────────────────────────────────────────────────┐
│  Validation Layer (validation.cpp)                                   │
│  MemPoolAccept / ConnectBlock: decides whether txs are valid        │
└────────────────────────────┬────────────────────────────────────────┘
                             │ For each input: verify spending auth
                             │
┌════════════════════════════▼════════════════════════════════════════┐
║  Script Interpreter (interpreter.cpp)       ◄── THIS DOCUMENT       ║
║  VerifyScript(): top-level dispatch                                 ║
║  EvalScript(): stack-based bytecode evaluator                       ║
║  VerifyWitnessProgram(): witness version routing                    ║
╚════════╤══════════════════╤════════════════════╤════════════════════╝
         │                  │                    │
         ▼                  ▼                    ▼
┌──────────────┐  ┌──────────────────┐  ┌────────────────────────┐
│  Signature   │  │  Hash Primitives │  │  Key Verification      │
│  Cache       │  │  (hash.h)        │  │  CPubKey::Verify()     │
│  (sigcache.h)│  │  SHA256, RIPEMD  │  │  XOnlyPubKey::         │
│              │  │  TaggedHash      │  │    VerifySchnorr()     │
└──────────────┘  └──────────────────┘  └────────────────────────┘
```

**Key insight**: The script interpreter is Bitcoin's **authorization engine**.
Every satoshi ever spent had to pass through this code. It answers one question:
"Does the spender prove they have the right to spend these coins?" This is done
by executing a small stack-based programming language embedded in transactions.

**Files involved**:

| File | Role |
|------|------|
| `src/script/interpreter.h` | Core interfaces: EvalScript, VerifyScript, signature checkers |
| `src/script/interpreter.cpp` | All implementations (~2200 lines) |
| `src/script/script.h` | CScript, CScriptNum, opcode enum, CScriptWitness |
| `src/script/script_error.h` | ScriptError enum (47 error codes) |
| `src/script/verify_flags.h` | Type-safe `script_verify_flags` wrapper |
| `src/script/sigcache.h` | Signature verification cache |
| `src/pubkey.h` | CPubKey (ECDSA) and XOnlyPubKey (Schnorr) |
| `src/hash.h` | HashWriter, TaggedHash, CHash256, CHash160 |

---

## 2. The Core Mental Model

Bitcoin Script is a **stack-based, non-Turing-complete language**. It has no
loops, no recursion, and strict resource limits. Think of it as a reverse-Polish
calculator that can also check cryptographic signatures.

```
 Spending transaction                    Previous transaction
 ┌──────────────────┐                   ┌──────────────────┐
 │  Input:           │                   │  Output:          │
 │  scriptSig:       │   unlocks ──▶    │  scriptPubKey:    │
 │  [sig] [pubkey]   │                   │  OP_DUP           │
 │                   │                   │  OP_HASH160       │
 │  witness:         │                   │  <hash160>        │
 │  (for segwit)     │                   │  OP_EQUALVERIFY   │
 └──────────────────┘                   │  OP_CHECKSIG      │
                                         └──────────────────┘

         Combined execution on the stack:
         ─────────────────────────────────
         Push sig           → [sig]
         Push pubkey        → [sig, pubkey]
         OP_DUP             → [sig, pubkey, pubkey]
         OP_HASH160         → [sig, pubkey, hash(pubkey)]
         Push <hash160>     → [sig, pubkey, hash(pk), expected]
         OP_EQUALVERIFY     → [sig, pubkey]  (or fail)
         OP_CHECKSIG        → [true]  (or [false])
```

The verification succeeds if the final stack has exactly one element that
evaluates to `true`.

### The Four Layers of Script Verification

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Witness Dispatch (VerifyWitnessProgram)           │
│  Routes witness v0 (P2WPKH/P2WSH) and v1 (Taproot)        │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Script Orchestration (VerifyScript)               │
│  Runs scriptSig, then scriptPubKey, then P2SH/witness      │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Bytecode Evaluation (EvalScript)                  │
│  The opcode dispatch loop — stack machine execution         │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Cryptographic Primitives                          │
│  ECDSA/Schnorr verification, hashing, signature hashing    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Script Versions — Four Eras of Bitcoin Scripting

The `SigVersion` enum tracks which era's rules apply:

```cpp
enum class SigVersion {
    BASE = 0,       // Legacy: bare scripts + P2SH (2009–)
    WITNESS_V0 = 1, // SegWit v0: P2WPKH + P2WSH (BIP 141, 2017–)
    TAPROOT = 2,    // Witness v1 key-path: Schnorr (BIP 341, 2021–)
    TAPSCRIPT = 3,  // Witness v1 script-path: Tapscript (BIP 342, 2021–)
};
```

Each version changes:

| Aspect | BASE | WITNESS_V0 | TAPROOT | TAPSCRIPT |
|--------|------|------------|---------|-----------|
| **Signature** | ECDSA (DER) | ECDSA (DER) | Schnorr (64B) | Schnorr (64B) |
| **Sighash** | Legacy serialization | BIP143 | BIP341 | BIP342 |
| **Pubkey** | Compressed/uncompressed | Compressed only | X-only (32B) | X-only (32B) |
| **Multi-sig** | OP_CHECKMULTISIG | OP_CHECKMULTISIG | N/A (key-path) | OP_CHECKSIGADD |
| **Script in** | scriptSig | witness stack | N/A | witness stack |
| **Size limit** | 10,000 bytes | 10,000 bytes | N/A | No script limit |
| **FindAndDelete** | Yes | No | N/A | No |
| **OP_SUCCESS** | N/A | N/A | N/A | Immediate success |

---

## 4. Class-by-Class Deep Dive

### 4.1 BaseSignatureChecker (abstract)

The **strategy pattern** interface for signature verification. The interpreter
never calls cryptographic functions directly — it always goes through this
interface, enabling testing with mock checkers.

```cpp
class BaseSignatureChecker {
    virtual bool CheckECDSASignature(...) const;   // Default: false
    virtual bool CheckSchnorrSignature(...) const;  // Default: false
    virtual bool CheckLockTime(...) const;          // Default: false
    virtual bool CheckSequence(...) const;          // Default: false
};
```

**Why virtual?** So that tests can inject a `DummySignatureChecker` that
always returns true, and so the signature cache can wrap the real checker
transparently.

### 4.2 GenericTransactionSignatureChecker\<T\>

The concrete checker for real transaction validation:

| Field | Type | Purpose |
|-------|------|---------|
| `txTo` | `const T*` | Transaction being verified |
| `nIn` | `unsigned int` | Input index being checked |
| `amount` | `CAmount` | Value of the output being spent |
| `txdata` | `const PrecomputedTransactionData*` | Cached hashes |
| `m_mdb` | `MissingDataBehavior` | ASSERT_FAIL (consensus) or FAIL (policy) |
| `m_sighash_cache` | `SigHashCache` (mutable) | ECDSA midstate cache |

Two type aliases:
```cpp
using TransactionSignatureChecker = GenericTransactionSignatureChecker<CTransaction>;
using MutableTransactionSignatureChecker = GenericTransactionSignatureChecker<CMutableTransaction>;
```

**Why templated?** Signing (with `CMutableTransaction`) and verification (with
`CTransaction`) use the same signature hash computation. The template avoids
duplicating the logic.

### 4.3 DeferringSignatureChecker

A **decorator** that delegates all checks to another checker:

```cpp
class DeferringSignatureChecker : public BaseSignatureChecker {
    const BaseSignatureChecker& m_checker;
    // All methods forward to m_checker
};
```

Used by `CachingTransactionSignatureChecker` in sigcache.h to layer caching
on top of real verification.

### 4.4 PrecomputedTransactionData

Caches expensive hash computations shared across all inputs in a transaction:

```
PrecomputedTransactionData
├── BIP143 (SegWit v0) — double-SHA256:
│   ├── hashPrevouts     ← SHA256d(all previous outpoints)
│   ├── hashSequence     ← SHA256d(all nSequence values)
│   └── hashOutputs      ← SHA256d(all outputs)
│
├── BIP341 (Taproot) — single-SHA256:
│   ├── m_prevouts_single_hash
│   ├── m_sequences_single_hash
│   ├── m_outputs_single_hash
│   ├── m_spent_amounts_single_hash    ← New: amounts of all spent outputs
│   └── m_spent_scripts_single_hash    ← New: scriptPubKeys of all spent outputs
│
└── m_spent_outputs: vector<CTxOut>    ← The actual UTXOs being spent
```

**Why two sets of hashes?** BIP143 uses double-SHA256 (historical Bitcoin
convention), while BIP341 switched to single-SHA256 for efficiency and
because double-hashing provides no meaningful extra security.

The `Init()` method auto-detects which hashes to precompute based on whether
the transaction has witness v0 or v1 inputs.

### 4.5 ScriptExecutionData

Mutable state tracked during Taproot/Tapscript execution:

| Field | Type | Purpose |
|-------|------|---------|
| `m_tapleaf_hash` | `uint256` | Hash of the leaf script being executed |
| `m_codeseparator_pos` | `uint32_t` | Byte offset of last OP_CODESEPARATOR (0xFFFFFFFF = none) |
| `m_annex_present` | `bool` | Whether witness has an annex (0x50 prefix) |
| `m_annex_hash` | `uint256` | SHA256 of the annex data |
| `m_validation_weight_left` | `int64_t` | Remaining signature budget (BIP342) |
| `m_output_hash` | `optional<uint256>` | Cached output hash for SIGHASH_SINGLE |

Each field has an `_init` boolean guard — lazy initialization, computed only
when first needed.

### 4.6 SigHashCache

Caches SHA256 midstates for ECDSA sighash computation:

```cpp
class SigHashCache {
    std::optional<std::pair<CScript, HashWriter>> m_cache_entries[6];
    // Slots: ALL, NONE, SINGLE × {with, without} ANYONECANPAY
};
```

**How it helps**: When a script has multiple OP_CHECKSIG operations (like
multisig), each signature needs a sighash. The expensive part (hashing the
transaction) is the same for all signatures with the same sighash type — only
the scriptCode may differ. The cache stores the SHA256 midstate just before
the sighash type byte is written, allowing fast completion.

### 4.7 ConditionStack (internal to interpreter.cpp)

An optimized representation of the IF/ELSE/ENDIF nesting stack:

```cpp
class ConditionStack {
    uint32_t m_stack_size;       // Nesting depth
    uint32_t m_first_false_pos;  // Depth of first false (NO_FALSE if all true)
};
```

**Clever optimization**: Instead of storing a `vector<bool>` of all condition
values, it only tracks the *depth of the first false*. This is sufficient
because:
- If all conditions are true → we're executing
- If any condition is false → we're skipping
- We only need to know *where* the first false is to correctly handle ELSE/ENDIF

This avoids O(depth) memory for deeply nested but unexecuted branches.

### 4.8 CScript (`script/script.h`)

The script bytecode container. Inherits from `prevector<36, uint8_t>` — a
small-buffer-optimized vector that stores up to 36 bytes inline (most standard
scripts fit).

Key methods:
- `GetOp(pc, opcode, data)` — read next instruction, advancing the iterator
- `IsPayToScriptHash()` — match `OP_HASH160 <20B> OP_EQUAL`
- `IsWitnessProgram(version, program)` — match `OP_n <2-40B>`
- `IsPayToTaproot()` — match `OP_1 <32B>`
- `IsPushOnly()` — only push operations (no opcodes > OP_16)

### 4.9 CScriptNum (`script/script.h`)

Script's number type. Internally stores `int64_t` but enforces:
- **Input**: max 4 bytes by default (range ±2³¹-1), 5 bytes for CLTV/CSV
- **Output**: results may temporarily exceed 4 bytes (int64 range)
- **Encoding**: sign-magnitude, little-endian, minimal (no leading zeros)

```
 Value    Encoded bytes
 ─────    ────────────────
   0      [] (empty)
   1      [0x01]
  -1      [0x81]
 127      [0x7f]
 128      [0x80, 0x00]
-128      [0x80, 0x80]
 255      [0xff, 0x00]
```

The `fRequireMinimal` flag (from SCRIPT_VERIFY_MINIMALDATA) rejects non-minimal
encodings like `[0x00]` for zero or `[0x01, 0x00]` for 1.

---

## 5. UML Class Diagram

```
                    ┌─────────────────────────────────┐
                    │    BaseSignatureChecker          │
                    │    (abstract)                    │
                    ├─────────────────────────────────┤
                    │ + CheckECDSASignature()          │
                    │ + CheckSchnorrSignature()        │
                    │ + CheckLockTime()                │
                    │ + CheckSequence()                │
                    └──────────┬──────────────────────┘
                               │ inherits
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
┌─────────────────────┐ ┌────────────┐ ┌───────────────────────┐
│ GenericTransaction   │ │ Deferring  │ │ CachingTransaction    │
│ SignatureChecker<T>  │ │ Signature  │ │ SignatureChecker       │
├─────────────────────┤ │ Checker    │ │ (sigcache.h)          │
│ - txTo: const T*    │ ├────────────┤ ├───────────────────────┤
│ - nIn: unsigned int │ │ - m_checker│ │ - store: SignatureCache│
│ - amount: CAmount   │ │   (ref)    │ │                       │
│ - txdata: Precomp.* │ └────────────┘ │ Checks cache before   │
│ - m_mdb: MissingData│                │ calling real verify    │
│ - m_sighash_cache   │                └───────────────────────┘
├─────────────────────┤
│ # VerifyECDSA...()  │
│ # VerifySchnorr.()  │
└─────────────────────┘
  instantiated as:
  TransactionSignatureChecker         (T = CTransaction)
  MutableTransactionSignatureChecker  (T = CMutableTransaction)


┌─────────────────────────────────────┐
│     PrecomputedTransactionData       │
├─────────────────────────────────────┤
│ BIP143:                             │
│   hashPrevouts, hashSequence,       │
│   hashOutputs                       │
│ BIP341:                             │
│   m_prevouts_single_hash, ...       │
│   m_spent_amounts_single_hash, ...  │
│ Common:                             │
│   m_spent_outputs: vector<CTxOut>   │
├─────────────────────────────────────┤
│ + Init(tx, spent_outputs)           │
└─────────────────────────────────────┘


┌─────────────────────────────────────┐
│       ScriptExecutionData            │
├─────────────────────────────────────┤
│ m_tapleaf_hash: uint256             │
│ m_codeseparator_pos: uint32_t       │
│ m_annex_present: bool               │
│ m_annex_hash: uint256               │
│ m_validation_weight_left: int64_t   │
│ m_output_hash: optional<uint256>    │
└─────────────────────────────────────┘


┌───────────────────────────┐    ┌───────────────────────────┐
│ CScript : prevector<36>   │    │ CScriptNum                │
├───────────────────────────┤    ├───────────────────────────┤
│ + GetOp(pc, op, data)     │    │ - m_value: int64_t        │
│ + IsPayToScriptHash()     │    │ + getvch() → vector<u8>   │
│ + IsWitnessProgram(v, p)  │    │ + operator+, -, &         │
│ + IsPayToTaproot()        │    │ + operator==, <=>         │
│ + IsPushOnly()            │    │ + CScriptNum(vch, min, sz)│
│ + GetSigOpCount()         │    └───────────────────────────┘
└───────────────────────────┘
```

---

## 6. The Verification Entry Point — VerifyScript()

`VerifyScript()` is the top-level function called for every transaction input.
It orchestrates the multi-phase evaluation:

```
VerifyScript(scriptSig, scriptPubKey, witness, flags, checker):

  Phase 1: Execute scriptSig
  ───────────────────────────
  EvalScript(stack, scriptSig, flags, checker, BASE)
  stackCopy = stack    ← Save for P2SH later

  Phase 2: Execute scriptPubKey
  ─────────────────────────────
  EvalScript(stack, scriptPubKey, flags, checker, BASE)
  if stack empty or top is false → FAIL

  Phase 3: Bare witness check
  ────────────────────────────
  if SCRIPT_VERIFY_WITNESS && scriptPubKey.IsWitnessProgram():
    scriptSig must be empty          ← Prevents malleability
    VerifyWitnessProgram(witness, version, program, ...)
    stack = [true]                   ← Bypass cleanstack for witness

  Phase 4: P2SH evaluation
  ─────────────────────────
  if SCRIPT_VERIFY_P2SH && scriptPubKey.IsPayToScriptHash():
    scriptSig must be push-only
    redeemScript = stackCopy.back()  ← Pop from original scriptSig stack
    EvalScript(stack, redeemScript, flags, checker, BASE)
    if result is false → FAIL

    Phase 4b: P2SH-wrapped witness
    ──────────────────────────────
    if redeemScript.IsWitnessProgram():
      VerifyWitnessProgram(witness, version, program, ..., is_p2sh=true)
      stack = [true]

  Phase 5: Final checks
  ──────────────────────
  if CLEANSTACK: stack must have exactly 1 element
  if witness flag set but no witness program found: unexpected witness → FAIL
  return SUCCESS
```

**Historical note**: scriptSig and scriptPubKey are run *sequentially on the
same stack*, not concatenated. This prevents a classic attack (CVE-2010-5141)
where `scriptSig = OP_1` would satisfy any scriptPubKey if they were
concatenated.

---

## 7. The Evaluation Engine — EvalScript()

The heart of the interpreter — a `for` loop that iterates over opcodes:

```
EvalScript(stack, script, flags, checker, sigversion, execdata):

  pc = script.begin()              ← Program counter
  pbegincodehash = script.begin()  ← Start of signable region
  vfExec = ConditionStack()        ← IF/ELSE nesting tracker
  altstack = []                    ← Secondary stack
  nOpCount = 0                     ← Opcode counter (max 201)
  opcode_pos = 0                   ← Byte position (for Tapscript sighash)

  for each opcode read via GetOp(pc, opcode, pushdata):

    ┌──────────────────────────────────────────────────────┐
    │  fExec = vfExec.all_true()                            │
    │  (Are we in an executed branch?)                      │
    └───────────────────────┬──────────────────────────────┘
                            │
    ┌───────────────────────▼──────────────────────────────┐
    │  Gate 1: Push data > 520 bytes?  → PUSH_SIZE error   │
    │  Gate 2: Disabled opcode?        → DISABLED error    │
    │  Gate 3: Non-push opcode?        → nOpCount++        │
    │           nOpCount > 201?        → OP_COUNT error    │
    └───────────────────────┬──────────────────────────────┘
                            │
    ┌───────────────────────▼──────────────────────────────┐
    │  if fExec && opcode is push:                         │
    │    Check minimal encoding if MINIMALDATA flag        │
    │    stack.push_back(pushdata)                         │
    │                                                      │
    │  elif fExec || opcode is IF/ELSE/ENDIF:              │
    │    switch(opcode):                                   │
    │      ... dispatch to handler ...                     │
    └───────────────────────┬──────────────────────────────┘
                            │
    ┌───────────────────────▼──────────────────────────────┐
    │  Post-op check:                                      │
    │  stack.size() + altstack.size() > 1000? → SIZE error │
    └──────────────────────────────────────────────────────┘

  Post-loop:
  vfExec must be empty (all IF blocks closed)
  return SUCCESS
```

**The critical fExec gate**: When `fExec` is false (we're inside an unexecuted
IF branch), *only* IF/ELSE/ENDIF opcodes are processed. Everything else is
silently skipped. This allows dead code in scripts without causing errors —
essential for things like `OP_IF <path_A> OP_ELSE <path_B> OP_ENDIF`.

### CastToBool — Script's Truth Function

```
CastToBool(value):
  [] (empty)     → false
  [0x00]         → false
  [0x00, 0x00]   → false
  [0x80]         → false  (negative zero!)
  [0x00, 0x80]   → false  (also negative zero)
  everything else → true
```

Any byte vector with at least one non-zero byte (ignoring a trailing 0x80 sign
bit) is `true`.

---

## 8. Opcode Reference by Category

### 8.1 Constants

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_0` / `OP_FALSE` | → `[]` | Push empty byte vector |
| `OP_1` – `OP_16` | → `[n]` | Push number 1–16 |
| `OP_1NEGATE` | → `[-1]` | Push -1 |
| `OP_PUSHDATA1/2/4` | → `[data]` | Push data with 1/2/4-byte length prefix |

### 8.2 Flow Control

| Opcode | Description |
|--------|-------------|
| `OP_NOP` | No operation |
| `OP_IF` / `OP_NOTIF` | Pop condition, enter branch. **Tapscript**: condition must be exactly `[]` or `[0x01]` |
| `OP_ELSE` | Toggle current branch |
| `OP_ENDIF` | End conditional block |
| `OP_VERIFY` | Pop; if false → FAIL |
| `OP_RETURN` | Immediately FAIL (marks output as provably unspendable) |

### 8.3 Stack Manipulation

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_DUP` | `[x] → [x, x]` | Duplicate top |
| `OP_DROP` | `[x] → []` | Remove top |
| `OP_SWAP` | `[x, y] → [y, x]` | Swap top two |
| `OP_ROT` | `[x, y, z] → [y, z, x]` | Rotate top three |
| `OP_OVER` | `[x, y] → [x, y, x]` | Copy second-from-top |
| `OP_PICK` | `[..., n] → [..., item_n]` | Copy nth item to top |
| `OP_ROLL` | `[..., n] → [...]` | Move nth item to top |
| `OP_NIP` | `[x, y] → [y]` | Remove second |
| `OP_TUCK` | `[x, y] → [y, x, y]` | Insert copy of top before second |
| `OP_IFDUP` | `[x] → [x, x]` if true | Duplicate if non-zero |
| `OP_DEPTH` | `→ [n]` | Push stack depth |
| `OP_SIZE` | `[x] → [x, len(x)]` | Push byte length of top (does not pop) |
| `OP_2DUP` | `[x, y] → [x, y, x, y]` | Duplicate top pair |
| `OP_2DROP` | `[x, y] → []` | Remove top pair |
| `OP_2SWAP` | `[a, b, c, d] → [c, d, a, b]` | Swap pairs |
| `OP_2OVER` | `[a, b, c, d] → [a, b, c, d, a, b]` | Copy second pair |
| `OP_2ROT` | `[a, b, c, d, e, f] → [c, d, e, f, a, b]` | Rotate pairs |
| `OP_3DUP` | `[x, y, z] → [x, y, z, x, y, z]` | Duplicate top triple |
| `OP_TOALTSTACK` | `[x] → []`, altstack: `→ [x]` | Move to alt stack |
| `OP_FROMALTSTACK` | `[] → [x]`, altstack: `[x] → []` | Move from alt stack |

### 8.4 Arithmetic (CScriptNum: 4-byte input, int64 internal)

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_ADD` | `[a, b] → [a+b]` | Addition |
| `OP_SUB` | `[a, b] → [a-b]` | Subtraction |
| `OP_1ADD` | `[a] → [a+1]` | Increment |
| `OP_1SUB` | `[a] → [a-1]` | Decrement |
| `OP_NEGATE` | `[a] → [-a]` | Negate |
| `OP_ABS` | `[a] → [\|a\|]` | Absolute value |
| `OP_NOT` | `[a] → [!a]` | Boolean NOT (0→1, else→0) |
| `OP_0NOTEQUAL` | `[a] → [a≠0]` | Boolean coercion |
| `OP_BOOLAND` | `[a, b] → [a&&b]` | Logical AND |
| `OP_BOOLOR` | `[a, b] → [a\|\|b]` | Logical OR |
| `OP_NUMEQUAL` | `[a, b] → [a==b]` | Numeric equality |
| `OP_LESSTHAN` | `[a, b] → [a<b]` | Less than |
| `OP_GREATERTHAN` | `[a, b] → [a>b]` | Greater than |
| `OP_MIN` / `OP_MAX` | `[a, b] → [min/max]` | Min/max |
| `OP_WITHIN` | `[x, min, max] → [min≤x<max]` | Range check |

### 8.5 Cryptographic

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_RIPEMD160` | `[x] → [ripemd160(x)]` | 20-byte RIPEMD-160 |
| `OP_SHA1` | `[x] → [sha1(x)]` | 20-byte SHA-1 |
| `OP_SHA256` | `[x] → [sha256(x)]` | 32-byte SHA-256 |
| `OP_HASH160` | `[x] → [ripemd160(sha256(x))]` | 20-byte hash (for addresses) |
| `OP_HASH256` | `[x] → [sha256(sha256(x))]` | 32-byte double-hash |

### 8.6 Signature Operations

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_CHECKSIG` | `[sig, pk] → [bool]` | Verify ECDSA or Schnorr signature |
| `OP_CHECKSIGVERIFY` | `[sig, pk] → []` | CHECKSIG + VERIFY (fail if false) |
| `OP_CHECKMULTISIG` | `[sigs..., n, pks..., m] → [bool]` | M-of-N ECDSA (**disabled in Tapscript**) |
| `OP_CHECKMULTISIGVERIFY` | Same → `[]` | CHECKMULTISIG + VERIFY |
| `OP_CHECKSIGADD` | `[sig, num, pk] → [num+1 or num]` | **Tapscript only**: increment counter if sig valid |
| `OP_CODESEPARATOR` | (none) | Update sighash boundary position |

### 8.7 Time-Lock Operations

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_CHECKLOCKTIMEVERIFY` | `[n] → [n]` (no pop) | Require tx.nLockTime ≥ n (BIP65) |
| `OP_CHECKSEQUENCEVERIFY` | `[n] → [n]` (no pop) | Require input.nSequence ≥ n (BIP112) |

### 8.8 Comparison

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_EQUAL` | `[a, b] → [a==b]` | Byte-for-byte equality |
| `OP_EQUALVERIFY` | `[a, b] → []` | EQUAL + VERIFY |

### 8.9 Disabled Opcodes (always error, since 2010)

```
OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT,           ← String ops
OP_INVERT, OP_AND, OP_OR, OP_XOR,               ← Bitwise ops
OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD,       ← Arithmetic
OP_LSHIFT, OP_RSHIFT                              ← Shift ops
```

These were disabled in response to CVE-2010-5137 (various DoS and overflow
bugs). Some may be re-enabled in future soft forks with proper bounds checking.

---

## 9. Signature Hashing — What Gets Signed

The sighash is the message that gets signed/verified. Different sighash types
let signers commit to different parts of the transaction:

### 9.1 Sighash Types

```
┌─────────────────────┬──────────────────────────────────────────┐
│ SIGHASH_ALL (0x01)  │ Sign all inputs + all outputs            │
│                     │ (default, most common)                   │
├─────────────────────┼──────────────────────────────────────────┤
│ SIGHASH_NONE (0x02) │ Sign all inputs + no outputs             │
│                     │ (anyone can redirect the funds)           │
├─────────────────────┼──────────────────────────────────────────┤
│ SIGHASH_SINGLE(0x03)│ Sign all inputs + only the matching      │
│                     │ output (same index as this input)         │
├─────────────────────┼──────────────────────────────────────────┤
│ ANYONECANPAY (0x80) │ Modifier: sign only this input           │
│                     │ (others can add more inputs)              │
├─────────────────────┼──────────────────────────────────────────┤
│ SIGHASH_DEFAULT(0x0)│ Taproot only: equivalent to ALL but      │
│                     │ encoded as 0x00 to save 1 byte            │
└─────────────────────┴──────────────────────────────────────────┘
```

### 9.2 Legacy Sighash (BASE)

Uses `CTransactionSignatureSerializer` — a custom serializer that modifies how
the transaction is written based on sighash type:

```
Legacy sighash computation:
  1. Create modified copy of transaction:
     - Remove OP_CODESEPARATOR from scriptCode
     - Blank all input scripts except the one being signed
     - If NONE: remove all outputs, zero other sequences
     - If SINGLE: blank all outputs except matching index
     - If ANYONECANPAY: only include the signed input
  2. Append 4-byte sighash type as little-endian
  3. Double-SHA256 the serialization
```

**Performance issue**: Every signature requires re-serializing a modified copy of
the entire transaction. For a transaction with 100 inputs, each input requires
hashing ~100 inputs → O(n²) total work. This was the motivation for BIP143.

### 9.3 SegWit v0 Sighash (BIP143)

Fixes the quadratic hashing problem with precomputed sub-hashes:

```
BIP143 sighash:
  1. Precompute (shared across all inputs):
     hashPrevouts  = SHA256d(all outpoints)      ← unless ANYONECANPAY
     hashSequence  = SHA256d(all sequences)       ← unless ANYONECANPAY/NONE/SINGLE
     hashOutputs   = SHA256d(all outputs)         ← unless NONE/SINGLE

  2. Per input:
     SHA256d(
       version
     + hashPrevouts
     + hashSequence
     + outpoint_being_spent
     + scriptCode
     + amount                    ← New: commits to input value
     + sequence
     + hashOutputs
     + locktime
     + sighash_type
     )
```

**Key improvement**: Commits to the `amount` being spent, preventing fee
manipulation attacks on hardware wallets.

### 9.4 Taproot Sighash (BIP341)

Further improvements using tagged hashes and more committed data:

```
BIP341 sighash:
  Tagged with "TapSighash" (domain separation)

  SHA256(
    SHA256("TapSighash") || SHA256("TapSighash")   ← tag
  + 0x00                                             ← epoch
  + hash_type
  + version + locktime
  + sha256(prevouts) + sha256(amounts) + sha256(scriptPubKeys)  ← New!
  + sha256(sequences) + sha256(outputs)
  + spend_type (ext_flag | annex_present)
  + input_data (outpoint or index depending on ANYONECANPAY)
  + [annex_hash if present]
  + [output hash if SIGHASH_SINGLE]
  + [tapleaf_hash + key_version + codesep_pos if TAPSCRIPT]
  )
```

**New commitments**:
- `sha256(amounts)`: All input amounts (not just this one) — prevents fee
  manipulation even with ANYONECANPAY
- `sha256(scriptPubKeys)`: All spent scripts — prevents signing for the wrong
  address type
- `tapleaf_hash`: Which script path is being used (TAPSCRIPT only)
- `codesep_pos`: Position of last OP_CODESEPARATOR (TAPSCRIPT only)
- Single-SHA256 instead of double-SHA256 (BIP341 rationale: no security benefit)

---

## 10. Witness Program Dispatch — VerifyWitnessProgram()

This function routes witness programs to the correct handler based on version
and program size:

```
VerifyWitnessProgram(witness, witversion, program, flags, checker):

  ┌──────────────────────────────────────────────────────────────┐
  │  witversion == 0                                              │
  ├──────────────┬───────────────────────────────────────────────┤
  │ program = 20B│  P2WPKH: witness = [sig, pubkey]              │
  │ (KEYHASH)    │  Construct script:                             │
  │              │    OP_DUP OP_HASH160 <program> OP_EQUALVERIFY  │
  │              │    OP_CHECKSIG                                  │
  │              │  ExecuteWitnessScript(witness, script, V0)     │
  ├──────────────┼───────────────────────────────────────────────┤
  │ program = 32B│  P2WSH: witness = [inputs..., witnessScript]   │
  │ (SCRIPTHASH) │  Pop witnessScript, verify SHA256 == program   │
  │              │  ExecuteWitnessScript(inputs, witnessScript, V0)│
  ├──────────────┼───────────────────────────────────────────────┤
  │ other size   │  FAIL (wrong length)                           │
  └──────────────┴───────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  witversion == 1 && program = 32B && TAPROOT flag set         │
  ├──────────────┬───────────────────────────────────────────────┤
  │ Annex check: │  If ≥2 witness items and last starts with 0x50:│
  │              │    Pop annex, hash it, store in execdata        │
  ├──────────────┼───────────────────────────────────────────────┤
  │ stack == 1   │  KEY-PATH SPEND                                │
  │              │  Single item = Schnorr signature                │
  │              │  Verify against program (= tweaked pubkey)      │
  │              │  → Success or fail, no script execution         │
  ├──────────────┼───────────────────────────────────────────────┤
  │ stack > 1    │  SCRIPT-PATH SPEND                             │
  │              │  Pop control block (last item)                  │
  │              │  Pop script (second-to-last)                    │
  │              │  Remaining items = script inputs                │
  │              │  Verify Taproot commitment:                     │
  │              │    internal_key = control[1..33]                │
  │              │    leaf_hash = TapLeaf(version, script)         │
  │              │    root = walk Merkle path in control block     │
  │              │    Verify program == Tweak(internal_key, root)  │
  │              │  If leaf_version == 0xc0 (Tapscript):           │
  │              │    ExecuteWitnessScript(inputs, script, TAPSCR) │
  │              │  Else: unknown leaf → success (forward compat)  │
  └──────────────┴───────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  witversion == 1 && IsPayToAnchor()                           │
  │  → Success (anyone-can-spend anchor output)                   │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  witversion ≥ 2 (unknown)                                     │
  │  → Success (forward compatibility for future soft forks)      │
  │    Unless DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM → FAIL        │
  └──────────────────────────────────────────────────────────────┘
```

---

## 11. Taproot Deep Dive — Key-Path vs Script-Path

### 11.1 The Taproot Structure

```
               Output scriptPubKey: OP_1 <Q>
                         │
                    Q = tweaked output key
                    Q = P + H(P || merkle_root) · G
                         │
              ┌──────────┴──────────┐
              │                     │
         Key-path:              Script-path:
         Sign with Q            Reveal script from tree
         (single Schnorr sig)   (provide Merkle proof)
                                     │
                              ┌──────┴──────┐
                              │  Merkle Tree │
                              │              │
                             / \            / \
                           /     \        /     \
                         leaf₁  leaf₂  leaf₃  leaf₄
                         (0xc0) (0xc0)  ...    ...
```

### 11.2 Key-Path Spending

The simplest case — no scripts involved:

```
Witness: [64-byte Schnorr signature]

Verification:
  1. Q = program (from scriptPubKey)
  2. sig = witness[0]
  3. CheckSchnorrSignature(sig, Q, TAPROOT, execdata)
     └── SignatureHashSchnorr(tx, input, hashtype, TAPROOT)
     └── XOnlyPubKey(Q).VerifySchnorr(sighash, sig)
```

**Why key-path is special**: No script is executed at all. The signature commits
to the transaction directly. This is the most efficient spending path and should
be the default for single-key wallets.

### 11.3 Script-Path Spending

Reveals one leaf of the Merkle tree:

```
Witness: [input₁, input₂, ..., script, control_block]

Control block format:
  ┌─────────┬──────────────────┬──────────┬──────────┬─────┐
  │ 1 byte  │    32 bytes      │ 32 bytes │ 32 bytes │ ... │
  │ leaf_ver │  internal_key    │  node₁   │  node₂   │     │
  │ + parity │  (x-only)       │ (sibling)│ (sibling)│     │
  └─────────┴──────────────────┴──────────┴──────────┴─────┘
  Size: 33 + 32k bytes (k = 0 to 128 = tree depth)

Verification:
  1. leaf_hash = TaggedHash("TapLeaf", leaf_version || CompactSize(len) || script)
  2. Walk the Merkle path:
     k = leaf_hash
     for each node in control_block[33..]:
       k = TaggedHash("TapBranch", sort(k, node))     ← Lexicographic sort!
  3. merkle_root = k
  4. parity = control[0] & 1
  5. Verify: Q == TweakPubKey(internal_key, merkle_root, parity)
  6. Execute script with remaining witness items
```

**Lexicographic sorting** in TapBranch ensures the same tree can be constructed
regardless of left/right ordering — the tree structure is canonical.

### 11.4 OP_CHECKSIGADD — Tapscript Multi-Signature

Tapscript replaces OP_CHECKMULTISIG with a composable primitive:

```
Old (legacy):  OP_0 <sig1> <sig2> OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
               → Single opcode, O(n×m) key-signature matching

New (Tapscript): <sig3> <sig2> <sig1>
                 <pk1> OP_CHECKSIG
                 <pk2> OP_CHECKSIGADD
                 <pk3> OP_CHECKSIGADD
                 OP_2 OP_NUMEQUAL
               → Each key checked individually, counter incremented

OP_CHECKSIGADD operation:
  Pop: [sig, counter, pubkey]
  if sig is non-empty and valid:
    Push: [counter + 1]
  else if sig is empty:
    Push: [counter]        ← Skip this key
  else (non-empty but invalid):
    → FAIL                 ← No silent failures in Tapscript
```

**Advantage**: Each key is verified independently with constant-time matching.
No O(n×m) scanning. Signers that want to skip provide an empty signature.

### 11.5 Tapscript Validation Weight Budget

BIP342 limits the total work a Tapscript can demand:

```
validation_weight_left = total_witness_size + 50

Each non-empty signature verification costs 50 weight units.
If validation_weight_left goes negative → FAIL
```

This replaces the per-script sigop limit with a per-witness weight-proportional
budget. Larger witnesses (which cost more to relay) are allowed more signature
checks.

### 11.6 OP_SUCCESS — Forward Compatibility

Tapscript reserves opcodes 0x50, 0x62, 0x7e-0xfe as `OP_SUCCESSx`. If any
of these appear in a script:

- **Consensus**: The script immediately succeeds (no further evaluation)
- **Policy** (DISCOURAGE_OP_SUCCESS): Rejected for relay

This allows future soft forks to redefine these opcodes with new semantics.
Old nodes will accept the transactions (success), while new nodes will enforce
the new rules.

---

## 12. Verification Flags — Consensus vs Policy

The `script_verify_flags` type is a type-safe bitmask (prevents accidental
integer mixing) that controls which rules apply:

### Consensus Flags (enforced for blocks)

| Flag | BIP | Purpose |
|------|-----|---------|
| `SCRIPT_VERIFY_P2SH` | 16 | Evaluate P2SH redeemscripts |
| `SCRIPT_VERIFY_DERSIG` | 66 | Require strict DER signature encoding |
| `SCRIPT_VERIFY_LOW_S` | 62 | Require low-S signature values |
| `SCRIPT_VERIFY_NULLDUMMY` | 147 | CHECKMULTISIG dummy must be empty |
| `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` | 65 | Enable OP_CLTV |
| `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` | 112 | Enable OP_CSV |
| `SCRIPT_VERIFY_WITNESS` | 141 | Enable segregated witness |
| `SCRIPT_VERIFY_TAPROOT` | 341 | Enable Taproot validation |

### Policy Flags (enforced for relay/mempool, not blocks)

| Flag | Purpose |
|------|---------|
| `SCRIPT_VERIFY_STRICTENC` | Reject non-standard signature encoding |
| `SCRIPT_VERIFY_SIGPUSHONLY` | scriptSig must be push-only |
| `SCRIPT_VERIFY_MINIMALDATA` | All pushes must use minimal encoding |
| `SCRIPT_VERIFY_CLEANSTACK` | Exactly one stack element must remain |
| `SCRIPT_VERIFY_MINIMALIF` | IF/NOTIF args must be minimal |
| `SCRIPT_VERIFY_NULLFAIL` | Failed CHECKSIG must have empty signature |
| `SCRIPT_VERIFY_WITNESS_PUBKEYTYPE` | Witness pubkeys must be compressed |
| `SCRIPT_VERIFY_CONST_SCRIPTCODE` | Reject OP_CODESEPARATOR in non-segwit |

### Soft-Fork Safety Flags

| Flag | Purpose |
|------|---------|
| `DISCOURAGE_UPGRADABLE_NOPS` | Reject NOP1–NOP10 (reserved for future opcodes) |
| `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` | Reject unknown witness versions |
| `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` | Reject unknown leaf versions |
| `DISCOURAGE_OP_SUCCESS` | Reject OP_SUCCESS opcodes |
| `DISCOURAGE_UPGRADABLE_PUBKEYTYPE` | Reject unknown pubkey formats |

**Design principle**: `DISCOURAGE_*` flags are policy-only. They let nodes
reject non-standard transactions for relay while still accepting them in blocks.
This is how Bitcoin's soft-fork upgrade mechanism works — nodes don't relay
transactions they don't understand, but they accept blocks containing them.

---

## 13. Caching & Performance Optimizations

### 13.1 Signature Cache (`sigcache.h`)

The most impactful optimization. When a transaction enters the mempool, all its
signatures are verified. When the same transaction later appears in a block,
the signatures would be verified again — unless cached.

```
CachingTransactionSignatureChecker
  inherits TransactionSignatureChecker
  wraps SignatureCache

  VerifyECDSASignature(sig, pubkey, sighash):
    entry = ComputeEntryECDSA(sighash, sig, pubkey)  ← Salted hash
    if cache.Get(entry):
      return true                                     ← Cache hit!
    if base.Verify(sig, pubkey, sighash):
      cache.Set(entry)                                ← Cache for later
      return true
    return false

  VerifySchnorrSignature(sig, pubkey, sighash):
    entry = ComputeEntrySchnorr(sighash, sig, pubkey)
    (same cache-check-then-verify pattern)
```

The cache uses a cuckoo hash map with random salt (prevents attackers from
crafting entries that collide).

### 13.2 PrecomputedTransactionData

Avoids recomputing the same hashes for every input in a transaction:

```
Without precomputation (per-input cost):
  BIP143: hash all prevouts + hash all sequences + hash all outputs = O(n)
  For n inputs: n × O(n) = O(n²)

With precomputation (total cost):
  Compute 3 hashes once = O(n)
  For n inputs: O(n) + n × O(1) = O(n)
```

### 13.3 SigHashCache

For scripts with multiple OP_CHECKSIG/OP_CHECKMULTISIG operations, the ECDSA
sighash computation up to the sighash-type byte is often identical. The
SigHashCache stores the SHA256 midstate at that point, allowing the final hash
to be completed with just one block of hashing instead of re-hashing the entire
transaction.

### 13.4 ConditionStack Optimization

Instead of `vector<bool>` for tracking IF/ELSE nesting (O(depth) memory), the
ConditionStack uses just two integers. Since Bitcoin scripts can nest IFs deeply
in unexecuted branches, this avoids allocating memory for code paths that are
never evaluated.

---

## 14. Security Model & Consensus Limits

### Hard Limits

| Limit | Value | Enforced In |
|-------|-------|-------------|
| Max script size | 10,000 bytes | CScript check before eval |
| Max element size | 520 bytes | EvalScript push check |
| Max stack + altstack | 1,000 items | EvalScript post-op check |
| Max non-push opcodes | 201 | EvalScript nOpCount |
| Max pubkeys per CHECKMULTISIG | 20 | CHECKMULTISIG handler |
| Max Taproot control block | 4,129 bytes (33 + 128×32) | VerifyWitnessProgram |
| Max Taproot tree depth | 128 | Control block size check |
| Tapscript validation weight | witness_size + 50 | ExecuteWitnessScript |

### Signature Validation Rules

| Rule | BASE | WITNESS_V0 | TAPSCRIPT |
|------|------|------------|-----------|
| DER encoding required | BIP66 | BIP66 | N/A (Schnorr) |
| Low-S required | Policy | Policy | N/A (Schnorr) |
| Empty sig on failure | Policy (NULLFAIL) | Policy | **Consensus** |
| Compressed pubkey only | No | Policy | N/A (x-only) |
| FindAndDelete sig from script | Yes | No | No |
| Signature commits to amount | No | Yes | Yes |

### The "NULLFAIL" Rule Evolution

A critical anti-malleability measure that tightened over versions:

```
BASE:      Empty signature required on failed CHECKSIG (policy only)
WITNESS_V0: Same as BASE (policy only)
TAPSCRIPT:  Non-empty invalid signature → consensus FAIL
            (empty signature → "not participating", always allowed)
```

In Tapscript, there's no ambiguity: either provide a valid signature, or
provide an empty byte vector to indicate you're not signing. A non-empty
invalid signature is always a consensus error.

---

## 15. Improvement Proposals

### 15.1 Extract Opcode Handlers into a Dispatch Table

The current EvalScript is a ~800-line switch statement. Each opcode handler
could be a function pointer in a static dispatch table:

```cpp
using OpcodeHandler = bool(*)(EvalState&);
static const OpcodeHandler dispatch[256] = { ... };
```

This would improve readability, make each handler independently testable, and
reduce the cognitive load of reading a single monolithic function. The function
pointer overhead is negligible compared to crypto operations.

### 15.2 Separate Consensus from Policy Script Checking

Currently, the same `EvalScript` function handles both consensus and policy
checks, distinguished only by flags. This means every flag combination must be
carefully tested. Separating into `EvalScriptConsensus()` (minimal, auditable)
and `EvalScriptPolicy()` (wraps consensus + extra checks) would make the
consensus-critical path smaller and easier to audit.

### 15.3 Remove Legacy Sighash Code Path

The `CTransactionSignatureSerializer` (legacy sighash) handles edge cases like
`SIGHASH_SINGLE` with mismatched input/output counts (returns hash of 0x01 — a
known historical bug). Since all modern wallets use SegWit or Taproot, this code
could be moved to a separate file and clearly marked as frozen/legacy, reducing
the maintenance surface of the main interpreter.

### 15.4 Type-Safe Opcode Dispatch

The opcode enum uses raw `unsigned char` values, and many comparisons use
integer ranges (`0 <= opcode && opcode <= OP_PUSHDATA4`). A strongly-typed
opcode classification (e.g., `OpcodeCategory::PUSH`, `OpcodeCategory::CRYPTO`)
would make the dispatch logic clearer and catch errors at compile time.

### 15.5 Decouple Signature Hashing from Script Evaluation

`SignatureHash()` and `SignatureHashSchnorr()` are defined alongside script
evaluation but are conceptually independent — they compute a transaction digest,
not execute script. Moving them to a dedicated `sighash.{h,cpp}` would clarify
the architecture and make them easier to reuse in wallet signing code.

### 15.6 Unify the Two EvalChecksig Functions

`EvalChecksigPreTapscript()` and `EvalChecksigTapscript()` share significant
logic but diverge on ECDSA vs Schnorr, FindAndDelete, and the empty-signature
semantic. A shared `EvalChecksigCommon()` that takes a version-specific behavior
struct would reduce duplication while keeping the version-specific logic
explicit.

### 15.7 Replace CHECKMULTISIG State Machine with Explicit Iteration

The legacy `OP_CHECKMULTISIG` implementation uses a complex loop with multiple
index variables (`ikey`, `isig`, `nKeysCount`, `nSigsCount`) and an extra dummy
stack element (a consensus bug preserved for compatibility). Documenting this
as a finite state machine with explicit state transitions would make the code
more maintainable, even if the behavior cannot change.

---

> **Document scope**: This document describes `src/script/interpreter.{h,cpp}`
> and its supporting script infrastructure as of early 2026 (8f0e1f6540). For
> the validation layer that calls VerifyScript for every transaction input, see
> [VALIDATION_ARCHITECTURE.md](VALIDATION_ARCHITECTURE.md). For how transactions
> reach validation, see [NET_PROCESSING_ARCHITECTURE.md](NET_PROCESSING_ARCHITECTURE.md).

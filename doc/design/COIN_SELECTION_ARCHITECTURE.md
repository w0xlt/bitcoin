# Bitcoin Core Coin Selection Architecture Guide

> A didactic guide for new developers to understand how Bitcoin Core's wallet
> chooses which coins (UTXOs) to spend when building a transaction.

---

## Table of Contents

1. [Why Coin Selection Matters](#1-why-coin-selection-matters)
2. [The Full Pipeline at a Glance](#2-the-full-pipeline-at-a-glance)
3. [Data Structures Deep Dive](#3-data-structures-deep-dive)
4. [UML Class Diagram](#4-uml-class-diagram)
5. [The Selection Flow in Detail](#5-the-selection-flow-in-detail)
6. [The Four Algorithms](#6-the-four-algorithms)
7. [The Waste Metric — How the Wallet Picks a Winner](#7-the-waste-metric--how-the-wallet-picks-a-winner)
8. [Output Grouping & Privacy](#8-output-grouping--privacy)
9. [The Filter Progression — Increasingly Permissive Rounds](#9-the-filter-progression--increasingly-permissive-rounds)
10. [Special Behaviors](#10-special-behaviors)
11. [Thread Safety & Locking](#11-thread-safety--locking)
12. [Improvement Proposals](#12-improvement-proposals)

---

## 1. Why Coin Selection Matters

Bitcoin doesn't have "accounts" with balances. Instead, your wallet holds
**UTXOs** (Unspent Transaction Outputs) — individual "coins" of various
amounts. When you want to send 0.5 BTC, the wallet must decide *which*
coins to combine.

This choice affects:

```
  ┌─────────────────────────────────────────────────────────────┐
  │                  Why it matters                             │
  │                                                             │
  │  Fees        Which coins you pick determines the tx size,  │
  │              which determines the fee you pay.              │
  │                                                             │
  │  Privacy     Combining coins from different sources links   │
  │              them on-chain. Bad selection leaks information. │
  │                                                             │
  │  UTXO Health Picking small coins consolidates them (good    │
  │              when fees are low). Picking large coins avoids  │
  │              creating dust change (good when fees are high). │
  │                                                             │
  │  Future Cost A coin selected today has a "long-term" cost:  │
  │              will it be cheaper to spend it now, or later?   │
  └─────────────────────────────────────────────────────────────┘
```

---

## 2. The Full Pipeline at a Glance

```
  User: "sendtoaddress bc1q... 0.5"
         │
         ▼
  ┌──────────────────────────────┐
  │     CreateTransaction()      │  Entry point (spend.cpp)
  │     Validates recipients     │
  └──────────────┬───────────────┘
                 │
                 ▼
  ┌──────────────────────────────┐
  │  CreateTransactionInternal() │  The real workhorse
  │                              │
  │  Phase 1: Setup              │  Fee rates, change params,
  │           ▼                  │  tx overhead size
  │  Phase 2: Gather Coins       │  FetchSelectedInputs() +
  │           ▼                  │  AvailableCoins()
  │  Phase 3: Select Coins       │  SelectCoins() →
  │           ▼                  │    AutomaticCoinSelection()
  │  Phase 4: Build Transaction  │  Outputs, change, shuffle
  │           ▼                  │
  │  Phase 5: Finalize Fees      │  Adjust change, apply SFFO
  │           ▼                  │
  │  Phase 6: Sign & Validate    │  Sign, check weight/fees
  └──────────────┬───────────────┘
                 │
                 ▼
  ┌──────────────────────────────┐
  │  AutomaticCoinSelection()    │
  │                              │
  │  For each filter (easy→hard):│
  │    GroupOutputs()            │
  │    AttemptSelection()        │
  │      ├─ Try OutputType A     │
  │      ├─ Try OutputType B     │
  │      └─ Try mixed (fallback) │
  │         │                    │
  │         ▼                    │
  │    ChooseSelectionResult()   │
  │      ├─ BnB                  │  ← changeless match
  │      ├─ CoinGrinder          │  ← min weight (high fees)
  │      ├─ Knapsack             │  ← legacy fallback
  │      └─ SRD                  │  ← random draw
  │         │                    │
  │         ▼                    │
  │    Pick result with min waste│
  └──────────────────────────────┘
```

---

## 3. Data Structures Deep Dive

### 3.1 `COutput` — A Single Spendable Coin

**File**: `coinselection.h`

This is the wallet's view of a single UTXO that *could* be spent:

```
┌─────────────────────────────────────────────────────────────┐
│                         COutput                             │
│                                                             │
│  outpoint ───────► COutPoint (txid + vout index)            │
│  txout    ───────► CTxOut (scriptPubKey + amount)            │
│                                                             │
│  ── Confirmation Status ──────────────────────────────────  │
│  depth       : int     (+N = N confirmations,               │
│                         0 = mempool, <0 = conflicted)       │
│  from_me     : bool    (did this wallet create the tx?)     │
│  safe        : bool    (safe to spend? not from external    │
│                         unconfirmed source)                  │
│  solvable    : bool    (do we have the keys to spend this?) │
│  time        : int64_t (transaction timestamp)              │
│                                                             │
│  ── Fee Calculations (pre-computed per coin) ─────────────  │
│  input_bytes : int     (signed input size in bytes, -1=unk) │
│  fee         : CAmount (cost to spend at current feerate)   │
│  long_term_fee : CAmount (cost at consolidation feerate)    │
│  effective_value : CAmount = value - fee                    │
│  ancestor_bump_fees : CAmount (CPFP cost for ancestors)     │
└─────────────────────────────────────────────────────────────┘
```

**Key concept — effective value**: If you have a 10,000 sat coin and it
costs 500 sat to spend it, its `effective_value` is 9,500 sat. This is
what the algorithms actually work with — the *usable* amount after paying
to include the input.

A coin with negative effective value is **dust** — it costs more to spend
than it's worth. Most algorithms skip these.

### 3.2 `OutputGroup` — Coins Grouped by Script

**File**: `coinselection.h`

When the wallet wants to avoid linking addresses (the `avoid_partial_spends`
feature), it groups all UTXOs paid to the same script:

```
  ┌────────────────────────────────────────────────────┐
  │                   OutputGroup                      │
  │                                                    │
  │  m_outputs[] ──► vector of shared_ptr<COutput>     │
  │                                                    │
  │  ── Aggregated Stats ────────────────────────────  │
  │  m_value          : total raw value of all outputs │
  │  effective_value  : total effective value           │
  │  fee              : total fee at current rate       │
  │  long_term_fee    : total fee at consolidation rate │
  │  m_weight         : total weight (witness units)    │
  │                                                    │
  │  ── Eligibility Info ────────────────────────────  │
  │  m_depth          : min depth across all outputs   │
  │  m_from_me        : true if all outputs are ours   │
  │  m_ancestors      : aggregated ancestor count      │
  │  m_descendants    : max descendant count           │
  │                                                    │
  │  ── Methods ─────────────────────────────────────  │
  │  Insert(output)        : add coin, update stats    │
  │  EligibleForSpending() : check against filter      │
  │  GetSelectionAmount()  : effective or raw value     │
  └────────────────────────────────────────────────────┘
```

**Why group?** If you received 3 payments to the same address (0.1, 0.2,
0.3 BTC), spending just the 0.3 BTC coin reveals that the other two belong
to you too (they share the same script). Grouping forces you to spend all
three together, avoiding this leak.

**Without** `avoid_partial_spends`: each `COutput` becomes its own
single-element `OutputGroup`.

### 3.3 `SelectionResult` — The Algorithm's Answer

**File**: `coinselection.h`

```
┌─────────────────────────────────────────────────────────────┐
│                    SelectionResult                          │
│                                                             │
│  m_selected_inputs ──► set of OutputGroups (the picks)      │
│  m_target          ──► CAmount (what we needed to reach)    │
│  m_algo            ──► SelectionAlgorithm (who found this)  │
│  m_waste           ──► CAmount (the waste score)            │
│  m_weight          ──► int (total input weight)             │
│                                                             │
│  m_algo_completed  ──► bool (searched the full space?)      │
│  m_selections_evaluated ──► size_t (how many combos tried)  │
│  bump_fee_group_discount ──► CAmount (shared ancestor fee   │
│                               savings)                      │
│                                                             │
│  ── Key Methods ──────────────────────────────────────────  │
│  AddInput(group)       : add an OutputGroup to the result   │
│  RecalculateWaste()    : compute waste metric               │
│  GetChange()           : calculate change output amount     │
│  GetWaste()            : return computed waste value         │
│  Merge(other)          : combine two results (manual+auto)  │
│  operator<(other)      : compare by waste (lower = better)  │
└─────────────────────────────────────────────────────────────┘
```

The `operator<` is what makes `std::min()` work across algorithm results:
pick the one with the lowest waste. If waste is tied, prefer more inputs
(consolidation opportunity).

### 3.4 `CoinSelectionParams` — The Tuning Knobs

**File**: `coinselection.h`

These parameters control every aspect of the selection process:

```
┌─────────────────────────────────────────────────────────────┐
│                  CoinSelectionParams                        │
│                                                             │
│  ── Fee Rates ────────────────────────────────────────────  │
│  m_effective_feerate  : current tx feerate (sat/vB)         │
│  m_long_term_feerate  : consolidation rate (~10 sat/vB)     │
│  m_discard_feerate    : threshold for discarding dust       │
│                                                             │
│  ── Change Parameters ────────────────────────────────────  │
│  change_output_size   : serialized size of change output    │
│  change_spend_size    : input size for spending change later│
│  m_change_fee         : fee cost of adding change output    │
│  m_cost_of_change     : change_fee + future spend cost      │
│  m_min_change_target  : randomized minimum change amount    │
│  min_viable_change    : below this, change becomes fees     │
│                                                             │
│  ── Transaction Constraints ──────────────────────────────  │
│  tx_noinputs_size     : tx size without any inputs          │
│  m_max_tx_weight      : weight limit (400k or TRUC limit)   │
│  m_version            : tx version (1, 2, or 3/TRUC)       │
│                                                             │
│  ── Behavior Flags ───────────────────────────────────────  │
│  m_subtract_fee_outputs : fee subtracted from recipients?   │
│  m_avoid_partial_spends : group coins by script?            │
│  m_include_unsafe_inputs: allow unconfirmed external coins? │
│                                                             │
│  ── Randomness ───────────────────────────────────────────  │
│  rng_fast             : random context (deterministic in    │
│                         tests)                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.5 `CCoinControl` — User Overrides

**File**: `coincontrol.h`

When a user calls RPCs like `send` with specific options, those preferences
flow through `CCoinControl`:

```
┌─────────────────────────────────────────────────────────────┐
│                      CCoinControl                           │
│                                                             │
│  ── Coin Preselection ────────────────────────────────────  │
│  m_selected_inputs  : map<COutPoint, PreselectedInput>      │
│  m_allow_other_inputs : can auto-selection add more coins?  │
│                                                             │
│  ── Fee Overrides ────────────────────────────────────────  │
│  fOverrideFeeRate   : ignore wallet default feerate?        │
│  m_feerate          : custom fee rate                       │
│  m_confirm_target   : custom confirmation target (blocks)   │
│  m_fee_mode         : CONSERVATIVE / ECONOMICAL / UNSET     │
│                                                             │
│  ── Change Control ───────────────────────────────────────  │
│  destChange         : custom change destination             │
│  m_change_type      : override change output type           │
│                                                             │
│  ── Behavior Flags ───────────────────────────────────────  │
│  m_signal_bip125_rbf    : RBF signaling                     │
│  m_avoid_partial_spends : spend entire groups?              │
│  m_avoid_address_reuse  : skip previously-spent addresses?  │
│  m_include_unsafe_inputs: allow unconfirmed external coins? │
│                                                             │
│  ── Depth Filters ────────────────────────────────────────  │
│  m_min_depth / m_max_depth : confirmation depth range       │
│                                                             │
│  ── Advanced ─────────────────────────────────────────────  │
│  m_version          : tx version override (e.g., TRUC v3)   │
│  m_locktime         : locktime override                     │
│  m_max_tx_weight    : weight limit override                 │
│  m_external_provider: signing data for external inputs      │
└─────────────────────────────────────────────────────────────┘
```

**`PreselectedInput`** (nested class): When a user manually selects a
specific UTXO, this class tracks it along with optional custom
scriptSig/scriptWitness data and a selection order for deterministic
input ordering.

### 3.6 `CoinsResult` — Available Coins Container

**File**: `spend.h`

```
┌─────────────────────────────────────────────────────────────┐
│                       CoinsResult                           │
│                                                             │
│  coins : map<OutputType, vector<COutput>>                   │
│                                                             │
│  total_amount           : sum of all raw values             │
│  total_effective_amount : sum of all effective values        │
│                                                             │
│  All()      → flat vector of all COutputs                   │
│  Size()     → total count                                   │
│  Shuffle()  → randomize within each type                    │
│  Erase(set) → remove specific outpoints                     │
│  Add(type, output) → insert a coin                          │
└─────────────────────────────────────────────────────────────┘
```

Coins are organized **by OutputType** (LEGACY, P2SH_SEGWIT, BECH32,
BECH32M). This is critical for privacy — the wallet tries to select
coins of a single type to avoid revealing that different address formats
belong to the same person.

### 3.7 `CoinEligibilityFilter` — Eligibility Criteria

**File**: `coinselection.h`

```
┌─────────────────────────────────────────────────────────────┐
│                  CoinEligibilityFilter                      │
│                                                             │
│  conf_mine      : min confirmations for our own outputs     │
│  conf_theirs    : min confirmations for external outputs    │
│  max_ancestors  : max unconfirmed ancestor transactions     │
│  max_descendants: max descendant transactions               │
│  m_include_partial_groups : allow partially-eligible groups? │
└─────────────────────────────────────────────────────────────┘
```

These filters are used in a **progression** from strict to permissive
(see [Section 9](#9-the-filter-progression--increasingly-permissive-rounds)).

---

## 4. UML Class Diagram

```
┌──────────────────────┐         ┌──────────────────────────┐
│     CCoinControl     │         │    CoinFilterParams      │
│──────────────────────│         │──────────────────────────│
│ m_selected_inputs    │         │ min_amount / max_amount  │
│ m_allow_other_inputs │         │ min_sum_amount           │
│ m_feerate            │         │ max_count                │
│ destChange           │         │ skip_locked              │
│ m_avoid_partial_*    │         │ include_immature_coinbase│
└──────────┬───────────┘         └──────────┬───────────────┘
           │ passed to                      │ passed to
           ▼                                ▼
┌═══════════════════════════════════════════════════════════════════┐
║              CreateTransactionInternal()                         ║
║═════════════════════════════════════════════════════════════════ ║
║                                                                  ║
║  Uses CCoinControl + wallet state to build CoinSelectionParams   ║
║                                                                  ║
║  Calls:                                                          ║
║    FetchSelectedInputs() ──► manual coins from CCoinControl      ║
║    AvailableCoins()      ──► wallet UTXOs → CoinsResult          ║
║    SelectCoins()         ──► orchestrates selection               ║
╚══════════════════════════════════════════════════╤════════════════╝
                                                   │
                                                   ▼
                                    ┌──────────────────────────┐
                                    │   CoinSelectionParams    │
                                    │──────────────────────────│
                                    │ m_effective_feerate      │
                                    │ m_long_term_feerate      │
                                    │ m_cost_of_change         │
                                    │ m_min_change_target      │
                                    │ m_max_tx_weight          │
                                    │ m_subtract_fee_outputs   │
                                    └──────────┬───────────────┘
                                               │ used by
                                               ▼
        ┌──────────────────────────────────────────────────────────┐
        │               AutomaticCoinSelection()                   │
        │──────────────────────────────────────────────────────────│
        │                                                          │
        │  For each CoinEligibilityFilter:                         │
        │    GroupOutputs() → OutputGroupTypeMap                   │
        │    AttemptSelection()                                    │
        │      └─ ChooseSelectionResult()                          │
        └──────────────────────────┬───────────────────────────────┘
                                   │ runs algorithms on
                                   ▼
┌──────────────────┐  ┌──────────────────┐  ┌───────────────────┐
│   OutputGroup    │  │ SelectionResult  │  │CoinEligibility-   │
│──────────────────│  │──────────────────│  │ Filter            │
│ m_outputs[]      │  │ m_selected_inputs│  │───────────────────│
│ effective_value  │  │ m_target         │  │ conf_mine         │
│ fee / long_term  │  │ m_algo           │  │ conf_theirs       │
│ m_weight         │  │ m_waste          │  │ max_ancestors     │
│ m_depth          │  │ m_weight         │  │ max_descendants   │
│ m_ancestors      │  │──────────────────│  └───────────────────┘
│──────────────────│  │ RecalculateWaste │
│ EligibleFor-     │  │ GetChange()      │
│  Spending()      │  │ operator<()      │
│ GetSelection-    │  │ Merge()          │
│  Amount()        │  └──────────────────┘
└──────┬───────────┘
       │ contains 1..*
       ▼
┌──────────────────┐
│     COutput      │
│──────────────────│
│ outpoint         │
│ txout            │
│ effective_value  │
│ fee              │
│ long_term_fee    │
│ input_bytes      │
│ depth / safe     │
└──────────────────┘

                    ┌───────────────────────┐
                    │  CoinsResult          │
                    │───────────────────────│
                    │ coins: map<OutputType,│
                    │   vector<COutput>>    │
                    │ total_amount          │
                    │ total_effective_amount│
                    └───────────────────────┘

Algorithm Enum:
┌──────────────────────────────────────────────┐
│  SelectionAlgorithm                          │
│  ─────────────────                           │
│  BNB      = 0  (Branch and Bound)            │
│  KNAPSACK = 1  (Legacy subset-sum)           │
│  SRD      = 2  (Single Random Draw)          │
│  CG       = 3  (CoinGrinder)                │
│  MANUAL   = 4  (User preselected)            │
└──────────────────────────────────────────────┘
```

---

## 5. The Selection Flow in Detail

### 5.1 `SelectCoins()` — The Orchestrator

```
  SelectCoins(wallet, available_coins, preset_inputs, params)
       │
       ├─ 1. Subtract preset input values from target
       │     target -= sum(preset effective values)
       │
       ├─ 2. If preset covers target entirely:
       │     └─ Return result with algo = MANUAL
       │
       ├─ 3. Otherwise, call AutomaticCoinSelection()
       │     for the remaining target
       │
       ├─ 4. Merge manual + automatic results
       │
       └─ 5. Validate total weight <= m_max_tx_weight
```

### 5.2 `AutomaticCoinSelection()` — The Strategy

This is where the real decision-making happens. It uses a **filter
progression** (see Section 9) — starting with the strictest criteria
and relaxing them until selection succeeds:

```
  AutomaticCoinSelection(wallet, available_coins, params)
       │
       │  For each CoinEligibilityFilter (strict → permissive):
       │       │
       │       ├─ GroupOutputs(coins, params, filter)
       │       │     → OutputGroupTypeMap (coins grouped by type + filter)
       │       │
       │       ├─ AttemptSelection(groups, params)
       │       │     │
       │       │     │  For each OutputType separately:
       │       │     │     └─ ChooseSelectionResult(type_groups, params)
       │       │     │          → SelectionResult or failure
       │       │     │
       │       │     ├─ Return best single-type result if found
       │       │     │
       │       │     └─ Fallback: try mixed types (all together)
       │       │          └─ ChooseSelectionResult(all_groups, params)
       │       │
       │       └─ If AttemptSelection succeeded → return result
       │
       └─ All filters exhausted → return error
```

**Why try each OutputType separately?** Privacy. If you have both
bech32 and legacy UTXOs, combining them in a single transaction reveals
they belong to the same wallet. By trying each type alone first, the
wallet avoids this fingerprint.

### 5.3 `ChooseSelectionResult()` — Run All Algorithms, Pick Best

```
  ChooseSelectionResult(groups, params)
       │
       ├─ Calculate max_selection_weight from budget
       │
       ├─ IF not SFFO:
       │     └─ Try BnB on positive_group ─────────► result_bnb
       │
       ├─ ALWAYS:
       │     └─ Try Knapsack on mixed_group ────────► result_knapsack
       │
       ├─ IF effective_feerate >= 3 × long_term_feerate:
       │     └─ Try CoinGrinder on positive_group ──► result_cg
       │
       ├─ ALWAYS:
       │     └─ Try SRD on positive_group ──────────► result_srd
       │
       ├─ For each successful result:
       │     └─ RecalculateWaste(change_cost, target, ...)
       │
       └─ Return min(results) by waste metric
              (ties broken by more inputs = better)
```

---

## 6. The Four Algorithms

### 6.1 Branch and Bound (BnB) — The Changeless Ideal

**Goal**: Find a combination of coins that **exactly** matches the target
(within the cost-of-change tolerance), producing **no change output**.

**Why no change is ideal**: A change output costs fees now (to create it)
and fees later (to spend it). It also creates a link to your future
transaction.

```
  Search Tree (include / exclude each coin):

  Coins sorted by descending effective_value: [50k, 30k, 20k, 8k]
  Target: 58k  (range: 58k to 58k + cost_of_change)

                         root (0)
                        /         \
                   +50k            skip 50k
                   /    \              |
              +30k       skip 30k    ...
              (80k)      (50k)
              OVER!         |
               ✗        +20k  skip 20k
                         (70k)  (50k)
                         OVER!    |
                          ✗    +8k  skip 8k
                               (58k)  (50k)
                               MATCH!  NOT ENOUGH
                                ✓        ✗
```

**Key properties**:
- Explores up to 100,000 nodes (TOTAL_TRIES), then gives up
- Only works on coins with positive effective value
- Skipped entirely when SFFO (Subtract Fee From Outputs) is active
- Produces `waste = sum(fee - long_term_fee)` per input (no change term)
- **Best case**: exact match with minimal waste

### 6.2 CoinGrinder — The Weight Minimizer

**Goal**: Find the **lightest** set of inputs that covers the target,
producing change. Optimized for high-feerate environments.

**When used**: Only when `effective_feerate >= 3 × long_term_feerate`.
At high feerates, minimizing input weight saves more money than
optimizing for the waste metric.

```
  Why weight matters at high fees:

  Fee rate: 100 sat/vB

  Option A: 3 inputs (300 vB total) → fee = 30,000 sat
  Option B: 1 input  (100 vB total) → fee = 10,000 sat
                                       Saves 20,000 sat!

  At low fees (5 sat/vB), the same difference is only 1,000 sat,
  and consolidation benefits outweigh the cost.
```

**Algorithm**: Depth-first search similar to BnB, but optimizes for
minimum weight instead of exact match. Uses three operations:
- **EXPLORE**: Include next coin (need more funds)
- **SHIFT**: Skip current coin, try alternatives (found solution or too heavy)
- **CUT**: Prune subtree (can't improve on best known solution)

### 6.3 Single Random Draw (SRD) — The Fast Pragmatist

**Goal**: Quick, probabilistic selection. Shuffle coins randomly, add
until the target is met.

```
  Pool: [A, B, C, D, E, F, G]  (shuffled randomly)
  Target: 100k + CHANGE_LOWER(50k) + change_fee

  Step 1: Add A (40k)  → total: 40k   (not enough)
  Step 2: Add B (25k)  → total: 65k   (not enough)
  Step 3: Add C (60k)  → total: 125k  (not enough, need 150k+)
  Step 4: Add D (35k)  → total: 160k  (enough! ✓)

  If weight exceeds limit:
    Drop the smallest-value input via priority queue
    Keep going
```

**Key properties**:
- Very fast — O(n) in typical case
- Includes `CHANGE_LOWER` (50,000 sat) in target so change is meaningful
- Not exhaustive — may miss better solutions
- Provides a solid baseline that other algorithms must beat

### 6.4 Knapsack Solver — The Legacy Workhorse

**Goal**: Approximate subset-sum solution. The oldest algorithm in the
wallet, kept for its ability to handle **mixed groups** (including dust).

```
  Phase 1: Check for exact match
    applicable_coins = coins where value < target + min_change
    if sum(applicable) == target → use all of them

  Phase 2: Stochastic approximation (1000 iterations)
    For each iteration:
      Pass 1 (random): include each coin with 50% probability
      Pass 2 (greedy): include remaining coins if under target
      Track best subset closest to target

  Phase 3: Compare with "lowest larger"
    Find smallest single coin >= target
    If its waste < approximation's waste → use it instead
```

**Unique property**: Knapsack is the only algorithm that runs on
`mixed_group`, which includes dust outputs (negative effective value).
The others only operate on `positive_group`.

---

## 7. The Waste Metric — How the Wallet Picks a Winner

The waste metric is the universal scoring system. After all algorithms
run, the result with the **lowest waste** wins.

```
  waste = timing_cost + change_or_excess_cost - bump_discount

  Where:

  ┌─────────────────────────────────────────────────────────────┐
  │ timing_cost (for each selected input):                      │
  │                                                             │
  │   fee_at_current_rate - fee_at_long_term_rate               │
  │                                                             │
  │   If current_rate > long_term_rate: timing_cost > 0         │
  │     (we're "overpaying" relative to the long-term average)  │
  │                                                             │
  │   If current_rate < long_term_rate: timing_cost < 0         │
  │     (we're getting a "deal" — good time to consolidate!)    │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │ change_or_excess_cost:                                      │
  │                                                             │
  │   IF change output is created:                              │
  │     cost = change_fee + spend_change_fee_at_discard_rate    │
  │     (fee to create it now + fee to spend it later)          │
  │                                                             │
  │   IF no change (excess donated to fees):                    │
  │     cost = selected_effective_value - target                │
  │     (the overpayment is pure waste)                         │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │ bump_discount:                                              │
  │                                                             │
  │   If multiple unconfirmed inputs share ancestors, the       │
  │   CPFP bump cost is shared (not paid redundantly).          │
  │   This discount rewards selecting related unconfirmed UTXOs │
  │   together.                                                 │
  └─────────────────────────────────────────────────────────────┘
```

### Worked Example

```
  Feerate: 20 sat/vB (current) vs 10 sat/vB (long-term)

  Selected 2 inputs:
    Input A: 100 vB → current fee=2000, long_term fee=1000
    Input B: 150 vB → current fee=3000, long_term fee=1500

  timing_cost = (2000-1000) + (3000-1500) = 2500

  Change output created (1000 sat fee to create, 500 sat to spend later):
  change_cost = 1500

  Total waste = 2500 + 1500 = 4000 sat

  ─────────────────────────────────────────────

  Alternative: BnB found exact match with 3 inputs:
    Input C: 80 vB  → current fee=1600, long_term fee=800
    Input D: 90 vB  → current fee=1800, long_term fee=900
    Input E: 70 vB  → current fee=1400, long_term fee=700

  timing_cost = (800) + (900) + (700) = 2400
  excess = 0 (exact match, no change!)

  Total waste = 2400 + 0 = 2400 sat  ← WINNER (lower waste)
```

---

## 8. Output Grouping & Privacy

### How `GroupOutputs()` Works

```
  AvailableCoins() returns:
    BECH32:  [COutput_1(addr_A, 0.5), COutput_2(addr_A, 0.3),
              COutput_3(addr_B, 1.0)]
    LEGACY:  [COutput_4(addr_C, 0.2)]


  ════════════════════════════════════════════════════════
  WITHOUT avoid_partial_spends (default):
  ════════════════════════════════════════════════════════

    Each coin → its own OutputGroup:
      Group_1: [COutput_1]  (addr_A, 0.5 BTC)
      Group_2: [COutput_2]  (addr_A, 0.3 BTC)
      Group_3: [COutput_3]  (addr_B, 1.0 BTC)
      Group_4: [COutput_4]  (addr_C, 0.2 BTC)


  ════════════════════════════════════════════════════════
  WITH avoid_partial_spends:
  ════════════════════════════════════════════════════════

    Coins to same script are merged:
      Group_1: [COutput_1, COutput_2]  (addr_A, 0.8 BTC total)
      Group_2: [COutput_3]             (addr_B, 1.0 BTC)
      Group_3: [COutput_4]             (addr_C, 0.2 BTC)

    ► Spending from addr_A now requires spending BOTH coins.
    ► This prevents partial-spend leaks.
```

### Privacy: Output Type Separation

```
  AttemptSelection() tries each type separately first:

    ┌──────────────────────────────────────────────────────┐
    │  1st attempt: BECH32 coins only                      │
    │     → ChooseSelectionResult(bech32_groups)            │
    │     → Success? Use it.  (no type mixing!)             │
    │                                                       │
    │  2nd attempt: LEGACY coins only                      │
    │     → ChooseSelectionResult(legacy_groups)            │
    │     → Success? Use it.                                │
    │                                                       │
    │  Fallback: mixed types                                │
    │     → ChooseSelectionResult(all_groups)               │
    │     → Less private, but ensures we can spend          │
    └──────────────────────────────────────────────────────┘

  Why? If a transaction has both bc1q... and 1... inputs,
  chain analysis can deduce they belong to the same wallet.
```

---

## 9. The Filter Progression — Increasingly Permissive Rounds

The wallet doesn't immediately use all available coins. It starts with
the most "conservative" set and only relaxes criteria if selection fails:

```
  Round  conf_mine  conf_theirs  max_ancestors  Description
  ─────  ─────────  ──────────  ─────────────  ─────────────────────────
  1      1          6           0              Confirmed only, strict
  2      1          1           0              Confirmed, relaxed depth
  3*     0          1           2              Allow own unconfirmed change
  4      0          1           ⅓ limit        Small ancestor chains
  5      0          1           ½ limit        Medium ancestor chains
  6      0          1           limit-1        Nearly full chains, partial groups
  7**    0          0           limit-1        Include unsafe external coins
  8***   0          1           limit          No chain limit rejection

  *   Only if m_spend_zero_conf_change is true
  **  Only if m_include_unsafe_inputs is true
  *** Only if !walletRejectLongChains
```

**Why this progression?**

- **Round 1**: Ideal case — only well-confirmed coins. No risk, no
  mempool dependency.
- **Rounds 2-3**: Slightly relaxed. Own unconfirmed change is safe to
  re-spend because we trust ourselves.
- **Rounds 4-6**: Allow longer unconfirmed ancestor chains. This is
  needed in high-activity wallets.
- **Round 7**: Last resort — include coins from unconfirmed *external*
  transactions (risky: they could be double-spent).
- **Round 8**: Remove chain-length limits entirely.

Each round is a complete run of all four algorithms. The first round
that produces a valid result wins.

---

## 10. Special Behaviors

### 10.1 Subtract Fee From Outputs (SFFO)

Normally, the wallet selects enough coins to cover `amount + fee`.
With SFFO, the fee comes out of the recipient's amount:

```
  Normal:    Select coins >= 1.0 BTC + 0.001 fee
             Recipient gets: 1.0 BTC

  SFFO:      Select coins >= 1.0 BTC
             Recipient gets: 1.0 - 0.001 = 0.999 BTC
```

When SFFO is active:
- BnB is **skipped** (it can't handle the fee subtraction)
- The fee is split equally among all SFFO-marked outputs

### 10.2 Change Target Randomization

To prevent fingerprinting by change amount patterns:

```
  if payment <= 25,000 sat:
      change_target = 50,000 sat (CHANGE_LOWER)
  else:
      change_target = random(50,000 ... min(2 × payment, 1,000,000 sat))
```

This means each transaction aims for a *different* change amount,
making it harder to identify which output is the change.

### 10.3 TRUC (Version 3) Transactions

TRUC transactions have special rules:
- Maximum one unconfirmed child
- The `truc_child_in_mempool` field in `CWalletTx` tracks this
- `CoinSelectionParams::m_version` is set to `TRUC_VERSION`
- Weight limit drops to `TRUC_CHILD_MAX_WEIGHT` (~4kvB)

### 10.4 Ancestor Bump Fees (CPFP Awareness)

When selecting unconfirmed UTXOs, their ancestors may need fee-bumping
via CPFP (Child Pays For Parent):

```
  Unconfirmed parent tx (low fee)
       │
       └─► UTXO_A (value: 100k sat, ancestor_bump_fee: 5k sat)

  effective_value = 100k - spend_fee - 5k = ~93k sat

  The selection accounts for the CPFP cost upfront.
```

If multiple selected UTXOs share the same ancestor, the bump fee is
only paid once — this is the `bump_fee_group_discount`.

### 10.5 Anti-Fee-Sniping

After coin selection, `DiscourageFeeSniping()` sets the transaction
locktime to the current block height. This prevents miners from
"replaying" the transaction in a reorganized chain to steal fees.

---

## 11. Thread Safety & Locking

Coin selection runs entirely under `CWallet::cs_wallet`:

```
  CreateTransaction()
    └─ LOCK(cs_wallet)    ← acquired at the start
         │
         ├─ AvailableCoins()        ← reads mapWallet, m_txos
         ├─ SelectCoins()           ← reads mapWallet for IsMine
         ├─ Build transaction       ← reads m_address_book
         └─ SignTransaction()       ← reads ScriptPubKeyMans
```

All coin selection data structures (`COutput`, `OutputGroup`,
`SelectionResult`, etc.) are **stack-local** or returned by value.
They don't persist beyond `CreateTransaction()` and don't need their
own synchronization.

---

## 12. Improvement Proposals

### 12.1 Extract Coin Selection Into a Pure Library

**Problem**: Coin selection logic in `coinselection.cpp` is *almost*
pure — it operates on `OutputGroup`/`COutput` without touching `CWallet`.
But the orchestration in `spend.cpp` (`AutomaticCoinSelection`,
`GroupOutputs`, `AttemptSelection`) is deeply coupled to `CWallet` for
`AvailableCoins()`, `IsMine()`, and fee estimation.

**Suggestion**: Create a clean separation:

```
  ┌─────────────────────────────┐
  │  coinselection.{h,cpp}      │  ← Pure algorithms (already nearly there)
  │  No wallet dependency       │
  └─────────────┬───────────────┘
                │ called by
                ▼
  ┌─────────────────────────────┐
  │  selection_strategy.{h,cpp} │  ← NEW: filter progression, output type
  │  No wallet dependency       │     separation, algorithm orchestration
  └─────────────┬───────────────┘
                │ called by
                ▼
  ┌─────────────────────────────┐
  │  spend.{h,cpp}              │  ← Wallet-aware: AvailableCoins(),
  │  Depends on CWallet         │     tx building, signing
  └─────────────────────────────┘
```

**Benefit**: The strategy layer would be unit-testable without any wallet
infrastructure.

### 12.2 Consolidate the Filter Progression

**Problem**: The 8-round filter progression is implemented as a long
sequence of `if` statements with hard-coded filter values in
`AutomaticCoinSelection()`. Adding or modifying a round requires
understanding the entire chain.

**Suggestion**: Declare the progression as data:

```cpp
static const std::vector<CoinEligibilityFilter> FILTER_PROGRESSION = {
    {1, 6, 0},                      // Confirmed only, strict
    {1, 1, 0},                      // Confirmed, relaxed depth
    {0, 1, 2},                      // Own unconfirmed change
    {0, 1, max_ancestors/3},        // Small chains
    {0, 1, max_ancestors/2},        // Medium chains
    {0, 1, max_ancestors-1, true},  // Large chains, partial groups
    // ... conditional entries added dynamically
};

for (const auto& filter : BuildFilterProgression(params)) {
    auto result = AttemptSelection(GroupOutputs(coins, filter), params);
    if (result) return *result;
}
```

**Benefit**: The entire strategy becomes declarative, easier to review,
and simpler to extend.

### 12.3 Make `CoinSelectionParams` Immutable

**Problem**: `CoinSelectionParams` is passed around as a mutable reference
and modified in-flight (e.g., `m_subtract_fee_outputs` can change).
This makes it hard to reason about which values are "initial" vs "computed".

**Suggestion**: Split into two structs:

```cpp
// Immutable inputs (set once at the start of CreateTransaction)
struct CoinSelectionConfig {
    const CFeeRate effective_feerate;
    const CFeeRate long_term_feerate;
    const CFeeRate discard_feerate;
    const bool avoid_partial_spends;
    const int max_tx_weight;
    // ...
};

// Computed/derived values (calculated from config + context)
struct CoinSelectionDerived {
    CAmount cost_of_change;       // computed from feerates + sizes
    CAmount min_change_target;    // randomized per tx
    size_t change_output_size;    // depends on output type
    // ...
};
```

### 12.4 Unify `OutputGroup` Construction

**Problem**: `GroupOutputs()` in `spend.cpp` is ~130 lines of complex
grouping logic with two completely different code paths (with/without
`avoid_partial_spends`). The logic for splitting groups at 100 entries,
handling partial vs full groups, and building `OutputGroupTypeMap` is
interleaved and hard to follow.

**Suggestion**: Extract a `GroupBuilder` class:

```cpp
class OutputGroupBuilder {
public:
    OutputGroupBuilder(const CoinSelectionParams& params);

    // Add all available coins
    void AddCoins(const CoinsResult& coins);

    // Get groups for a specific filter
    OutputGroupTypeMap GetGroups(const CoinEligibilityFilter& filter) const;

private:
    // Internal: group by script, split at max size, etc.
    std::map<CScript, std::vector<COutput>> m_by_script;
};
```

### 12.5 Explicit Algorithm Selection Strategy

**Problem**: The decision of *which algorithms to run* is buried inside
`ChooseSelectionResult()` with inline conditions like
`if (effective_feerate >= 3 * long_term_feerate)`. As more algorithms
are added, this becomes a growing chain of special cases.

**Suggestion**: Make the algorithm lineup explicit and configurable:

```cpp
struct AlgorithmConfig {
    SelectionAlgorithm algo;
    bool use_positive_group;  // vs mixed_group
    std::function<bool(const CoinSelectionParams&)> should_run;
};

static const std::vector<AlgorithmConfig> ALGORITHM_LINEUP = {
    {BNB,      true,  [](auto& p) { return !p.m_subtract_fee_outputs; }},
    {CG,       true,  [](auto& p) { return p.m_effective_feerate >= 3 * p.m_long_term_feerate; }},
    {KNAPSACK, false, [](auto&)   { return true; }},
    {SRD,      true,  [](auto&)   { return true; }},
};
```

### 12.6 Better Error Reporting from Selection Failures

**Problem**: When coin selection fails, `AutomaticCoinSelection()` returns
a generic error. The user sees "Insufficient funds" even when the real
problem may be: all coins are locked, or mempool ancestor limits are
hit, or the target is just above the available amount.

**Suggestion**: Track *why* each filter round failed:

```cpp
struct SelectionAttemptResult {
    std::optional<SelectionResult> result;

    // Diagnostics (filled when result is nullopt)
    CAmount available_at_filter;   // how much was eligible
    CAmount target;                // what we needed
    size_t coins_considered;       // how many passed the filter
    size_t coins_rejected_depth;   // rejected for confirmation depth
    size_t coins_rejected_ancestors; // rejected for ancestor limits
};
```

This would enable much better error messages:
- "Insufficient funds: 0.95 BTC available but need 1.0 BTC"
- "Insufficient confirmed funds: need 6 more confirmations on 0.5 BTC"
- "All eligible coins exceed mempool ancestor limit"

### 12.7 Reduce Redundant Re-grouping

**Problem**: `GroupOutputs()` is called once per filter round (up to 8
times). Each call re-iterates all coins, re-groups them, and re-checks
eligibility. Most of the grouping work (by script, by type) is identical
across rounds — only the eligibility filter changes.

**Suggestion**: Group once, filter many times:

```cpp
// Do the expensive grouping work once
auto base_groups = GroupOutputsByScript(coins, params);

// Then for each filter, just apply eligibility
for (const auto& filter : filter_progression) {
    auto eligible = ApplyFilter(base_groups, filter);
    auto result = AttemptSelection(eligible, params);
    if (result) return *result;
}
```

---

## Appendix: File Map

| File | Purpose |
|------|---------|
| `coinselection.h` | Core data structures: `COutput`, `OutputGroup`, `SelectionResult`, `CoinSelectionParams`, `CoinEligibilityFilter` |
| `coinselection.cpp` | Algorithm implementations: BnB, CoinGrinder, SRD, Knapsack. Waste calculation. Change target randomization |
| `spend.h` | `CoinsResult`, `CoinFilterParams`, function declarations for `CreateTransaction`, `AvailableCoins` |
| `spend.cpp` | Transaction creation pipeline: `CreateTransaction[Internal]`, `SelectCoins`, `AutomaticCoinSelection`, `AttemptSelection`, `ChooseSelectionResult`, `GroupOutputs` |
| `coincontrol.h` | `CCoinControl` and `PreselectedInput` — user-facing coin control options |

---

*This document reflects the state of Bitcoin Core's coin selection code
as of early 2026 (8f0e1f6540). The algorithms and strategies are under
active development — improvements to waste calculation, new algorithms,
and better CPFP handling are ongoing areas of work.*

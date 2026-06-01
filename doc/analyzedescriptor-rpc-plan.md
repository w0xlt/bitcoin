# Wallet Descriptor Analysis RPC Plan

This document evaluates a proposed wallet-aware descriptor analysis RPC, tentatively named `analyzedescriptor`, and lays out an implementation plan.

The RPC is intended to answer two main questions before creating or importing a joint descriptor, especially for multisig and taproot descriptors:

- Preflight / verify: does this wallet hold private key material for any slot of the descriptor?
- Script representation: can the wallet parse the descriptor and return a structured representation that a GUI can render so the user can visually audit the descriptor before wallet creation or import?

The implementation should borrow the descriptor-walking pattern from PR #35377 and use an explicit DFS rather than recursive traversal where practical.

## LLM Directives

- Do not push anything.
- Do not post anything online.
- Do not create PRs, issues, comments, or other remote updates.
- Keep all operations contained to this repository folder or `/tmp`.
- Do not try to access, search, read, or write folders outside this repository or
  `/tmp`, to avoid permission interruptions and accidental scope expansion.
- Use all available CPU threads when building and running tests unless explicitly
  instructed otherwise.
- Keep notes about discovered couplings, failed seams, and behavior-sensitive
  areas as the work progresses.
- If continuing would require accepting paid capacity, quota extensions, or other
  external authorization, stop and wait for explicit instruction.

## Reviewability Directives

- All commits must be easy to review and understand.
- All commits must be focused, clean, and self-contained.
- Avoid mixing refactors, behavior changes, tests, and GUI changes in one commit unless the split would be artificial.
- Prefer small mechanical commits before semantic commits when descriptor internals need to be exposed.
- Keep each commit buildable and testable.
- Avoid adding backward-compatibility code unless there is a concrete compatibility requirement.
- Avoid designing a large generic framework before the RPC shape and GUI needs are clear.

## Bottom Line

The RPC is feasible.

The preflight / ownership portion is medium-sized and fits the existing wallet descriptor architecture. The script/tree representation is the larger part because the current public descriptor API intentionally exposes high-level behavior but not the internal descriptor AST.

This should be treated as a wallet-aware descriptor inspection API, not just a util RPC. Existing `getdescriptorinfo` is wallet-agnostic and cannot answer whether the wallet owns relevant private keys.

## Existing Architecture

Relevant components in the current tree:

- `src/rpc/output_script.cpp`: implements `getdescriptorinfo` and `deriveaddresses`.
- `src/script/descriptor.h`: exposes the public `Descriptor` interface.
- `src/script/descriptor.cpp`: contains internal descriptor node types such as `DescriptorImpl`, `PKHDescriptor`, `WSHDescriptor`, `TRDescriptor`, `MultisigDescriptor`, and `MiniscriptDescriptor`.
- `src/script/signingprovider.h`: defines `SigningProvider` and `FlatSigningProvider` used to test or provide key material.
- `src/wallet/rpc/backup.cpp`: implements `importdescriptors` and already performs descriptor preflight-style validation.
- `src/wallet/rpc/wallet.cpp`: implements `gethdkeys`, `createwalletdescriptor`, and `addhdkey`, which already inspect wallet-held HD keys.
- `src/wallet/scriptpubkeyman.h` and `src/wallet/scriptpubkeyman.cpp`: store descriptor private keys and expose helpers such as `HasPrivKey()` and `GetKey()`.
- `src/wallet/wallet.h` and `src/wallet/wallet.cpp`: expose wallet-level descriptor/key helpers such as `GetActiveHDPubKeys()` and `GetKey()`.

Existing public descriptor APIs include:

- `Descriptor::HavePrivateKeys()` answers whether a provider has all private keys required by the descriptor.
- `Descriptor::Expand()` expands scripts and fills solving data.
- `Descriptor::ExpandPrivate()` expands available private keys for a position.
- `Descriptor::GetPubKeys()` returns root public keys and extended public keys.
- `Descriptor::Warnings()` returns semantic/safety warnings.
- `Descriptor::GetMaxKeyExpr()` and `Descriptor::GetKeyCount()` expose key-expression counts, currently mainly for tests.

Current public descriptor APIs do not expose:

- Descriptor function tree shape.
- Per-key-expression details.
- Multisig threshold as structured data.
- Taproot script tree as structured descriptor nodes.
- Miniscript node tree as structured data.

## Relationship To PR #35377

PR #35377 is not directly this RPC. Its relevant ideas are:

- Refactor descriptor import logic away from RPC-specific `UniValue` handling.
- Add wallet key matching helpers so descriptor imports can use private keys already known to the wallet.
- Add a non-recursive descriptor traversal using a `todo` stack over internal `DescriptorImpl` nodes.
- Match descriptor xpub expressions to wallet-held xprvs, including origin/path substitution.

For this RPC, the most relevant pattern is the explicit descriptor DFS:

```cpp
std::vector<const DescriptorImpl*> todo = {this};
while (!todo.empty()) {
    const DescriptorImpl* desc = todo.back();
    todo.pop_back();
    // Inspect desc->m_pubkey_args and desc->m_subdescriptor_args.
    for (const auto& sub : desc->m_subdescriptor_args) {
        todo.push_back(sub.get());
    }
}
```

This avoids recursion depth concerns and follows patterns already present in `DescriptorImpl::GetMaxKeyExpr()` and `DescriptorImpl::GetKeyCount()`.

## Feasibility Assessment

### Preflight / Wallet Key Ownership

This part is definitely implementable.

The main distinction is that existing `Descriptor::HavePrivateKeys()` answers whether all required private keys are available. The proposed RPC needs a more nuanced answer:

- Does the descriptor string itself include private keys?
- Does the wallet hold private key material for any descriptor key slot?
- Does the wallet hold private key material for all descriptor key slots?
- Which key slots matched the wallet?
- Which matches are exact keys versus HD parent/root keys?
- Is the result incomplete because the wallet is locked?

A robust result should distinguish at least:

- `input_has_private_keys`: private keys were included in the input descriptor.
- `wallet_has_any_private_key`: wallet has at least one relevant private key.
- `wallet_has_all_private_keys`: wallet has every relevant key expression, where this can be determined.
- `unknown_due_to_locked_wallet`: some HD/private-key matching could not be proven because the wallet was locked.
- `matched_keys`: per key expression or slot, including match status and public key/xpub identity.

Encrypted wallets need careful semantics. Exact presence of stored private key material can often be reported from metadata without unlocking via `HasPrivKey()`. Proving derivability through hardened paths may require an unlocked wallet or a metadata-only matching path that does not need secret derivation. If exact proof requires private derivation and the wallet is locked, the RPC should either require unlock or return an explicit unknown state.

### Script Representation

This is possible but larger.

A minimal representation can be generated today using `Descriptor::Expand()`:

- `scriptPubKey`
- `redeemScript`, where applicable
- `witnessScript`, where applicable
- taproot spend data, where available

However, that is not enough for a GUI audit tree. A GUI-friendly representation needs structured descriptor internals, for example:

```json
{
  "type": "wsh",
  "child": {
    "type": "sortedmulti",
    "threshold": 2,
    "keys": [
      {"key": "...", "wallet_has_private": true},
      {"key": "...", "wallet_has_private": false}
    ]
  }
}
```

For `tr(...)`, the representation should include:

- Internal key.
- Whether the wallet owns the internal key.
- Script-path leaves.
- Taproot tree depth/path information.
- Leaf script descriptors, including miniscript or multisig details.

For miniscript, the first implementation may return a miniscript string plus key annotations. A complete implementation can expose a miniscript node tree using `miniscript::Node`'s existing iterative tree helpers.

### DFS / Non-Recursive Traversal

Reimplementing with DFS is natural and consistent with existing code.

Existing patterns:

- `DescriptorImpl::GetMaxKeyExpr()` uses an explicit `std::vector<const DescriptorImpl*> todo` stack.
- `DescriptorImpl::GetKeyCount()` uses the same approach.
- `miniscript::ForEachNode()` is already an explicit stack traversal.
- `miniscript::Node::TreeEval()` supports non-recursive bottom-up evaluation.
- PR #35377 applies the same idea to descriptor key substitution.

## Expected Complexity

| Scope | Complexity | Notes |
| --- | --- | --- |
| Boolean wallet ownership only | Small/Medium | Add wallet RPC, parse descriptor, match wallet keys, add tests. |
| Correct HD xpub/xprv matching like PR #35377 | Medium | Needs wallet-known-key helper and descriptor key matching/substitution. |
| Per-slot ownership details | Medium | Requires descriptor key-expression introspection. |
| Basic script hex representation | Small/Medium | Can use `Expand()` and existing solving data. |
| Full descriptor AST JSON | Medium/Large | Requires new descriptor analysis structs or visitor APIs. |
| Full miniscript/taproot GUI tree | Large | More API design and test surface. |
| GUI integration | Medium additional | Should likely use wallet interfaces instead of JSON-RPC directly. |

## RPC Naming

`analyzedescriptor` is plausible but overlaps conceptually with `getdescriptorinfo`.

Candidates:

- `analyzedescriptor`
- `inspectdescriptor`
- `getwalletdescriptorinfo`
- `analyzewalletdescriptor`

If the RPC depends on wallet-held keys, the name should make the wallet dependency clear. `getwalletdescriptorinfo` or `analyzewalletdescriptor` are more explicit than `analyzedescriptor`.

## Proposed RPC Semantics

The RPC should be non-mutating:

- No descriptor import.
- No rescan.
- No keypool top-up.
- No wallet descriptor creation.
- No wallet database writes.

Possible arguments:

```json
{
  "descriptor": "wsh(sortedmulti(2,...))#checksum",
  "range": 0,
  "include_scripts": true,
  "include_tree": true,
  "include_private_key_status": true
}
```

Notes:

- `range` is needed for ranged descriptors when deriving representative pubkeys/scripts.
- If omitted for ranged descriptors, the RPC can either analyze root expressions only or default to index `0` for preview.
- The result must not expose private key material.
- The result should avoid returning private descriptors.

Possible top-level result:

```json
{
  "descriptor": "canonical-public-descriptor#checksum",
  "checksum": "...",
  "isrange": true,
  "issolvable": true,
  "input_has_private_keys": false,
  "wallet_has_any_private_key": true,
  "wallet_has_all_private_keys": false,
  "unknown_due_to_locked_wallet": false,
  "warnings": [],
  "keys": [],
  "script": {},
  "tree": {}
}
```

## Suggested Key Representation

Each key expression should have a stable identifier. The existing parser already assigns `m_expr_index` to key expressions.

Suggested fields:

```json
{
  "index": 0,
  "expression": "[fingerprint/path]xpub.../0/*",
  "origin": "fingerprint/path",
  "is_range": true,
  "is_bip32": true,
  "root_xpub": "xpub...",
  "derived_pubkey": "...",
  "wallet_has_private_key": true,
  "wallet_match_type": "root_xprv"
}
```

Potential `wallet_match_type` values:

- `none`
- `exact_private_key`
- `exact_xprv`
- `root_xprv`
- `derived_from_wallet_xprv`
- `unknown_locked`

## Suggested Descriptor Tree Representation

Keep the tree shape close to descriptor language primitives and avoid inventing a GUI-specific model in consensus/script code.

Examples:

```json
{
  "type": "sh",
  "children": [
    {
      "type": "wsh",
      "children": [
        {
          "type": "sortedmulti",
          "threshold": 2,
          "key_indexes": [0, 1, 2]
        }
      ]
    }
  ]
}
```

Taproot example:

```json
{
  "type": "tr",
  "internal_key_index": 0,
  "leaves": [
    {
      "depth": 0,
      "type": "multi_a",
      "threshold": 2,
      "key_indexes": [1, 2, 3]
    }
  ]
}
```

For miniscript, a first version can use:

```json
{
  "type": "miniscript",
  "miniscript": "and_v(v:pk(...),older(144))",
  "key_indexes": [0]
}
```

A later version can expose full miniscript fragments:

```json
{
  "type": "and_v",
  "children": [
    {"type": "v", "child": {"type": "pk", "key_index": 0}},
    {"type": "older", "value": 144}
  ]
}
```

## Behavior-Sensitive Areas

Keep notes as work progresses for the following areas:

- Locked encrypted wallets.
- Hardened derivation and whether matching requires private derivation.
- Ranged descriptors and default preview index.
- Multipath descriptors and whether all expansions are analyzed.
- `combo()` descriptors that expand to multiple script types.
- `raw()` and `addr()` descriptors, which are not solvable and may not have key slots.
- `unused()` descriptors, which intentionally do not produce scripts.
- `musig()` key aggregation and participant ownership.
- Taproot key-path versus script-path ownership.
- Miniscript policies where owning one key does not mean a satisfiable spend path exists.
- Descriptor checksums and whether the RPC requires them.
- Avoiding private key leakage in all JSON output.

## Implementation Plan

### Phase 1: Define Scope And RPC Contract

Goal: settle the first stable API surface before touching descriptor internals.

Tasks:

- Choose RPC name.
- Decide whether checksum is required. Prefer matching `deriveaddresses` and wallet import behavior by requiring checksum for wallet-sensitive analysis, unless there is a usability reason not to.
- Decide locked-wallet behavior.
- Decide whether ranged descriptors require an explicit index or default to `0` for preview.
- Define initial JSON schema for key ownership, script preview, and descriptor tree.
- Document that no private key material is returned.

Suggested commit:

- `doc: add wallet descriptor analysis RPC design`

### Phase 2: Add Descriptor Analysis Data Structures

Goal: introduce neutral C++ structs independent of RPC JSON.

Potential files:

- `src/script/descriptor.h`
- `src/script/descriptor.cpp`

Possible structs:

```cpp
struct DescriptorKeyAnalysis;
struct DescriptorNodeAnalysis;
struct DescriptorAnalysis;
```

The structs should represent public information only:

- Descriptor node type.
- Key expression indexes.
- Threshold values.
- Child node relationships.
- Taproot leaf depths.
- Miniscript string initially, if full miniscript AST is deferred.

Suggested commit:

- `script: add descriptor analysis result types`

### Phase 3: Implement Descriptor DFS Introspection

Goal: expose enough internal descriptor structure for the RPC without leaking implementation details into wallet/RPC code.

Tasks:

- Add a `Descriptor` method such as `Analyze()` or `GetAnalysis()`.
- Implement analysis in `DescriptorImpl` using an explicit DFS stack.
- Include key expression indexes from `PubkeyProvider::m_expr_index`.
- Include multisig thresholds from `MultisigDescriptor` and `MultiADescriptor`.
- Include wrapper nodes for `sh`, `wsh`, `tr`, `pkh`, `wpkh`, `pk`, `combo`, `rawtr`, `addr`, `raw`, and `unused`.
- Include taproot leaf depths from `TRDescriptor::m_depths`.
- For `MiniscriptDescriptor`, initially expose the miniscript string and key indexes. Defer full miniscript AST unless required by the GUI.

Suggested commit:

- `script: expose public descriptor analysis tree`

### Phase 4: Add Descriptor Key Matching Helpers

Goal: determine which descriptor key slots are known to the wallet.

Potential files:

- `src/wallet/wallet.h`
- `src/wallet/wallet.cpp`
- `src/wallet/scriptpubkeyman.h`
- `src/wallet/scriptpubkeyman.cpp`

Tasks:

- Add wallet helper to enumerate known descriptor private key material without exposing secrets in the RPC response.
- Reuse or adapt PR #35377's `GetKnownKeys()` idea if appropriate.
- Add metadata-only exact key checks where possible using `HasPrivKey()`.
- For xpub/xprv matching, support exact root xpub matches first.
- Add origin/path matching for descriptor xpubs derived from wallet-held xprvs.
- Return tri-state ownership when locked wallet prevents proving derivation.

Suggested commits:

- `wallet: add descriptor private key inventory helper`
- `wallet: match descriptor key expressions to wallet keys`

### Phase 5: Implement RPC Backend

Goal: combine descriptor analysis and wallet key matching in a non-mutating wallet RPC.

Potential file:

- `src/wallet/rpc/wallet.cpp`, or a new focused wallet RPC source file if the existing file becomes too large.

Tasks:

- Parse descriptor string into `FlatSigningProvider` and `Descriptor` objects.
- Preserve multipath expansions in the response.
- Compute existing descriptor facts: canonical descriptor, checksum, `isrange`, `issolvable`, warnings.
- Compute `input_has_private_keys` from parse provider state.
- Annotate each key expression with wallet ownership.
- Compute `wallet_has_any_private_key` and `wallet_has_all_private_keys` from key annotations.
- Optionally expand scripts at the requested preview index.
- Convert descriptor analysis structs to `UniValue` only in the RPC layer.
- Add named argument conversion in `src/rpc/client.cpp` if needed.

Suggested commit:

- `rpc: add wallet descriptor analysis RPC`

### Phase 6: Add Functional Tests

Goal: verify user-visible RPC behavior.

Potential file:

- `test/functional/wallet_analyzedescriptor.py`

Test cases:

- Wallet has one key in a multisig descriptor.
- Wallet has no keys in a multisig descriptor.
- Wallet has all keys in a descriptor.
- Descriptor input includes private keys.
- Watch-only wallet behavior.
- Encrypted locked wallet behavior.
- Encrypted unlocked wallet behavior if needed for HD matching.
- Ranged descriptor with preview index.
- Multipath descriptor response shape.
- `sh(wsh(sortedmulti(...)))` tree shape.
- Taproot `tr(internal,multi_a(...))` basic tree shape.
- Invalid descriptor and checksum errors.

Suggested commit:

- `test: cover wallet descriptor analysis RPC`

### Phase 7: Add Unit Tests For Descriptor Introspection

Goal: verify internal analysis independent of wallet RPC.

Potential file:

- `src/test/descriptor_tests.cpp`

Test cases:

- `pkh(KEY)` node type and key index.
- `wsh(sortedmulti(2,...))` threshold and key ordering.
- `tr(KEY,{pk(KEY),multi_a(2,...)})` leaf depths.
- Miniscript string extraction.
- Multipath descriptor expansion behavior.

Suggested commit:

- `test: cover descriptor analysis tree`

### Phase 8: Optional GUI Interface

Goal: make the GUI consume the analysis without shelling out through JSON-RPC where possible.

Potential files:

- `src/interfaces/wallet.h`
- `src/wallet/interfaces.cpp`
- GUI model/dialog files, depending on final UX.

Tasks:

- Add wallet interface method returning typed analysis data or JSON-like data.
- Add GUI rendering for descriptor tree.
- Highlight wallet-owned keys.
- Highlight unknown/locked key status.
- Show warnings before wallet creation/import.

Suggested commits:

- `interfaces: expose wallet descriptor analysis`
- `qt: add descriptor analysis preview`

## Recommended Initial Slice

Start with a narrow but useful RPC:

- Wallet-aware only.
- No GUI changes yet.
- No full miniscript AST yet.
- Support descriptor wrappers, multisig, sorted multisig, taproot internal key, and taproot leaves.
- Return miniscript as a string plus key ownership annotations.
- Return explicit unknown states for locked-wallet HD matching.

This keeps the first implementation reviewable while validating the core architecture.

## Build And Test Guidance

Use all available CPU threads unless explicitly instructed otherwise.

Example commands:

```bash
cmake --build build -j"$(nproc)"
ctest --test-dir build -j"$(nproc)"
test/functional/wallet_analyzedescriptor.py
```

Adjust `build` to the active build directory in the local checkout.

## Open Questions

- Should the RPC require descriptor checksums?
- Should ranged descriptors default to index `0`, or require an explicit preview index?
- Should locked wallets return `unknown_locked` or fail with `RPC_WALLET_UNLOCK_NEEDED` for ownership analysis?
- How much miniscript structure does the GUI need in the first version?
- Should multipath descriptors return one analysis object per expansion?
- Should the RPC live under wallet RPCs only, or should a wallet-agnostic subset extend `getdescriptorinfo`?
- Is `wallet_has_all_private_keys` meaningful for arbitrary miniscript, or should the RPC avoid claiming satisfiability beyond key ownership?

## Risk Summary

The main engineering risk is not parsing descriptors; that already works. The risk is exposing a stable, GUI-friendly representation of descriptor internals without overfitting to current C++ class layout or leaking private key material.

The safest path is incremental:

- First expose key ownership and simple descriptor structure.
- Then expand taproot/miniscript representation based on GUI needs.
- Keep wallet key matching carefully separated from descriptor tree serialization.

## Progress Notes

Initial implementation slice started on branch `feature/analyzedescriptor-rpc`.

Discovered couplings and seams:

- `Descriptor` previously exposed behavior but not structure. The first slice adds data-only public analysis structs and keeps JSON conversion in wallet RPC code.
- Wallet ownership can be reported for exact root pubkey/xpub matches without unlocking encrypted wallets by using a new wallet-level `HasPrivKey()` helper.
- Full HD origin/path matching is separate from exact root matching and should follow the PR #35377-style xpub/xprv substitution approach in a focused follow-up.
- Representative script expansion currently uses private keys supplied in the input descriptor, not wallet-derived private keys. Hardened derivation from wallet-held keys needs a follow-up if script preview must work for those descriptors.
- Miniscript is represented as a descriptor node with its expression string in the first slice. A full miniscript AST should be added only if the GUI needs that granularity.
- `musig()` participant ownership is not fully represented by the initial key-expression model and needs dedicated follow-up handling.
- Functional testing needs generated test config when run directly: `--configfile=build/test/config.ini`.

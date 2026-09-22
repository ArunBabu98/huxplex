# ADR-0018: Signature role profiles — the suite descriptor is `(role, version)`

- Status: Accepted
- Date: 2026-09-22
- Deciders: Founding architect, cryptography, protocol

## Context

[ADR-0002](0002-cryptographic-parameter-set.md) made agility the overriding architectural
property: every signed object carries an algorithm-suite version, and the verifier dispatches on
it. That decision fixed the **version** axis. It did not consider a second axis.

The September 2026 Layer-0 review
([`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md) §2.1)
surfaced the gap, following *Domain-Specific Post-Quantum Signatures for Blockchains*
(arXiv:2609.24689):

> *"Most academic post-quantum signature work targets the wrong abstraction for public
> blockchains … none of the current schemes is a drop-in replacement for the signature layer of
> modern public blockchains."*

Transaction authorization and quorum certification are **different design problems** — different
adversaries, different cost models, different required operations:

| Role class | Needs | Huxplex objects | Size budget |
|---|---|---|---|
| **Transaction** (T-class) | bind chain ID, nonce, fee, intent; priced rejection of invalid input; unbounded volume | `Transaction`, `Intent`, `GossipMessage`, `DhtEntry` | ≤ 3 KB (TGEN) |
| **QuorumCert** (Q-class) | public aggregation, merge semantics, slashing evidence, light-client verification; O(validators) volume | `Vote`, block certificate | aggregation-dominated |
| **Identity** | longevity, structure-free assumptions, rare signing | validator identity, `did:huxplex`, DID key rotation | large OK (TROOT) |
| **Governance** | longevity, auditability, very rare signing | Work Visa issuance, constitutional records, registry updates | large OK (TROOT) |

Huxplex already implements *half* of this distinction: ADR-0002 splits hot ML-DSA-44 signing from
long-lived SLH-DSA-128s identity, which is exactly the T/TROOT split. What it does **not** do is
distinguish `Transaction` from `Vote` — both are pinned to one hot-path scheme — and the suite
descriptor has no field in which that distinction could be expressed.

### Why this cannot wait

Every signed object embeds an algorithm identifier, and [ADR-0011](0011-canonical-serialization.md)
makes the encoding canonical and byte-deterministic. Once **G2** serializes `Transaction`,
`Block`, `Vote`, `GossipMessage` and `DhtEntry` with a one-field descriptor, adding a second field
changes the byte layout of every consensus object — a state migration and a hard fork, not a
parameter change. G2 is the gate immediately after G1.

### The forces

- **Agility is already the top priority.** A role axis is the same argument applied to a second
  dimension: the project accepted that hard-coding an *algorithm* is a mistake; hard-coding
  *one algorithm for all purposes* is the same mistake at a different granularity.
- **Aggregation is role-specific.** Every PQ quorum-certificate aggregation candidate (Chipmunk,
  Lemur+, DKKW/LeanSig — see [`cryptography.md`](../02-architecture/cryptography.md)) applies to
  **votes only**, never to user transactions. Without a role axis there is nowhere to put the
  answer to **R-A1**.
- **The parameter question is separable, and should stay separable.** ML-DSA-44 vs ML-DSA-65
  (**R-A2**) is a live question with real costs on both sides (BSC measured 40–50% TPS loss at
  44; Sui chose 65). Adopting the role axis does **not** require answering it.
- **v1 scope is frozen.** The [v1 scope contract](../15-specifications/06-v1-scope.md) §1 defines
  v1 as *"signing every block and vote with ML-DSA-44."* A decision that changes v1's algorithms
  needs an RFC; a decision that changes only the *descriptor shape* does not.

## Options

- **A — Keep `(version)` only.** Simplest; matches ADR-0002 as written. *Cost:* forecloses
  role-specific aggregation and role-specific parameters; the fix after G2 is a state migration.
  *Risk:* the one irreversible mistake available at this gate.
- **B — `(role, version)` resolution, with all roles pointing at the same primitives in v1.**
  One enum plus a resolution table. Zero behavioural change, zero size change, zero benchmark
  dependency at v1. Later divergence is a registry update. *Cost:* one extra field on the
  descriptor; a conformance test (G1-T6); slightly more surface to get right at G1.
- **C — Full role divergence now** (e.g. ML-DSA-65 for Q-class, ML-DSA-44 for T-class).
  Maximum immediate benefit. *Cost:* changes v1's frozen scope, requires an RFC, and pre-empts
  the G1 benchmarks that are supposed to inform R-A2.

## Decision

**Option B.** Suite resolution is `(role, suite version) → primitive set`.

### 1. The role enum

```rust
// Illustrative; the normative form lives in the cryptography spec.
#[non_exhaustive]                       // roles may be ADDED under governance
pub enum SigRole {
    Transaction,   // T-class: Transaction, Intent, GossipMessage, DhtEntry
    QuorumCert,    // Q-class: Vote, block certificate
    Identity,      // validator identity, did:huxplex
    Governance,    // Work Visa issuance, constitutional records, registry updates
}
```

Roles are a **closed set that grows by addition only**. A role is never removed or renumbered;
an obsolete role is marked deprecated in the registry and its objects remain verifiable forever.

### 2. Genesis mapping (suite v1)

Every role resolves to the primitives ADR-0002 already chose. **Nothing about v1's bytes on the
wire changes except the descriptor.**

| Role | Suite v1 primitive | Rationale |
|---|---|---|
| `Transaction` | **ML-DSA-44** | Unchanged from ADR-0002; matches the frozen v1 scope |
| `QuorumCert` | **ML-DSA-44** | Unchanged; the aggregation answer (R-A1) lands here later |
| `Identity` | **SLH-DSA-128s** | Unchanged from ADR-0002's long-lived identity role |
| `Governance` | **SLH-DSA-128s** | Unchanged; same longevity argument as `Identity` |

**R-A2 (ML-DSA-44 vs -65) is explicitly deferred to the G1 benchmarks and is now a per-role
question.** v1 stays on ML-DSA-44 across the board — see the *Consequences* note on v1 scope.

### 3. Versioning discipline — everything scales by version bump

This ADR exists to make future change a **registry update**, never a redesign. The rules that
guarantee it:

| Rule | Statement |
|---|---|
| **V1** | Every signed object carries **both** `role` and `suite_version`. Neither is optional, neither is inferred from the object type at verification time. |
| **V2** | Roles are **added, never removed or renumbered**. `#[non_exhaustive]`; an unknown role fails closed (G1-T4's rule, extended to the role axis). |
| **V3** | A role's primitive may change **only** by introducing a new suite version. Suite `vN` is immutable once any object has been signed under it. |
| **V4** | Roles version **independently**. Bumping `QuorumCert` from v1 to v2 (e.g. to adopt an aggregating scheme) MUST NOT require re-signing, re-encoding, or migrating any `Transaction` object. |
| **V5** | Old `(role, version)` pairs stay verifiable **forever**. The registry is append-only; historical state is never re-validated under a newer suite. |
| **V6** | Every context string keeps its `:vN` suffix ([cryptography spec §5](../15-specifications/02-cryptography-spec.md)). A role change that alters what is signed is also a context bump. |
| **V7** | The `(role, version) → primitive` table is **governance-updatable data**, not code. Adding a row is a parameter change; changing a committed row is forbidden by V3. |

> **The test of this discipline is G1-T1 extended:** register a second scheme, flip *one role's*
> default, and verify that objects under the old `(role, version)` still verify, that the other
> roles are untouched, and that no state structure changed.

### 4. Cross-role separation is a security property

A signature produced under one role MUST NOT verify under another, for every ordered pair. This
is the same argument as the context-string registry — domain separation on a second axis — and is
pinned by **G1-T6**. Role separation without enforced rejection is decoration.

## Consequences

- ➕ **The irreversible mistake at G1 is avoided at near-zero cost.** v1 ships identical bytes on
  the wire apart from the descriptor.
- ➕ **R-A1 (PQ aggregation) now has somewhere to land.** An aggregating scheme can be adopted for
  `QuorumCert` alone, by version bump, without touching transactions.
- ➕ **R-A2 becomes a per-role parameter question**, which is how the 2026 literature frames it,
  and it stays deferrable to real benchmark data rather than being forced now.
- ➕ Makes explicit a split the project had already half-made (hot ML-DSA vs. long-lived SLH-DSA),
  rather than inventing a new concept.
- ➖ Two axes to get right at G1 instead of one; the descriptor is larger by one small field on
  every signed object.
- ➖ More conformance surface: the role × role rejection matrix (G1-T6) joins the context × context
  matrix (G1-T2).
- ⚠️ **Scope note:** this does **not** change the [v1 scope contract](../15-specifications/06-v1-scope.md),
  because every role resolves to the algorithms v1 already names. Diverging a role's primitive
  *would* be a scope change and requires an RFC.
- ⚠️ Risk accepted: four roles may prove to be the wrong cut. V2 makes adding a fifth cheap;
  it does not make re-cutting the existing four cheap. The four chosen map directly to the
  literature's T/Q/TROOT classes and to objects that already exist in the data model.

## Links
- Supplements (does not supersede) [ADR-0002](0002-cryptographic-parameter-set.md)
- [ADR-0011 (canonical serialization)](0011-canonical-serialization.md) — why the window closes at G2
- [cryptography architecture](../02-architecture/cryptography.md) §*Role separation*
- [cryptography spec §1](../15-specifications/02-cryptography-spec.md) — normative role table
- Origin: [`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md) §2.1, action A1
- Open problems: [R-A1](../11-research/open-problems.md) (aggregation lands on `QuorumCert`), [R-A2](../11-research/open-problems.md) (now per-role)
- Tests: [`16-action-plan.md`](../16-action-plan.md) G1-T1, **G1-T6**
- External: *Domain-Specific Post-Quantum Signatures for Blockchains*, arXiv:2609.24689 (2026)

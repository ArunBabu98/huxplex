# ADR-0022: Split G2 into wire and consensus encoding, and fix the Layer-0 definition

- Status: Accepted
- Date: 2026-09-30
- Deciders: Founding architect, protocol

## Context

Three documents disagree about what Layer 0 requires.

| Document | Says |
|---|---|
| [`04-sequencing-and-risks.md`](../18-implementation-plan/04-sequencing-and-risks.md) § *What "Layer 0 complete" means* | Layer 0 = **G0 + G1 + G5** |
| The same file's critical path | `G1 → G2 … ` *"canonical encoding — **NOT in this plan**"* ` → G5` |
| [`16-action-plan.md`](../16-action-plan.md) | **G5 entry: G2** |

So **Layer 0, as defined, cannot complete without a gate its own definition omits.** The
contradiction was found by the completion audit
([`20-completion/` §5.2](../20-completion/00-layer0-v1-completion-report.md)) rather than during
planning, which is the usual sign that a boundary was drawn by convenience.

### Why this is not bookkeeping

On 2026-09-23 a **live signature forgery** was found in shipped `hux-network` code: `DhtEntry`
signed the bare concatenation `key ‖ value`, which encodes no field boundary, so `("abc","XY")`
and `("ab","cXY")` produced identical signed bytes. Any observer could re-split a record and
republish the publisher's signature **under a different DHT key**, holding no key material.

That is precisely the ambiguity **G2-T2** exists to forbid — *two distinct values must never
share one encoding* — and the crypto spec had blessed the construction as *"the grandfathered
primitive encoding"* ([ADR-0011](0011-canonical-serialization.md) rule 5).

**The encoding discipline G2 exists to impose was needed before G5 shipped envelope code, not
after.** Deferring canonical encoding past the transport means every wire type gets hand-rolled
framing, and each one is another chance to repeat that bug in a place where it is invisible.

A second, quieter consequence: **G1-T6 cannot fully close without G2.** Proving a *signature* is
bound to its role requires the `(role, version)` descriptor to be carried **on the signed
object**. G1 can prove roles are pairwise distinct and that a verifier refuses a mismatch; the
binding itself needs an encoding to live in.

### The observation that makes a split possible

G2's scope is six types. **G5 needs two of them.**

| Type | Needed by |
|---|---|
| `GossipMessage`, `DhtEntry` | **G5** — they go on the wire |
| `Resource`, `Transaction`, `Block`, `Vote` | G3, G6 — they live in state |

G5 never touches `TxId`, nullifiers, resource commitments or BLAKE3. At G5 a gossiped block is
**opaque bytes**; what is inside it is G3's problem. The line between the two halves is not
arbitrary — it is *"types on the wire"* versus *"types in state"*, and nothing crosses it.

## Options

- **A — Redefine Layer 0 as G0 + G1 + G2 + G5.** Honest; the term matches what is required.
  *Cost:* Layer 0 absorbs the whole of canonical encoding, including `TxId`, witness exclusion and
  BLAKE3 commitments, none of which the transport needs. The milestone inflates and stops meaning
  *"the substrate everything else is built on."*
- **B — Split G2; G5 depends only on the half it needs.** **Accepted.**
- **C — Leave the definition; accept that G2 sits in the middle, undocumented.** Cheapest today
  and the version most likely to be rediscovered painfully — by someone starting G5 and finding it
  blocked on a gate nobody scheduled. **Rejected**: the status layer being true is the point of
  [`20-completion/`](../20-completion/).
- **D — Move G5 out of Layer 0** (Layer 0 = G0 + G1 + G2a; transport becomes L1). Defensible —
  transport is arguably not *substrate* — but it contradicts every document that calls transport
  part of Layer 0, including the readme and the verification guide. Renaming is more disruptive
  than splitting. **Rejected.**

## Decision

**Option B.** G2 splits along the wire/state line, and the Layer-0 definition is corrected.

### 1. The split

| Gate | Scope | Gate tests | Entry | Unblocks |
|---|---|---|---|---|
| **G2a — wire encoding** | canonical `Codec` + canonical decode for `GossipMessage` and `DhtEntry`; the `(role, version)` descriptor on the wire | **G2-T1**, **G2-T2**, **G2-T4** over the wire types | G1 | **G5** |
| **G2b — consensus encoding** | `Resource`, `Transaction`, `Block`, `Vote`; BLAKE3 commitments, nullifiers, `TxId`, witness exclusion | **G2-T1**, **G2-T2**, **G2-T3**, **G2-T4** over the consensus types | G1 | G3 |

**G2-T3** (`TxId` excludes witnesses) belongs to **G2b alone** — `TxId` is a consensus type and
does not exist at G5. The other three tests apply to both halves, each scoped to its own types.

### 2. The Layer-0 definition

> **Layer 0 is complete when G0, G1, G2a and G5 have all closed.**

G2b stays where it always was: before G3, outside Layer 0.

### 3. The constraint the split creates

**G2a freezes the wire encoding.** So `GossipMessage` and `DhtEntry` MUST carry the
`(role, version)` descriptor from their first canonical encoding onward. Freezing a wire format
that cannot express the descriptor would recreate, on the wire types, exactly the state-migration
trap [ADR-0018](0018-signature-role-profiles.md) exists to avoid on the consensus types.

This is the single thing to get right in G2a, and it is why G2a cannot start before G1's
descriptor shape is settled. It is settled: `AlgoSuite { role, version }` shipped with the
registry.

### 4. Amendment to ADR-0011

[ADR-0011](0011-canonical-serialization.md) **rule 5** is superseded — see that ADR's amendment.
The `key ‖ value` grandfathering was unsafe, and its migration trigger (*"when those types gain
fields"*) was the wrong one.

## Consequences

- ➕ **The Layer-0 definition becomes achievable.** It no longer depends on a gate it does not name.
- ➕ **G5 unblocks on a small, well-scoped prerequisite** — two types, three tests — instead of the
  whole of canonical encoding.
- ➕ **The wire types get canonical treatment before more wire code is written.** The DHT forgery
  was the cost of not doing this; the framing fix already did a piece of G2a by hand, and G2a
  subsumes it properly.
- ➕ **G1-T6's second half gets a home.** It completes at G2a, when the descriptor reaches the wire
  — stated rather than left to be discovered at the G1 gate review.
- ➖ **One more gate boundary to track**, and two gates whose names differ by one letter. Mitigated
  by the split being semantic (wire vs. state) rather than a numbered subdivision of convenience.
- ➖ The reported Layer-0 completion percentage **falls**, because the denominator grew. That is a
  more accurate number, not a regression.
- ⚠️ **G2a and G2b must share one `Codec`.** The split is about *which types are encoded when*,
  never about two encoders. Two codecs would be two dialects and would reintroduce the fork risk
  the gate exists to prevent. Any divergence is a defect, not a design freedom.

## Links
- Supersedes nothing; **amends** the Layer-0 definition in [`04-sequencing-and-risks.md`](../18-implementation-plan/04-sequencing-and-risks.md) and G5's entry condition in [`16-action-plan.md`](../16-action-plan.md)
- Amends [ADR-0011](0011-canonical-serialization.md) rule 5 (see its 2026-09-30 amendment)
- [ADR-0018](0018-signature-role-profiles.md) — why the descriptor must be on the wire from the first frozen encoding
- Origin: [`20-completion/00-layer0-v1-completion-report.md`](../20-completion/00-layer0-v1-completion-report.md) §5.1 (the forgery) and §5.2 (the ordering gap)
- [data model & encoding spec](../15-specifications/01-data-model-and-encoding.md)

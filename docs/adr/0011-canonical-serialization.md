# ADR-0011: Canonical serialization & deterministic encoding

- Status: Accepted
- Date: 2026-06-21
- Deciders: Founding architect, protocol

## Context

The readme's tech-stack lists "postcard / bincode" for serialization without choosing. But for a
blockchain this is not a free choice: **any object that is hashed or signed must have exactly one
canonical byte encoding**, identical across implementations and versions, forever. Non-determinism
here is a consensus break (two honest nodes compute different hashes for the same logical object)
and a signature-malleability surface.

Current code side-steps this: gossip/DHT payloads are hashed/signed as raw `Vec<u8>`
(`DhtEntry` concatenates `key || value` by hand). That works for opaque bytes but does not scale
to structured transactions, blocks, and HRM resources.

Forces:
- **Determinism** — one logical value ⇒ one byte string. No map-ordering ambiguity, no optional
  fields that round-trip differently, no float nondeterminism.
- **Canonicality / non-malleability** — decoding then re-encoding MUST reproduce the exact input
  bytes; reject any non-canonical encoding rather than normalizing it.
- **Compactness** — PQ signatures are already 2,420 B; the envelope must not add bloat.
- **`no_std` / portability** — primitives should encode without heavy runtime deps.
- **Schema evolution** — fields will be added; needs explicit versioning (see ADR-0002 suite
  versioning and the data-model spec).

## Options

- **A — `bincode`.** Ubiquitous, fast. *Cost:* historically several config knobs (endianness,
  int encoding, varint) that, if mismatched, silently break determinism across versions; not
  designed as a canonical wire format.
- **B — `postcard`.** Compact, `no_std`-first, `serde`-based, stable wire format designed for
  embedded/deterministic use; varint-encoded. *Cost:* `serde` derives can still permit
  non-canonical inputs unless we enforce strict decode + re-encode checks.
- **C — A bespoke canonical codec (SSZ/SCALE-like).** Maximum control over canonicality and
  Merkleization. *Cost:* large up-front effort; reinvents a wheel before we need it.

## Decision

**Option B — `postcard` as the canonical codec for all consensus objects, behind an internal
`Codec` trait, with enforced canonical-decode.**

1. All hashed/signed objects implement an internal `Codec` (encode/decode) rather than calling a
   serializer directly, so the codec can be swapped under the agility umbrella without touching
   call sites.
2. **Canonical-decode rule:** decoding MUST verify that re-encoding the decoded value yields the
   original bytes; otherwise reject as non-canonical. This kills malleability regardless of the
   underlying library.
3. Every top-level signed object is wrapped with the **algorithm-suite/version byte(s)** from
   ADR-0002 so encodings are self-describing and upgrade-safe.
4. Floating point is **forbidden** in any consensus object. Integers are fixed-width and
   explicitly sized in the spec.
5. The existing hand-rolled `key || value` concatenation in `DhtEntry` is grandfathered for the
   primitive networking types but is **superseded** for structured types by `Codec`; it will be
   migrated when those types gain fields.

`bincode` may still be used for non-consensus, local-only data (e.g. a node's private database
cache) where canonicality is irrelevant — but never for anything hashed, signed, or gossiped.

## Consequences

- ➕ One deterministic, compact, `no_std`-friendly wire format for consensus.
- ➕ The `Codec` trait + canonical-decode rule means the *property* (determinism/non-malleability)
  is enforced structurally, not by convention.
- ➕ Self-describing version bytes align with crypto-agility.
- ➖ Canonical-decode (decode → re-encode → compare) costs a little CPU on ingest; acceptable and
  worth it for non-malleability.
- ➖ `serde` flexibility must be constrained (no untagged enums, no `#[serde(flatten)]`, explicit
  field order) — to be codified in the data-model spec and clippy/review rules.

## Amendment — 2026-09-30: rule 5 superseded, rule 3 extended

### Rule 5 was unsafe, and its migration trigger was wrong

Rule 5 grandfathered `DhtEntry`'s hand-rolled `key || value` concatenation *"for the primitive
networking types"*, to be migrated *"when those types gain fields."*

On 2026-09-23 that construction was found to be **forgeable**. Concatenation encodes no field
boundary, so `("abc","XY")` and `("ab","cXY")` produce identical signed bytes, and `verify()` —
which rebuilds the payload from the record's own fields — **accepted the re-split**. Any observer
of a signed record could republish the publisher's signature **under a different DHT key** while
holding no key material. Since the DHT key decides routing, that is routing-table poisoning by a
peer that possesses nothing. It falsified **G5-T5** and was exactly the ambiguity **G2-T2**
forbids.

Two things were wrong, and the second is the more important:

1. **The grandfathering itself.** `key || value` was treated as a tolerable primitive encoding.
   It was an *ambiguous* one, which is a different and much worse thing.
2. **The migration trigger.** *"When those types gain fields"* implies the risk scales with field
   count. It does not. **Two** variable-length fields are enough for ambiguity; the trigger should
   have been the presence of a variable-length field at all.

**Rule 5 is replaced by:**

> **5′.** Ad-hoc concatenation of variable-length fields is **forbidden** in any signed or hashed
> payload. Where a primitive encoding genuinely predates the `Codec` — as `DhtEntry`'s did — it
> MUST frame every variable-length field with an explicit length. `DhtEntry` now signs
> `u64_be(len(key)) ‖ key ‖ u64_be(len(value)) ‖ value`
> ([wire spec §4](../15-specifications/05-network-wire-protocol.md),
> [crypto spec §6.3](../15-specifications/02-cryptography-spec.md)). These encodings are
> superseded by `Codec` at **G2a**, not "when fields are added".

> **The general lesson, worth keeping:** ad-hoc concatenation is never a neutral shortcut. It is
> an encoding decision, and an ambiguous one. The three existing tamper tests never caught this,
> because each mutates one field and so *changes* the concatenation — tamper-resistance and
> encoding-unambiguity are different properties, and only the second forbids two distinct values
> sharing one signature.

### Rule 3 predates the role axis

Rule 3 requires every top-level signed object to be wrapped with *"the algorithm-suite/version
byte(s) from ADR-0002."* [ADR-0018](0018-signature-role-profiles.md) has since made the descriptor
**two-dimensional**: resolution is `(role, suite version)`, and the shipped `AlgoSuite` carries
both.

> **3′.** Every top-level signed object carries the full `AlgoSuite` descriptor — **both** `role`
> and `suite_version` — not a version alone. Neither field is optional and neither is inferred
> from the object's type at verification time (ADR-0018 rule V1).

This is load-bearing for the G2a/G2b split in [ADR-0022](0022-g2-split-wire-and-consensus-encoding.md):
G2a freezes the *wire* encoding, so `GossipMessage` and `DhtEntry` must carry the descriptor from
their first canonical encoding, or the split recreates the state-migration trap ADR-0018 exists to
avoid.

### Scope unchanged

The codec choice (postcard), the `Codec` trait, the canonical-decode rule and the float
prohibition all stand. [ADR-0022](0022-g2-split-wire-and-consensus-encoding.md) splits *when*
types are encoded, never *how* — there is **one** `Codec` across G2a and G2b. Two would be two
dialects, which is the fork risk the gate exists to prevent.

## Links
- [data model & encoding spec](../15-specifications/01-data-model-and-encoding.md)
- [ADR-0002 crypto parameter set / suite versioning](0002-cryptographic-parameter-set.md)
- Amended by [ADR-0022](0022-g2-split-wire-and-consensus-encoding.md) (G2a/G2b split); rule 3 extended by [ADR-0018](0018-signature-role-profiles.md)
- Code: `crates/hux-network/src/message.rs` — `DhtEntry` now length-framed; migrates to `Codec` at G2a

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

## Links
- [data model & encoding spec](../15-specifications/01-data-model-and-encoding.md)
- [ADR-0002 crypto parameter set / suite versioning](0002-cryptographic-parameter-set.md)
- Code: `crates/hux-network/src/message.rs` (`DhtEntry` manual concatenation — to migrate)

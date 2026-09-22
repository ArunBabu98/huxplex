# ADR-0010: Hash function selection per domain (SHAKE-256 vs BLAKE3)

- Status: Accepted
- Date: 2026-06-21
- Deciders: Founding architect, cryptography

## Context

[ADR-0002](0002-cryptographic-parameter-set.md) lists the hash as "**BLAKE3 / SHAKE-256
(256-bit)**" — i.e. it never decided *which hash is used where*. Meanwhile two sources disagree:

- The repository `readme.md` lists **BLAKE3** as the hashing primitive.
- The **code** uses **SHAKE-256** (`sha3::Shake256`) to derive `PeerId` from an ML-DSA-44 public
  key (`crates/hux-network/src/peer.rs`), and the executive summary records `PeerId = SHAKE-256(pk)[..32]`
  as 🟢 ground truth.

This is the same class of readme-vs-reality conflict that [ADR-0001](0001-canonical-architecture-reconciliation.md)
resolved for the token model. It must be closed before more code hashes anything, because the
hash function is consensus-critical (it determines identifiers, Merkle roots, and content
addresses) and is very hard to change later.

Forces:
- **Determinism & cross-implementation agreement** — every node and reimplementation must hash
  identically; the choice and its exact invocation must be specified, not implied by code.
- **Domain separation** — different uses (identity, state Merkle tree, content addressing,
  transcript hashing) should not collide.
- **Performance** — BLAKE3 is extremely fast and parallel/tree-friendly (good for large state &
  Merkle trees). SHAKE-256 (Keccak/SHA-3 family) is an XOF, is already a dependency, and gives
  family diversity from the BLAKE/ChaCha lineage.
- **Provenance of the existing code** — SHAKE-256 is already implemented and tested for `PeerId`.
- **Agility** — per ADR-0002, whatever we pick sits behind the versioned suite descriptor.

## Options

- **A — BLAKE3 everywhere.** Fastest, simplest, great for Merkle trees. *Cost:* would require
  changing the already-implemented/tested `PeerId` derivation; single hash family.
- **B — SHAKE-256 everywhere.** Already used; SHA-3 standardized; XOF is convenient for
  arbitrary-length outputs and KDFs. *Cost:* slower than BLAKE3 for large state hashing.
- **C — Domain-split: SHAKE-256 for identity/transcript/XOF needs; BLAKE3 for bulk state &
  Merkle hashing.** Matches existing code, plays each hash to its strength, gives family
  diversity. *Cost:* two primitives to specify, audit, and keep agile.

## Decision

**Option C, with SHAKE-256 as the default and BLAKE3 reserved for an explicit, named role.**

| Domain | Hash | Rationale |
|---|---|---|
| `PeerId` and node/account identity fingerprints | **SHAKE-256** (XOF, 32-byte squeeze) | Already implemented & tested; matches 🟢 ground truth |
| Arbitrary-length derivation / fingerprints needing an XOF | **SHAKE-256** | Native XOF, no truncation ambiguity |
| Transcript / challenge hashing (e.g. handshake transcripts) | **SHAKE-256** | Keeps the SHA-3 family on the authentication path |
| **Bulk state hashing & Merkle/Jellyfish tree nodes** (when built) | **BLAKE3** (256-bit) | Speed + tree-mode parallelism for large state; this is the *only* place BLAKE3 is mandated |
| HKDF (session keys) | **HKDF-SHA-256** (unchanged) | Already implemented in `kem.rs`; not changed by this ADR |

Rules:
1. Every hash invocation MUST be specified in
   [`docs/15-specifications/02-cryptography-spec.md`](../15-specifications/02-cryptography-spec.md)
   with its domain, primitive, output length, and (for XOFs) squeeze length.
2. Both hashes are registered in the algorithm-suite descriptor (ADR-0002) and are
   governance-rotatable; this ADR fixes only **suite v1**.
3. The readme's blanket "BLAKE3" claim is **superseded** by this table; the canonical blueprint
   (this ADR + the crypto spec) is authoritative.

## Consequences

- ➕ Closes the readme-vs-code conflict; no code change required for what already exists
  (SHAKE-256 `PeerId` stays).
- ➕ Family diversity (Keccak + BLAKE) on top of the lattice/hash-based signature diversity.
- ➕ BLAKE3 is held in reserve for exactly the workload (huge Merkle state) where its speed pays
  off, instead of being used blanketly.
- ➖ Two hash primitives to audit and keep agile; the spec must be meticulous about which is used
  where to preserve determinism.
- ➖ Until the state/Merkle layer exists, BLAKE3 is unused in code; the dependency is added only
  when that layer lands (avoid premature deps).

## Links
- [ADR-0002 cryptographic parameter set](0002-cryptographic-parameter-set.md),
  [ADR-0003 HRM state model](0003-state-model-hrm.md)
- [cryptography architecture](../02-architecture/cryptography.md),
  [crypto spec](../15-specifications/02-cryptography-spec.md)
- Code: `crates/hux-network/src/peer.rs` (SHAKE-256 PeerId), `crates/hux-crypto/src/kem.rs` (HKDF-SHA-256)

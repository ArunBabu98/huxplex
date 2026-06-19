# ADR-0002: Cryptographic parameter set + agility-first

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect, cryptography

## Context

We must choose concrete PQ primitives for genesis. The primitives are young (FIPS 203/204/205
standardized 2024), have less cryptanalysis than RSA/ECC, and will evolve. The existing code
already uses ML-DSA-44 and ML-KEM-768.

## Options

- **A — Pick one optimal set and hard-code it** (e.g., all-lattice ML-DSA-44 + ML-KEM-768).
  Simple, fast. *Risk*: a single lattice break is fatal; hard-coding fights future migration.
- **B — Pick a diversified set behind a versioned agility registry.** Lattice for hot path, hash-
  based for high-assurance, hybrid KEX during transition; everything swappable. More upfront work.
- **C — Maximize security level now (ML-DSA-87, ML-KEM-1024).** Conservative margins. *Cost*:
  even larger signatures/keys worsen the bandwidth/state problem; still single-family risk.

## Decision

**Option B.** Genesis "suite v1":

| Role | Primitive | NIST cat |
|---|---|---|
| Hot-path signing (tx/vote) | **ML-DSA-44** (1312/2560/2420 B) | 1 |
| Validator long-lived identity | **SLH-DSA-128s** (hash-based) | 1 |
| Transport KEX | **ML-KEM-768 + X25519 (hybrid)** | 3 (+classical) |
| Leader randomness | **LB-VRF** | — |
| ZK | **zk-STARK** (hash-based) | — |
| Hash | **BLAKE3 / SHAKE-256** (256-bit) | — |

The **overriding decision is agility, not the specific algorithms**: every signed/encrypted object
carries an `algo_suite` version; primitives sit behind traits; the suite is governance-rotatable
without a state-model fork. Family diversity (lattice + hash-based) is mandatory so no single
break is fatal.

Deferred sub-decision: ML-DSA-44 (Cat 1) vs ML-DSA-65 (Cat 3) for the hot path — revisit with
Phase-0 benchmarks (R-A2). Because of agility, this is a parameter change, not a redesign.

## Consequences

- ➕ Survives a single-scheme break (diversity + agility + hybrid).
- ➕ Aligns with current NIST/IETF migration guidance (agility, hybrid, staged).
- ➖ More engineering than hard-coding; must refactor current hard-coded sizes
  (`[u8;1312]`/`[u8;2420]`) behind the suite descriptor.
- ➖ LB-VRF / PQ-SSLE constructions are less mature (R-A3) — devnet may use classical-randomness
  fallback initially.

## Links
- [crypto-agility](../03-post-quantum/crypto-agility.md), [pq-cryptography](../03-post-quantum/pq-cryptography.md), [cryptography](../02-architecture/cryptography.md)
</content>

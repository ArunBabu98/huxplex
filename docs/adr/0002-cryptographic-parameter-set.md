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

## Review note — 2026-09-22

A Layer-0 technology review against the 2026 state of the art
([`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md))
**does not disturb this decision** — Option B (diversity behind an agility registry) is the
year's best-supported call, given the May 2026 Luo preprint claiming (and failing to establish)
a quantum break of ML-KEM, and the February 2026 MLWE/LWE hardness-gap result. Four items are
recorded here for the ADRs that will amend the suite table; none is actioned by this note.

| # | Finding | Bearing |
|---|---|---|
| 1 | **The suite has no *role* dimension.** arXiv:2609.24689 shows transaction authorization and quorum certification are different design problems; `Transaction` and `Vote` are currently pinned to one scheme | `algo_suite` should be `{role, version}`. Must be settled **before G1 builds the registry** — later it is a state migration. Proposed `adr/0018-*` |
| 2 | **R-A2 has moved toward Cat 3.** Sui chose ML-DSA-65 over 44 (AI-assisted attacks on lattice schemes; verification at Ed25519 parity); CNSA 2.0 mandates ML-DSA-87. Against that, BSC shipped ML-DSA-44 and measured **40–50% TPS loss**. Separately, genesis pairs a **Cat-1 signature with a Cat-3 KEX**, which was not deliberate | Re-run R-A2 **per role**, not globally |
| 3 | **LB-VRF is superseded by iVRF** — hash-based, 0.02 ms eval/verify (faster than the classical ECVRF Algorand uses), no ZK proof of correct PRF evaluation, +32 B for forward security. It also moves consensus randomness off the lattice family | Amend the suite table and R-A3, subject to verifying the uniqueness properties map to a bounded Q-BFT validator set |
| 4 | **Implementation attacks, not cryptanalysis, are the live threat**: ML-DSA secret-key recovery from sign leakage at **190,000 signatures** (eprint 2026/1366) — days of validator signing — plus fault attacks whose vulnerable pattern is verified present in PQM4, liboqs, PQClean and wolfSSL | Makes key-epoch rotation cadence a cryptographic parameter (ADR-0014) and the multi-vendor rule a requirement |

## Links
- [crypto-agility](../03-post-quantum/crypto-agility.md), [pq-cryptography](../03-post-quantum/pq-cryptography.md), [cryptography](../02-architecture/cryptography.md)
- 2026 review: [`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md) §1.2, §2.1, §2.2, §2.4, §4
</content>

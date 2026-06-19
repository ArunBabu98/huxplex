# Quantum-Era Risks

A focused treatment of the quantum dimension — the risk that defines Huxplex's existence and
the one most often hand-waved by "post-quantum" projects.

## The core risk: scheduled cryptographic obsolescence

A cryptographically relevant quantum computer (CRQC) running Shor's algorithm breaks:

- **ECDSA / EdDSA / Schnorr / BLS** — every signature scheme securing every major chain today.
- **RSA / DH / ECDH** — key exchange underlying TLS and most encrypted transport.

Grover's algorithm gives a quadratic speedup on unstructured search, halving the effective
security of symmetric/hash primitives (a 256-bit hash → ~128-bit quantum security — still
fine, which is why we use 256-bit hashing).

The timeline is uncertain (estimates range widely), but the *risk is asymmetric*: the cost of
preparing early is bounded; the cost of being late is total and retroactive.

## "Harvest now, decrypt later" (HNDL)

The attacker does not need a CRQC *today*. They record encrypted traffic and on-chain public
keys *now*, and decrypt/forge *later* when a CRQC exists. Implications:

- Any data encrypted with classical KEX today is already at risk if recorded.
- Any address whose public key is exposed on-chain (e.g., after first spend) is a future
  forgery target. Account-model chains expose public keys on every transaction.
- **You cannot fix this retroactively.** A chain that launches classically and "migrates
  later" leaves a permanent window of harvestable material.

This is the single strongest argument for PQ-*native* rather than PQ-*retrofit*, and it is
Huxplex's reason to exist.

## Risk register (quantum-specific)

| Risk | Likelihood | Impact | Time profile | Mitigation |
|---|---|---|---|---|
| CRQC breaks chosen PQ scheme via *new* cryptanalysis (not Shor — lattice attack) | Medium (PQ schemes are young) | Catastrophic | Any time | **Crypto-agility registry**, hybrid classical+PQ, SLH-DSA (hash-based, structure-free) fallback |
| HNDL on transport / encrypted vaults | High (passive, happening now) | High | Now → CRQC | ML-KEM-768 (+ hybrid) for all transport; no classical-only KEX |
| HNDL on exposed on-chain public keys | High | High | Now → CRQC | PQ-native signatures from genesis; one-time-ish address hygiene; consider hash-locked accounts |
| Grover weakens hash/symmetric margin | Low (well-understood) | Medium | At CRQC | 256-bit SHAKE/BLAKE3; AEAD with ≥256-bit keys |
| Implementation bug in young PQ libraries | Medium | High | Now | Vendor multiple impls, fuzzing, KATs (FIPS test vectors), audits, isolation |
| Side-channel leakage in PQ signing (timing on rejection sampling) | Medium | High | Now | Constant-time vetted libs (`libcrux`), side-channel audits |
| Standards churn (NIST/IETF revise FIPS 203/204/205 or add new) | High | Medium | Ongoing | Agility; treat the suite as versioned data, not hard-coded |
| Quantum attack on VRF/SSLE/zk used in consensus | Medium | High | At CRQC | Use lattice/hash-based VRF (LB-VRF), hash-based zk-STARKs (no pairings) |
| Over-reliance on a *single* PQ family (all-lattice) | Medium | High | Any | Diversify: lattice (ML-DSA/ML-KEM) + hash (SLH-DSA) so one family break ≠ total break |

## The "young cryptography" problem

ML-DSA and ML-KEM were standardized recently (FIPS 203/204, 2024) and have far less
cryptanalytic history than RSA/ECC. SLH-DSA (FIPS 205) is conservative (hash-based) but large
and slow. This creates a genuine dilemma:

- We *must* use PQ now (HNDL), but the PQ schemes are *less battle-tested*.

**Resolution (and the single most important architectural stance):** do not bet the protocol
on any one algorithm. Specifically:

1. **Hybrid where cheap** — for transport KEX, combine a classical (X25519) and PQ (ML-KEM)
   shared secret so an attacker must break *both*. (NIST/IETF endorse hybrid KEMs during
   transition.)
2. **Diversify families** — lattice for the hot path (fast, small-ish), hash-based (SLH-DSA)
   for long-lived validator/root identity (structure-free, only breaks if hashes break).
3. **Agility registry** — algorithm IDs are first-class on-chain data; the suite can be
   rotated by governance without forking the state model. See
   [`03-post-quantum/crypto-agility.md`](../03-post-quantum/crypto-agility.md).

## Quantum risks beyond cryptography

- **Quantum-assisted optimization** could give some validators/agents an edge in any
  optimization-based mechanism (solver auctions, novelty scoring). Design mechanisms whose
  fairness does not depend on equal compute.
- **QRNG dependence** — the vision references QRNG-seeded sharding (`epoch_qrng_seed`).
  Hardware QRNG is a *centralization and trust* risk; prefer a decentralized, bias-resistant
  beacon (verifiable randomness from LB-VRF / threshold) and treat any single QRNG as one
  input only. 🔴
- **Post-quantum *and* AI together** — a quantum-accelerated AI adversary is the worst-case
  composite threat; it is why human veto + agility + diversity are all simultaneously required.

## Design commitments that follow

1. PQ from genesis; no classical-only path for anything long-lived. (🟢 primitives already exist.)
2. Hybrid transport KEX during the transition window.
3. Family diversity (lattice + hash) — no monoculture.
4. 256-bit hashing throughout.
5. Versioned algorithm registry + governance-driven rotation, with a documented migration
   playbook ([`03-post-quantum/migration-strategy.md`](../03-post-quantum/migration-strategy.md)).
6. Constant-time, audited, multi-vendor PQ implementations with FIPS KAT testing.

---

### Open Questions
- What is the right decentralized randomness beacon to replace/augment a trusted QRNG?
- Should genesis accounts be hash-locked (public key revealed only at spend, à la P2PKH) to reduce HNDL exposure even with PQ signatures?
- Trigger criteria for activating a suite migration: what observable signals (cryptanalysis result, NIST advisory) start the clock?
</content>

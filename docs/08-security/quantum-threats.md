# Quantum Threats (Security View)

Operational companion to [`01-vision/quantum-era-risks.md`](../01-vision/quantum-era-risks.md).
That doc is strategic; this one is the security team's concrete checklist for the quantum
adversary.

## The two clocks

1. **The HNDL clock (running now).** Every byte of classically-encrypted data and every exposed
   classical public key recorded today is a future liability. There is no "later" — mitigation
   must already be in place. Status: ✅ PQ-native from genesis; ⚠️ enforce *no classical-only*
   path anywhere.
2. **The CRQC clock (uncertain future).** When a CRQC exists, anything still relying on broken
   primitives fails instantly and retroactively. Status: defended by agility + diversity.

## Concrete quantum attack scenarios & responses

| Scenario | What breaks | Huxplex response |
|---|---|---|
| Shor breaks any classical sig/KEX we ever used | forgery, decryption of recorded traffic | none used on critical path; hybrid transport's classical half is *additive*, not sole |
| New lattice cryptanalysis weakens ML-DSA/ML-KEM | hot-path signatures/KEX | **emergency suite migration** to SLH-DSA/other; family diversity means hash-based path survives |
| Grover speeds search on hashes/symmetric | reduced margin | 256-bit SHAKE/BLAKE3 + 256-bit AEAD → ~128-bit quantum margin (acceptable) |
| Quantum attack on VRF/SSLE | leader-election bias | LB-VRF (lattice) / hash-based fallbacks; classical-randomness fallback only on devnet |
| Quantum attack on ZK assumptions | proof forgery | zk-STARK (hash-based) — no pairings/DL; PQ-safe by construction |
| Side-channel + quantum combo on signing | key extraction | constant-time libs + side-channel audits (classical defense, still required) |

## The "single point of cryptographic failure" audit

A recurring security review must verify **no component silently depends on a single algorithm**:

- [ ] Every signed object carries `algo_suite`; verifier dispatches (no hard-coded ML-DSA-only path).
- [ ] At least one **non-lattice** (hash-based) scheme is always live in the registry (diversity).
- [ ] Transport uses **hybrid** (classical+PQ) so neither alone is load-bearing during transition.
- [ ] ZK uses **hash-based** STARKs only (no pairing-based SNARKs anywhere security-critical).
- [ ] Hashes/symmetric are **256-bit** everywhere.
- [ ] The migration state machine is **tested on testnet** (can we actually rotate?).
- [ ] No classical-only encryption for any long-lived secret (HNDL).

This checklist is part of every audit ([audits](audits.md)) and every phase gate.

## Quantum-specific operational concerns

- **QRNG trust**: any hardware QRNG (vision's `epoch_qrng_seed`) is a centralization/trust risk.
  Treat it as *one input* to a decentralized, bias-resistant randomness beacon (LB-VRF/threshold),
  never the sole source. 🔴 (Open item.)
- **Library maturity**: `libcrux-*` at `0.0.x` — pin, vendor, track CVEs, and keep a second
  implementation ready (multi-vendor agility).
- **Standards churn**: NIST/IETF may revise FIPS 203/204/205 or add schemes — the agility
  registry absorbs this without a fork.
- **Composite quantum+AI adversary**: the worst case is a quantum-accelerated AI attacker;
  defense is the *combination* of agility, diversity, human veto, and economic bounds — no single
  mechanism suffices.

## Detection: how would we even know?

Quantum breaks may not announce themselves. Detection strategy:
- **Monitor the cryptanalysis literature & NIST/IETF advisories** (a named responsibility).
- **Anomaly detection**: unexpected valid signatures from never-spent keys, impossible forgeries,
  statistical oddities in randomness — could indicate a break in progress.
- **Bug-bounty + research grants** specifically for PQ cryptanalysis of our suite.
- **Pre-committed trigger criteria** that start the migration clock (see
  [`03-post-quantum/migration-strategy.md`](../03-post-quantum/migration-strategy.md)).

## MVP / Production / Future

- **MVP**: PQ-native primitives (🟢), `algo_suite` field present, 256-bit hashing, hybrid handshake.
- **Production**: full agility registry with a live hash-based fallback, tested migration state
  machine, side-channel audits, cryptanalysis-monitoring role, decentralized randomness beacon.
- **Future**: automated suite deprecation, formal verification of agility/migration, periodic
  scheduled suite reviews, PQ aggregation if it matures.

---

### Open Questions
- What observable signal reliably indicates a PQ scheme is being broken *before* catastrophic loss?
- Decentralized, bias-resistant randomness beacon to replace trusted QRNG?
- Is hybrid-signature (not just hybrid-KEX) worth the doubled signature size as extra insurance?
</content>

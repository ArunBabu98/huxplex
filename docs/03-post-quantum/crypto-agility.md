# Crypto-Agility

> **This is the single most important architectural property of Huxplex.** A chain meant to
> last decades on young cryptography must be able to change its cryptography. Agility ranks
> above any individual algorithm choice (Principle #4). Decision: [ADR-0002](../adr/0002-cryptographic-parameter-set.md).

## The thesis

> Do not optimize for the perfect PQ algorithm. Optimize for the ability to *replace* any PQ
> algorithm. Standards will evolve; some schemes will be weakened. The protocol that survives
> is the one where crypto is *versioned data*, not *hard-coded assumption*.

This aligns with current NIST/IETF migration guidance, which emphasizes cryptographic agility
and staged adoption over premature parameter optimization.

## The algorithm registry

The core mechanism is an on-chain, governance-controlled **algorithm registry** that maps suite
versions to concrete primitives. Every signed/encrypted object references a suite by id.

```rust
// Conceptual — the existing `SignatureSchemeId` enum is the seed of this.
struct AlgoSuite {
    version: u16,            // monotonic; appears in every signed object
    signature: SigAlgId,     // e.g. ML_DSA_44, ML_DSA_65, SLH_DSA_128s, FUTURE_X
    kem: KemAlgId,           // e.g. ML_KEM_768, HYBRID_X25519_MLKEM768
    hash: HashAlgId,         // e.g. BLAKE3_256, SHAKE_256
    vrf: VrfAlgId,           // e.g. LB_VRF
    status: SuiteStatus,     // Proposed | Active | DualAccept | Deprecated | Sunset
}
```

- The registry is **append-mostly**: new suites are added; old suites change *status*, never
  disappear (history must stay verifiable).
- Changes go through governance (routine path) or emergency governance (active break), always
  under the human veto.

### Today vs. target

```rust
// TODAY (src/crypto/signaturescheme.rs) — the embryo of agility:
pub enum SignatureSchemeId { Dilithium2 }   // one variant

// TARGET — a versioned, multi-primitive, status-bearing registry (above).
```

The codebase *already* threads `scheme` through keys, signatures, and the `SchemeMismatch`
error — the design instinct is correct; it just needs to grow from one algorithm into a managed
registry.

## Design requirements for agility

1. **Versioned objects.** Every signature, key, KEM ciphertext, and address commitment carries
   (directly or via context) its `algo_suite` version. The verifier dispatches on it.
2. **No global crypto constants.** Sizes (1312/2560/2420…) live behind the suite, not as magic
   numbers sprinkled across the code. ⚠️ Today these are hard-coded in `publickey.rs`/`signature.rs`
   (`[u8; 1312]`, `[u8; 2420]`); Production must parameterize them by suite.
3. **Pluggable implementations.** A `Signer`/`Verifier`/`Kem` trait per role; concrete impls are
   selected by suite. This also lets us swap *libraries* (multi-vendor) without protocol change.
4. **Downgrade resistance.** The suite version is bound *inside* the signed payload (like the
   context string), so an attacker can't strip a v2 object down to v1.
5. **Diversity by construction.** The registry always contains at least one *non-lattice*
   (hash-based) option so no single mathematical break is fatal.
6. **Negotiation for transport.** The PQ-TLS handshake negotiates the highest mutually-supported
   suite, with a governance-set floor (no sub-floor downgrade).

## Agility beyond algorithms

Crypto-agility generalizes to a broader "infrastructure agility" stance:

- **VM agility**: `Vm` trait (`wasmi` → `wasmtime` → RISC-V) — [execution-engine](../02-architecture/execution-engine.md).
- **Storage agility**: `StateStore` trait (RocksDB → …) — [storage](../02-architecture/storage.md).
- **Consensus agility**: even the BFT variant is upgrade-gated, though far more conservatively.

The principle is the same: protocol logic depends on *interfaces and versioned descriptors*, not
on concrete choices that can't change.

## Anti-patterns we explicitly avoid

- ❌ Hard-coding `ML-DSA-44` sizes/calls across the codebase (current state — to be refactored).
- ❌ A single `enum` with one variant treated as permanent.
- ❌ Crypto choices baked into serialization formats with no version byte.
- ❌ "We'll add agility later" — agility added late requires a hard fork; it must be in v1's bones.

## Testing agility

- Round-trip a *dummy* second suite in tests (e.g., register a fake `V2` that maps to the same
  primitives but a different version) to prove dispatch + dual-accept logic works **before** a
  real migration is ever needed.
- Testnet migration rehearsal (see [migration-strategy.md](migration-strategy.md)).
- Negative tests: downgrade attempts must fail; cross-suite signature confusion must fail
  (extends the existing cross-context test discipline 🟢).

## MVP / Production / Future

- **MVP**: `algo_suite` version field on every signed object (even with a single suite);
  primitive sizes/calls behind a suite descriptor; one `Signer`/`Verifier` trait.
- **Production**: full on-chain registry with status lifecycle, governance-gated additions,
  negotiation in the handshake, downgrade-resistance tests, a registered hash-based fallback.
- **Future**: automated suite-deprecation workflows, formal verification of the dispatch/
  downgrade logic, agility extended cleanly to ZK proof systems.

---

### Open Questions
- Where should the registry live — genesis-config + governance module, or a special system resource (HRM)?
- How to version *ZK proof systems* agilely (STARK params evolve too)?
- Minimum set of primitives that must always be "live" to guarantee diversity (e.g., always ≥1 lattice + ≥1 hash-based)?
</content>

# `hux-crypto`

Huxplex **Layer 0** — post-quantum cryptographic primitives.

Crate 0 of the workspace. Everything above depends on it; it depends on nothing in Huxplex.

## What is here today 🟢

| Primitive | Detail |
|---|---|
| **ML-DSA-44** (FIPS 204) | sign / verify, context-bound, hedged (randomized) signing. pk 1,312 B · sk 2,560 B · sig 2,420 B |
| **ML-KEM-768** (FIPS 203) | keygen / encaps / decaps + HKDF-SHA-256 **directional** session key derivation |
| **BIP32 → ML-DSA** | `m/44'/931931'/{purpose}'/0'/{index}'`, hardened at every level, with [`KeyPurpose`] |
| **Domain separation** | `huxplex-{network}:{purpose}:v{n}` context strings, exhaustively replay-tested |
| **Secret hygiene** | `PrivateKey` is redacted in `Debug`, zeroized on drop, compared in constant time |

## What is not here yet 🟡

The **versioned algorithm registry** — `(role, version) → primitive` dispatch — arrives at gate
**G1**. Until then `SignatureSchemeId` has a single variant and sizes are still hard-coded; that
is the gap G1 closes. `slh_dsa`, `lb_vrf`, `pq_ssle` and `zk_stark` exist as `#[cfg(test)]` API
contracts with `#[ignore]`d conformance suites labelled by the gate that un-ignores them.

## Rules for working in this crate

1. **Never call an architecture-specific backend path** (`mlkem768::avx2::*`, `::neon::*`).
   Always the top-level dispatching entry point — it selects at runtime and falls back to
   portable. Architecture portability is a decentralization property.
2. **No homemade cryptography.** Compose standardized primitives; never invent a scheme.
3. **Every protocol signature carries a context string** from the registry in the
   [cryptography spec](../../docs/15-specifications/02-cryptography-spec.md) §5.
4. **Secrets do not leave through `Debug`, logs, or serialization.** `expose_secret()` is
   deliberately awkward so every call site is greppable.
5. **Production signing must not accept caller-supplied randomness.** Hedged signing is
   mandatory; deterministic lattice signing plus fault injection is a key-recovery path.

## Docs

- Architecture: [`docs/02-architecture/cryptography.md`](../../docs/02-architecture/cryptography.md)
- Normative spec: [`docs/15-specifications/02-cryptography-spec.md`](../../docs/15-specifications/02-cryptography-spec.md)
- Decisions: [ADR-0002](../../docs/adr/0002-cryptographic-parameter-set.md) (suite),
  [ADR-0010](../../docs/adr/0010-hash-function-domains.md) (hashes),
  [ADR-0014](../../docs/adr/0014-validator-key-management.md) (key custody),
  [ADR-0018](../../docs/adr/0018-signature-role-profiles.md) (role profiles)
- Build plan: [`docs/18-implementation-plan/02-g1-crypto-core.md`](../../docs/18-implementation-plan/02-g1-crypto-core.md)
- **Verifying it yourself:** [`docs/19-verification/`](../../docs/19-verification/)

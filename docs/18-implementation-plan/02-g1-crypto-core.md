# 02 — G1 · Crypto core and the agility registry

> *"Build the registry **before** the algorithms, or every later layer will hardcode an algorithm
> ID."* — [`16-action-plan.md`](../16-action-plan.md#g1--crypto-core-and-the-agility-registry)
>
> **Entry:** G0 closed. **Unblocks:** G2 (and therefore everything).
>
> This gate has a **closing window**: G2 freezes canonical encoding
> ([ADR-0011](../adr/0011-canonical-serialization.md)). Anything about the suite descriptor's
> *shape* that is wrong here becomes a state migration there.

## The shape to build

```
crates/hux-crypto/src/
├── lib.rs
├── suite/
│   ├── mod.rs          # AlgoSuite, SigRole, resolution, registry errors
│   ├── registry.rs     # (role, version) -> primitive; append-only table
│   └── ids.rs          # SignatureSchemeId, KemId, HashId — stable discriminants
├── traits.rs           # Signer, Verifier, Kem, Hasher — the only path to a primitive
├── sig/
│   ├── ml_dsa.rs       # libcrux-ml-dsa
│   └── slh_dsa.rs      # fips205
├── kem/ml_kem.rs
├── hash/{shake,blake3}.rs
├── hd.rs               # BIP32 + KeyPurpose (🟢 already implemented)
└── context.rs          # context-string construction, network-parameterized (🟢)
```

## Tasks

### A. The registry — the core of the gate

| ID | Task | Acceptance |
|---|---|---|
| **C1** ⬜ | `SigRole { Transaction=0, QuorumCert=1, Identity=2, Governance=3, Transport=4 }`, `#[non_exhaustive]`, discriminants matching `KeyPurpose` | A compile-time assertion that `SigRole::X as u32 == KeyPurpose::X.index()` for every variant |
| **C2** ⬜ | `AlgoSuite` versioned descriptor; resolution is `(role, version) → primitive set` | **G1-T1** and **G1-T6** below |
| **C3** ⬜ | Registry is **append-only**: unknown role or unknown version fails closed with a distinct error, never a default | **G1-T4** |
| **C4** ⬜ | Traits `Signer`/`Verifier`/`Kem`/`Hasher`; **no direct call to a named scheme outside the registry** | A CI grep (or a lint) proving no `libcrux_ml_dsa::` path exists outside `sig/ml_dsa.rs` |
| **C5** ⬜ | Suite-v1 rows: all four signing roles → ML-DSA-44; `Identity`/`Governance` → SLH-DSA-128s per [ADR-0018](../adr/0018-signature-role-profiles.md) §2 | Matches [crypto spec §1.1](../15-specifications/02-cryptography-spec.md) exactly |

> **Design note — keep the registry dumb.** It is a lookup table plus a dispatch, not a policy
> engine. Where the table *lives on-chain* (genesis config vs. an HRM system resource) is an open
> question owned by [crypto-agility.md](../03-post-quantum/crypto-agility.md) and belongs to G3.
> At G1 the table is static, behind a trait, with a seam for a state-backed source later.
> Building the governance path now would be scaffolding for a state model that does not exist.

### B. Remove the hard-coded sizes

[ADR-0002](../adr/0002-cryptographic-parameter-set.md)'s explicit negative consequence: *"must
refactor current hard-coded sizes (`[u8;1312]`/`[u8;2420]`) behind the suite descriptor."*

| ID | Task | Acceptance |
|---|---|---|
| **C6** ⬜ | Sizes come from the suite descriptor. Current sites: `publickey.rs` (1312, 2420), `signature.rs` (2560) | A second signature scheme can be registered without editing any size literal |

> ⚠️ This is the task most likely to be done shallowly. The test that catches a shallow job is
> **G1-T1** — if registering a dummy V2 requires touching a size constant, C6 is not finished.

### C. SLH-DSA-128s

| ID | Task | Acceptance |
|---|---|---|
| **C7** ⬜ | Implement `sig/slh_dsa.rs` on **`fips205`** (pure Rust, no `unsafe`, all 12 parameter sets) | The 24 `slh_dsa_128s_tests` pass with `#[ignore]` removed; sizes 32 / 64 / 7,856 hold |
| **C8** ⬜ | CI **differential test** against RustCrypto `slh-dsa` — dev-dependency only, never a runtime dependency | Same seed ⇒ identical key and signature bytes; a deliberate mutation fails the test |

### D. Secret hygiene and KATs

| ID | Task | Acceptance |
|---|---|---|
| **C9** ⬜ | Production signing sources randomness from the system CSPRNG and **cannot accept a caller-supplied value**; a separate test-only entry point takes explicit randomness ([crypto spec §3](../15-specifications/02-cryptography-spec.md)) | Two functions, not one with a flag. The test-only path is unreachable from the public API |
| **C10** ⬜ | Byte-exact KAT fixtures for ML-DSA-44, ML-KEM-768, SLH-DSA-128s, and the hash domains — signature fixtures pin the 32-byte randomness | **G1-T3** on both architectures |
| **C11** ⬜ | `libcrux` ↔ `aws-lc-rs` ML-DSA differential test ([ADR-0019](../adr/0019-transport-authentication.md) condition 4) | Same input ⇒ identical verification verdict; cross-verification of each other's signatures |

> **Why C9 is phrased as "two functions, not one with a flag."** A `deterministic: bool` parameter
> is a downgrade switch waiting for a misconfiguration, and deterministic lattice signing plus
> fault injection is a demonstrated key-recovery path (eprint 2025/2009).

### E. Deferred at this gate

`lb_vrf`, `pq_ssle`, `zk_stark` stay `#[ignore]`d with their `GATE:` labels — the
[v1 scope contract](../15-specifications/06-v1-scope.md) forbids them. **Do not implement iVRF
here** even though [ADR-0002](../adr/0002-cryptographic-parameter-set.md)'s review note prefers it
over LB-VRF; that is a G6 decision and v1 uses classical-randomness leader selection.

## 🎯 Gate tests

| ID | Property | Note |
|---|---|---|
| **G1-T1** | **Algorithm rotation without state migration.** Register a second scheme, flip *one role's* default; old objects still verify, other roles untouched, zero state-structure changes | The entire agility thesis in one test. Exercise it per-role, not globally |
| **G1-T2** | **Cross-context replay fails** — exhaustive over every ordered pair of registry contexts | 🟢 partly exists; extend to the full sweep including `dht:entry` now that it is network-parameterized |
| **G1-T3** | **KAT byte-exactness** on both architectures | Signature fixtures must pin randomness (C9) |
| **G1-T4** | **Unknown algorithm ID is rejected, never ignored** — extend to unknown *role* | Fail-open on an ID is how agility becomes a downgrade attack |
| **G1-T5** | **Hybrid handshake retains PQ security if the classical half is broken** | Force X25519 output to a constant; session keys still differ |
| **G1-T6** | **Role confusion is rejected** — every ordered pair of roles | New in [ADR-0018](../adr/0018-signature-role-profiles.md). The role axis is worthless without it |

## G1 exit

- The registry is the only path to a primitive (C4 enforced mechanically, not by convention).
- SLH-DSA green; its 24 tests un-ignored; differential test passing.
- KATs committed and green on both architectures.
- **G1-T1 and G1-T6 demonstrated in CI** — these two are the gate.
- No size literal outside the suite descriptor.

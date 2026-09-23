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
| **C1** ✅ | `SigRole { Transaction=0, QuorumCert=1, Identity=2, Governance=3, Transport=4 }`, `#[non_exhaustive]`, discriminants matching `KeyPurpose` | A compile-time assertion that `SigRole::X as u32 == KeyPurpose::X.index()` for every variant |
| **C2** ✅ | `AlgoSuite` versioned descriptor; resolution is `(role, version) → primitive set` | **G1-T1** and **G1-T6** below |
| **C3** ✅ | Registry is **append-only**: unknown role or unknown version fails closed with a distinct error, never a default | **G1-T4** |
| **C4** ✅ | Traits `Signer`/`Verifier`/`Kem`/`Hasher`; **no direct call to a named scheme outside the registry** | A CI grep (or a lint) proving no `libcrux_ml_dsa::` path exists outside `sig/ml_dsa.rs` |
| **C5** ✅ | Suite-v1 rows: all four signing roles → ML-DSA-44; `Identity`/`Governance` → SLH-DSA-128s per [ADR-0018](../adr/0018-signature-role-profiles.md) §2 | Matches [crypto spec §1.1](../15-specifications/02-cryptography-spec.md) exactly |

> **Design note — keep the registry dumb.** It is a lookup table plus a dispatch, not a policy
> engine. Where the table *lives on-chain* (genesis config vs. an HRM system resource) is an open
> question owned by [crypto-agility.md](../03-post-quantum/crypto-agility.md) and belongs to G3.
> At G1 the table is static, behind a trait, with a seam for a state-backed source later.
> Building the governance path now would be scaffolding for a state model that does not exist.

### A — as built (2026-09-23)

```
crates/hux-crypto/src/
├── suite/{mod,ids,registry}.rs   # SigRole, SuiteVersion, AlgoSuite, SuiteError; the v1 table
├── traits.rs                      # Verifier, Signer, SignatureScheme; implementation()
├── sig/ml_dsa.rs                  # the ONLY file permitted to name libcrux_ml_dsa
└── kem/ml_kem.rs                  # the ONLY file permitted to name libcrux_ml_kem
```

Conformance: `crates/hux-crypto/tests/suite_registry.rs`, 16 tests.
Enforcement: `scripts/check-primitive-encapsulation.sh`, in CI and `verify-layer0.sh`, and
**verified to fail on an injected violation** rather than only to pass on a clean tree.

Three decisions worth recording, because each could reasonably have gone the other way:

1. **`Signer` and `Verifier` are separate traits**, not one. Verifying is not signing: a light
   client, an archival verifier, or a node validating history under a retired suite must verify
   with no capacity to sign — which is precisely what rule V5 (*old pairs stay verifiable
   forever*) requires. Merging them would make "can verify" imply "can sign", and that
   implication is false for most of a chain's life. `traits::verifier()` returns a handle that
   **cannot** sign, making the absence of that capability a type-level fact.

2. **`Kem` and `Hasher` traits are deliberately deferred.** Each has exactly one candidate today
   (ML-KEM-768, SHAKE-256) and no second before G5. A trait written against one implementation
   encodes that implementation's shape and gets redesigned when the second arrives. The
   encapsulation check already confines both vendor crates, which is the property C4 actually
   asks for. They land with the hybrid KEX and BLAKE3 respectively.

3. **"Registered but unimplemented" is its own error.** Suite v1 resolves `Identity` and
   `Governance` to SLH-DSA-128s, which does not exist until C7. `SuiteError::SchemeUnimplemented`
   is distinct from `UnknownPair`, and neither ever falls back to a working scheme — silently
   substituting a hot-path primitive for a root-of-trust one is the exact downgrade this registry
   exists to prevent. Pinned by
   `unimplemented_scheme_is_distinct_from_unknown_and_never_substituted`.

> **Zero is never a valid identifier** for a role, a suite version or a scheme. A zeroed or
> default-constructed descriptor field therefore cannot be mistaken for v1 — fail-closed by
> construction rather than by a check a caller can forget.

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
| **G1-T1** | **Algorithm rotation without state migration.** Register a second scheme, flip *one role's* default; old objects still verify, other roles untouched, zero state-structure changes | 🟡 **half green.** The descriptor half is proven (`g1_t1_descriptor_shape_supports_per_role_rotation`): resolution is per-`(role, version)`, and suite v1 *already* resolves `Identity` to a different primitive than the hot roles, so the table is genuinely per-role rather than one global default wearing a role label. The rotation half needs a second **implemented** scheme — it completes at C7 |
| **G1-T2** | **Cross-context replay fails** — exhaustive over every ordered pair of registry contexts | 🟢 partly exists; extend to the full sweep including `dht:entry` now that it is network-parameterized |
| **G1-T3** | **KAT byte-exactness** on both architectures | Signature fixtures must pin randomness (C9) |
| **G1-T4** | **Unknown algorithm ID is rejected, never ignored** — extend to unknown *role* | 🟢 **green** — five tests: unknown role, unknown version, unknown scheme, zero-is-never-valid, and consistent resolution across every registered pair |
| **G1-T5** | **Hybrid handshake retains PQ security if the classical half is broken** | Force X25519 output to a constant; session keys still differ |
| **G1-T6** | **Role confusion is rejected** — every ordered pair of roles | 🟡 **structural half green** — every ordered pair of roles is proven pairwise distinct in discriminant and key purpose, and `RoleMismatch` names both roles. Binding a *signature* to its role needs the descriptor on the signed object, which is G2's encoding work |

## G1 exit

- The registry is the only path to a primitive (C4 enforced mechanically, not by convention).
- SLH-DSA green; its 24 tests un-ignored; differential test passing.
- KATs committed and green on both architectures.
- **G1-T1 and G1-T6 demonstrated in CI** — these two are the gate.
- No size literal outside the suite descriptor.

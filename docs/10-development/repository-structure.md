# Repository Structure

## Today (ground truth)

The repo is a single Rust crate (`huxplex`, edition 2024) with two modules:

```
huxplex/
├── Cargo.toml                 # libcrux-ml-dsa, libcrux-ml-kem, hkdf, sha2/3, bip32, rand, thiserror, hex
├── Cargo.lock
├── readme.md                  # the v1 research-chain vision
├── .gitignore
└── src/
    ├── lib.rs                 # mod crypto; mod network;
    ├── crypto/
    │   ├── mod.rs             # (mostly the ML-DSA test suite — extensive)
    │   ├── signaturescheme.rs # enum SignatureSchemeId { Dilithium2 }  ← agility seed
    │   ├── signature.rs       # Keypair: generate/sign  (ML-DSA-44)
    │   ├── publickey.rs       # PublicKey::verify (context-bound)
    │   ├── privatekey.rs      # PrivateKey { scheme, bytes }
    │   ├── kem.rs             # ML-KEM-768 keygen/encaps/decaps + HKDF session key
    │   ├── bip32.rs           # derive_mldsa_seed (m/44'/931931'/0'/0'/i')
    │   └── error.rs           # CryptoError / CryptoResult
    └── network/
        ├── mod.rs             # (network test suite)
        ├── message.rs         # GossipMessage, DhtEntry (sign/verify)
        ├── topic.rs           # GossipTopic + gossip_context
        ├── peer.rs            # PeerId = SHAKE-256(pk)[..32]
        └── error.rs           # NetworkError
```

This is a clean, well-tested **primitive library**. The structure below is how it grows into a
protocol without throwing this away — `crypto` and `network` become the bottom crates of a
workspace.

## Target: a Cargo workspace of cohesive crates

A **modular monolith** (ADR-0005): one workspace, many crates, layered like
[`02-architecture/system-overview.md`](../02-architecture/system-overview.md). Crate boundaries
mirror architectural layers so subsystems are independently testable and (per the v4 endgame)
**exportable**.

```
huxplex/
├── Cargo.toml                      # [workspace]
├── crates/
│   ├── hux-crypto/                 # ← today's src/crypto, grown into the agility registry
│   │   ├── suite/                  # AlgoSuite registry, versioned dispatch
│   │   ├── sig/ kem/ hash/ vrf/    # trait + impls (ML-DSA, ML-KEM, SLH-DSA, LB-VRF…)
│   │   └── hd/                     # BIP32→ML-DSA derivation
│   ├── hux-types/                  # core domain types: Resource, Tx, Block, Hash, ids
│   ├── hux-state/                  # HRM state, JMT, nullifiers, StateStore trait (RocksDB)
│   ├── hux-vm/                     # HuxVM (Vm trait: wasmi→wasmtime), gas, host fns
│   ├── hux-scheduler/              # TCHAO / Block-STM parallel execution
│   ├── hux-consensus/              # Q-BFT, DAG mempool, leader election, slashing
│   ├── hux-network/                # ← today's src/network, grown into real libp2p/QUIC
│   ├── hux-economy/                # tokens (HUX/SVRGN/SNTNC), staking, fees, treasury
│   ├── hux-identity/               # did:huxplex, Work Visa, provenance, personhood
│   ├── hux-governance/             # Hive-Mind governance, constitution
│   ├── hux-zk/                     # zk-STARK integration (versioned proof systems)
│   ├── hux-node/                   # the binary: wires everything; config; RPC
│   ├── hux-rpc/                    # JSON-RPC / gRPC API
│   └── hux-sdk/                    # client SDK + wallet primitives
├── bin/                            # hux-node, hux-cli
├── docs/                           # ← this blueprint
├── specs/                          # formal specs (TLA+, etc.)
├── proptest-regressions/ fuzz/     # testing artifacts
└── scripts/ deploy/                # ops, devnet, reproducible-build tooling
```

## Dependency rule (enforced)

Crates depend **downward only** (no cycles): `node → {consensus, economy, identity, governance,
rpc} → {vm, scheduler, state, network} → {types} → {crypto}`. This is checked in CI (e.g.,
`cargo-deny`/custom lint) — a cycle is a build failure. It keeps the layering real and the
crypto/network crates exportable as standalone modules (v4 endgame).

## Why a workspace, not a framework or microservices

- **Not Substrate**: PQ-native + HRM + custom consensus fight the framework's classical/account
  assumptions (ADR-0005).
- **Not microservices**: a blockchain node is a tightly-coupled state machine; network boundaries
  inside it add failure modes without benefit. Crate boundaries give modularity without that cost.
- **Workspace**: independent testing/versioning, shared lints/CI, and clean export of modules.

## Conventions

- One crate per architectural concern; crate name `hux-<concern>`.
- Public API surface minimized; `pub(crate)` by default.
- Each crate has its own `README.md` (purpose + links to the relevant `/docs` section) and tests.
- Specs live in `specs/`, linked from the relevant doc.

## Migration from current → target (incremental)

1. Convert the crate to a workspace; move `src/crypto` → `crates/hux-crypto`, `src/network` →
   `crates/hux-network` (minimal churn — same code). ⬅️ **scheduled at G0** (decided 2026-09-22)
2. Grow `hux-crypto` into the suite registry (agility). ⬅️ **G1**
3. Add `hux-types`; then `hux-state`, `hux-vm`, `hux-consensus` per the Phase-1 plan. ⬅️ **G2+**
4. Layer economy/identity/governance in Phases 2–3.

No rewrite — the existing crypto/network code is the foundation, literally crate 0.

> **Timing decided 2026-09-22** ([ADR-0005](../adr/0005-build-strategy.md) amendment). Steps 1–2
> happen *before* the agility registry is written, because the registry is `hux-crypto`'s public
> surface and G0 item 4 already requires moving the same code. `hux-types` is deliberately **not**
> created at this gate — it has no members until G2. Step-by-step plan:
> [`18-implementation-plan/00-workspace-migration.md`](../18-implementation-plan/00-workspace-migration.md).

## Dependency policy for third-party cryptography

Recorded 2026-09-22 alongside [ADR-0019](../adr/0019-transport-authentication.md):

| Primitive | Implementation | Assurance | Notes |
|---|---|---|---|
| ML-DSA-44, ML-KEM-768 (protocol) | **`libcrux-*`** | **Formally verified** (hax + F*: panic freedom, correctness, secret independence over field arithmetic, NTT, serialization) | Pinned `0.0.x`; not all modules are verified |
| ML-DSA-44 (TLS transport) | **`aws-lc-rs`** via rustls | Audited, FIPS-validatable; **not** formally verified | C/assembly, BoringSSL lineage. **Non-FIPS build only** |
| SLH-DSA-128s | **`fips205`** | Pure Rust, no `unsafe`, all 12 parameter sets | |
| SLH-DSA-128s (CI oracle) | **`slh-dsa`** (RustCrypto) | Second vendor | Differential test only, never a runtime dependency |

**Rule:** where two implementations of one primitive exist in the tree, CI MUST run a
**differential test** between them. This is what makes [`cryptography.md`](../02-architecture/cryptography.md)
engineering rule 4 (multi-vendor) real rather than aspirational.

---

### Open Questions
- Single workspace vs. splitting exportable modules (causal clock, pruning, novelty) into their own repos early?
- Where do formal specs live relative to code (in-tree `specs/` vs separate)?
- Could a formally verified pure-Rust rustls `CryptoProvider` (libcrux-backed) eventually replace `aws-lc-rs`, removing the assurance asymmetry above? (Reversible — a provider swap is a config change, not a protocol change.)
</content>

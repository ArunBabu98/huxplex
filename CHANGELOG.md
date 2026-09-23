# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Pre-1.0 note: while the version is `0.x`, the API and protocol are unstable and may change in
> any release. Breaking changes will still be called out under **Changed**/**Removed**.

## [Unreleased]

### Added
- **The algorithm-suite registry (G1 · C1–C5).** Resolution is `(role, suite version) → primitive`
  ([ADR-0018](docs/adr/0018-signature-role-profiles.md), [crypto spec §1.1](docs/15-specifications/02-cryptography-spec.md)).
  `SigRole` carries the five roles with discriminants **asserted equal to `KeyPurpose` at compile
  time** — a runtime test can be deleted; a `const` assertion stops the crate compiling.
  `SuiteVersion`, `AlgoSuite` and an append-only table complete the descriptor. Unknown roles,
  versions and scheme identifiers all fail closed with distinct errors, and **zero is never a
  valid identifier**, so a zeroed field cannot be mistaken for v1. 16 conformance tests cover
  G1-T4 (green), and the structural halves of G1-T1 and G1-T6.
- **`Signer` and `Verifier` as separate traits.** Verifying is not signing: a light client or an
  archival verifier validating history under a retired suite must verify with no capacity to
  sign — exactly what ADR-0018 rule V5 requires. `traits::verifier()` returns a handle that
  cannot sign, making the absence of that capability a type-level fact rather than a review
  comment. (`Kem`/`Hasher` are deliberately deferred: each has one candidate implementation
  today, and a trait written against one implementation encodes its shape.)
- **`scripts/check-primitive-encapsulation.sh` (G1 · C4)** — fails if any Rust source names
  `libcrux_ml_dsa` or `libcrux_ml_kem` outside its single designated module. In CI and
  `verify-layer0.sh`, and **verified to fail on an injected violation**, not merely to pass on a
  clean tree. The agility thesis is that no layer above the registry knows its algorithm; one
  direct call falsifies it, and looks like ordinary working code in review.
- Repository engineering scaffolding: `LICENSE` (Apache-2.0), `NOTICE`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, this changelog, lint/toolchain config (`rustfmt.toml`, `clippy.toml`,
  `deny.toml`, `rust-toolchain.toml`), and CI (`.github/workflows/`).
- `docs/14-use-cases/` — use cases, applications & impacts catalogue.
- `docs/15-specifications/` — normative specification layer: data model & encoding, cryptography
  spec with context-string registry and test vectors, HRM state-transition spec, consensus spec,
  network wire protocol, and the frozen v1 scope contract.
- ADR-0010 (hash function), ADR-0011 (canonical serialization), ADR-0012 (network transport),
  ADR-0013 (`did:huxplex` method), ADR-0014 (validator key management & custody).
- `docs/brainstorming/01-layer0-technology-review-2026.md` — non-normative review of every
  Layer-0 choice against the September 2026 state of the art, with ten actions arising.
- New open problems: R-A9 (key-rotation cadence vs. the 190k-signature ML-DSA sign-leakage
  bound), R-A10 (side-channel/fault test methodology), R-B11 (erasure-coded block broadcast vs.
  GossipSub), R-B12 (QUIC anti-amplification vs. PQ handshake size).
- New gate tests: G1-T6 (signature role confusion is rejected), G5-T6 (handshake respects
  QUIC's 3× amplification limit).

- **ADR-0018** — signature role profiles: the suite descriptor is `(role, version)`, with
  `Transaction` / `QuorumCert` / `Identity` / `Governance` roles and seven versioning rules
  (roles added never removed, roles version independently, old pairs verifiable forever). All
  four roles resolve to the algorithms ADR-0002 already chose, so v1's wire bytes are unchanged.
- `DhtEntry` is now network-parameterized (`dht_entry_context(network)`), closing the last
  implementation site that hard-coded `huxplex-mainnet:`. New test
  `test_dht_entry_cross_network_replay_fails`.
- **ADR-0019** — transport authentication: **native ML-DSA-44 TLS certificates over QUIC**,
  mutual auth, ALPN `huxplex/{network}/1`, 1-RTT resumption without 0-RTT early data, client
  Initial padded against RFC 9000 §8.1. Enabled by `draft-ietf-tls-mldsa-06`
  (`SignatureScheme` 0x0904) and rustls 0.23.44 (2026-09-07). Rejected: bespoke handshake,
  libp2p-style certificate extension, and AuthKEM/KEMTLS (individual draft with no IETF standing;
  requires a long-term KEM key as identity; no non-repudiation).
- New gate test **G5-T7** — TLS `CertificateVerify` signatures and Huxplex protocol signatures
  must not be interchangeable.
- **BIP32 key purposes.** The derivation path gains a purpose level —
  `m/44'/931931'/{purpose}'/0'/{index}'` — with `KeyPurpose::{Transaction, QuorumCert, Identity,
  Governance, Transport}` matching the ADR-0018 roles. Purpose `1'` is **reserved** so a future
  aggregating quorum-certificate scheme can own a key tree without colliding with session keys;
  purpose `4'` is the TLS certificate key, held apart from the consensus key because a TLS stack
  needs the raw private key and that would defeat ADR-0014's remote-signer isolation. Purpose `0'`
  reproduces the original path byte-for-byte, so no existing key or test vector changed
  (`test_transaction_purpose_reproduces_the_original_path`,
  `test_key_purposes_are_domain_separated_at_the_same_index`). **108 tests pass** (was 105).

- **Cargo workspace.** The single `huxplex` crate is now `crates/hux-crypto` and
  `crates/hux-network`, with shared `[workspace.dependencies]` and `[workspace.lints]`
  (`unsafe_code = "forbid"`, verified live by an `unsafe {}` probe). `hux-network → hux-crypto`,
  never upward — enforced by `scripts/check-layering.sh` in CI, proven by a negative test.
- **Test suites extracted to `crates/*/tests/`**, split by concern: `ml_dsa`, `ml_kem`,
  `domain_separation`, `hd_derivation`, `peer_identity`, `topics`, `envelopes`. Both `lib.rs`
  files dropped from 3,874 / 687 lines to **36 / 10**. Integration tests reach only the public
  API, so an over-broad `pub` now shows up immediately. The four gated stub suites
  (`slh_dsa`, `lb_vrf`, `pq_ssle`, `zk_stark`) stay co-located inside their `#[cfg(test)]`
  modules — moving them to `tests/` would have required making `unimplemented!()` cryptography
  publicly reachable. 112 tests and all 84 `GATE:`-labelled ignores unchanged throughout (the
  tree now stands at 117 / 81 — three vacuously-gated size assertions were un-ignored afterwards,
  and the DHT field-framing fix added two).
- **Reproducible release builds (G0-T2)** — `scripts/check-reproducible.sh` stages two
  independent clean copies of the source, builds each at a canonical path, and compares artifact
  hashes. Runs in CI and via `verify-layer0.sh --full`. Recipe: pinned toolchain + `--locked` +
  `SOURCE_DATE_EPOCH` + `--remap-path-prefix` + **a canonical build path** — the last one is
  required because `--remap-path-prefix` takes the source path as its argument, so two build
  paths give two `RUSTFLAGS` strings, and `RUSTFLAGS` feeds rustc's `-C metadata` hash. Erasing
  the path from the output does not erase it from the flag that erased it.
- **`scripts/verify-layer0.sh`** — one-command verification: formatting, clippy, layering,
  `--locked` build, tests, docs, both walkthroughs, and a determinism re-run, with a PASS/FAIL
  summary. Exits non-zero if anything fails.
- **Self-verifying walkthroughs** — `cargo run -p hux-crypto --example crypto_walkthrough` and
  `cargo run -p hux-network --example network_walkthrough`. Each prints what it is doing and
  asserts it, so they are demonstrations and tests simultaneously. Both run in CI.
- `docs/19-verification/` — how a developer or contributor checks Layer 0 themselves: quick
  start, what each automated check proves, per-property manual procedures for crypto and
  networking, cross-architecture diffing, and an explicit list of what is **not** verifiable yet.
- CI runs an explicit architecture matrix (`x86_64`, `aarch64` Linux, `aarch64` macOS), the
  layering check, the architecture-portability guard, the reproducible-build job, and both
  walkthroughs. It first executed on 2026-09-23 via PR #9 — before that `ci.yml` triggered only on
  `push: [master]` and `pull_request`, and the Layer-0 branch had no PR, so the matrix had never
  run at all. **All three legs green, 115 · 0 · 81 each, with byte-identical derived values.**
- **G0-8 — the architecture-portability guard.** `scripts/check-arch-portability.sh` fails if any
  Rust source calls a backend path directly (`::avx2::`, `::neon::`, `::simd256::`, `::simd128::`,
  `::portable::`); `scripts/check-arch-negative.sh` injects `mlkem768::avx2::generate_key_pair`
  into a throwaway copy of the tree and asserts the compiler rejects it (`E0433`) on aarch64. One
  proves nobody wrote the call, the other proves the build would notice if they did — *a matrix
  that only ever passes does not prove it would catch the regression it exists for.*
- **`cargo test --doc`** in CI and the local harness. No doctests exist today; the run guards the
  case where someone adds one, since `--all-targets` excludes them.
- `docs/20-completion/` — a dated, evidence-backed audit of where the project actually stands
  against its own gates, plus the complete list of what remains to be completed and tested.
  Verdict as of 2026-09-23: **Layer 0 for v1 is roughly one third complete** — **G0 closed**,
  G1 and G5 not started.
- Four secret-hygiene tests and a `zeroize_now()` wipe API.
- `docs/18-implementation-plan/` — how Layer 0 actually gets built: workspace migration, G0/G1/G5
  task breakdowns with per-task acceptance criteria, sequencing rules, five named risks, and
  explicit stop conditions.

### Fixed
- **`DhtEntry` signatures were forgeable across the key/value boundary.** The signed payload was
  the bare concatenation `key || value`, which encodes no field boundary — so `("abc","XY")` and
  `("ab","cXY")` sign identically, and `verify()`, which rebuilds the payload from the record's
  own fields, accepted the re-split. An attacker who observed **any** signed record could
  republish the publisher's signature **under a different DHT key** while holding no key
  material; since the key decides routing, that is routing-table poisoning for free. This
  falsified G5-T5 ("a record signed for one key cannot be republished under another") and was the
  exact ambiguity G2-T2 forbids. The payload is now length-framed —
  `u64_be(len(key)) || key || u64_be(len(value)) || value` — normative in the
  [wire protocol](docs/15-specifications/05-network-wire-protocol.md) and
  [cryptography spec](docs/15-specifications/02-cryptography-spec.md), and pinned by
  `test_dht_entry_key_value_boundary_is_unambiguous` and
  `test_dht_entry_empty_key_and_empty_value_are_distinguishable`. **This changes the signed
  bytes** — free now, since no network exists, and expensive after one does. The three existing
  tamper tests never caught it because they mutate one field at a time, which changes the
  concatenation; this attack preserves it. Tamper-resistance and encoding-unambiguity are
  different properties, and only the second forbids two records sharing one signature.
- **`PrivateKey` leaked secret key material through `Debug`.** A derived `Debug` meant any
  `dbg!`, `{:?}`, `tracing::debug!` or panic message carrying a `Keypair` printed all 2,560
  bytes of the ML-DSA-44 signing key — and validator logs are routinely shipped off-host. The
  type now has a redacting `Debug`, private bytes behind a deliberately awkward
  `expose_secret()`, `ZeroizeOnDrop`, and **constant-time** equality (a byte-wise `==` on secret
  material short-circuits and is a timing oracle). Found during the September 2026 decision
  review, not by a test — which is why four tests now pin it.

### Changed
- **Four build decisions recorded 2026-09-22.** (1) The **workspace split happens at G0**, before
  the agility registry ([ADR-0005](docs/adr/0005-build-strategy.md) amendment). (2) SLH-DSA-128s
  is implemented on **`fips205`**, with RustCrypto **`slh-dsa`** as a CI differential oracle.
  (3) Session-key rotation cadence is **50,000 signatures or 7 days** — ≈4× margin under the
  190k sign-leakage bound ([ADR-0014](docs/adr/0014-validator-key-management.md) amendment,
  closing R-A9). (4) **`aws-lc-rs` accepted on five conditions** (non-FIPS only, pinned versions,
  C-toolchain pin, libcrux↔AWS-LC differential test, revisit if a verified pure-Rust provider
  appears) — recorded against principles 12 and 15, **not** principle 8: AWS-LC sits inside that
  principle's "vetted, audited cryptographic primitive code" carve-out, and the real tension is
  unverified crypto alongside formally verified `libcrux`.
- `docs/10-development/repository-structure.md` — migration steps dated to gates, plus a new
  **dependency policy for third-party cryptography** table and the rule that two implementations
  of one primitive require a CI differential test.
- G0 gains items 6–8: the workspace split, the `PrivateKey` `Debug` **secret-leak bug**, and the
  C-toolchain pin that G0-T2 now depends on.
- **Decisions closed 2026-09-22** in `docs/15-specifications/02-cryptography-spec.md`: hedged
  ML-DSA signing confirmed as normative (with a required production/test API split so KAT
  fixtures stay byte-exact); every context string network-parameterized; `peer_a`/`peer_b`
  directional derivation fixed as **initiator-first**. All three of that spec's standing open
  questions are now closed.
- `docs/15-specifications/05-network-wire-protocol.md` — **§2 rewritten** from a bespoke
  four-flight handshake to standard TLS 1.3 with native ML-DSA certificates (ADR-0019); new §5.1
  making it normative that **GossipSub is not fixed as the permanent block path**, and that no
  consensus object's validity may depend on how it was disseminated.
- `docs/adr/0012-network-transport.md` — amended: rules 4 (handshake) and 5 (no separate
  transport key) superseded by ADR-0019; rules 1–3 and 6 stand. The QUIC-vs-Noise sub-decision is
  closed — neither, because ML-DSA now enters TLS natively.
- The retired context `huxplex-{network}:tls:handshake:v1` is struck from the registry and will
  not be recycled; transport network separation moves to ALPN.
- `docs/02-architecture/cryptography.md` — added signature **role separation** (T-class /
  Q-class / identity / governance), a quorum-certificate aggregation candidate table
  (Chipmunk / Lemur+ / STARK-compressed, all stateful), and an implementation-attack section.
  Suite table marks ML-DSA-44 and LB-VRF as under review.
- `docs/02-architecture/networking.md` — split propagation by traffic shape (erasure-coded
  broadcast for blocks, GossipSub for mempool/intents/control), added the QUIC
  anti-amplification byte budget, and **answered** the standing open question about libp2p:
  upstream's post-quantum work covers confidentiality only, so the ML-DSA authentication
  transport is ours regardless.
- Dated review notes appended to ADR-0002, ADR-0012 and ADR-0014. **No accepted decision is
  changed** — the notes record evidence for the ADRs that will amend them (`0018`–`0020`).
- `docs/11-research/open-problems.md` — R-A1 reframed from "does PQ aggregation exist?" to a
  candidate comparison; R-A2 scoped per-role; R-A3 updated LB-VRF → iVRF.
- `docs/17-landscape-2026.md` §6 — what other chains shipped at L0 (BSC, Sui, StarkNet,
  Ethereum) and the move to erasure-coded block propagation.

### Notes
- No functional/code changes to the crypto or network primitives in this entry — documentation,
  decisions, and tooling only.

## [0.1.0] - 2026

### Added
- Post-quantum cryptographic primitives: ML-DSA-44 sign/verify, ML-KEM-768 KEM with HKDF session
  key derivation, BIP32 → ML-DSA seed derivation (`m/44'/931931'/0'/0'/{i}'`), and
  domain-separated context strings with cross-context replay tests.
- Networking primitive types: `PeerId` (SHAKE-256 of the ML-DSA-44 public key), signed
  `GossipMessage`, and signed Kademlia `DhtEntry`.

[Unreleased]: https://github.com/ArunBabu98/huxplex/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ArunBabu98/huxplex/releases/tag/v0.1.0

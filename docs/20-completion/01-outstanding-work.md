# 01 — Outstanding work: what must be completed and tested

> **As of 2026-09-23, at `d8e3c85`.** Derived from the audit in
> [`00-layer0-v1-completion-report.md`](00-layer0-v1-completion-report.md). This is the *complete*
> remaining path to "Layer 0 for v1 is done", in the order it should be done.
>
> **Phase A is complete — G0 is closed. Phase B is 5 of 11 — the registry (C1–C5) is in.**
> Start at **B2 (C6)**, then C9 → C10 → C7/C8 → B5. Two decisions in Phase C block G5 and should
> be taken in parallel, since neither depends on G1.
>
> Nothing here is new scope. Every item traces to
> [`16-action-plan.md`](../16-action-plan.md), [`18-implementation-plan/`](../18-implementation-plan/)
> or [`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md). Where this file
> adds something, it is marked **(new — found 2026-09-23)** and says why.

## The remaining path, in order

| # | Step | Why here | Blocked by |
|---|---|---|---|
| 1 | **C6** — no size literal outside the suite descriptor | finishes the registry's job; cheapest remaining task | — |
| 2 | **C9** — split signing into production (CSPRNG-only) and test-only (explicit randomness) | **two functions, not a flag** | — |
| 3 | **C10** — byte-exact KAT fixtures | signature KATs cannot be pinned without a deterministic entry point | **C9** |
| 4 | **C7 / C8** — SLH-DSA-128s on `fips205`, with the RustCrypto differential oracle | un-ignores 22 tests, and **completes G1-T1** by giving the registry a second implemented scheme | — |
| 5 | **B5** — hybrid X25519 + ML-KEM-768 | **G1-T5**, and G5 needs it | — |
| 6 | **G1-T2** — exhaustive ordered-pair sweep over the context registry | the role sweep is done; the context sweep is not | — |
| — | **G1 closes** | | |
| 7 | 🚧 **The identity ADR** — libp2p `PeerId` vs `SHAKE-256(spki)[..32]` | decides the shape of every G5 task | *a decision, not code* |
| 8 | 🚧 **The G2 ordering question** — Layer 0 is defined as G0+G1+G5, but G5's entry is G2 | Layer 0 as defined cannot close without a gate its definition omits | *a decision, not code* |
| 9 | **G2** — canonical encoding (if the answer to 8 is "yes, it's in scope") | also the only way G1-T6 fully closes | 8 |
| 10 | **N0b, N1–N11** — the transport | | 7, 9 |
| — | **G5 closes → Layer 0 complete** | | |

**Steps 7 and 8 are decisions, and both are on the critical path.** Neither depends on G1, so
both can be taken now, in parallel with steps 1–6. Leaving them until G5 starts is how a gate
stalls at its first task.

Two follow-ons that are not Layer 0 but are unblocked by it: **C10 unblocks
[issue #12](https://github.com/ArunBabu98/huxplex/issues/12)** (the digest-stack upgrade, which
needs KATs to prove no `PeerId` changes), and **G5 activates G0-7**, the C-toolchain pin, because
`aws-lc-rs` enters the tree there.

---

## Phase A — close G0 ✅ *complete, 2026-09-23*

> Everything G0 was written to fix was fixed; what was missing was proof. Both halves now exist.
> Kept here as the record of what was done and how it was verified.

### A1 · Make CI actually run ✅ *done*

**Finding.** `.github/workflows/ci.yml` triggered only on `push: branches: [master]` and
`pull_request`. All Layer-0 work lived on `layer0/g0-workspace-and-verification`, pushed but with
no PR — so CI had **never executed** against the workspace. The newest `CI` run of any kind was
2026-09-12, before the workspace existed. The matrix, the layering gate, the reproducible-build
job and cargo-deny were configuration, not results.

- [x] Opened [PR #9](https://github.com/ArunBabu98/huxplex/pull/9), merged as `7912117`. Fired
      `CI` and `Security` for the first time. **8/8 jobs green.**
- [x] Confirmed each leg's true architecture from its `uname -m` output, not the tick:
      `x86_64`, `aarch64`, `arm64`.
- [x] `Security` (cargo-deny) green against the workspace lockfile.

> Note for future long-running branches: the `push` trigger still covers only `master`. A PR is
> what fires CI. Widening it to `branches: [master, 'layer0/**']` would give branch feedback
> without one — not required, since the PR route works, but cheap.

### A2 · Write the G0-T1 negative case ✅ *done — G0-8*

**Why.** *A matrix that can only pass does not prove it would catch the regression it was built
for.* Both halves landed, because neither replaces the other:

- [x] [`scripts/check-arch-portability.sh`](../../scripts/check-arch-portability.sh) — static
      guard over `crates/*/src` and `crates/*/tests` for `::avx2::`, `::neon::`, `::simd256::`,
      `::simd128::`, `::portable::`. Whole-line comments exempt (so `kem.rs` can explain the rule
      by naming it); `Cargo.toml` exempt (target-gated features are the *correct* way to select a
      backend). Runs in the `static gates` CI job. **Verified to fail on an injected violation.**
- [x] [`scripts/check-arch-negative.sh`](../../scripts/check-arch-negative.sh) — stages a
      throwaway copy of the working tree, injects `mlkem768::avx2::generate_key_pair`, and asserts
      the compiler rejects it. Skips on x86-64, where the backend exists and rejecting it would
      prove nothing. Requires the failure to mention `avx2`/`E0433`, so an unrelated compile error
      cannot be misread as success. Result: `error[E0433]: failed to resolve: could not find
      'avx2' in 'mlkem768'`.

**Acceptance met:** matrix green on three architectures, **and** a deliberate architecture-specific
call fails on aarch64.

### A3 · Align the test invocations ✅ *done*

The acceptance wording said `--all-targets`; CI and `verify-layer0.sh` ran `--all-features`.
Neither combined them, and `--all-targets` excludes doctests.

- [x] One invocation everywhere: `cargo test --all-targets --all-features --locked`, plus an
      explicit `cargo test --doc --all-features --locked`. Applied in `ci.yml`,
      `scripts/verify-layer0.sh`, and the acceptance wording in
      [`18-implementation-plan/01-g0-repository-health.md`](../18-implementation-plan/01-g0-repository-health.md).
      *(There are no doctests today — the `--doc` run guards the case where someone adds one.)*

### A4 · Re-verify the already-green things in CI ✅ *done*

- [x] **G0-T2** reproducible build — green on the runner; `/tmp/hux-reproducible-build` works there.
- [x] **Layering** — green in the `static gates` job.
- [x] **Walkthroughs** — run on all three legs, and their output **diffed across architectures**.
      Only the architecture name each program prints differs; every derived value (HD purpose
      seeds, `PeerId`s, shared secrets) is byte-identical. This is the cross-architecture check
      [`19-verification/README.md`](../19-verification/README.md) asks contributors to perform.

### A5 · Correct the stale figures in the documentation ✅ *done as part of this audit*

The suite is **115 passed / 0 failed / 81 ignored** (hux-crypto 76 + 81 ignored, hux-network 39),
not `112 / 0 / 84`. Commit `63ad3d5` un-ignored three size-constant assertions. Corrected in:

- [x] `docs/16-action-plan.md` — ground-truth table, G0 item 8, G0-T1 and G0-T3 rows
- [x] `docs/18-implementation-plan/00-workspace-migration.md` — W1, W2, acceptance
- [x] `docs/18-implementation-plan/01-g0-repository-health.md` — G0-T3 exit row
- [x] `docs/19-verification/README.md` — the check table
- [x] `CHANGELOG.md` — the workspace-split entry

> Keep this honest going forward: the counts appear in five files, so a change to the ignore set
> means five edits. Consider having `verify-layer0.sh` print the counts and referencing *it* from
> the docs rather than restating the numbers.

### G0 exit checklist — all met

| | Criterion | Status |
|---|---|---|
| ✅ | Workspace migration complete | done |
| ✅ | `PrivateKey` no longer prints secrets | done |
| ✅ | G0-T2 — automated two-build comparison | done, locally and on a runner |
| ✅ | G0-T3 — every ignored test carries a `GATE:` label | done, 81/81 |
| ✅ | **G0-T1 — green on both architectures in CI** | three architectures, byte-identical derived values |
| ✅ | **G0-T1 negative case** | G0-8, both halves |
| ⏸️ | G0-7 — C-toolchain pin | deferred to G5 by design; `aws-lc-rs` is not in the tree |

**G0 is closed.**

---

## Phase B — G1 · crypto core and the agility registry · *the gate with a closing window*

> **Entry:** G0 closed. **Unblocks:** G2, and therefore everything.
> Full task breakdown: [`18-implementation-plan/02-g1-crypto-core.md`](../18-implementation-plan/02-g1-crypto-core.md).
> **5 of 11 tasks done** — the registry (C1–C5) landed 2026-09-23; C6–C11 remain.
>
> **Order matters: the registry comes before the primitives.** A primitive written first will be
> called directly from somewhere, and that call site will survive. That ordering held, and it is
> why C4 is enforceable at all.

### B1 · The registry (C1–C5) ✅ *done 2026-09-23*

[PR #17](https://github.com/ArunBabu98/huxplex/pull/17), two commits — the mechanical vendor-crate
confinement first, the abstraction second.

- [x] **C1** `SigRole { Transaction=0, QuorumCert=1, Identity=2, Governance=3, Transport=4 }`,
      `#[non_exhaustive]`. Discriminants asserted equal to `KeyPurpose` in a **`const` block**, not
      a test: a test can be deleted, a const assertion stops the crate compiling. If the two ever
      diverge, a key derived for one purpose becomes usable under another role — silently.
- [x] **C2** `AlgoSuite { role, version }`; resolution is `(role, version) → primitive`. Both axes
      present, neither inferred from the object's type at verification time (rule V1).
- [x] **C3** Append-only table. Unknown role, unknown version and unknown scheme each fail closed
      with a **distinct** error, and **zero is never a valid identifier** for any of the three —
      so a zeroed or default-constructed descriptor field cannot be read as v1.
- [x] **C4** `Verifier` / `Signer` / `SignatureScheme` traits, plus
      [`check-primitive-encapsulation.sh`](../../scripts/check-primitive-encapsulation.sh) in CI
      and `verify-layer0.sh`. **Verified to fail on an injected violation**, not merely to pass on
      a clean tree.
- [x] **C5** Suite-v1 rows matching [crypto spec §1.1](../15-specifications/02-cryptography-spec.md)
      row for row.

**Conformance:** `crates/hux-crypto/tests/suite_registry.rs`, 16 tests.

> **Three decisions recorded, because each could have gone the other way:**
> **(1)** `Signer` and `Verifier` are separate traits — a verify-only handle cannot sign, which is
> what rule V5 needs from a light client or an archival verifier.
> **(2)** `Kem` and `Hasher` traits are **deferred** against the plan's literal wording: each has
> one candidate implementation today, and a trait written against one implementation encodes its
> shape. The encapsulation check already delivers what C4 asks for.
> **(3)** "Registered but unimplemented" is its own error — `SchemeUnimplemented` ≠ `UnknownPair`,
> and neither ever falls back to a working scheme.

> **Keep the registry dumb** — a lookup table plus a dispatch, not a policy engine. Where the table
> *lives on-chain* is a G3 question. It was built that way and should stay that way.

### B2 · Remove the hard-coded sizes (C6) ⬅️ **next**

Half-started by the registry: `traits::SchemeSizes` already exposes sizes *from the resolved
scheme*, and `c6_sizes_are_available_from_the_resolved_scheme` asserts a caller can read them
without naming a literal. What remains is that the literals still live in `sig/ml_dsa.rs`, and
nothing has yet proved a *second* scheme can be registered without touching one.

- [ ] **C6** No size literal outside the suite descriptor. Remaining sites: the `PK_LEN` /
      `SK_LEN` / `SIG_LEN` / `SEED_LEN` constants in
      [`sig/ml_dsa.rs`](../../crates/hux-crypto/src/sig/ml_dsa.rs) — legitimate *there*, as the
      scheme's own definition, but every consumer must read them via `SchemeSizes`.
      **Test:** register a dummy second scheme with different sizes and confirm nothing outside
      its own module needed editing.

> ⚠️ The task most likely to be done shallowly. **R1** in
> [`04-sequencing-and-risks.md`](../18-implementation-plan/04-sequencing-and-risks.md): if
> registering a dummy V2 requires editing a size literal, C6 is not finished. The dummy-scheme
> test is the only thing that catches a shallow job — an assertion that the *current* sizes are
> readable does not.

### B3 · SLH-DSA-128s (C7–C8)

- [ ] **C7** Implement on **`fips205`** (pure Rust, no `unsafe`). Sizes 32 / 64 / 7,856.
      **Test:** the **22** `slh_dsa_128s_tests` pass with `#[ignore]` removed.
      *(The plan says 24; the count is 22 as of `63ad3d5` — three were un-ignored, of which two
      were SLH-DSA size assertions that already pass.)*
- [ ] **C8** CI differential test against RustCrypto `slh-dsa` — **dev-dependency only**.
      **Test:** same seed ⇒ identical key and signature bytes; a deliberate mutation fails.

### B4 · Secret hygiene and KATs (C9–C11)

- [ ] **C9** Split signing into two functions: production signing sources randomness from the
      system CSPRNG and **cannot** accept a caller-supplied value; a separate test-only entry point
      takes explicit randomness. Today `Keypair::sign` calls `rand::rng()` unconditionally and has
      no deterministic path.
      > **Two functions, not one with a flag.** A `deterministic: bool` is a downgrade switch
      > waiting for a misconfiguration, and deterministic lattice signing plus fault injection is a
      > demonstrated key-recovery path.
      > **C9 blocks C10:** without it, signature KATs cannot be pinned at all.
- [ ] **C10** Byte-exact KAT fixtures for ML-DSA-44, ML-KEM-768, SLH-DSA-128s and the hash domains
      ([ADR-0010](../adr/0010-hash-function-domains.md)); signature fixtures pin the 32-byte
      randomness. **None exist in the tree today** — there is no fixtures directory and no
      committed vectors.
- [ ] **C11** `libcrux` ↔ `aws-lc-rs` ML-DSA differential test
      ([ADR-0019](../adr/0019-transport-authentication.md) condition 4).

### B5 · Hybrid key agreement

- [ ] Hybrid X25519 + ML-KEM-768, needed by G5. Does not exist; `kem.rs` is ML-KEM only.

### G1 gate tests — current state

| ID | Property | Today |
|---|---|---|
| **G1-T1** | Algorithm rotation without state migration — register a second scheme, flip **one role's** default; old objects still verify, other roles untouched, zero state-structure changes | 🟡 **half** — descriptor half proven; rotation needs a second *implemented* scheme → **C7** |
| **G1-T2** | Cross-context replay fails — **exhaustive over every ordered pair** of registry contexts, including `dht:entry` | 🟡 three good tests exist; the exhaustive *context* sweep is still to do (the *role* sweep is done) |
| **G1-T3** | KAT byte-exactness on **both** architectures | ❌ blocked on **C9 → C10** |
| **G1-T4** | Unknown algorithm ID — and unknown **role** — rejected, never ignored | 🟢 **green** — five tests |
| **G1-T5** | Hybrid retains PQ security if the classical half is broken — force X25519 output to a constant, session keys still differ | ❌ no hybrid → **B5** |
| **G1-T6** | Role confusion rejected — every ordered pair of roles | 🟡 **structural half** — roles proven pairwise distinct; binding a *signature* to its role needs the descriptor on the wire → **G2** |

> **G1-T6 cannot fully close inside G1.** Proving a signature is bound to its role requires the
> descriptor to be *carried on the signed object*, which is G2's canonical encoding. G1 can prove
> the roles are distinct and that a mismatch is refused; it cannot prove the binding until there
> is an encoding to bind it in. Worth deciding explicitly whether G1 exits with T6 at its
> structural half, or whether the gate waits on G2 — see the ordering question in Phase C.

**G1 exit:** ~~registry is the only path to a primitive~~ ✅ (enforced mechanically, not by
convention); SLH-DSA green and un-ignored; KATs committed and green on both architectures;
**G1-T1 and G1-T6 demonstrated in CI**; no size literal outside the suite descriptor.

> **Re-check before starting:** `libcrux` and `fips205` releases, per the *keeping this plan honest*
> rule — two findings in the September 2026 review were overturned within weeks.

---

## Phase C — G5 · transport · *blocked on two decisions, not on code*

> **Entry:** G2 (canonical encoding) — which is outside Layer 0 and outside this file. G5 is listed
> here because Layer 0 is not complete without it, not because it can start next.
> Full breakdown: [`18-implementation-plan/03-g5-transport.md`](../18-implementation-plan/03-g5-transport.md).
>
> Today: **five files, 209 lines**, with no `libp2p`, `quinn`, `rustls`, `aws-lc-rs` or `tokio`
> anywhere in `Cargo.lock`.

### C0 · The N0 spike ✅ *closed 2026-09-23*

- [x] **N0** Answered against vendored sources, not documentation. **Outcome 3: quinn must be
      driven behind libp2p's `Transport` trait.** Finding recorded in
      [`03-g5-transport.md`](../18-implementation-plan/03-g5-transport.md).
      - `libp2p_quic::Config` keeps its TLS configs in private fields with no setter. No injection
        point.
      - The "small `libp2p-tls` fork" fails for an unanticipated reason: `make_*_config` take
        `&libp2p_identity::Keypair`, and `KeyType` is `{Ed25519, RSA, Secp256k1, Ecdsa}` — **an
        ML-DSA key cannot travel through that signature.** The fork cascades into
        `libp2p-identity`.
      - ✅ **ADR-0019's load-bearing assumption confirmed at the source:** rustls 0.23.45 defines
        `ML_DSA_44 => 0x0904`, matching the ADR exactly, wired through the `aws-lc-rs` provider
        libp2p-tls already uses. **The stop condition was not reached** — no certificate-extension
        bridge is needed.

### C0b · 🚧 **BLOCKER — the identity ADR** *(write before N1)*

The spike surfaced something outside its original framing and more consequential than the crate
choice. `libp2p-core` hands the swarm `(PeerId, StreamMuxerBox)` typed on
**`libp2p_identity::PeerId`** — a multihash over a protobuf Ed25519-class key. Huxplex's is
`SHAKE-256(ML-DSA-44 pk)[..32]` (wire spec §4, `peer.rs`, asserted by **G5-T2**). GossipSub and
Kademlia are generic over libp2p's.

- [ ] **Decide and record an ADR.** Three options, with consequences:

| Option | Consequence |
|---|---|
| **(a)** adopt libp2p's `PeerId` | keeps GossipSub + Kademlia unmodified; contradicts ADR-0019, the wire spec, `peer.rs` and G5-T2, and makes identity depend on Ed25519 in a PQ chain — self-defeating |
| **(b)** Huxplex `PeerId` end-to-end, own gossip + DHT | fully consistent with ADR-0019; abandons libp2p's battle-tested GossipSub scoring that **G5-T3** leans on; much the largest scope |
| **(c)** dual identity with a proven binding — libp2p `PeerId` for the swarm, Huxplex `PeerId` at the application layer, bound by the ML-DSA certificate and verified at `Identified` | pragmatic; the binding becomes a security-critical invariant needing its own gate test |

> **(c)** looks likeliest, but it is an ADR, not a choice to make inside an implementation PR.
> **Nothing else in G5 should start until this is settled** — it decides the shape of N1–N11.

### C0c · New from the spike

- [ ] **N0b** Drive `quinn` 0.11 behind libp2p's `Transport` trait; add `quinn` and
      `rustls` 0.23.45 (`aws-lc-rs`, non-FIPS) as direct dependencies. `libp2p-quic` is not the
      transport.
      > The upside of outcome 3: N1–N5 become *implementation* rather than integration, and every
      > ADR-0019 requirement — ALPN, mutual auth, custom verifier, 0-RTT off, Initial padding —
      > becomes directly expressible on a config Huxplex constructs. **G5-T6**'s ≈130-byte
      > amplification margin is far easier to assert that way.
- [ ] **Amend ADR-0019** to record outcome 3 and why outcome 2 failed (libp2p-identity, not
      libp2p-tls).

### C1 · Certificates and authentication (N1–N5)

- [ ] **N1** Self-signed X.509: SPKI = ML-DSA-44 public key, ML-DSA-44 self-signature,
      `SignatureScheme` `mldsa44` = **0x0904**; key is the `Transport` purpose
      `m/44'/931931'/4'/0'/{i}'` — already derivable today.
- [ ] **N2** Custom `ServerCertVerifier` / `ClientCertVerifier`: verify self-signature →
      `SHAKE-256(spki)[..32]` → compare to expected `PeerId` → abort on mismatch.
      **No CA, no trust store, no name checking, no revocation.**
- [ ] **N3** **Mutual** authentication; an unauthenticated peer never reaches an application stream.
- [ ] **N4** ALPN `huxplex/{network}/1`; QUIC refuses cross-network dials before Huxplex code runs.
- [ ] **N5** Pin `rustls` ≥ 0.23.44, `aws-lc-rs` provider, **non-FIPS**; add `aws-lc-rs` /
      `aws-lc-sys` to `deny.toml` review — a deliberate principle-8 exception.
- [ ] **G0-7 lands here:** pin the C toolchain (a container image with a fixed `cc`), referenced
      from CI *and* the reproducible-build documentation.
      **Acceptance:** `scripts/check-reproducible.sh` still passes with `aws-lc-rs` in the tree.
      > **Stop condition (R4).** If a pinned container cannot produce byte-identical artifacts, the
      > decision returns to ADR-0019's addendum. Do **not** weaken the reproducibility requirement.

### C2 · Transport behaviour (N6–N8)

- [ ] **N6** Pad the client Initial so the responder's ≈7,970 B first flight stays inside RFC 9000
      §8.1's 3× budget. **~130 bytes of headroom — see R3.**
- [ ] **N7** 1-RTT resumption **on**, 0-RTT early data **off**. **Test:** early data is refused.
- [ ] **N8** Peer lifecycle state machine: `Disconnected → Connecting → Handshaking → Identified →
      Active`, with backoff and banning. **Test:** a peer's messages are not processed before
      `Identified`.

### C3 · Discovery and messaging (N9–N11)

- [ ] **N9** Kademlia DHT over the existing signed `DhtEntry`; DHT key = publisher's `PeerId`;
      verify before routing.
- [ ] **N10** GossipSub for mempool / intents / control, reusing the existing signed envelopes;
      message-ID dedup, **no re-signing on forward**.
- [ ] **N11** Peer scoring plus penalties for invalid signatures, cross-context replay attempts and
      spam.

> **Do not** build erasure-coded block broadcast at this gate. v1 may carry blocks over GossipSub;
> the guardrail is only that nothing above the transport may *assume* it (**R5**).

### G5 gate tests — all to be written

| ID | Property | Today |
|---|---|---|
| **G5-T1** | Authenticated handshake, no downgrade: classical-only rejected; MITM certificate fails the `PeerId` check; no client certificate ⇒ no application stream; cross-network ALPN refused by QUIC | ❌ |
| **G5-T2** | `PeerId` is bound to the key | 🟡 struct-level; extend to a live connection |
| **G5-T3** | Gossip amplification bounded under a flood of malformed and unsigned messages; offender scored down and disconnected | ❌ |
| **G5-T4** | Propagation under 20% loss and a healed partition; all honest nodes converge | ❌ |
| **G5-T5** | Signed DHT entries reject forgery and replay, including cross-network | 🟡 struct-level; extend to the live DHT |
| **G5-T6** | Responder's first flight never exceeds 3× bytes received, **measured on the wire**, re-asserted whenever the suite changes | ❌ |
| **G5-T7** | A TLS `CertificateVerify` signature must not verify as any Huxplex protocol signature, and no `huxplex-…:v1` signature may be accepted by the TLS layer — for every registry context | ❌ |

> **G5-T6 and G5-T7 are the two most likely to be skipped**, and the two that guard the properties
> nothing else does.

**G5 exit:** 5 nodes discover each other, mutually authenticate over QUIC with ML-DSA certificates,
gossip and sustain sessions; abuse tests green; G5-T6 and G5-T7 green; the N0 finding recorded.

**When Phases A, B and C are all closed, Layer 0 is complete** — and G2, canonical encoding, is the
next gate.

---

## Phase D — beyond Layer 0, toward v1 · *for orientation only*

Not Layer-0 work, and not to be started early. Listed so the distance is visible:

| Gate | Deliverable | State |
|---|---|---|
| **G2** | Canonical `Codec` (postcard) + canonical decode; `Resource`, `Transaction`, `Block`, `Vote`, `GossipMessage`, `DhtEntry` | no code |
| **G3** | HRM single-shard state, CommitmentSet + NullifierSet over a JMT, RocksDB, `TxWeight` | no code |
| **G4a** | Deterministic gas-metered execution (TCHAO deferred to v1.x) | no code |
| **G6** | Q-BFT three-phase commit, DAG mempool, signer guard, slashing | no code |
| **G7 ★** | 3–5 node devnet, 24-hour soak, research report — **the v1 exit gate** | no code |

The v1 Definition of Done stands at **3 of 21** boxes
([`06-v1-scope.md`](../15-specifications/06-v1-scope.md) §2). Its exit criteria — a 24-hour soak
without a safety fault, a published research report, a security self-review — are not approachable
from here.

> **Standing rule:** if it is not in §2 of the v1 scope contract, it is out of v1 by definition, and
> moving it in requires an RFC. That rule is the defence against risk #1, *scope collapse*.

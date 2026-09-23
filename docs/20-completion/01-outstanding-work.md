# 01 — Outstanding work: what must be completed and tested

> **As of 2026-09-23, commit `63ad3d5`.** Derived from the audit in
> [`00-layer0-v1-completion-report.md`](00-layer0-v1-completion-report.md). This is the *complete*
> remaining path to "Layer 0 for v1 is done", in the order it should be done.
>
> Nothing here is new scope. Every item traces to
> [`16-action-plan.md`](../16-action-plan.md), [`18-implementation-plan/`](../18-implementation-plan/)
> or [`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md). Where this file
> adds something, it is marked **(new — found 2026-09-23)** and says why.

---

## Phase A — close G0 · *days, not weeks*

> Everything G0 was written to fix is fixed. What is missing is proof. These are the two items
> standing between the repository and a closed gate, plus the doc corrections that fell out of the
> audit.

### A1 · Make CI actually run **(new — found 2026-09-23)** 🔴 blocking

**Finding.** `.github/workflows/ci.yml` triggers only on `push: branches: [master]` and
`pull_request`. All Layer-0 work lives on `layer0/g0-workspace-and-verification`, which is pushed
but has no PR — so CI has **never executed** against the workspace. `gh run list --branch
layer0/g0-workspace-and-verification` is empty; the newest `CI` run of any kind is 2026-09-12,
before the workspace existed.

Until this is fixed, the architecture matrix, the layering gate, the reproducible-build job and
cargo-deny are configuration, not results — and standing rule #1 of the action plan says a gate is
done when its tests pass *in CI*.

**Do:**

- [ ] Open a pull request for `layer0/g0-workspace-and-verification` → `master`. This alone fires
      both `CI` and `Security` for the first time.
- [ ] *Or, in addition:* widen the `push` trigger to cover the working branches, e.g.
      `branches: [master, 'layer0/**']`, so long-running Layer-0 branches get feedback without a PR.
- [ ] Confirm all three matrix legs report their true architecture — the workflow already runs
      `uname -m && rustc -vV`; read the output rather than the green tick.
- [ ] Confirm the `Security` (cargo-deny) job passes against the **workspace** lockfile. It passes
      locally today, but CI has only ever checked the pre-workspace tree.

**Acceptance:** a CI run exists for the branch, and every job on it is green on
`ubuntu-latest` (x86_64), `ubuntu-24.04-arm` (aarch64) and `macos-latest` (aarch64-darwin).

### A2 · Write the G0-T1 negative case 🔴 blocking

**Why.** *A matrix that can only pass does not prove it would catch the regression it was built
for.* The original G0 break was an unconditional `mlkem768::avx2::*` call — x86-64 only. Nothing
currently prevents a recurrence except a CI job that has never failed.

**Do:**

- [ ] Add a deliberate-regression check: a job step (or a short script under `scripts/`) that
      introduces an `avx2::`-style architecture-specific call and asserts the **aarch64** leg
      fails to compile, then restores the tree. Keep it self-contained — a fixture crate or a
      `sed`-and-revert step, not a committed broken file.
- [ ] Alternatively, or additionally, enforce the standing rule statically: a CI grep forbidding
      `::avx2::`, `::neon::`, `::simd256::` and `::simd128::` outside a manifest, which is cheaper
      to maintain and fails with a clear message. Prefer this *as well as* the negative case, not
      instead of it — the grep proves nobody wrote the call; the negative case proves the matrix
      would notice if they did.

**Acceptance (G0-T1, full):** `cargo test --all-targets --all-features --locked` green on both
architectures in CI, **and** a deliberate architecture-specific call fails the aarch64 job.

### A3 · Align the test invocations with the stated acceptance criterion **(new — found 2026-09-23)**

The G0-T1 acceptance wording is `cargo test --all-targets --locked`. CI and
`scripts/verify-layer0.sh` both run `cargo test --all-features --locked`. Neither combines the
two, and `--all-targets` notably *excludes* doctests.

- [ ] Settle on one invocation — `cargo test --all-targets --all-features --locked`, plus a
      separate `cargo test --doc` if doctests are wanted — and use it identically in
      `verify-layer0.sh`, `ci.yml`, and the acceptance wording in
      [`18-implementation-plan/01-g0-repository-health.md`](../18-implementation-plan/01-g0-repository-health.md).

### A4 · Re-verify the things that are already green, in CI

These pass locally and are expected to pass remotely; they have simply never been confirmed off
this machine.

- [ ] **G0-T2** reproducible build — the `reproducible` job runs `scripts/check-reproducible.sh`.
      Confirm the canonical path `/tmp/hux-reproducible-build` works on the GitHub runner.
- [ ] **Layering** — `scripts/check-layering.sh` in the `layering` job.
- [ ] **Walkthroughs** — both `--example` runs, on all three matrix legs. Compare the printed key,
      `PeerId` and shared-secret values **across architectures**; they are seed-deterministic, so
      any difference is a fork-class bug.

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

### G0 exit checklist

| | Criterion | Status |
|---|---|---|
| ✅ | Workspace migration complete | done |
| ✅ | `PrivateKey` no longer prints secrets | done |
| ✅ | G0-T2 — automated two-build comparison | done, re-verified 2026-09-23 |
| ✅ | G0-T3 — every ignored test carries a `GATE:` label | done, 81/81 |
| ⬜ | **G0-T1 — green on both architectures in CI** | blocked on A1 |
| ⬜ | **G0-T1 negative case** | A2 |
| ⏸️ | G0-7 — C-toolchain pin | correctly deferred to G5; `aws-lc-rs` is not in the tree |

---

## Phase B — G1 · crypto core and the agility registry · *the gate with a closing window*

> **Entry:** G0 closed. **Unblocks:** G2, and therefore everything.
> Full task breakdown: [`18-implementation-plan/02-g1-crypto-core.md`](../18-implementation-plan/02-g1-crypto-core.md).
> Nothing below has been started. `crates/hux-crypto/src/` still holds the flat pre-G1 module set.
>
> **Order matters: the registry comes before the primitives.** A primitive written first will be
> called directly from somewhere, and that call site will survive.

### B1 · The registry (C1–C5)

- [ ] **C1** `SigRole { Transaction=0, QuorumCert=1, Identity=2, Governance=3, Transport=4 }`,
      `#[non_exhaustive]`, discriminants matching `KeyPurpose` — which already exists in
      [`bip32.rs`](../../crates/hux-crypto/src/bip32.rs) with exactly these values.
      **Test:** a compile-time assertion that `SigRole::X as u32 == KeyPurpose::X.index()` for
      every variant, so the two can never drift.
- [ ] **C2** `AlgoSuite` versioned descriptor; resolution is `(role, version) → primitive set`.
- [ ] **C3** Registry is **append-only**; an unknown role or version fails closed with a distinct
      error, never a default.
- [ ] **C4** Traits `Signer` / `Verifier` / `Kem` / `Hasher` as the *only* path to a primitive.
      **Test:** a CI grep proving no `libcrux_ml_dsa::` or `libcrux_ml_kem::` path exists outside
      `sig/ml_dsa.rs` and `kem/ml_kem.rs`. Today both are called directly from `signature.rs`,
      `publickey.rs` and `kem.rs`.
- [ ] **C5** Suite-v1 rows per [ADR-0018](../adr/0018-signature-role-profiles.md) §2 and
      [crypto spec §1.1](../15-specifications/02-cryptography-spec.md).

> **Keep the registry dumb** — a lookup table plus a dispatch, not a policy engine. Where the table
> *lives on-chain* is a G3 question.

### B2 · Remove the hard-coded sizes (C6)

- [ ] **C6** Sizes come from the suite descriptor. Current sites, confirmed by this audit:
      `publickey.rs` — `[u8; 1312]`, `[u8; 2420]`; `signature.rs` — `[u8; 2560]`.

> ⚠️ The task most likely to be done shallowly. **R1** in
> [`04-sequencing-and-risks.md`](../18-implementation-plan/04-sequencing-and-risks.md): if
> registering a dummy V2 requires editing a size literal, C6 is not finished.

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

### G1 gate tests — all to be written

| ID | Property | Today |
|---|---|---|
| **G1-T1** | Algorithm rotation without state migration — register a second scheme, flip **one role's** default; old objects still verify, other roles untouched, zero state-structure changes | ❌ nothing to rotate |
| **G1-T2** | Cross-context replay fails — **exhaustive over every ordered pair** of registry contexts, including `dht:entry` | 🟡 three good tests exist; extend to the full sweep once a registry defines the set |
| **G1-T3** | KAT byte-exactness on **both** architectures | ❌ blocked on C9 + C10 |
| **G1-T4** | Unknown algorithm ID — and unknown **role** — rejected, never ignored | ❌ unrepresentable today: the enum has one variant |
| **G1-T5** | Hybrid retains PQ security if the classical half is broken — force X25519 output to a constant, session keys still differ | ❌ no hybrid |
| **G1-T6** | Role confusion rejected — every ordered pair of roles | ❌ no roles in the verifier |

**G1 exit:** registry is the only path to a primitive (enforced mechanically, not by convention);
SLH-DSA green and un-ignored; KATs committed and green on both architectures; **G1-T1 and G1-T6
demonstrated in CI**; no size literal outside the suite descriptor.

> **Re-check before starting:** `libcrux` and `fips205` releases, per the *keeping this plan honest*
> rule — two findings in the September 2026 review were overturned within weeks.

---

## Phase C — G5 · transport · *runs in parallel, but only after G2*

> **Entry:** G2 (canonical encoding) — which is outside Layer 0 and outside this file. G5 is listed
> here because Layer 0 is not complete without it, not because it can start next.
> Full breakdown: [`18-implementation-plan/03-g5-transport.md`](../18-implementation-plan/03-g5-transport.md).
>
> Today: **five files, 183 lines**, with no `libp2p`, `quinn`, `rustls`, `aws-lc-rs` or `tokio`
> anywhere in `Cargo.lock`.

### C0 · Run the N0 spike — *before any certificate code* 🔴

- [ ] **N0** Does `libp2p-quic` accept a custom rustls configuration carrying an ML-DSA-44
      certificate and a custom verifier — or must quinn be driven behind libp2p's `Transport`
      trait, or `libp2p-tls` forked? Timebox it.
      **Acceptance:** a written finding appended to `03-g5-transport.md`, plus an ADR amendment if
      the integration path changed.
      > Writing certificate code against an integration that turns out to be impossible is the most
      > expensive mistake available in this gate (**R2**).

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

# 01 — Outstanding work: what must be completed and tested

> **As of 2026-10-08, at the head of `layer0/g1-remaining` — Layer 0 complete.** Originally written 2026-09-23 from
> the audit in [`00-layer0-v1-completion-report.md`](00-layer0-v1-completion-report.md) as the
> *complete* remaining path to "Layer 0 for v1 is done". **That path has now been walked end to
> end.** Every task below is implemented and every Layer-0 gate test passes locally; what is left
> is the one thing standing rule #1 requires — **the gates going green in CI**.
>
> Nothing here was new scope. Every item traces to
> [`16-action-plan.md`](../16-action-plan.md), [`18-implementation-plan/`](../18-implementation-plan/)
> or [`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md). Where the work
> *found* something the plan did not anticipate, it is marked **(found 2026-10-07)**.

## The path, as walked

| # | Step | Commit | Result |
|---|---|---|---|
| 1 | **C6** — no size literal outside the suite descriptor | `3fd4379` | ✅ a dummy scheme with foreign sizes drives keygen and signing unchanged |
| 2 | **C9** — production signing CSPRNG-only; test-only explicit randomness | `abb08eb` | ✅ `SigningRandomness` constructible only inside `hux-crypto`; `compile_fail` doctests prove it |
| 3 | **C10** — ML-DSA-44 and ML-KEM-768 KATs | `2f022a9` | ✅ fixtures in `tests/kat/`, reproduced by RustCrypto `ml-dsa` / `ml-kem` |
| 4 | **C7 / C8** — SLH-DSA-SHAKE-128s on `fips205`, RustCrypto differential | `b3a3dc6` | ✅ 22 tests un-ignored; **G1-T1 complete** |
| 5 | **B5** — hybrid X25519 + ML-KEM-768, and the `Kem` trait | `453771d` | ✅ **G1-T5 green**; X25519 matches RFC 7748 §6.1 |
| 6 | **G1-T2** — exhaustive context sweep | `25d89f4` | ✅ the §5 registry as code; 650 ordered pairs |
| 6′ | **C11** — libcrux ↔ aws-lc-rs ML-DSA differential | `f1449df` | ✅ also the crypto half of G5-T7 |
| 7 | **G2a** — canonical `Codec`; `GossipMessage`, `DhtEntry` carry the descriptor | `be2ee69` | ✅ G2-T1/T2/T4 green; **G1-T6 complete**; wire v1 frozen |
| 8 | **N0b, N1–N11** — the transport; **G0-7** | `6983ca2` | ✅ G5-T1…T7 green; 5-node exit test passes |
| 9 | Pre-close review: R1–R11 fixed | `ba1e5fb`, `7433a79` | ✅ see *Review* below |
| — | **CI green on the three-architecture matrix → G1, G2a, G5 close → Layer 0 complete** | run [37746269760](https://github.com/ArunBabu98/huxplex/actions/runs/37746269760) | ✅ **2026-10-08** — third run; the first two failed on R10 and R11 |

✅ **[Issue #12](https://github.com/ArunBabu98/huxplex/issues/12) is closed** — the digest-stack
upgrade landed 2026-09-30, proven byte-neutral by the hash KATs.

## Open items

None blocks Layer 0. Each is a decision for its owner, recorded so it is not rediscovered.

1. **(found 2026-10-07) DHT records: role vs. key purpose.** `DhtEntry` is accepted only when
   keyed by its signer's `PeerId` — that is what stops a peer squatting another's key (G5-T5). A
   node's `PeerId` comes from its **`Transport`**-purpose key, so that is the key that signs its
   record; but crypto spec §5 places `dht:entry` under the **`Transaction`** role. Purposes are not
   machine-checked, so nothing fails — but it is exactly the purpose/role drift C1 exists to
   prevent. Options: move `dht:entry` to the `Transport` role (a spec change, and a new context
   version), or bind a `Transaction` key to the `PeerId` through the validator-registration record.
   **Decided 2026-10-08: bind a `Transaction` key.** Spec §5 stands; the binding arrives with the
   validator-registration record (G6). Until then records stay on the `Transport` key, and this
   item stays open as the reminder that they must move. **Owner: protocol.**
2. **(found 2026-10-07) The first-flight margin is ≈ 150 B.** Measured on the wire by G5-T6 with
   Initial padding at 1,372 B and 4-byte connection IDs. The structural alternative is TLS **raw
   public keys** (RFC 7250): the identity *is* the key, so the X.509 wrapper and its self-signature
   (≈ 2.5 KB of the flight) carry nothing the `CertificateVerify` does not. That would be an
   ADR-0019 change. **Decided 2026-10-08: deferred, revisit at G6** — the margin holds (147–161 B
   over 15 runs) and G5-T6 guards it; G6 is where something may next want to grow the first
   flight. **Owner: networking.**
3. **SLH-DSA keys have no HD derivation path.** BIP32 yields 32 bytes; SLH-DSA-128s needs a 48-byte
   seed. `Keypair::generate` refuses rather than inventing a derivation;
   `Keypair::generate_from_seed` takes the 48 bytes. The `Identity` key's derivation needs
   specifying before validator registration exists. **Owner: crypto.**
4. **`multibase` is pinned at 0.9.2** in `Cargo.lock` because `base45` 3.2 needs rustc 1.88
   without declaring it. A `cargo update` without `--precise` will break the 1.85 build; the pin
   lifts when the toolchain moves. **Owner: build.**

---

## Review of `master..HEAD` — 2026-10-08

A critical review of the Layer-0 branch before it closed, done by hand against the gate
definitions in [`16-action-plan.md`](../16-action-plan.md). Every fix landed in `ba1e5fb` with a
test, and every new test was **mutation-checked**: re-introducing the old behaviour makes it fail.

### Fixed

| # | Finding | Severity | Fix | Test |
|---|---|---|---|---|
| R1 | **G5-T5 was weaker than its definition.** "Nor replayed after expiry": `DhtEntry` had no ordering, so a publisher's old, genuinely signed record could be replayed over its newer one, rolling the DHT back to a stale address. Forgery tests all passed, because the replayed record *is* genuine | high | signed `seq` in `DhtEntry` (wire v1 re-cut before G2a closed; golden vector regenerated); nodes keep only a superseding record; lookups return the highest `seq` | `g5_t5_an_old_record_cannot_be_replayed_over_a_newer_one`, `g5_t5_the_sequence_number_is_signed_and_orders_generations` |
| R2 | **Muxer panic.** `poll` / `poll_close` re-polled a completed `async` block after the connection ended — *"resumed after completion"*. The swarm happens not to re-poll today; nothing promised it | medium | both answer from `close_reason()` once the connection has one | `muxer_close_and_poll_are_safe_to_repeat_after_the_end` (panicked before) |
| R3 | **`remove_listener` killed outbound connections** — it closed the endpoint they share | medium | stop accepting (`set_server_config(None)`); keep the endpoint | `removing_the_listener_keeps_outbound_connections` |
| R4 | **Dial-before-listen leaked.** The ephemeral endpoint ran a server whose accept queue nothing drained — every inbound to it queued forever | medium | a dial-only endpoint has no server config | structural (no server ⇒ nothing to queue); documented in `p2p.rs` |
| R5 | **No connection ceiling.** Every Kademlia `RoutingUpdated` dialled; inbound was unlimited | medium | `connection_limits`: `max_peers` (128), 64 pending handshakes, 2 per peer; discovery dials stop at `target_peers` (32) | `bounds_connections_never_exceed_max_peers` |
| R6 | **Unbounded memory from a hostile peer**: the event channel (valid gossip from self-signed spam keys), the peer table (one entry per identity ever seen), the per-peer dial-config cache (Kademlia hands out invented `PeerId`s), the accepted-connection hand-off | medium | events bounded and **dropped** when full; idle peers forgotten after 10 min; config cache capped at 256 (FIFO); hand-off bounded at 64, quinn `max_incoming` 256 | `bounds_an_application_that_stops_reading_cannot_grow_the_node`, `n8_disconnected_peers_are_forgotten_so_the_table_stays_bounded`, `the_dial_config_cache_is_bounded` |
| R7 | **Offences by an already-banned peer re-banned it** — extending the ban and re-announcing `PeerBanned` for messages already in flight | low | `Verdict::AlreadyBanned`; the ban keeps its original expiry | `n11_an_offence_by_a_banned_peer_neither_extends_nor_repeats_the_ban` |
| R8 | **G5-T7 swept 24 contexts, G1-T2 26** — "every registry context" meant two different sets | low | the same four topic shapes as G1-T2 | `g5_t7_tls_and_protocol_signatures_never_verify_as_each_other` |
| R9 | **IPv6 untested** | low | — | `ipv6_two_nodes_authenticate_and_gossip_over_loopback` |
| R11 | **A graylisted offender was silenced but never disconnected.** GossipSub's own scoring graylists a peer at its second invalid delivery (−100 × 2² × 0.5 = −200, past −80) and then drops its traffic *before* the node sees it, so the `PeerTable` score stops at −40…−60 and the −100 ban is never reached. An attacker that sends a short burst and goes quiet keeps its connection — and, with R5, a connection slot — indefinitely. G5-T3 passed only when several messages happened to be read before the first verdict landed; it **failed CI run [37743273385](https://github.com/ArunBabu98/huxplex/actions/runs/37743273385) on x86_64** | medium | the node checks GossipSub's score as it reports each rejection, and a graylisting bans (`Offence::GossipGraylisted`). A 1 s poll was tried first and missed the window (≤ one decay interval) under load | G5-T3 rewritten: one attacker per offence kind, each bursting and then going quiet; each must be recognised as exactly its kind, banned and disconnected. Without the fix: **3/3 failures**; with it **0/15** |
| R10 | **The G5 exit test raced Kademlia.** It sampled routing tables the instant connections completed; a peer enters the table only after confirming the protocol on a stream. **This is what failed CI run [37741299344](https://github.com/ArunBabu98/huxplex/actions/runs/37741299344)** on x86_64 and macOS (3 entries, not 4) | test | wait for the routing tables, as for the connections | the exit test |

### Recorded as acceptable, with the reason

| Finding | Why it stands |
|---|---|
| The command channel is unbounded | only the local application writes to it |
| Ban expiry runs on a 1 s tick | 1 s of granularity on a 600 s ban |
| GossipSub score parameters are hand-picked | G5-T3's ban comes from the Huxplex `PeerTable`, whose penalties are tested exactly; GossipSub's scores are a second layer. Calibrate against the G7 soak, not before there is traffic to calibrate on |
| **G5-T3 proves a ban, not a bandwidth figure.** The definition says "per-peer bandwidth stays bounded" | the bound is real but is a product, not a measurement: ≤ 5 offences (ban at −100, minimum penalty −20) × `MAX_ENVELOPE_LEN` (4 MiB) ≈ 20 MiB, each costing one decode and at most one ML-DSA verification, **per identity**. Identities are free, so the Sybil bound is the connection ceiling (R5). A measured per-peer byte test is a G7-soak item |
| G5-T1 "no stream before mutual authentication" is proven at the quinn layer, not through the swarm | `HuxTransport` yields a connection to the swarm only after `Connecting` resolves, which requires the client certificate to have verified (`client_auth_mandatory`); there is no earlier object the swarm could open a stream on |
| G5-T6 is measured on loopback | the byte count is path-independent; the 1,420-byte tunnel MTU is what `INITIAL_DATAGRAM_SIZE` is sized for |
| The hybrid KEM (`kem/hybrid.rs`) has no production caller | TLS's `X25519MLKEM768` is aws-lc-rs's, by ADR-0019. Huxplex's own hybrid is for application-layer key agreement, which no gate has yet asked for. Its KATs and G1-T5 keep it honest until one does |
| `network_walkthrough` does not exercise the transport | it walks the envelope and identity rules; the transport has `tests/network.rs`. Extending the walkthrough is cheap and worth doing, but not a gate item |
| No `cargo-fuzz` target; G2-T4 is a 10⁶-iteration test | G2's exit criterion ("fuzz target in CI") is a **G2** criterion, shared by both halves; it is task **E8** of [G2b](../18-implementation-plan/05-g2b-consensus-encoding.md), covering the wire decoders too. G2a closes on G2-T1/T2/T4 as ADR-0022 scoped it |

### Measured, not assumed

- **Flake rate.** `cargo test --all-targets --all-features --locked`, 6 runs at `d70bb9f` and 5 at
  `ba1e5fb`, arm64: **0 failures in 11 runs** — yet CI failed twice, once each on R10 and R11.
  Neither reproduced locally until the test was made to look for it: R11's G5-T3 failed locally
  **5 times in 12** once an intermediate rewrite removed the batching luck that hid it. *Local
  green is weak evidence for the network tests*; the CI matrix is the evidence. After the R11
  fix: `tests/network.rs` **0 failures in 30 runs** (2 × 15).
- **G5-T6 margin**, 15 runs of `cargo test -p hux-network --test transport g5_t6 -- --nocapture`:
  client flight **2,744 B** every run, budget **8,232 B**, margin **147–161 B** (median 154 B).

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
> **11 of 11 tasks done** — the registry (C1–C5) landed 2026-09-23; C6–C11 and B5 2026-10-07.
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

### B2 · Remove the hard-coded sizes (C6) ✅ *done 2026-10-07*

Half-started by the registry: `traits::SchemeSizes` already exposes sizes *from the resolved
scheme*, and `c6_sizes_are_available_from_the_resolved_scheme` asserts a caller can read them
without naming a literal. What remains is that the literals still live in `sig/ml_dsa.rs`, and
nothing has yet proved a *second* scheme can be registered without touching one.

- [x] **C6** No size literal outside the suite descriptor. Remaining sites: the `PK_LEN` /
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

### B3 · SLH-DSA-128s (C7–C8) ✅ *done 2026-10-07*

- [x] **C7** Implement on **`fips205`** (pure Rust, no `unsafe`). Sizes 32 / 64 / 7,856.
      **Test:** the **22** `slh_dsa_128s_tests` pass with `#[ignore]` removed.
      *(The plan says 24; the count is 22 as of `63ad3d5` — three were un-ignored, of which two
      were SLH-DSA size assertions that already pass.)*
- [x] **C8** CI differential test against RustCrypto `slh-dsa` — **dev-dependency only**.
      **Test:** same seed ⇒ identical key and signature bytes; a deliberate mutation fails.

### B4 · Secret hygiene and KATs (C9–C11) ✅ *done 2026-10-07*

- [x] **C9** Split signing into two functions: production signing sources randomness from the
      system CSPRNG and **cannot** accept a caller-supplied value; a separate test-only entry point
      takes explicit randomness. **Done:** `Signer::sign` takes a `SigningRandomness` only
      `hux-crypto` can construct; `Keypair::sign_with_randomness` exists only under `cfg(test)`,
      and `compile_fail` doctests prove neither is reachable from the public API.
      > **Two functions, not one with a flag.** A `deterministic: bool` is a downgrade switch
      > waiting for a misconfiguration, and deterministic lattice signing plus fault injection is a
      > demonstrated key-recovery path.
      > **C9 blocks C10:** without it, signature KATs cannot be pinned at all.
- [x] **C10** Byte-exact KAT fixtures for ML-DSA-44, ML-KEM-768, SLH-DSA-128s and the hash domains
      ([ADR-0010](../adr/0010-hash-function-domains.md)); signature fixtures pin the 32-byte
      randomness. **Done:** `crates/hux-crypto/tests/kat/` — ML-DSA-44, ML-KEM-768, SLH-DSA-128s,
      the hybrid KEM, plus the earlier hash/KDF vectors; every one reproduced by an independent
      implementation.
- [x] **C11** `libcrux` ↔ `aws-lc-rs` ML-DSA differential test
      ([ADR-0019](../adr/0019-transport-authentication.md) condition 4).

### B5 · Hybrid key agreement ✅ *done 2026-10-07*

- [x] Hybrid X25519 + ML-KEM-768 — `kem/hybrid.rs`, TLS `X25519MLKEM768` layout, HKDF combiner binding the X25519 values (X-Wing). `Kem` trait landed with it.

### G1 gate tests — current state

| ID | Property | Today |
|---|---|---|
| **G1-T1** | Algorithm rotation without state migration — register a second scheme, flip **one role's** default; old objects still verify, other roles untouched, zero state-structure changes | 🟢 **green in CI** — a test-only suite v2 flips `QuorumCert` to SLH-DSA (`suite/registry.rs`) |
| **G1-T2** | Cross-context replay fails — **exhaustive over every ordered pair** of registry contexts, including `dht:entry` | 🟢 **green in CI** — 650 ordered pairs, enumerated from `hux_crypto::context` |
| **G1-T3** | KAT byte-exactness on **both** architectures | 🟢 **green in CI** on x86_64, aarch64, arm64 (run 37746269760) |
| **G1-T4** | Unknown algorithm ID — and unknown **role** — rejected, never ignored | 🟢 **green** — five tests |
| **G1-T5** | Hybrid retains PQ security if the classical half is broken — force X25519 output to a constant, session keys still differ | 🟢 **green in CI** — `kem/hybrid.rs` |
| **G1-T6** | Role confusion rejected — every ordered pair of roles | 🟢 **green in CI** — closed by G2a: the descriptor is signed (`wire_encoding.rs`) |

> **G1-T6 closed through G2a**, as ADR-0022 anticipated: the descriptor is the first field of
> every wire envelope and inside the signed preimage, so a relabelled role is refused as
> `RoleMismatch` *and* the original signature fails over the relabelled bytes.

**G1 exit:** ~~registry is the only path to a primitive~~ ✅ (enforced mechanically, not by
convention); SLH-DSA green and un-ignored; KATs committed and green on both architectures;
**G1-T1 and G1-T6 demonstrated in CI**; no size literal outside the suite descriptor.

> **Re-check before starting:** `libcrux` and `fips205` releases, per the *keeping this plan honest*
> rule — two findings in the September 2026 review were overturned within weeks.

---

## Phase C — G5 · transport · *entry is now G2a*

> **Entry:** G2 (canonical encoding) — which is outside Layer 0 and outside this file. G5 is listed
> here because Layer 0 is not complete without it, not because it can start next.
> Full breakdown: [`18-implementation-plan/03-g5-transport.md`](../18-implementation-plan/03-g5-transport.md).
>
> **As built (2026-10-07):** `hux-network/src/transport/` (cert, tls, quic, p2p, muxer, socket),
> `peers.rs` and `node.rs` — libp2p **0.56** (rustc 1.85), quinn 0.11, rustls 0.23.45 on aws-lc-rs.

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

### C0b · The identity question ✅ *resolved 2026-09-30 — [ADR-0021](../adr/0021-peer-identity-across-libp2p.md)*

The spike surfaced something outside its original framing and more consequential than the crate
choice. `libp2p-core` hands the swarm `(PeerId, StreamMuxerBox)` typed on
**`libp2p_identity::PeerId`** — a multihash over a protobuf Ed25519-class key. Huxplex's is
`SHAKE-256(ML-DSA-44 pk)[..32]` (wire spec §4, `peer.rs`, asserted by **G5-T2**). GossipSub and
Kademlia are generic over libp2p's.

- [x] **Decided and recorded:** option (c) — **one identity, two encodings**.

(a) was rejected because it anchors peer identity on Ed25519 in a post-quantum chain: a CRQC
would not break consensus signatures but *would* break Sybil resistance and DHT record
authorisation. (b) was rejected on cost — it abandons libp2p's GossipSub scoring, which **G5-T3**
leans on. A fourth option, forking `libp2p-identity` to add an ML-DSA key type, was rejected as
unnecessary once (c) turned out to need no fork.

**(c) is cheaper than it first looked.** It is not a dual identity:

```
libp2p PeerId = 0x00 ‖ 0x20 ‖ <32-byte Huxplex PeerId>     // identity-coded multihash
```

`PeerId::from_multihash` is public and accepts identity-coded digests up to 42 bytes, so the
libp2p form is a **lossless re-encoding** of the Huxplex `PeerId` — verified round-tripping
against the real crate. There is no binding to prove, because the relationship is definitional
rather than cryptographic, and **ADR-0012 rule 5 is satisfied as written** rather than amended.

Available *because* N0 chose outcome 3: Huxplex constructs the `(PeerId, StreamMuxerBox)` pair
itself. Under `libp2p-quic` it would not be — recorded as a standing condition, not an assumption.

**Carry into N0b/N2 as acceptance criteria** (ADR-0021 rules I1–I5), in particular:
- [x] **I3** — conversion is total and lossless, asserted in **both** directions.
- [x] **I4** — compile-time assertion that the Huxplex `PeerId` stays ≤ 42 bytes, so a future
      hash change fails the build rather than the network.
- [x] **I5** — the TLS verifier is the sole authority; the libp2p `PeerId` is derived from its
      verified output, never trusted as received.

### C0c · New from the spike ✅

- [x] **N0b** Drive `quinn` 0.11 behind libp2p's `Transport` trait; add `quinn` and
      `rustls` 0.23.45 (`aws-lc-rs`, non-FIPS) as direct dependencies. `libp2p-quic` is not the
      transport.
      > The upside of outcome 3: N1–N5 become *implementation* rather than integration, and every
      > ADR-0019 requirement — ALPN, mutual auth, custom verifier, 0-RTT off, Initial padding —
      > becomes directly expressible on a config Huxplex constructs. **G5-T6**'s ≈130-byte
      > amplification margin is far easier to assert that way.
- [x] **Amend ADR-0019** to record outcome 3 and why outcome 2 failed (libp2p-identity, not
      libp2p-tls).

### C1 · Certificates and authentication (N1–N5) ✅ *done 2026-10-07*

- [x] **N1** Self-signed X.509: SPKI = ML-DSA-44 public key, ML-DSA-44 self-signature,
      `SignatureScheme` `mldsa44` = **0x0904**; key is the `Transport` purpose
      `m/44'/931931'/4'/0'/{i}'` — already derivable today.
- [x] **N2** Custom `ServerCertVerifier` / `ClientCertVerifier`: verify self-signature →
      `SHAKE-256(spki)[..32]` → compare to expected `PeerId` → abort on mismatch.
      **No CA, no trust store, no name checking, no revocation.**
- [x] **N3** **Mutual** authentication; an unauthenticated peer never reaches an application stream.
- [x] **N4** ALPN `huxplex/{network}/1`; QUIC refuses cross-network dials before Huxplex code runs.
- [x] **N5** Pin `rustls` ≥ 0.23.44, `aws-lc-rs` provider, **non-FIPS**; add `aws-lc-rs` /
      `aws-lc-sys` to `deny.toml` review — a deliberate principle-8 exception.
- [x] **G0-7 lands here:** pin the C toolchain (a container image with a fixed `cc`), referenced
      from CI *and* the reproducible-build documentation.
      **Acceptance:** `scripts/check-reproducible.sh` still passes with `aws-lc-rs` in the tree.
      > **Stop condition (R4).** If a pinned container cannot produce byte-identical artifacts, the
      > decision returns to ADR-0019's addendum. Do **not** weaken the reproducibility requirement.

### C2 · Transport behaviour (N6–N8) ✅ *done 2026-10-07*

- [x] **N6** Pad the client Initial so the responder's ≈7,970 B first flight stays inside RFC 9000
      §8.1's 3× budget. **~130 bytes of headroom — see R3.**
- [x] **N7** 1-RTT resumption **on**, 0-RTT early data **off**. **Test:** early data is refused.
- [x] **N8** Peer lifecycle state machine: `Disconnected → Connecting → Handshaking → Identified →
      Active`, with backoff and banning. **Test:** a peer's messages are not processed before
      `Identified`.

### C3 · Discovery and messaging (N9–N11) ✅ *done 2026-10-07*

- [x] **N9** Kademlia DHT over the existing signed `DhtEntry`; DHT key = publisher's `PeerId`;
      verify before routing.
- [x] **N10** GossipSub for mempool / intents / control, reusing the existing signed envelopes;
      message-ID dedup, **no re-signing on forward**.
- [x] **N11** Peer scoring plus penalties for invalid signatures, cross-context replay attempts and
      spam.

> **Do not** build erasure-coded block broadcast at this gate. v1 may carry blocks over GossipSub;
> the guardrail is only that nothing above the transport may *assume* it (**R5**).

### G5 gate tests — all green in CI (run 37746269760)

| ID | Property | Today |
|---|---|---|
| **G5-T1** | Authenticated handshake, no downgrade: classical-only rejected; MITM certificate fails the `PeerId` check; no client certificate ⇒ no application stream; cross-network ALPN refused by QUIC | 🟢 `tests/transport.rs` — all four refused in the handshake |
| **G5-T2** | `PeerId` is bound to the key | 🟢 live — an impostor presenting a copied certificate is refused in both directions |
| **G5-T3** | Gossip amplification bounded under a flood of malformed and unsigned messages; offender scored down and disconnected | 🟢 `tests/network.rs` — real attacker peer; banned, disconnected, nothing forwarded |
| **G5-T4** | Propagation under 20% loss and a healed partition; all honest nodes converge | 🟢 `tests/network.rs` — in-process datagram filter, 5 nodes |
| **G5-T5** | Signed DHT entries reject forgery and replay, including cross-network | 🟢 live DHT — squatting, re-keying and cross-network records refused by every node |
| **G5-T6** | Responder's first flight never exceeds 3× bytes received, **measured on the wire**, re-asserted whenever the suite changes | 🟢 2,744 B in, ≈ 8,080 B out of an 8,232 B budget — **(found 2026-10-07)** the planned ≈ 130 B margin was ≈ 20 B until padding and CIDs were re-sized |
| **G5-T7** | A TLS `CertificateVerify` signature must not verify as any Huxplex protocol signature, and no `huxplex-…:v1` signature may be accepted by the TLS layer — for every registry context | 🟢 every registry context, both directions; TLS context pinned **empty** |

> **G5-T6 and G5-T7 are the two most likely to be skipped**, and the two that guard the properties
> nothing else does.

**G5 exit:** 5 nodes discover each other, mutually authenticate over QUIC with ML-DSA certificates,
gossip and sustain sessions; abuse tests green; G5-T6 and G5-T7 green; the N0 finding recorded.

**When Phases A, B and C are all closed in CI, Layer 0 is complete** — and G2b, the consensus
encoding, is the next gate.

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

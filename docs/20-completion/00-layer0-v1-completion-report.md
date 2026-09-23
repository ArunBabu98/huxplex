# 00 — Layer 0 / v1 completion report

> **Audit date:** 2026-09-23 · **Originally at:** `63ad3d5` · **Updated after:** `7912117` (PR #9 merged) and G0-8
> **Host:** `aarch64-apple-darwin` (Apple M4), rustc 1.85.0 (pinned), plus the three CI legs
>
> Method: run the tree, read the source, query CI. Every ✅ and ❌ below has a command behind it.
> Where this report and the blueprint disagree, this report is describing what happened and the
> blueprint is describing what was intended.

---

## 1. Verdict

**Layer 0 for v1 is NOT complete.**

The project's own definition of the term is the three-row table in
[`18-implementation-plan/04-sequencing-and-risks.md`](../18-implementation-plan/04-sequencing-and-risks.md#what-layer-0-complete-means):
Layer 0 is complete when **G0**, **G1** and **G5** have all closed. Measured against it:

| | Criterion (verbatim from that table) | Reality | |
|---|---|---|---|
| **G0** | Workspace split; dual-architecture CI green; reproducible builds demonstrated by an automated two-build comparison; no secret printable via `Debug` | Workspace ✅ · reproducibility ✅ · `Debug` ✅ · **CI green on three architectures** ✅ | 🟢 **CLOSED** |
| **G1** | Registry is the only path to a primitive; SLH-DSA green with 24 tests un-ignored; KATs byte-exact on both architectures; G1-T1 and G1-T6 green | No registry, no SLH-DSA, no KAT fixtures, no role dimension in code. 0 of 11 tasks | 🔴 |
| **G5** | 5 nodes mutually authenticate over QUIC with ML-DSA certificates, discover via Kademlia, gossip under 20% loss; G5-T6 and G5-T7 green | No transport, no swarm, no TLS, no peer state machine. The entry spike (N0) has not been run | 🔴 |

One gate closed, two untouched. **Roughly one third of Layer 0 exists.**

A second, wider reading of the question — *is v1 complete?* — resolves the same way and more
emphatically: v1 is the 3–5 node devnet of
[`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md), and gates G2 (encoding),
G3 (ledger), G4 (execution), G6 (consensus) and G7 (devnet) have no code whatsoever. See §6.

---

## 2. Evidence: what was run, and what it produced

| Check | Command | Result |
|---|---|---|
| Full local harness | `./scripts/verify-layer0.sh` | **12/12 PASS** — fmt, clippy `-D warnings`, layering, arch-portability guard, build `--locked`, tests, doctests, docs, both walkthroughs, determinism re-run, arch negative case. (9/9 at audit time; G0-8 added three.) |
| Reproducible build (G0-T2) | `./scripts/check-reproducible.sh` | **PASS** — `libhux_crypto.rlib` `5e495a84…b5a0` and `libhux_network.rlib` `334fb745…2957` identical across two independent clean copies |
| Test suite | `cargo test --all-targets --all-features --locked` | **117 passed · 0 failed · 81 ignored** (hux-crypto 76 + 81 ignored; hux-network 41). Was 115 at audit time; the DHT field-framing fix (§5.1) added two |
| Gate labels (G0-T3) | `grep -rn '#\[ignore' crates/` | **81/81 labelled** — `GATE: G1` ×22, `GATE: G6+` ×33, `GATE: G10` ×26 |
| Supply chain | `cargo deny check advisories licenses bans sources` | **ok** — one documented, owned, dated advisory exception (`RUSTSEC-2026-0173`) |
| Second architecture (local) | `cargo test --all-features --locked --target x86_64-apple-darwin` | **115 passed** — but see §3.2, this is Rosetta and it proves less than it appears to |
| CI history *(at audit time)* | `gh run list --branch layer0/g0-workspace-and-verification` | **empty — zero runs** |
| **CI matrix** *(after PR #9)* | `gh run view 35854233815` | **8/8 jobs green.** `x86_64` / `aarch64` / `arm64`, each **115 · 0 · 81** — see §3.1 |
| **Cross-architecture agreement** | walkthrough output diffed across all three legs | **Identical** but for the architecture name each program prints — see §3.2 |
| **G0-8 negative case** | `./scripts/check-arch-negative.sh` | **PASS** — injected `mlkem768::avx2::*` rejected with `E0433` on aarch64 |

### 2.1 Corrected figures

The suite is **115 / 0 / 81**, not the **112 / 0 / 84** recorded throughout `/docs`. The
difference is exactly commit `63ad3d5`, *"un-ignore three vacuously-gated tests"*, which moved
three size-constant assertions out of the ignored set. Every affected document is corrected as
part of this audit; the list is in [`01-outstanding-work.md` §5](01-outstanding-work.md).

---

## 3. G0 · Repository health — 🟢 CLOSED 2026-09-23

Everything G0 was written to fix had been fixed, and fixed well. What was missing was the
*proof* — and G0's whole thesis is that an unproven claim about portability is how the repository
broke in the first place. Both halves of that proof now exist.

### 3.1 The blocking finding, and its resolution

**The finding.** [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) triggered on:

```yaml
on:
  push:
    branches: [master]
  pull_request:
```

The Layer-0 work was five commits on `layer0/g0-workspace-and-verification`, pushed to `origin`
with **no pull request**. Neither trigger fired, `gh run list` for the branch returned nothing,
and the newest `CI` run of any kind was **2026-09-12** — before commit `8dbc640` created the
workspace. The architecture matrix, the layering gate, the reproducible-build job and the
`Security` workflow had therefore never seen the workspace at all.

That was not a code defect. It was the gap between "wired" and "ran" — precisely the distinction
G0 exists to enforce, per standing rule #1 of
[`16-action-plan.md`](../16-action-plan.md#4-standing-rules): *a gate is done when its
high-concept tests pass in CI, not when the code is written.*

**The resolution.** [PR #9](https://github.com/ArunBabu98/huxplex/pull/9), merged as `7912117`.
First CI run in the repository's history against the workspace — `gh run view 35854233815`:

| Job | Result |
|---|---|
| rustfmt · clippy · doc build | ✓ |
| static gates (layering) | ✓ |
| test (x86_64) · test (aarch64) · test (aarch64-darwin) | ✓ **115 · 0 · 81** each |
| reproducible build (G0-T2) | ✓ on a runner, first time |
| cargo-deny (`Security` workflow) | ✓ against the workspace lockfile, first time |

### 3.2 Cross-architecture agreement — the result worth keeping

[`19-verification/README.md`](../19-verification/README.md) asks contributors to run the
walkthroughs on two architectures and confirm the printed key, `PeerId` and shared-secret values
are **identical**, since they are deterministic in their seeds. Doing that across all three CI
legs:

```
x86_64 vs aarch64-linux    →  3 differing lines
x86_64 vs aarch64-darwin   →  3 differing lines
```

All three differences are the architecture name the program prints about itself
(`All Layer-0 cryptographic invariants held on x86_64` vs `aarch64`), plus a log header. **Every
derived value is byte-identical**: the five HD purpose seeds (`755c2dcb…`, `3c4e962a…`,
`a77709ef…`, `6310e5e7…`, `2c9cd7fd…`), the `PeerId`s, the shared secrets.

That is the substantive claim behind G0-T1 — the simd256, simd128 and portable backends are
output-identical in practice, so a backend difference cannot fork the network.

> **Why the earlier local x86-64 run did not establish this.** The audit first ran the suite
> against the `x86_64-apple-darwin` target on an Apple M4 — 115 tests, all passing. But probing
> that translated environment directly gave `avx2 = false`, `avx = false`, `sse4.2 = true`:
> Rosetta 2 exposes no AVX2, so libcrux dispatched to the **portable** backend and the `simd256`
> feature was compiled but never executed. It proved the target compiles, nothing more. Only
> native x86-64 hardware could settle it, and only CI had that.

### 3.3 G0-8 — the negative case

A matrix that can only pass does not prove it would catch the regression it exists for. Two
checks now close that gap, both added on top of the merge:

| Script | Proves | Result |
|---|---|---|
| [`check-arch-portability.sh`](../../scripts/check-arch-portability.sh) | nobody **wrote** a direct backend path — scans `crates/*/src` and `crates/*/tests` for `::avx2::`, `::neon::`, `::simd256::`, `::simd128::`, `::portable::`, exempting whole-line comments and the target-gated features in `Cargo.toml` | ✓ 24 files, clean; verified to **fail** when a violation is injected |
| [`check-arch-negative.sh`](../../scripts/check-arch-negative.sh) | the build would **notice** if they did — stages a throwaway copy of the working tree, injects `mlkem768::avx2::generate_key_pair`, and asserts the compiler rejects it | ✓ `error[E0433]: failed to resolve: could not find 'avx2' in 'mlkem768'` on aarch64 |

The negative check skips itself on x86-64, where the backend genuinely exists and rejecting it
would prove nothing, and it requires the failure to actually mention `avx2`/`E0433` — otherwise an
unrelated compile error would be misread as success.

### 3.3 G0 item-by-item

| Item | Claim in docs | Verified | Note |
|---|---|---|---|
| 1 · ML-KEM backend dispatch | ✅ | ✅ | `kem.rs` calls only `mlkem768::{generate_key_pair,encapsulate,decapsulate}` — no backend path anywhere in the tree |
| 2 · Four phantom modules | ✅ | ✅ | `slh_dsa`/`lb_vrf`/`pq_ssle`/`zk_stark` are `#[cfg(test)]` in `lib.rs`; unreachable from the public API |
| 3 · `E0121` placeholder | ✅ | ✅ | compiles clean |
| 4 · Split the 3,607-line module | ✅ | ✅ | `hux-crypto/src/lib.rs` is 36 lines; suites in `crates/*/tests/` |
| 5 · **CI on both architectures** | 🟦 configured | ✅ **green on three** | Was never able to run; fixed by PR #9. §3.1 |
| 6 · `pub mod` + `forbid(unsafe_code)` | ✅ | ✅ | workspace lint, 0 warnings |
| 7 · `PeerId` short-read | ✅ | ✅ | `XofReader::read` in `peer.rs`, with the reasoning in a comment |
| 8 · Workspace split | ✅ | ✅ | two crates, downward-only layering, gate script passes |
| 9 · `PrivateKey` secret leak | ✅ | ✅ | redacted `Debug`, `ZeroizeOnDrop`, constant-time `Eq`, `expose_secret()` |
| 10 · C-toolchain pin | ⏸️ deferred to G5 | ⏸️ **correctly deferred** | `aws-lc-rs` is genuinely not in the tree; pinning now would mix two variables in the G0-T2 baseline |

| Gate test | Status | Evidence |
|---|---|---|
| **G0-T1** — compiles and passes on x86-64 **and** aarch64 | ✅ **green** | CI matrix: `x86_64`, `aarch64`, `arm64`, each 115 · 0 · 81, with byte-identical derived values (§3.1, §3.2) |
| **G0-T1 negative case** — a deliberate `avx2::` call must *fail* the aarch64 job | ✅ **green** | `check-arch-negative.sh` — injected call rejected with `E0433`; paired with the static guard (§3.3) |
| **G0-T2** — reproducible builds | ✅ **green** | Byte-identical `.rlib`s locally and on a runner. Baseline is pure-Rust; **must be re-run when `aws-lc-rs` lands at G5** |
| **G0-T3** — every ignore names its gate | ✅ **green** | 81/81 |

**G0 is closed.** The one criterion that remains deliberately deferred is G0-7, the C-toolchain
pin, which belongs to G5 because `aws-lc-rs` is not in the tree yet — see
[`01-outstanding-work.md` Phase C](01-outstanding-work.md).

> What closing G0 actually buys: from here, no change merges unless three architectures agree,
> the build is reproducible, the layering holds, no direct backend path was written, and a
> deliberate regression would be caught. **G1 may begin.**

---

## 4. G1 · Crypto core and the agility registry — 🔴 not started

Zero of the eleven tasks C1–C11 in
[`18-implementation-plan/02-g1-crypto-core.md`](../18-implementation-plan/02-g1-crypto-core.md)
have been begun. The planned shape (`suite/`, `traits.rs`, `sig/`, `kem/`, `hash/`) does not exist
on disk; `crates/hux-crypto/src/` still holds the flat pre-G1 module set.

### 4.1 What the source actually shows

**There is no registry, and no role dimension in code.**
[`signaturescheme.rs`](../../crates/hux-crypto/src/signaturescheme.rs) is four lines with a single
variant:

```rust
pub enum SignatureSchemeId { Dilithium2 }
```

Dispatch is a `match` inlined at each call site in `signature.rs` and `publickey.rs`. There is no
`AlgoSuite`, no `SigRole`, no `(role, version) → primitive` resolution, no append-only table, and
no trait boundary — so **every primitive is reached by a direct call to a named scheme**, which is
the precise condition C4 exists to forbid.

`KeyPurpose` in [`bip32.rs`](../../crates/hux-crypto/src/bip32.rs) *does* carry the five roles with
the ADR-0018 discriminants. That is the derivation half only. Nothing yet enforces that a key of
purpose *n* may sign only under role *n*, because there is no verifier that knows what a role is.

**Sizes are hard-coded**, exactly as ADR-0002 warned (C6):
`[u8; 1312]` and `[u8; 2420]` in `publickey.rs`, `[u8; 2560]` in `signature.rs`.

**SLH-DSA-128s is unimplemented** (C7/C8). `src/slh_dsa.rs` is a `#[cfg(test)]` API contract with
`unimplemented!()` bodies; 22 of its tests are `#[ignore]`d under `GATE: G1`. `fips205` is not a
dependency, nor is RustCrypto `slh-dsa` as the differential oracle.

**No KAT fixtures exist anywhere in the tree** (C10). There is no fixtures directory and no
committed vectors; `grep -rn "KAT" crates/*/tests/` returns nothing. G1-T3 therefore cannot be
attempted yet.

**C9 blocks C10.** `Keypair::sign` draws its 32 bytes from `rand::rng()` unconditionally and
exposes no test-only entry point taking explicit randomness. Until the two-function split lands,
*signature* KATs cannot be pinned at all — only keygen vectors could be.

**No hybrid X25519 + ML-KEM-768 key agreement** exists (G1-T5), and no
`libcrux` ↔ `aws-lc-rs` differential test (C11).

### 4.2 Gate-test coverage today

| Test | Status |
|---|---|
| **G1-T1** — algorithm rotation without state migration | ❌ impossible to write; nothing to rotate |
| **G1-T2** — cross-context replay fails | 🟡 **partial** — `test_all_canonical_context_strings_are_mutually_domain_separated`, `test_mainnet_and_testnet_tx_contexts_are_domain_separated`, `test_dht_entry_cross_network_replay_fails` exist and pass. Not the exhaustive ordered-pair sweep over a registry, because there is no registry |
| **G1-T3** — KAT byte-exactness | ❌ no fixtures |
| **G1-T4** — unknown algorithm ID fails closed | ❌ unrepresentable: the enum has one variant, so an unknown ID cannot be constructed |
| **G1-T5** — hybrid retains PQ security | ❌ no hybrid |
| **G1-T6** — role confusion rejected | ❌ no roles in the verifier |

One of six partially covered. **G1 has not started.**

> Note the ordering hazard the plan itself flags: G2 freezes canonical encoding
> ([ADR-0011](../adr/0011-canonical-serialization.md)), so anything wrong about the
> `(role, version)` descriptor's *shape* after that point is a state migration rather than a
> parameter change. G1 is the gate with a closing window.

---

## 5. G5 · Transport — 🔴 not started

### 5.1 A live forgery found in the shipped envelope code (2026-09-23)

Before any of the missing transport work below, a defect in what *does* exist:

`DhtEntry` signed the bare concatenation `key ‖ value`. That encodes no field boundary, so
`("abc","XY")` and `("ab","cXY")` produce identical signed bytes — and `verify()` rebuilds the
payload from the record's own fields, so it **accepted** the re-split. Demonstrated on master:

```
forged re-split record verified = true
a record signed for key [97, 98, 99] verified under key [97, 98]
```

An attacker who observes any signed record can republish the publisher's signature **under a
different DHT key**, holding no key material. The key decides routing, so this is routing-table
poisoning by a peer that possesses nothing — the precise opposite of **G5-T5**, *"a record signed
for one key cannot be republished under another."*

It is also exactly the ambiguity **G2-T2** exists to forbid: two distinct values must never share
one encoding. The crypto spec described `key || value` as *"the grandfathered primitive
encoding"* — treating as a style concession what was in fact a forgery.

**Why the existing tests missed it.** `test_dht_entry_tampered_key_…`,
`…tampered_value_…` and `…wrong_signer_…` all mutate one field independently, which changes the
concatenation, so they passed throughout. Tamper tests establish that *changing* a field breaks
the signature. They do not establish that the encoding is *unambiguous*. Those are different
properties, and only the second forbids two distinct records sharing one signature.

**Fixed** by framing both fields — `u64_be(len(key)) ‖ key ‖ u64_be(len(value)) ‖ value` —
normative in [wire spec §4](../15-specifications/05-network-wire-protocol.md) and
[crypto spec §6.3](../15-specifications/02-cryptography-spec.md), pinned by
`test_dht_entry_key_value_boundary_is_unambiguous` and
`test_dht_entry_empty_key_and_empty_value_are_distinguishable`. It changes the signed bytes,
which is free now and would not have been once a network existed.

> **The transferable lesson.** Ad-hoc concatenation of variable-length fields is not a neutral
> shortcut; it is an encoding decision, and an ambiguous one. This is an argument for doing G2
> earlier rather than later — see §5.2 on the ordering problem.

### 5.2 An ordering gap in the definition of "Layer 0 complete"

Layer 0 is defined as **G0 + G1 + G5**
([04-sequencing-and-risks](../18-implementation-plan/04-sequencing-and-risks.md)). But G5's entry
condition is **G2** — canonical encoding — and that same document's critical path marks G2
*"NOT in this plan"*:

```
G0 closed
  └→ G1  (C1…C11)         registry first, then primitives
       └→ G2 …            canonical encoding — NOT in this plan
            └→ G5 (N0 first, then N1…N11)
```

So Layer 0, as defined, cannot complete without a gate its own definition omits. Either G2 is de
facto part of Layer 0, or G5's dependency on it needs re-examining. This is a decision to take
deliberately rather than discover midway through G5.

§5.1 is evidence for taking it sooner: a canonical-encoding defect was already live in shipped
envelope code, and the spec had blessed it. The encoding discipline G2 would have imposed was
needed before G5, not after.

**What is unblocked regardless:** **N0**, the entry spike, is pure investigation with no code in
the tree, and the sequencing doc explicitly lists it as startable immediately. Nothing else in
G5 should begin before the G2 question is settled.

### 5.3 What exists today

`hux-network` is **five source files, 209 lines**: `peer.rs` (PeerId), `topic.rs` (topic strings
and context derivation), `message.rs` (`GossipMessage`, `DhtEntry`), `error.rs`, and a 10-line
`lib.rs` of module declarations.

Its entire dependency set is `hux-crypto`, `thiserror`, `sha2`, `sha3`, `hex`. There is **no
`libp2p`, no `quinn`, no `rustls`, no `aws-lc-rs`, no `tokio`** anywhere in the workspace. There
is no swarm, no transport, no certificate code, no peer state machine, no live Kademlia and no
GossipSub.

**N0, the entry spike, has not been run.** It is the explicitly-first task of the gate — *does
`libp2p-quic` accept a custom rustls configuration carrying an ML-DSA-44 certificate?* — and its
answer determines how much of G5 is integration versus implementation, and in the worst case which
crates are dependencies at all. No finding is recorded in
[`18-implementation-plan/03-g5-transport.md`](../18-implementation-plan/03-g5-transport.md).

| Test | Status |
|---|---|
| **G5-T1** — authenticated handshake, no downgrade | ❌ no handshake |
| **G5-T2** — `PeerId` bound to the key | 🟡 **struct-level only** — 7 tests in `peer_identity.rs` prove the derivation; nothing proves it over a live connection |
| **G5-T3** — gossip amplification bounded | ❌ no peer scoring, no rate limits, no live gossip |
| **G5-T4** — propagation under partition | ❌ no network to partition |
| **G5-T5** — signed DHT entries reject forgery and replay | 🟡 **struct-level only** — forgery, tamper, cross-network replay and (since §5.1) key/value re-splitting are tested on the struct; there is no DHT |
| **G5-T6** — QUIC 3× amplification limit respected | ❌ no wire |
| **G5-T7** — transport ≠ protocol signatures | ❌ no TLS layer |

Two of seven partially covered, both at the type level. The honest summary — which
[`19-verification/02-network.md`](../19-verification/02-network.md) already states plainly — is
that `hux-network` today is **the cryptographic half of the network and none of the network**.

---

## 6. The wider v1 — for completeness

Layer 0 is the floor of v1, not v1. Against the Definition of Done in
[`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md) §2:

| Area | Checked | Reality |
|---|---|---|
| Cryptography & encoding | 3 of 6 | ML-DSA-44, ML-KEM-768 + HKDF, BIP32 ✅. KATs ❌, canonical `Codec` ❌, hash domains ❌ |
| Ledger & execution | 0 of 4 | No HRM, no STF, no pruning, no `TxWeight` |
| Consensus & networking | 0 of 5 | No Q-BFT, no signer guard, no leader selection, no transport, no devnet |
| Economy | 0 of 3 | No staking, no fees, no SNTNC |
| Operability & research output | 0 of 3 | No key custody, no metrics, no governance voting |

**3 of 21.** Gates G2, G3, G4, G6 and G7 have no code. The exit criteria — a 24-hour 3–5 node soak,
a published research report, a security self-review — are not approachable from here.

This is not a criticism of the project. It is what
[`00-executive-summary.md`](../00-executive-summary.md) §2 already says of itself: *"T0: primitives
done, protocol unbuilt."* That assessment remains accurate as of this audit.

---

## 7. What is genuinely strong

An honest completion report should not be only a list of absences. Verified today, these hold:

- **The reproducibility work is real and non-obvious.** The canonical-build-path insight —
  `--remap-path-prefix` takes the source path as its *argument*, so two paths give two `RUSTFLAGS`
  strings, which feed `-C metadata`, which feeds symbol names — is the same solution Debian and
  Nix reached, and it is documented with its reasoning rather than as a recipe.
- **Secret hygiene is thorough.** Redacted `Debug`, `ZeroizeOnDrop`, constant-time equality, and a
  test that sweeps `{:?}` *and* `{:#?}` for hex *and* decimal renderings. The constant-time test
  checks single-bit flips at both ends — constant-time must not mean wrong.
- **The ignored-test discipline works.** 81 ignores, 81 gate labels, zero exceptions. That
  inventory is a more honest backlog than most issue trackers.
- **Domain separation is tested as a property, not spot-checked.** Cross-topic, cross-shard,
  cross-network and cross-purpose replay all have failing-by-construction tests.
- **The documentation does not overclaim.** The executive summary, the verification README and
  `verify-layer0.sh` itself all say Layer 0 is incomplete, unprompted. The script prints it on a
  fully green run. That is rare and worth preserving.
- **The backends genuinely agree.** Three architectures, byte-identical derived values (§3.2).
  This was the project's central portability *claim*, and it is now a measurement.

The gap this report documented was between **built** and **proven**, and between **primitives**
and **Layer 0**. The first half is closed. The second half is G1 and G5.

---

## 8. Conclusion

> Layer 0 for v1 is **not complete**. **G0 is closed** — verified green on three architectures,
> with a negative case proving the guard works. **G1 and G5 have not started.** What exists is
> the **post-quantum primitive layer** with a working safety net under it, not the Layer-0
> substrate.

One of three gates. The next action is **G1**, and its first task is the registry — not
SLH-DSA, however much more satisfying a primitive is to write. A primitive built before the
registry gets called directly from somewhere, and that call site survives. Note also that G1
carries a closing window: G2 freezes canonical encoding, after which the `(role, version)`
descriptor's shape is a state migration rather than a parameter change.

Everything remaining is enumerated in [`01-outstanding-work.md`](01-outstanding-work.md).

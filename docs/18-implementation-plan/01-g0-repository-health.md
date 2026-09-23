# 01 — G0 · Repository health

> *"The gate nobody wants to write and everybody needs."* Four items remain open from
> [`16-action-plan.md`](../16-action-plan.md#g0--repository-health), plus one live bug found
> during the September 2026 decision review.
>
> **G0 unblocks everything.** Nothing in G1 or G5 should start before G0-T1 is green in CI on
> both architectures.

## Outstanding items

| ID | Item | Status |
|---|---|---|
| **G0-4** | Split `src/crypto/mod.rs` (3,607 lines) | ✅ done via [W2](00-workspace-migration.md) — `lib.rs` is now 36 lines |
| **G0-5** | CI on `x86_64` **and** `aarch64` | ✅ green on three (`ubuntu-latest`, `ubuntu-24.04-arm`, `macos-latest`) after [PR #9](https://github.com/ArunBabu98/huxplex/pull/9) — see below |
| **G0-8** *(new 2026-09-23)* | The G0-T1 **negative case** — a deliberate `avx2::` call must fail the aarch64 job | ✅ done — two scripts, see below |
| **G0-T2** | Reproducible builds — bit-identical artifacts across two clean checkouts | ✅ `scripts/check-reproducible.sh` passing |
| **G0-6** *(new)* | `PrivateKey` derives `Debug` — **secret-leak bug** | ✅ fixed 2026-09-22 |
| **G0-7** *(new)* | C-toolchain pin, required by [ADR-0019](../adr/0019-transport-authentication.md) condition 3 | ⏸️ **deferred to G5 by design** — `aws-lc-rs` is not in the tree yet; see below |

## G0-6 — the secret-leak bug ✅ *fixed 2026-09-22*

[`crates/hux-crypto/src/privatekey.rs`](../../crates/hux-crypto/src/privatekey.rs) derived
`Debug`:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]   // ← Debug prints the ML-DSA secret key
pub struct PrivateKey { pub scheme: SignatureSchemeId, pub bytes: Vec<u8> }
```

Any `dbg!`, `{:?}`, `tracing::debug!` or panic message carrying a `Keypair` prints 2,560 bytes of
secret key. This is not hypothetical — it is one careless log line away, and validator logs are
routinely shipped off-host.

**Fix:**

1. Remove `Debug` from the derive; implement it manually as `PrivateKey { scheme, bytes: <redacted> }`.
   A manual impl is better than none — deleting `Debug` entirely makes any struct *containing* a
   `PrivateKey` un-derivable, which pushes people toward worse workarounds.
2. Add `zeroize::Zeroizing` (or `ZeroizeOnDrop`) so key material is wiped on drop.
3. Replace `PartialEq` with a **constant-time** comparison, or remove it. Byte-wise `==` on
   secret material short-circuits and is a timing oracle. Check whether any test relies on it
   before removing.
4. `pub bytes: Vec<u8>` → private with an accessor that returns a guarded type, so the field
   cannot be copied into a log-friendly container by accident.

**Acceptance:** a test asserting `format!("{:?}", private_key)` contains neither the key bytes nor
any hex substring of them; `cargo clippy` clean; all existing tests still pass or are updated with
justification.

**Done.** All four parts landed, plus four tests:
`test_private_key_debug_never_leaks_secret_bytes` (sweeps both `{:?}` and `{:#?}`, and checks for
hex *and* decimal `Vec` renderings), `…equality_is_value_based_and_scheme_aware`,
`…constant_time_equality_holds_for_near_misses` (single-bit flips at both ends of the key must
still compare unequal — constant-time must not mean *wrong*), and `…zeroize_now_wipes_material`.
A fifth check is built into the crypto walkthrough so a human sees the redaction rather than
trusting a green tick.

> This is the kind of finding G0 exists for: the crypto is correct, and the *plumbing around it*
> leaks. Worth checking `Signature` and any future `SecretKey` type for the same pattern.

## G0-5 — dual-architecture CI ✅ *green on three architectures*

**Done:** `.github/workflows/ci.yml` now runs an explicit matrix —
`ubuntu-latest` (x86_64), `ubuntu-24.04-arm` (aarch64) and `macos-latest` (aarch64 Darwin) —
each reporting `uname -m` and `rustc -vV`, then running `cargo test --all-features --locked` and
both self-verifying walkthroughs.

### The blocker, found and fixed 2026-09-23

The workflow triggers on:

```yaml
on:
  push:
    branches: [master]
  pull_request:
```

All Layer-0 work is on `layer0/g0-workspace-and-verification`. It is pushed to `origin`, and it
has **no pull request**. Neither trigger fires, so `gh run list --branch
layer0/g0-workspace-and-verification` returns **nothing**, and the newest `CI` run of any kind is
**2026-09-12** — before commit `8dbc640` created the workspace.

So the matrix is not "unproven until it runs". It *cannot* run. The same is true of the layering
gate, the reproducible-build job, and the `Security` (cargo-deny) workflow, none of which have
ever seen the workspace lockfile.

**Fixed by** [PR #9](https://github.com/ArunBabu98/huxplex/pull/9) (merged `7912117`), which fired
`CI` and `Security` for the first time. Result — `gh run view 35854233815`, 8/8 jobs green:

| Leg | `uname -m` | Tests |
|---|---|---|
| `ubuntu-latest` | `x86_64` | 115 · 0 · 81 |
| `ubuntu-24.04-arm` | `aarch64` | 115 · 0 · 81 |
| `macos-latest` | `arm64` | 115 · 0 · 81 |

Plus the reproducible-build job and cargo-deny, both on a runner for the first time.

> The `push` trigger still covers only `master`, so a PR is what fires CI. Widening it to
> `branches: [master, 'layer0/**']` would give long-running branches feedback without one —
> optional, since the PR route works.

**The result worth keeping.** Diffing the walkthrough output across all three legs: the *only*
differing lines are the architecture name each program prints about itself. Every derived value —
the five HD purpose seeds, `PeerId`s, shared secrets — is **byte-identical**. That is the
cross-architecture check [`../19-verification/README.md`](../19-verification/README.md) asks
contributors to run, and it upgrades backend agreement from a claim to a measurement.

### Why the local x86-64 evidence was not enough

The full suite does pass for `--target x86_64-apple-darwin` (115 tests, identical to native
aarch64). But probing that translated environment directly:

```
avx2   = false
avx    = false
sse4.2 = true
```

Rosetta 2 exposes no AVX2 on Apple Silicon, so libcrux's multiplexing dispatcher fell back to the
**portable** backend. The `simd256` feature that `hux-crypto/Cargo.toml` enables for
`cfg(target_arch = "x86_64")` was compiled but **never executed** — and that is exactly the code
path whose absence on aarch64 caused the original G0 break.

Only native x86-64 hardware could settle it, and only CI had that. It now has.

**Why it is load-bearing:** G0's own standing rule — *"a PQ chain whose crypto builds on only one
ISA cannot have a diverse validator set."* The original G0 break was exactly this (an
unconditional `mlkem768::avx2::*` call). Nothing prevents a recurrence except CI.

**Acceptance (G0-T1):** `cargo test --all-targets --all-features --locked` green on both targets
**in CI**, and a deliberate `avx2::` call fails the aarch64 job. **Both met.**

> **Invocation mismatch, resolved.** The acceptance line said `--all-targets` while CI and
> `scripts/verify-layer0.sh` ran `--all-features`; neither combined them, and `--all-targets`
> excludes doctests. All three now use `cargo test --all-targets --all-features --locked`, with
> an explicit `cargo test --doc --all-features --locked` alongside. There are no doctests today —
> the `--doc` run guards the case where someone adds one.

## G0-8 — the negative case ✅ *done 2026-09-23*

*A matrix that only ever passes does not prove it would catch the regression it exists for.* Two
scripts, because neither substitutes for the other:

**[`scripts/check-arch-portability.sh`](../../scripts/check-arch-portability.sh)** — proves nobody
*wrote* a direct backend path. Scans `crates/*/src` and `crates/*/tests` for `::avx2::`,
`::neon::`, `::simd256::`, `::simd128::` and `::portable::`. Two deliberate exemptions: whole-line
comments (so `kem.rs` can explain the rule by naming the forbidden path) and `Cargo.toml` (where
`simd256`/`simd128` are target-gated *features*, which is precisely how a backend should be
chosen). Runs in the `static gates` CI job. Verified to fail on an injected violation, not just to
pass on a clean tree.

**[`scripts/check-arch-negative.sh`](../../scripts/check-arch-negative.sh)** — proves the build
would *notice* if they did. Stages a throwaway copy of the **working tree** (so an uncommitted
regression is caught too), appends a function calling `mlkem768::avx2::generate_key_pair`, and
asserts `cargo check` rejects it:

```
error[E0433]: failed to resolve: could not find `avx2` in `mlkem768`
```

Two guards against a false pass: it **skips on x86-64**, where the backend genuinely exists and
rejecting it would prove nothing; and it requires the compiler output to actually mention
`avx2`/`E0433`, so an unrelated compile error cannot be misread as success. Runs on the aarch64
matrix legs (`if: matrix.arch != 'x86_64'`) and in `verify-layer0.sh`.

## G0-7 — C-toolchain pin ⏸️ *deferred to G5, deliberately*

From [ADR-0019](../adr/0019-transport-authentication.md) condition 3. `aws-lc-rs` compiles C and
assembly at build time, so `rust-toolchain.toml` alone will no longer determine the output bytes.

**Why it is not done now:** `aws-lc-rs` is not a dependency yet — it arrives with the transport
at G5. Pinning a C toolchain for a tree that compiles no C would be ceremony, and it would also
make the G0-T2 baseline *less* informative by mixing two variables. The sequencing rule in
[04-sequencing-and-risks](04-sequencing-and-risks.md) says: establish reproducibility on the
pure-Rust tree first (**done**), then re-verify it as the first acceptance step of the transport
work. That is now a G5 entry task.

**What it will involve at G5:** pin the build environment — a container image with a fixed `cc`
version, referenced from CI *and* from the reproducible-build documentation so an external
verifier can reproduce it. Add `aws-lc-rs` / `aws-lc-sys` to `deny.toml` review (ADR-0019
condition 2) and confirm the **non-FIPS** feature set (condition 1) so CMake, Go and bindgen are
never invoked.

**Acceptance:** `scripts/check-reproducible.sh` still passes after `aws-lc-rs` lands.

## G0-T2 — reproducible builds ✅ *baseline established 2026-09-22*

`scripts/check-reproducible.sh` stages two independent clean copies of the source, builds each at
a canonical path, and compares artifact hashes. It runs in CI and is available locally via
`./scripts/verify-layer0.sh --full`.

**The recipe** (normative, in [`10-development/ci-cd.md`](../10-development/ci-cd.md)):
pinned toolchain + `--locked` + `SOURCE_DATE_EPOCH` + `--remap-path-prefix` + **a canonical build
path**.

> **The canonical build path was the non-obvious part.** A first attempt built at two *different*
> paths and failed. The reason is structural, not a bug: `--remap-path-prefix` takes the absolute
> source path as its argument, so two paths give two different `RUSTFLAGS` strings, and
> `RUSTFLAGS` feeds rustc's `-C metadata` hash, which feeds symbol names. **Erasing the path from
> the output does not erase it from the flag that erased it.** Debian and Nix solve this the same
> way — agree on one build path. Huxplex's is `/tmp/hux-reproducible-build`.

**Result:** `libhux_crypto.rlib` and `libhux_network.rlib` byte-identical across two independent
clean copies.

> ⚠️ **This is a baseline, not a finished property.** It is only *meaningful* once `aws-lc-rs` is
> in the tree. Re-verify as the first acceptance step of the transport work in
> [G5](03-g5-transport.md). If the C toolchain breaks reproducibility in a way pinning cannot
> fix, that is a **stop condition** — see [04-sequencing-and-risks](04-sequencing-and-risks.md)
> R4 — not something to paper over by weakening the requirement.

## G0 exit

| Criterion | Status |
|---|---|
| Workspace migration complete ([00](00-workspace-migration.md)) | ✅ |
| `PrivateKey` no longer prints secrets | ✅ |
| G0-T2 — automated two-build comparison | ✅ |
| G0-T3 — all 81 ignored tests carry a `GATE:` label | ✅ |
| G0-T1 — green on **both architectures in CI** | ✅ green on **three**, with byte-identical derived values |
| G0-T1 negative case — a deliberate `avx2::` call fails the aarch64 job | ✅ G0-8 |

**G0 is CLOSED (2026-09-23).** G0-7 (the C-toolchain pin) remains deliberately deferred to G5.

The gate did its job in the end: it was an *unproven* claim about portability that broke the
repository originally, and the audit found the proof mechanism had never been switched on. It is
now, it is green on three architectures, and it has a negative case proving it would fail if the
break returned. **G1 may begin** — registry first, per
[04-sequencing-and-risks](04-sequencing-and-risks.md) rule 1.

> Audited status, with the commands behind every row:
> [`../20-completion/00-layer0-v1-completion-report.md`](../20-completion/00-layer0-v1-completion-report.md) §3.

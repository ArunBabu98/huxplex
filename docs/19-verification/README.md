# 19 — Verifying Layer 0 yourself

> **For developers and contributors.** This folder tells you how to check that Huxplex's
> Layer-0 foundation actually does what the blueprint claims — on your machine, on your
> architecture, without trusting a CI badge or our word for it.
>
> Principle 15: *"Reproducibility and openness. Neutrality requires verifiability."* A claim you
> cannot check is a claim you should not believe.

## Quick start

```bash
git clone https://github.com/ArunBabu98/huxplex
cd huxplex
./scripts/verify-layer0.sh
```

That runs every automated check and prints a PASS/FAIL summary. It exits `0` only if all of
them pass. Expected runtime: under two minutes on a warm cache.

Add `--full` to include the reproducible-build check (two full release builds, several minutes):

```bash
./scripts/verify-layer0.sh --full
```

Then watch the invariants happen, step by step:

```bash
cargo run -p hux-crypto  --example crypto_walkthrough
cargo run -p hux-network --example network_walkthrough
```

Both programs print what they are doing **and assert it**, so they are demonstrations and tests
at the same time. If one prints its closing banner, the property held on your hardware.

## What you are verifying — and what you are not

**Be clear about the scope.** Huxplex is not a blockchain yet. Layer 0 is the post-quantum
cryptographic and networking substrate everything else will be built on, and even that is not
finished.

| Area | Status | Verifiable today |
|---|---|---|
| ML-DSA-44 signatures, context-bound | 🟢 implemented | ✅ yes |
| ML-KEM-768 + directional HKDF session keys | 🟢 implemented | ✅ yes |
| BIP32 → ML-DSA derivation with key purposes | 🟢 implemented | ✅ yes |
| Domain-separated context strings | 🟢 implemented | ✅ yes |
| Secret hygiene (redaction, zeroize, constant-time) | 🟢 implemented | ✅ yes |
| `PeerId`, signed gossip and DHT envelopes | 🟢 implemented | ✅ yes |
| **Algorithm agility registry** | 🟡 gate **G1** | ❌ not yet |
| **SLH-DSA-128s** | 🟡 gate **G1** | ❌ not yet (24 tests are `#[ignore]`d) |
| **QUIC transport, TLS with ML-DSA certs, live DHT, GossipSub** | 🟡 gate **G5** | ❌ not yet |
| Consensus, state, VM, tokens, agents | 🟡 later gates | ❌ not yet |

**Layer 0 is complete only when G0, G1 and G5 all close.** The build order and the tests that
unlock each gate are in [`../18-implementation-plan/`](../18-implementation-plan/) and
[`../16-action-plan.md`](../16-action-plan.md). For where the project actually stands against
them — audited, with the commands behind every claim — see
[`../20-completion/`](../20-completion/). As of 2026-09-23: **G0 closed; G1 and G5 not started.**

## What each automated check proves

| Check | What it establishes | Why it is in the list |
|---|---|---|
| Formatting is canonical | The tree matches `rustfmt.toml` | Diff noise hides real changes in security-critical code |
| No clippy lints | `-D warnings` across all targets and features | A warning tolerated once is a warning ignored forever |
| Crate layering is downward-only | `hux-network → hux-crypto`, never upward | Layering is what keeps the crypto crate independently auditable and exportable ([repository-structure](../10-development/repository-structure.md)) |
| No arch-specific backend paths | No `::avx2::`, `::neon::`, `::simd256::`, `::simd128::` call in any Rust source | Hardcoding one backend excludes an entire architecture from the validator set. This is the break that started G0 |
| Arch guard catches a regression | On aarch64, an injected `mlkem768::avx2::*` call is **rejected** by the compiler | A check that can only pass proves nothing. This one is verified by deliberately breaking the tree |
| Workspace builds | `--locked`, so the committed `Cargo.lock` is honoured | A build that silently resolves different dependencies is not the build we tested |
| Test suite | **117 tests pass, 81 correctly ignored** | Every ignored test names the gate that un-ignores it (G0-T3) |
| Docs build without warnings | `RUSTDOCFLAGS=-D warnings` | Broken intra-doc links mean the reasoning trail is rotting |
| Crypto walkthrough | The seven properties in [`01-crypto.md`](01-crypto.md) | Demonstration you can read, not just a green tick |
| Network walkthrough | The six properties in [`02-network.md`](02-network.md) | Same |
| Tests are deterministic | The suite passes twice in a row | For an L1, nondeterminism in the crypto path is a **fork risk**, not a flake |
| Builds are reproducible *(`--full`)* | Two independent clean copies produce byte-identical `.rlib`s | A binary nobody can independently reproduce is one everyone has to take on trust |

## Verifying the build is reproducible

```bash
./scripts/check-reproducible.sh
```

It stages two independent clean copies of the source, builds each **at the same canonical path**,
and compares artifact hashes.

> **Why the canonical path matters, and why it is not a fudge.** `--remap-path-prefix` takes the
> absolute source path as its *argument*, so building at two different paths produces two
> different `RUSTFLAGS` strings — and `RUSTFLAGS` feeds rustc's `-C metadata` hash, which feeds
> symbol names. Erasing the path from the output does not erase it from the flag that erased it.
> Debian and Nix solve this the same way: agree on one build path. Huxplex's is
> `/tmp/hux-reproducible-build` (override with `HUX_BUILD_PATH`).

The full recipe is in [`../10-development/ci-cd.md`](../10-development/ci-cd.md). **This baseline
is pure Rust.** When `aws-lc-rs` arrives at G5 it will compile C and assembly, the C toolchain
becomes part of the recipe, and this must be re-verified.

## Verifying on a second architecture

Architecture portability is a **decentralization property** here, not a convenience: a chain
whose crypto builds on only one ISA cannot have a diverse validator set. This is not
hypothetical — the repository once called an AVX2-only code path unconditionally, which broke
every ARM build.

If you have access to both, run the harness on `x86_64` and on `aarch64` and confirm the
walkthroughs print **identical** key, `PeerId` and shared-secret values. They are deterministic
in their seeds, so any difference between architectures is a bug worth reporting immediately.

> **This has been done, and it holds.** CI runs both walkthroughs on `x86_64` Linux, `aarch64`
> Linux and `aarch64` Darwin. Diffing the three transcripts, the only differing lines are the
> architecture name each program prints about itself — every derived value is byte-identical.
> The simd256, simd128 and portable backends provably agree, so a backend difference cannot fork
> the network. Re-run it yourself rather than trusting this paragraph; that is the point of the
> section.

You do not need two machines to check the *guard*, though. On aarch64:

```bash
./scripts/check-arch-negative.sh
```

It stages a throwaway copy of the tree, injects the exact call that once broke every ARM build
(`mlkem768::avx2::generate_key_pair`), and asserts the compiler rejects it with `E0433`. If that
ever passes, the portability guarantee is not being enforced and the matrix would not catch a
recurrence.

## If a check fails

1. Re-run with the transcript: the script prints the failing command's output inline.
2. Confirm your toolchain matches `rust-toolchain.toml` (`rustup show`). A different compiler
   version is the most common cause.
3. Check you are on a clean checkout: `git status --porcelain` should be empty.
4. If it still fails, that is worth an issue — include your `uname -m`, `rustc --version`, and
   the transcript. A failure on hardware we do not have is more valuable to us than a pass on
   hardware we do.

## Deeper verification

| Guide | Covers |
|---|---|
| [`01-crypto.md`](01-crypto.md) | Manual crypto checks: sizes against FIPS, tamper trials, domain separation, secret hygiene, backend portability |
| [`02-network.md`](02-network.md) | Manual network checks: identity binding, envelope forgery, cross-network and cross-shard replay |

## Reading the source yourself

The whole of Layer 0 is small enough to read in an afternoon — that is deliberate.

| Path | What |
|---|---|
| [`crates/hux-crypto/src/`](../../crates/hux-crypto/) | ML-DSA, ML-KEM, BIP32, contexts, secret types (`lib.rs` is 36 lines — it is just module declarations) |
| [`crates/hux-crypto/tests/`](../../crates/hux-crypto/) | The conformance suite, split by concern. Integration tests, so they reach only the **public** API |
| [`crates/hux-network/src/`](../../crates/hux-network/) | `PeerId`, gossip and DHT envelopes, topics |
| [`crates/hux-network/tests/`](../../crates/hux-network/) | Identity, topic and envelope conformance |
| [`../15-specifications/02-cryptography-spec.md`](../15-specifications/02-cryptography-spec.md) | The normative contract the code must satisfy |
| [`../adr/`](../adr/) | Why each choice was made, and what was rejected |

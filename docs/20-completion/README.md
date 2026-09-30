# 20 — Completion status

> **What this folder is.** A dated, evidence-backed answer to one question: *is Layer 0 for
> version 1 complete?* Everything here is verified by running the tree, not by reading the
> blueprint. Where a claim elsewhere in `/docs` disagrees with what the machine did, this folder
> records the machine.
>
> It is deliberately separate from [`16-action-plan.md`](../16-action-plan.md) (which says what
> the gates *are*) and [`18-implementation-plan/`](../18-implementation-plan/) (which says how
> the open ones get built). This folder says only *where we actually are*.

## The answer

**No. Layer 0 for v1 is not complete.** It is roughly **35%** complete: of its **four** gates, one
is closed, one is about half built, and two have not started.

| Gate | Layer-0 scope | Status | Completion |
|---|---|---|---|
| **G0** · Repository health | workspace, portability, reproducibility, secret hygiene | 🟢 **CLOSED 2026-09-23** — all four exit criteria green in CI on three architectures | 100% |
| **G1** · Crypto core + agility registry | `(role, version)` registry, SLH-DSA-128s, KATs, hybrid KEX | 🟦 **in progress** — C1–C5 (registry) and the hash/KDF half of C10 done; C6–C9, C11 and the rest of C10 open | ~55% |
| **G2a** · Wire encoding | canonical `Codec` + canonical decode for `GossipMessage`, `DhtEntry`, carrying the `(role, version)` descriptor | 🔴 **not started** — added to Layer 0 by [ADR-0022](../adr/0022-g2-split-wire-and-consensus-encoding.md) | 0% |
| **G5** · Transport | libp2p/QUIC, ML-DSA TLS certificates, live DHT, GossipSub | 🔴 **not started** — N0 ✅ closed, identity settled by [ADR-0021](../adr/0021-peer-identity-across-libp2p.md); entry is now **G2a** | ~2% |

> **What remains, in order:** G1's **C6** (sizes behind the descriptor) → **C9** (split
> deterministic signing) → **C10** (the KATs — C9 blocks it, and it unblocks
> [issue #12](https://github.com/ArunBabu98/huxplex/issues/12)) → **C7/C8** (SLH-DSA) → the
> **hybrid KEX** → **G1 closes** → **G2a** (two wire types) → **G5**. Full detail with acceptance
> criteria: [`01-outstanding-work.md`](01-outstanding-work.md).

> ✅ **Both blocking decisions were taken on 2026-09-30.**
> 1. **[ADR-0021](../adr/0021-peer-identity-across-libp2p.md)** — peer identity. **One identity,
>    two encodings**: the libp2p `PeerId` is an identity-coded multihash wrapping Huxplex's, so
>    there is no second identity and no binding to prove. ADR-0012 rule 5 is satisfied as written.
>    N1 is unblocked.
> 2. **[ADR-0022](../adr/0022-g2-split-wire-and-consensus-encoding.md)** — the ordering gap. G2
>    splits along the wire/state line; **Layer 0 is now G0 + G1 + G2a + G5**, which is achievable
>    as stated. G2b stays before G3.
>
> No decision currently blocks any Layer-0 work. Everything left is implementation.

The definition being measured against is
[`18-implementation-plan/04-sequencing-and-risks.md` § *What "Layer 0 complete" means*](../18-implementation-plan/04-sequencing-and-risks.md#what-layer-0-complete-means),
which is the project's own three-row contract for this question. Nothing here invents a new bar.

**The wider v1** — the devnet of [`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md)
— is further out still: 3 of its ~20 Definition-of-Done boxes are checked, and gates G2, G3, G4,
G6 and G7 have no code at all. Layer 0 is the *floor* of v1, not v1.

## How G0 closed — and what the original audit found

The audit that opened this folder found that **the CI G0 depends on had never executed against
this code.** `ci.yml` triggered only on `push: branches: [master]` and `pull_request`, and all
Layer-0 work sat on a branch with no PR. The matrix, the layering gate, the reproducible-build
job and cargo-deny were configuration, not results; the newest run of any kind was 2026-09-12,
before the workspace existed. The matrix was not "unproven until it runs" — it was *unable* to
run.

That was fixed by opening [PR #9](https://github.com/ArunBabu98/huxplex/pull/9), which merged as
`7912117`. First run, all green, and the cross-architecture result is the strong one:

| Leg | `uname -m` | Tests |
|---|---|---|
| `ubuntu-latest` | `x86_64` | 115 passed · 0 failed · 81 ignored |
| `ubuntu-24.04-arm` | `aarch64` | 115 passed · 0 failed · 81 ignored |
| `macos-latest` | `arm64` | 115 passed · 0 failed · 81 ignored |

Diffing the walkthrough output across all three legs, **the only differing lines are the
architecture name each program prints about itself.** Every derived value — the five HD purpose
seeds, `PeerId`s, shared secrets — is byte-identical. The simd256 / simd128 / portable backends
are output-identical in practice, not merely by claim.

The second half of G0-T1 then landed as **G0-8**: `scripts/check-arch-portability.sh` (nobody
wrote a backend path) and `scripts/check-arch-negative.sh` (the build would reject one if they
did — verified by injecting the original break and confirming `E0433`).

## What is proven today

Verified on **2026-09-23**, `aarch64-apple-darwin` (Apple M4), plus the three CI legs:

- `./scripts/verify-layer0.sh` — **12 of 12 checks PASS**
- `./scripts/check-reproducible.sh` — **byte-identical** `.rlib`s from two independent clean copies
- `cargo deny check advisories licenses bans sources` — **ok** on the workspace lockfile
- **115 tests pass, 0 fail, 81 correctly ignored**, every ignore carrying its `GATE:` label
- Identical results and identical derived values on **x86-64 Linux, aarch64 Linux and aarch64 Darwin**

That is a real, defensible primitive layer with a working safety net under it. It is still not
Layer 0 — G1 and G5 are the other two thirds.

## Contents

| File | What it holds |
|---|---|
| [`00-layer0-v1-completion-report.md`](00-layer0-v1-completion-report.md) | The full audit — evidence, gate-by-gate findings, and the verdict with its reasoning |
| [`01-outstanding-work.md`](01-outstanding-work.md) | Exactly what remains to be **completed** and **tested**, in the order it should be done |

## How to refresh this folder

These documents are a snapshot, and a snapshot rots. Re-run the evidence before trusting a
figure older than a few commits:

```bash
./scripts/verify-layer0.sh --full          # every check, including the two release builds
cargo test --all-features --locked         # the 115 / 81 counts
cargo deny check advisories licenses bans sources
gh run list --branch "$(git branch --show-current)"   # has CI actually run?
```

Update the dated header of each file when you do.

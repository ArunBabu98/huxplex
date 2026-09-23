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

**No. Layer 0 for v1 is not complete.** It is approximately **one third** complete: one of its
three gates is nearly closed, and two have not been started.

| Gate | Layer-0 scope | Status | Completion |
|---|---|---|---|
| **G0** · Repository health | workspace, portability, reproducibility, secret hygiene | 🟦 **near-closed** — every local check green; **two CI items open** | ~90% |
| **G1** · Crypto core + agility registry | `(role, version)` registry, SLH-DSA-128s, KATs, hybrid KEX | 🔴 **not started** — 0 of 11 tasks | 0% |
| **G5** · Transport | libp2p/QUIC, ML-DSA TLS certificates, live DHT, GossipSub | 🔴 **not started** — entry spike not run | 0% |

The definition being measured against is
[`18-implementation-plan/04-sequencing-and-risks.md` § *What "Layer 0 complete" means*](../18-implementation-plan/04-sequencing-and-risks.md#what-layer-0-complete-means),
which is the project's own three-row contract for this question. Nothing here invents a new bar.

**The wider v1** — the devnet of [`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md)
— is further out still: 3 of its ~20 Definition-of-Done boxes are checked, and gates G2, G3, G4,
G6 and G7 have no code at all. Layer 0 is the *floor* of v1, not v1.

## The single most important finding

> **The CI that G0 depends on has never executed against this code.**

`.github/workflows/ci.yml` triggers on `push: branches: [master]` and `pull_request`. All five
commits of the workspace split, the architecture matrix, the layering gate and the
reproducible-build job live on `layer0/g0-workspace-and-verification`, which is pushed but has
**no open pull request**. The most recent `CI` run of any kind is **2026-09-12**, ten days before
the workspace existed.

So the dual-architecture matrix that G0-T1 is defined by is not merely "unproven until it runs" —
it is *structurally unable to run* in its present configuration. Opening a PR for the branch is a
five-minute action that converts the largest open question in G0 into a result.

## What is genuinely proven

Re-verified on **2026-09-23**, on `aarch64-apple-darwin` (Apple M4), commit `63ad3d5`:

- `./scripts/verify-layer0.sh` — **9 of 9 checks PASS**
- `./scripts/check-reproducible.sh` — **byte-identical** `.rlib`s from two independent clean copies
- `cargo deny check advisories licenses bans sources` — **ok** on the workspace lockfile
- **115 tests pass, 0 fail, 81 correctly ignored**, every ignore carrying its `GATE:` label

That is a real, defensible primitive layer. It is not Layer 0.

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

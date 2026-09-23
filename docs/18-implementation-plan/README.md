# 18 — Implementation Plan: Layer 0

> **Scope: Layer 0 only** — the post-quantum crypto suite and the networking stack. Concretely,
> closing **G0** (repository health), **G1** (crypto core + agility registry) and **G5**
> (transport + P2P) from [`16-action-plan.md`](../16-action-plan.md).
>
> This is the *how*. [`16-action-plan.md`](../16-action-plan.md) is the *what and in what order*
> across all twelve gates; the ADRs are the *why*. Where this plan and an ADR disagree, **the ADR
> wins** and this plan is the thing to fix.

## Why this folder exists

Every architectural decision needed to build L0 is now closed. What remained was the gap between
"decided" and "buildable": which file, in what order, proven by which test. That gap is where
projects quietly substitute one design for another, so it is written down before any code moves.

## Contents

| File | Covers |
|---|---|
| [`00-workspace-migration.md`](00-workspace-migration.md) | Single crate → Cargo workspace (`hux-crypto`, `hux-network`). Happens **first** — everything else lands in the new layout |
| [`01-g0-repository-health.md`](01-g0-repository-health.md) | Closing G0: test-file split, dual-architecture CI, reproducible builds, secret-type hygiene |
| [`02-g1-crypto-core.md`](02-g1-crypto-core.md) | The agility registry, role dispatch, suite-parameterized sizes, SLH-DSA, KAT fixtures, differential tests |
| [`03-g5-transport.md`](03-g5-transport.md) | The `libp2p-quic` spike, ML-DSA certificates, ALPN, amplification budget, swarm, DHT, gossip |
| [`04-sequencing-and-risks.md`](04-sequencing-and-risks.md) | Critical path, what can run in parallel, the five things most likely to go wrong, and the stop conditions |

## The decisions this plan implements

All closed; none is re-opened here.

| ADR / decision | What it binds |
|---|---|
| [ADR-0018](../adr/0018-signature-role-profiles.md) | Suite descriptor is `(role, version)`; five roles; seven versioning rules |
| [ADR-0019](../adr/0019-transport-authentication.md) | Native ML-DSA-44 TLS certificates over QUIC; ALPN; `aws-lc-rs` on five conditions |
| [ADR-0005 amendment](../adr/0005-build-strategy.md) | Workspace split happens at G0 |
| [ADR-0014 amendment](../adr/0014-validator-key-management.md) | BIP32 purpose level; rotation at 50,000 signatures or 7 days |
| [ADR-0002 review note](../adr/0002-cryptographic-parameter-set.md) | v1 stays on ML-DSA-44 for every role |
| [Crypto spec](../15-specifications/02-cryptography-spec.md) §3, §4.1, §5 | Hedged signing; network-generalized contexts; initiator-first ordering |
| Dependency policy | `libcrux` (verified) for protocol, `aws-lc-rs` for TLS, `fips205` for SLH-DSA, `slh-dsa` as CI oracle |

## Ground rules for this work

1. **The gate tests are the definition of done**, not the task list. A gate closes when its
   🎯 tests are green in CI, on both architectures.
2. **No test is deleted.** G0's standing rule. A test that must change is changed with a
   justification in the commit message; a test that cannot yet pass is `#[ignore]`d **with its
   gate label**.
3. **Never call an architecture-specific backend path** (`mlkem768::avx2::*`, `::neon::*`).
   G0's other standing rule — architecture portability is a decentralization property.
4. **One decision per commit, and the ADR reference in the message.** If an implementation step
   requires a decision no ADR covers, stop and write the ADR first (principle 16).
5. **Every task below carries its acceptance criterion.** If it does not, it is not ready to
   start.

## Status legend

⬜ not started · 🟦 in progress · ✅ done · ⏸️ blocked · 🔬 spike (timeboxed, may change the plan)

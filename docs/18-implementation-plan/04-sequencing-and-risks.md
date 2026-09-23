# 04 — Sequencing, risks, and stop conditions

## Critical path

```
W1 → W2 → W3/W4/W5        workspace migration
  └→ G0-6 (secret leak)   ← can run immediately, independent
  └→ G0-5 (dual-arch CI)
  └→ G0-7 → G0-T2         C toolchain pin → reproducible builds

G0 closed
  └→ G1  (C1…C11)         registry first, then primitives
       └→ G2 …            canonical encoding — NOT in this plan
            └→ G5 (N0 first, then N1…N11)
```

Two things can start **immediately and in parallel** with the migration, because neither touches
the code being moved:

- **G0-6** (the `PrivateKey` `Debug` leak) — a small, self-contained fix on a live bug.
- **N0** (the `libp2p-quic` spike) — pure investigation, no code in the tree.

Everything else is sequential. The temptation to start G1's registry during the migration should
be resisted: a mechanical file move and a new abstraction in the same diff are unreviewable, and
the 108 tests only prove the move was clean if nothing else changed.

## Ordering rules that are not obvious

1. **Registry before primitives.** G1 builds `AlgoSuite` and the traits *before* SLH-DSA, even
   though SLH-DSA is more visibly "progress." A primitive written before the registry will be
   called directly from somewhere, and that call site will survive.
2. **Role dimension before G2.** [ADR-0011](../adr/0011-canonical-serialization.md) freezes
   canonical encoding at G2. The `(role, version)` descriptor must be settled before then or it
   is a state migration.
3. **Reproducibility baseline before `aws-lc-rs`.** Establish G0-T2 on the pure-Rust tree, then
   re-verify after the C dependency lands. Doing it only afterwards conflates two causes of
   failure.
4. **N0 before any certificate code.** See [03](03-g5-transport.md).

## The five things most likely to go wrong

### R1 — C6 (hard-coded sizes) is done shallowly

**Why it is likely:** removing `[u8;1312]` looks like a rename, and the code will compile and pass
every existing test while still being fundamentally fixed to one scheme.

**Detection:** G1-T1 — if registering a dummy V2 requires editing a size constant, it is not done.

**Consequence if missed:** the agility thesis is false while appearing true, and it is discovered
at the first real suite rotation, i.e. years later under pressure.

### R2 — the `libp2p-quic` integration is closed to us

**Why it is likely:** `libp2p_quic::Config` constructs its TLS config internally, and libp2p has
no reason to support a non-libp2p certificate format.

**Detection:** N0, deliberately first.

**Fallback:** ADR-0019's certificate-extension bridge. **Never** the exporter-binding phase — it
exists only to compensate for a classical binding the accepted design removes.

### R3 — the amplification margin is silently spent

**Why it is likely:** ≈7,970 B against ≈8,100 B is ~130 bytes of headroom. Any future addition —
ML-DSA-65 (+1.3 KB), a second certificate, an SLH-DSA proof (7,856 B) — breaks it, and the symptom
is a handshake that works on a LAN and fails for NAT'd peers.

**Detection:** G5-T6, asserted on the wire, re-run whenever the suite changes.

### R4 — `aws-lc-rs` breaks reproducible builds in a way pinning cannot fix

**Why it is possible:** C and assembly compilation is sensitive to toolchain version, host
headers, and build flags in ways `Cargo.lock` does not capture.

**Detection:** G0-T2 re-verified after the dependency lands (rule 3 above).

**Stop condition.** If a pinned container cannot produce byte-identical artifacts, that is a
genuine conflict with principle 15, and the decision goes back to the options in
[ADR-0019](../adr/0019-transport-authentication.md)'s addendum — most likely the
certificate-extension bridge, or investing in a libcrux-backed `CryptoProvider`. **Do not** paper
over it by weakening the reproducibility requirement; that requirement is why anyone can trust a
binary they did not build.

### R5 — scope creep into G6 work

**Why it is likely:** erasure-coded block propagation, iVRF, and quorum-certificate aggregation
are all *more interesting* than the registry, and all three now have accepted analysis behind
them. That is exactly what makes them dangerous here.

**Detection:** the [v1 scope contract](../15-specifications/06-v1-scope.md) — if it is not in §2,
it is out by definition, and moving it in requires an RFC.

**Consequence if missed:** risk #1 in the executive summary, *"scope collapse — building the AI
economy before a working chain,"* in its L0 form.

## Stop conditions

Work stops and a decision returns to the architect if:

- **N0 finds no viable `libp2p-quic` integration** — the fallback changes an accepted ADR.
- **G0-T2 cannot be met with `aws-lc-rs`** — see R4.
- **A libcrux ↔ `aws-lc-rs` or `fips205` ↔ `slh-dsa` differential test disagrees** — that is
  either a bug in a dependency or a misuse of one, and shipping past it is not an option.
- **Any implementation step needs a decision no ADR covers** — write the ADR first (principle 16).

## What "Layer 0 complete" means

| | Criterion | Status (2026-09-23) |
|---|---|---|
| **G0** | Workspace split; dual-architecture CI green; reproducible builds demonstrated by an automated two-build comparison; no secret printable via `Debug` | 🟢 **CLOSED 2026-09-23** — all four, green in CI on three architectures |
| **G1** | Registry is the only path to a primitive; SLH-DSA green with its tests un-ignored; KATs byte-exact on both architectures; **G1-T1** and **G1-T6** green | 🟦 C1–C5 done — the registry is the only path to a primitive, enforced by CI. C6–C11 open |
| **G5** | 5 nodes mutually authenticate over QUIC with ML-DSA certificates, discover via Kademlia, gossip under 20% loss; **G5-T6** and **G5-T7** green | 🔴 not started — N0 ✅ closed (quinn direct); N1 blocked on an identity ADR |

> This table is the definition of the term. The audit measuring against it, with the commands
> behind every status above, is [`../20-completion/`](../20-completion/).
> *(The G1 row said "24 tests"; the SLH-DSA ignored count is 22 as of `63ad3d5`.)*

At that point L0 is real code rather than primitives, and G2 (canonical encoding) is the next
gate — outside this plan.

## Keeping this plan honest

The September 2026 review had **two findings overturned within weeks** of being written: the QUIC
amplification arithmetic, and the claim that QUIC could not get ML-DSA authentication (rustls
shipped it two weeks later). Both were correct when written.

So: **re-check the fast-moving dependencies immediately before the gate that consumes them**, not
only at review time. Specifically — `rustls` and `draft-ietf-tls-mldsa` before N1;
`rust-libp2p` before N0; `libcrux` and `fips205` before C7. If a re-check changes an answer,
amend the ADR before writing code against the old one.

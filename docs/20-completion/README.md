# 20 — Completion status

> **What this folder is.** A dated, evidence-backed answer to one question: *is Layer 0 for
> version 1 complete?* Everything here is verified by running the tree, not by reading the
> blueprint. Where a claim elsewhere in `/docs` disagrees with what the machine did, this folder
> records the machine.
>
> It is deliberately separate from [`16-action-plan.md`](../16-action-plan.md) (which says what
> the gates *are*) and [`18-implementation-plan/`](../18-implementation-plan/) (which says how
> the open ones get built). This folder says only *where we actually are*.

## The answer — 2026-10-07

**Layer 0 is implemented, and every Layer-0 gate test passes — locally. It is not yet *closed*.**
Standing rule #1 of [`16-action-plan.md`](../16-action-plan.md#4-standing-rules) is that *a gate
is done when its high-concept tests pass in CI, not when the code is written*, and the branch
carrying G1's remainder, G2a and G5 (`layer0/g1-remaining`) has not run in CI yet. One green CI
run on the three-architecture matrix closes G1, G2a and G5 together.

| Gate | Layer-0 scope | Status |
|---|---|---|
| **G0** · Repository health | workspace, portability, reproducibility, secret hygiene | 🟢 **CLOSED 2026-09-23** — green in CI on three architectures. **G0-7** (C-toolchain pin) now landed with G5: the reproducible job runs in a digest-pinned container and compares the AWS-LC rlib too |
| **G1** · Crypto core + agility registry | `(role, version)` registry, SLH-DSA-128s, KATs, hybrid KEX | 🟩 **implemented, green locally** — C1–C11 and B5 done; G1-T1…T6 all green (T6's binding half via G2a) |
| **G2a** · Wire encoding | canonical `Codec` + decode for `GossipMessage`, `DhtEntry`, carrying the descriptor | 🟩 **implemented, green locally** — G2-T1, T2, T4 (10⁶ random inputs) green; wire format frozen by golden vectors |
| **G5** · Transport | libp2p/QUIC, ML-DSA TLS certificates, live DHT, GossipSub | 🟩 **implemented, green locally** — N0b–N11 done; G5-T1…T7 green; the 5-node exit test passes |

> **What remains for Layer 0:** push the branch, open a PR, and have the CI matrix go green —
> `x86_64`, `aarch64`, `arm64` — plus the new containerised reproducible-build job. Nothing else
> is outstanding. The full record, including what the work *found*, is in
> [`01-outstanding-work.md`](01-outstanding-work.md).

## What was proven, and how

Verified on **2026-10-07**, `aarch64-apple-darwin` (Apple M4), rustc 1.85.0:

- `./scripts/verify-layer0.sh` — **13 of 13 checks PASS**
- `./scripts/check-reproducible.sh` — **byte-identical** `libhux_crypto`, `libhux_types`,
  `libhux_network` **and `libaws_lc_sys`** (AWS-LC's compiled C) from two independent clean copies
- `cargo deny check advisories licenses bans sources` — **ok**
- `cargo test --all-targets --all-features --locked` — **260 passed · 0 failed · 59 ignored**.
  Every remaining ignore is `GATE: G6+` (33) or `GATE: G10` (26) — none is Layer 0.

### Per gate

| Gate test | Where | Result |
|---|---|---|
| G1-T1 rotation without migration | `hux-crypto/src/suite/registry.rs` | v2 table flips `QuorumCert` to SLH-DSA; v1 objects still verify; no other role moves |
| G1-T2 cross-context replay | `hux-crypto/tests/context_registry.rs` | 26 contexts × both networks, **650 ordered pairs**, enumerated from the registry |
| G1-T3 KAT byte-exactness | `tests/kat/*.kat` | ML-DSA-44, ML-KEM-768, SLH-DSA-128s, hybrid — **reproduced by RustCrypto** (and aws-lc for ML-DSA) |
| G1-T4 unknown ids fail closed | `tests/suite_registry.rs` | green since C3 |
| G1-T5 hybrid survives a broken classical half | `src/kem/hybrid.rs` | X25519 forced constant; every ML-KEM bit still reaches the key |
| G1-T6 role confusion | `hux-network/tests/wire_encoding.rs` | relabelled role refused, and the signature does not verify over the relabelled preimage |
| G2-T1 / T2 / T4 | `hux-network/tests/wire_encoding.rs` | round trip both ways; overlong varints, trailing bytes, unknown ids, mis-sized keys, every truncation refused; 10⁶ random + 2×10⁴ mutated inputs |
| G5-T1 no downgrade | `hux-network/tests/transport.rs` | classical-only KEX, MITM cert, missing client cert, wrong ALPN — all refused in the handshake |
| G5-T2 `PeerId` bound to key | `transport.rs`, `network.rs` | impostor with a copied certificate refused, both directions |
| G5-T3 amplification bounded | `network.rs` | real attacker peer floods 30 bad messages; banned, disconnected, nothing forwarded |
| G5-T4 loss + partition | `network.rs` | 20% datagram loss, then a partition healed — all 5 nodes converge |
| G5-T5 live DHT | `network.rs` | squatting, re-keying and cross-network records refused by every node |
| G5-T6 3× amplification | `transport.rs` | **measured on the wire**: 2,744 B in → ≤ 8,232 B budget; first flight ≈ 8,080 B (≈ 150 B margin) |
| G5-T7 TLS ≠ protocol signatures | `transport.rs`, `hux-crypto/tests/ml_dsa_differential_aws_lc.rs` | every registry context, both directions; the TLS context pinned empty |
| G5 exit | `network.rs` | 5 nodes discover via Kademlia, mutually authenticate, gossip, sustain sessions |

## What the work found

Implementation contradicted the plan in five places, each recorded where it lives:

1. **G5-T6's margin was ≈ 20 B, not ≈ 130 B**, and briefly negative — quinn sends a
   `NEW_CONNECTION_ID` packet inside the pre-validation window and, by design (quinn #1082), sends
   a full datagram whenever *any* budget remains. Fixed by 4-byte connection IDs and Initial
   padding of 1,372 B (the largest that fits a 1,420-byte IPv6 tunnel MTU). ADR-0019 amended.
2. **TLS resumption silently never happened** with a per-dial client config: rustls resumes only
   under the same verifier `Arc`. Fixed by caching dial configs per peer; N7's test now proves
   resumption on the wire rather than assuming it.
3. **libp2p 0.56, not 0.57**, keeps the pinned rustc 1.85 — ADR-0021's identity mechanism works
   unchanged on `libp2p-identity` 0.2.14. `multibase` is held at 0.9.2 because `base45` 3.2
   requires rustc 1.88 without declaring it.
4. **The context registry existed only as test lists**, one of which still called the retired
   `tls:handshake` context canonical. It is now code (`hux_crypto::context`).
5. **DHT records and their role.** A record is keyed by its signer's `PeerId`, so a node signs its
   own with the key its `PeerId` comes from — the **`Transport`**-purpose key — while spec §5 puts
   `dht:entry` under the **`Transaction`** role. Open; see
   [`01-outstanding-work.md`](01-outstanding-work.md#open-items).

**The wider v1** — the devnet of [`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md)
— remains well beyond Layer 0: G2b, G3, G4, G6 and G7 have no code. Layer 0 is the *floor* of v1.

## Contents

| File | What it holds |
|---|---|
| [`00-layer0-v1-completion-report.md`](00-layer0-v1-completion-report.md) | The 2026-09-23 audit — evidence, gate-by-gate findings, verdict. A dated record, with an update banner |
| [`01-outstanding-work.md`](01-outstanding-work.md) | The path that was followed, task by task, as built; open items |

## How to refresh this folder

These documents are a snapshot, and a snapshot rots. Re-run the evidence before trusting a
figure older than a few commits:

```bash
./scripts/verify-layer0.sh --full          # every check, including the two release builds
cargo test --all-targets --all-features --locked   # the 260 / 59 counts
cargo deny check advisories licenses bans sources
gh run list --branch "$(git branch --show-current)"   # has CI actually run?
```

Update the dated header of each file when you do.

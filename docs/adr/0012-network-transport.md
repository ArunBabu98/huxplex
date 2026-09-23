# ADR-0012: Network transport (libp2p / QUIC) + PQ-hybrid handshake

- Status: Accepted
- Date: 2026-06-21
- Deciders: Founding architect, networking

## Context

The architecture docs and readme assert "libp2p / QUIC" transport and a PQ-TLS handshake, but no
ADR records the decision, and the code only defines *message types* (`GossipMessage`, `DhtEntry`,
`GossipTopic`) and `PeerId` — there is **no transport, swarm, or peer state machine** yet
(🟡, per the executive summary). The crypto module already simulates a hybrid handshake using
context string `huxplex-{network}:tls:handshake:v1` and the ML-KEM-768 + HKDF directional
derivation, so the design intent exists; this ADR makes it canonical before the swarm is built.

Forces:
- **PQ confidentiality now** — transport must resist harvest-now-decrypt-later, i.e. a quantum
  adversary recording today's traffic. This means a PQ (or hybrid) key exchange, not classical
  TLS.
- **Don't reinvent P2P** — peer discovery, NAT traversal, multiplexing, and gossip are huge;
  reusing a mature stack (libp2p) is consistent with [ADR-0005](0005-build-strategy.md) (custom
  Rust workspace, but leverage existing building blocks).
- **Identity binding** — the transport identity MUST be the ML-DSA-44 key that yields `PeerId`,
  not a separate ad-hoc transport key.
- **Bandwidth** — ML-DSA-44 signatures are 2,420 B; the transport/gossip layer must tolerate and
  amortize this (batching, message IDs, not re-signing on every hop).

## Options

- **A — Raw QUIC (quinn) + custom overlay.** Full control, minimal deps. *Cost:* we must build
  discovery, gossipsub, Kademlia, peer scoring ourselves — months of undifferentiated work.
- **B — libp2p (rust-libp2p) over QUIC, with a custom security upgrade for the PQ-hybrid
  handshake.** Reuse gossipsub/Kademlia/identify/NAT; our `GossipTopic`/`DhtEntry` types already
  mirror libp2p's gossipsub/Kademlia model. *Cost:* libp2p's default security transports (Noise/
  TLS) are classical; we must add a hybrid handshake and bind it to the ML-DSA-44 identity.
- **C — Wait and design our own everything.** Maximum sovereignty. *Cost:* violates the
  anti-scope-collapse rule; reinvents proven infrastructure.

## Decision

**Option B — rust-libp2p over QUIC, with a PQ-hybrid handshake bound to the ML-DSA-44 identity.**

1. **Transport:** QUIC (UDP) as primary; TCP fallback. Multiplexing via QUIC streams.
2. **Discovery/routing:** libp2p Kademlia DHT; our existing `DhtEntry` (ML-DSA-44 signed) is the
   record format, with the DHT **key = `PeerId`** (already asserted by a test).
3. **Messaging:** libp2p GossipSub; our `GossipTopic` strings and per-message ML-DSA-44
   signatures (`gossip_context`) are the application-layer authentication, *in addition to*
   transport security.
4. **Handshake (suite v1):** hybrid **X25519 + ML-KEM-768** key agreement → HKDF-SHA-256 session
   key (the directional derivation already in `kem.rs`), with the transcript authenticated by an
   **ML-DSA-44** signature over context `huxplex-{network}:tls:handshake:v1`. Both a classical and
   a PQ KEM must be broken to compromise a session.
5. **Identity:** the libp2p peer identity is derived from the node's **ML-DSA-44** key so it
   equals `PeerId = SHAKE-256(pk)[..32]` (ADR-0010); no separate transport identity key.
6. The peer lifecycle state machine and scoring are specified in
   [`docs/15-specifications/05-network-wire-protocol.md`](../15-specifications/05-network-wire-protocol.md).

## Consequences

- ➕ Reuses battle-tested discovery/gossip/routing; we build only the differentiator (PQ-hybrid
  security + ML-DSA identity binding).
- ➕ Defense in depth: transport encryption *and* application-layer signed messages.
- ➕ Forward secrecy against both classical and quantum adversaries (hybrid).
- ➖ Integrating a custom security upgrade into libp2p is non-trivial and must be carefully
  reviewed (it is security-critical).
- ➖ libp2p is a large dependency surface (audit/`cargo-deny` burden).
- ➖ GossipSub + 2,420 B signatures stress bandwidth; message-ID dedup and batching are required,
  not optional (ties to the PQ-bloat risk #2).

## Review note — 2026-09-22

The Layer-0 technology review
([`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md))
**confirms Option B** — libp2p remains the right base, and litep2p is still non-default even
inside the Polkadot SDK. Three refinements are recorded for follow-on ADRs:

1. **Consequence 1 of this ADR is now a certainty, and only half-solved upstream.** The libp2p
   PQ effort ([specs#727](https://github.com/libp2p/specs/pull/727),
   [rust-libp2p#6481](https://github.com/libp2p/rust-libp2p/pull/6481)) standardizes
   `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` — **confidentiality only**. The spec states
   that *"authentication stays classical: in libp2p the identity key signs the static key."*
   Rule 5 above (`PeerId` derived from the ML-DSA-44 key) will therefore **never** be satisfied
   upstream. Huxplex carries a custom security transport regardless; plan it as a work item and
   an upstream contribution (an additional protocol ID), not as a risk. Note also that upstream
   PQ work is on **Noise**, not QUIC/TLS — QUIC gets X25519MLKEM768 free via rustls but gets
   ML-DSA authentication from nowhere, which re-opens the QUIC-vs-Noise sub-decision.
2. **QUIC's 3× anti-amplification limit is unaddressed by this ADR, but is not a problem as
   specified.** The responder's first flight (`ServerHello` ≈ 2,500 B: ML-KEM ct 1,088 +
   ML-DSA pk 1,312 + framing) sits comfortably inside the ~3,900 B budget a ≈1,300 B
   `ClientHello` buys; the 2,420 B transcript signatures travel in the *third and fourth*
   flights, after the address is validated. ML-DSA-65 would still fit (≈ 3,100 B). Self-certifying
   `PeerId`s — no X.509 chain, against ~17.5 KB for a PQ chain in TLS — are why.
   *(A 2026-09-22 draft of this note miscounted `Finished (R)` as part of the first flight and
   reported a deficit; corrected same day.)*

   What **is** undecided is prior to that: **does Huxplex's handshake replace QUIC's TLS crypto
   layer, or run as an application-level handshake over a standard QUIC + rustls
   `X25519MLKEM768` connection?** The amplification budget binds only in the first case. The
   second gets the hybrid KEX from upstream for free and never touches the limit, at the cost of
   mandatory channel binding (a TLS exporter mixed into the ML-DSA transcript) and pre-auth
   connection rate-limiting. Tracked as [R-B12](../11-research/open-problems.md); decide before
   G5 implementation.
3. **Decision 3 (GossipSub for messaging) should be split by traffic shape.** Erasure-coded
   broadcast — ethp2p (succeeding GossipSub in late 2026), RaptorCast, Turbine, Optimum P2P —
   is now standard for large single-source objects, and ML-DSA's 2,420 B signatures put Huxplex
   in exactly that regime. GossipSub stays correct for mempool, intents and control traffic,
   where its peer scoring and attack resilience are the point. Proposed `adr/0020-*`.

## Amendment — 2026-09-22: rules 4 and 5 superseded by ADR-0019

[ADR-0019](0019-transport-authentication.md) replaces the bespoke handshake with standard TLS 1.3
carrying **native ML-DSA-44 certificates** (`draft-ietf-tls-mldsa`, `SignatureScheme` 0x0904;
shipped in rustls 0.23.44 on 2026-09-07). The rest of this ADR — libp2p, QUIC, Kademlia with
signed `DhtEntry`, GossipSub with signed envelopes — **stands unchanged**.

| Rule | Status |
|---|---|
| 1 Transport (QUIC primary, TCP fallback) | ✅ unchanged |
| 2 Discovery (Kademlia, signed `DhtEntry`) | ✅ unchanged |
| 3 Messaging (GossipSub + signed envelopes) | ✅ unchanged (but see the §5.1 block-path guardrail in the wire spec) |
| **4 Handshake (bespoke hybrid + ML-DSA transcript signature)** | ⚠️ **superseded** — TLS 1.3 does the key agreement (`X25519MLKEM768`) and the authentication (ML-DSA `CertificateVerify`) |
| **5 Identity ("no separate transport identity key")** | ⚠️ **amended** — the transport key is now `KeyPurpose::Transport` (`m/44'/931931'/4'/0'/{index}'`), still an ML-DSA-44 key in the same hierarchy, still yielding `PeerId = SHAKE-256(pk)[..32]`. The *intent* (no ad-hoc unbound transport key) is preserved; the change is that a TLS stack needs the raw private key, and ADR-0014 rule 3 requires the consensus signer to stay behind a remote-signer boundary |
| 6 Peer lifecycle in the wire spec | ✅ unchanged |

This also **closes** the open sub-decision recorded in the Review note above (QUIC-vs-Noise,
custom `SecurityUpgrade` vs Noise-XX pattern): neither is needed, because ML-DSA now enters the
TLS handshake natively. The remaining integration risk — whether `libp2p-quic` accepts a custom
rustls configuration, or whether quinn must be driven directly behind libp2p's transport trait —
is a **G5 entry spike**, not an architecture question.

## Links
- Amended by [ADR-0019](0019-transport-authentication.md) (transport authentication)
- [networking architecture](../02-architecture/networking.md),
  [network wire protocol spec](../15-specifications/05-network-wire-protocol.md)
- 2026 review: [`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md) §1.1, §2.3, §3
- [ADR-0002 (hybrid KEX)](0002-cryptographic-parameter-set.md), [ADR-0005 (build strategy)](0005-build-strategy.md), [ADR-0010 (PeerId hash)](0010-hash-function-domains.md)
- Code: `crates/hux-network/src/{topic,message,peer}.rs`, `crates/hux-crypto/src/kem.rs`

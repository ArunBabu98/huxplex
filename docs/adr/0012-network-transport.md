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

## Links
- [networking architecture](../02-architecture/networking.md),
  [network wire protocol spec](../15-specifications/05-network-wire-protocol.md)
- [ADR-0002 (hybrid KEX)](0002-cryptographic-parameter-set.md), [ADR-0005 (build strategy)](0005-build-strategy.md), [ADR-0010 (PeerId hash)](0010-hash-function-domains.md)
- Code: `src/network/{topic,message,peer}.rs`, `src/crypto/kem.rs`

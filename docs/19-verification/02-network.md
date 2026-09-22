# 02 — Verifying the networking envelopes by hand

> Companion to `cargo run -p hux-network --example network_walkthrough`.
>
> ⚠️ **Read this first: there is no transport yet.** `hux-network` today provides peer identity
> and the *signed envelopes* — the cryptographic half of the network. There is no swarm, no
> QUIC, no live Kademlia, no GossipSub, no peer state machine. Those arrive at gate **G5**
> ([plan](../18-implementation-plan/03-g5-transport.md)).
>
> What you can verify today is narrower but real: **nothing on the wire is unauthenticated, and
> nothing replays across a boundary.**
>
> Normative contract: [`../15-specifications/05-network-wire-protocol.md`](../15-specifications/05-network-wire-protocol.md).

## 1. `PeerId` is the key

```
PeerId = SHAKE-256(ML-DSA-44 public key)[..32]
```

Self-certifying: identity **is** the key, so there is no registry that can revoke, reassign or
forge it. That is principle 1 — *"sovereignty by cryptographic proof … never from a permissioned
party."*

**Check it:**

```bash
cargo test -p hux-network peer_id
```

Properties that must hold: exactly 32 bytes; deterministic from the same key; distinct for
distinct keys; never all-zero or all-`0xFF`; lowercase hex rendering of 64 characters.

**One subtlety worth looking at yourself.** Read [`peer.rs`](../../crates/hux-network/src/peer.rs).
It uses `XofReader::read`, which always fills the buffer — not `std::io::Read::read`, which
returns a count that may be short. A short read would have silently **zero-padded** a peer
identity, in the code that defines peer identity. The comment explains why; the distinction is
the kind of thing worth checking rather than trusting.

## 2. Every envelope carries its own signature

Both message types are signed by the sender, not by a relay:

| Type | Signed over | Context |
|---|---|---|
| `GossipMessage` | `payload` | `huxplex-{network}:gossip:{topic}:v1` |
| `DhtEntry` | `key ‖ value` | `huxplex-{network}:dht:entry:v1` |

**Why it matters:** a relay that could mint traffic would be a trusted party in a system whose
whole premise is not having one. Verification recomputes the context from the message's **own**
`topic` and `network` fields, so tampering with either invalidates the signature rather than
changing what gets checked.

```bash
cargo test -p hux-network gossip
cargo test -p hux-network dht
```

## 3. Forgery and tampering trials

Try these yourself — edit the walkthrough and confirm each still rejects:

| Attack | Mutation | Expected |
|---|---|---|
| Topic hijack | `msg.topic = shard_mempool(0)` after signing on `blocks` | ❌ rejected |
| Cross-shard leak | `msg.topic = shard_blocks(1)` after signing on shard 0 | ❌ rejected |
| Cross-network replay | `msg.network = "testnet"` after signing on mainnet | ❌ rejected |
| DHT route poisoning | rewrite `entry.value` to a hostile address | ❌ rejected |
| Signer substitution | replace `entry.signer_pk` with another peer's key | ❌ rejected |
| Payload tampering | flip any byte of `payload` | ❌ rejected |

**The one to dwell on is route poisoning.** A Kademlia DHT whose records can be rewritten lets an
attacker redirect every peer lookup at themselves — an eclipse attack that needs no network
position at all. Signed records make it require the victim's key.

## 4. Cross-network replay, including the DHT

```bash
cargo test -p hux-network cross_network_replay
```

**Historical note worth knowing.** Until 2026-09-22 the DHT context was hard-coded to
`huxplex-mainnet:dht:entry:v1` — the `network` was not a field on `DhtEntry` at all. That meant
the cross-network rejection property was *structurally untestable for DHT records*, while being
tested for gossip. The spec called network separation "a hard requirement, verified by
cross-network rejection tests," and for one message type it silently was not.

The fix added `network` to the struct and `dht_entry_context(network)` alongside the existing
`gossip_context(network, topic)`, mirroring a pattern the gossip path already had right.

**The generalisable lesson for a reviewer:** when a security property is claimed for a class of
objects, check that it is tested for *every member of that class*, not for the one that was
easiest to test. A hard-coded constant is how a property becomes unfalsifiable.

## 5. Identity consistency end to end

One key must drive the `PeerId`, the DHT announcement and the gossip sender. If those could
diverge, a node could announce one identity and speak as another.

```bash
cargo test -p hux-network full_node_identity_pipeline
cargo test -p hux-network ten_validators
```

The second simulates a 10-validator set and asserts every `PeerId` is distinct and every DHT
announcement verifies — the minimum Sybil-resistance property at this layer.

## 6. Message sizes and the bandwidth problem

Worth seeing with your own eyes, because it shapes the entire design above:

```
ML-DSA-44 signature : 2,420 bytes   (ECDSA: 64–72)
ML-DSA-44 public key: 1,312 bytes   (ECDSA: 33)
```

Every gossip message carries 2,420 bytes of signature. This is why:

- the gossip layer **must** deduplicate by message ID and **must not** re-sign on forward;
- witness/signature data must be separable and prunable after finality (principle 9);
- block propagation is heading for erasure-coded broadcast rather than gossip
  ([wire spec §5.1](../15-specifications/05-network-wire-protocol.md));
- signature aggregation for quorum certificates is research problem **R-A1**, marked 🔴.

BSC shipped ML-DSA-44 for transaction signatures in 2026 and measured a **40–50% throughput
reduction**. That number is the honest cost of post-quantum security at this parameter set, and
it is why v1's research deliverable is *measuring* it rather than assuming it away.

## What is not verifiable yet (gate G5)

| Property | Test that will prove it |
|---|---|
| Authenticated handshake, no downgrade; MITM fails the `PeerId` check; mutual auth required; cross-network ALPN refused | G5-T1 |
| Gossip amplification bounded under a flood of malformed messages | G5-T3 |
| Propagation converges under 20% packet loss and a healed partition | G5-T4 |
| Signed DHT entries reject forgery and replay **on a live DHT** | G5-T5 |
| Responder's first flight respects QUIC's 3× anti-amplification limit | G5-T6 |
| TLS and Huxplex protocol signatures cannot be confused | G5-T7 |

Until those exist, treat `hux-network` as *"correctly signed envelopes with no network under
them."* That is an honest description, and it is the one the crate's own README gives.

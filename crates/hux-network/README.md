# `hux-network`

Huxplex **Layer 0** — networking.

Depends on [`hux-crypto`](../hux-crypto/) and nothing else in the workspace. **It must never
depend upward**; a cycle is a build failure (enforced in CI).

## What is here today 🟢

| Component | Detail |
|---|---|
| **`PeerId`** | `SHAKE-256(ml_dsa44_pk)[..32]` — self-certifying, 32 bytes |
| **`GossipMessage`** | `{ topic, network, payload, sig, from }`, ML-DSA-44 signed over `gossip_context(network, topic)` |
| **`DhtEntry`** | `{ key, value, network, sig, signer_pk }`, signed over `key‖value` with `huxplex-{network}:dht:entry:v1` |
| **`GossipTopic`** | `huxplex/shard/{id}/blocks`, `…/mempool`, `huxplex/intents` |

Every envelope is network-parameterized: a mainnet message cannot verify under a testnet
context, and that is tested for both gossip and DHT records.

## What is not here yet 🟡

**There is no transport, no swarm, no peer state machine, no live DHT.** These are message
*types* with real signatures — the cryptographic envelope is done, the network engine is not.

Gate **G5** brings: libp2p/QUIC, TLS 1.3 with **native ML-DSA-44 certificates** and mutual
authentication, ALPN `huxplex/{network}/1`, Kademlia discovery, GossipSub, and peer scoring.
Start with the `libp2p-quic` integration spike (N0) — it can change the shape of everything else.

## Docs

- Architecture: [`docs/02-architecture/networking.md`](../../docs/02-architecture/networking.md)
- Normative spec: [`docs/15-specifications/05-network-wire-protocol.md`](../../docs/15-specifications/05-network-wire-protocol.md)
- Decisions: [ADR-0012](../../docs/adr/0012-network-transport.md) (transport),
  [ADR-0019](../../docs/adr/0019-transport-authentication.md) (ML-DSA TLS certificates)
- Build plan: [`docs/18-implementation-plan/03-g5-transport.md`](../../docs/18-implementation-plan/03-g5-transport.md)
- **Verifying it yourself:** [`docs/19-verification/`](../../docs/19-verification/)

# 05 — Network Wire Protocol Specification

> Normative (🟡 message types exist; transport unbuilt). Defines the handshake sequence, peer
> lifecycle, and gossip/DHT framing. Justified by [ADR-0012](../adr/0012-network-transport.md)
> (rust-libp2p/QUIC + PQ-hybrid handshake). Identifiers, topics, and contexts are from the
> [cryptography spec](02-cryptography-spec.md).
>
> Keywords per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Layers

```
L0  Identity        : ML-DSA-44 keypair -> PeerId = SHAKE-256(pk)[..32]   (🟢 implemented)
L1  Transport       : QUIC (UDP), TCP fallback                            (🟡 libp2p)
L2  Security upgrade : hybrid X25519 + ML-KEM-768 -> HKDF session key,
                       transcript signed with ML-DSA-44                    (🟡)
L3  Discovery        : libp2p Kademlia DHT; records = signed DhtEntry      (🟢 type / 🟡 swarm)
L4  Messaging        : libp2p GossipSub; per-message ML-DSA-44 signatures  (🟢 type / 🟡 swarm)
```

## 2. Handshake (suite v1)

Bound to context `huxplex-{network}:tls:handshake:v1`. Both a classical and a PQ KEM must be
broken to compromise a session (hybrid forward secrecy).

```
Initiator (I)                                   Responder (R)
  ── ClientHello ─────────────────────────────►
     { suite, network, I.peer_id,
       X25519 ephemeral pub,
       ML-KEM-768 ek (1184 B) }
                                  ◄── ServerHello ──
                                     { suite, network, R.peer_id,
                                       X25519 ephemeral pub,
                                       ML-KEM-768 ciphertext (1088 B),
                                       R.ml_dsa_pk }
  # both sides now hold:
  #   ss_x   = X25519(eph_priv, peer_eph_pub)
  #   ss_kem = ML-KEM-768 shared secret (32 B)
  #   ss     = ss_x || ss_kem
  # session key (directional, crypto spec §4.2):
  #   k = HKDF-SHA-256(ikm=ss, info="ML-KEM-768-v1-DERIVE" || a || b || handshake_ctx)
  ── Finished (I) ────────────────────────────►
     ML-DSA-44 sig over transcript, ctx tls:handshake:v1
                                  ◄── Finished (R) ──
                                     ML-DSA-44 sig over transcript, ctx tls:handshake:v1
```

Rules:
1. Each side MUST verify the peer's `Finished` signature under the handshake context against the
   peer's ML-DSA-44 key, and MUST verify that key hashes to the claimed `PeerId` (crypto spec
   §6.1). A mismatch aborts the connection.
2. `a`/`b` in the HKDF `info` are the two peers' fingerprints in a fixed order
   (initiator first); this makes I→R and R→I keys distinct (directional).
3. The transcript covers all prior handshake bytes (both hellos). Replays across networks fail
   because the context embeds `{network}`.
4. Session keys are ephemeral; rekeying policy is defined by the transport (QUIC key update).

## 3. Peer lifecycle (state machine)

```
        dial / inbound
  Disconnected ─────────► Connecting
                              │ QUIC established
                              ▼
                          Handshaking ── fail ──► Disconnected (backoff)
                              │ both Finished verified + PeerId match
                              ▼
                          Identified ── DHT publish (signed DhtEntry) ──►
                              │
                              ▼
                           Active ◄── gossip / kad traffic
                              │ misbehavior / timeout
                              ▼
                       Scored-down / Banned
```

- A peer MUST reach **Identified** (verified ML-DSA-44 identity ⇒ `PeerId`) before any
  application message from it is processed.
- **Peer scoring:** GossipSub peer scoring plus Huxplex penalties for invalid signatures,
  cross-context replay attempts, and spam. Score below a threshold ⇒ disconnect/ban with backoff.
  (Hostile-agent / spam mitigation, risk #6.)

## 4. Discovery (Kademlia DHT)
- Records are `DhtEntry { key, value, sig, signer_pk }`, signed over `key‖value` with context
  `huxplex-mainnet:dht:entry:v1` (crypto spec §6.3).
- The DHT **key SHOULD be the publisher's `PeerId`**; `value` is its dialable address(es).
- A node MUST verify a `DhtEntry` signature before using it for routing (prevents routing-table
  poisoning — covered by existing tamper/wrong-signer tests).

## 5. Messaging (GossipSub)
- Topics per crypto spec §6.2: `huxplex/shard/{id}/blocks`, `huxplex/shard/{id}/mempool`,
  `huxplex/intents`.
- Every `GossipMessage` is ML-DSA-44–signed over its payload with
  `gossip_context(network, topic)`. Receivers MUST verify the signature against `from` and MUST
  recompute the context from the message's own `topic`/`network` (so topic/network tampering
  invalidates it).
- **Message-ID / dedup:** because each signature is 2420 B, the gossip layer MUST deduplicate by
  message id and MUST NOT re-sign on forward; validators sign once at origin. (PQ-bloat
  mitigation, risk #2.)
- Max payload sizes per topic are governance parameters; the signing path already handles ≥64 KB
  payloads (tested).

## 6. Network separation
`mainnet` and `testnet` are isolated at every signed layer: handshake, gossip, DHT, and tx/vote
contexts all embed (or will embed) the network name, so no message from one network can be
replayed on the other. This is a hard requirement, verified by cross-network rejection tests.

---

### Open Questions
- Exact libp2p security-upgrade integration: implement the hybrid handshake as a custom
  `SecurityUpgrade`, or run it inside a Noise-XX-like pattern adapted for ML-KEM? (Security-
  critical; needs review + possibly an RFC.)
- QC/vote propagation: dedicated topic vs. direct validator mesh — and how does 2420 B × (2f+1)
  QC size affect topic sizing?
- Address privacy: should DHT values be encrypted to reduce network-topology surveillance?

# 05 — Network Wire Protocol Specification

> Normative (🟡 message types exist; transport unbuilt). Defines the handshake, peer lifecycle,
> and gossip/DHT framing. Justified by [ADR-0012](../adr/0012-network-transport.md)
> (rust-libp2p/QUIC) and [ADR-0019](../adr/0019-transport-authentication.md) (native ML-DSA TLS
> certificates). Identifiers, topics, and contexts are from the
> [cryptography spec](02-cryptography-spec.md).
>
> Keywords per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Layers

```
L0  Identity     : ML-DSA-44 keypair -> PeerId = SHAKE-256(pk)[..32]      (🟢 implemented)
                   transport uses the `Transport` key purpose (ADR-0019)
L1  Transport    : QUIC (UDP), TCP fallback                               (🟡 libp2p)
L2  Security     : TLS 1.3 (RFC 9001) — X25519MLKEM768 key agreement,
                   mutual auth with native ML-DSA-44 certificates,
                   ALPN huxplex/{network}/1                               (🟡)
L3  Discovery    : libp2p Kademlia DHT; records = signed DhtEntry         (🟢 type / 🟡 swarm)
L4  Messaging    : libp2p GossipSub; per-message ML-DSA-44 signatures     (🟢 type / 🟡 swarm)
```

## 2. Handshake — TLS 1.3 over QUIC with native ML-DSA certificates

Per [ADR-0019](../adr/0019-transport-authentication.md). **There is no bespoke Huxplex
handshake.** QUIC's cryptographic handshake is TLS 1.3 (RFC 9001) and is not replaceable;
ML-DSA enters it natively as a certificate signature algorithm.

> *Revised 2026-09-22.* This section previously specified a custom four-flight
> ClientHello/ServerHello/Finished exchange with an ML-DSA transcript signature. That design is
> withdrawn — `draft-ietf-tls-mldsa` and rustls 0.23.44 (2026-09-07) make it unnecessary, and it
> required a classical key in the authentication path. See ADR-0019 for the full option
> analysis.

### 2.1 Key agreement
**`X25519MLKEM768`** hybrid, performed by the TLS stack. A peer offering only classical key
agreement MUST be rejected (G5-T1). Suite rotation is an agility-registry change
([ADR-0002](../adr/0002-cryptographic-parameter-set.md)).

### 2.2 Certificate — NORMATIVE

```
self-signed X.509 certificate
  SubjectPublicKeyInfo : ML-DSA-44 public key                (1,312 B)
  signatureAlgorithm   : id-ML-DSA-44  (2.16.840.1.101.3.4.3.17)
  self-signature       : ML-DSA-44                           (2,420 B)
TLS SignatureScheme    : mldsa44 = 0x0904
```

The certificate key is the node's **`Transport`-purpose** key,
`m/44'/931931'/4'/0'/{index}'` ([cryptography spec §4.1](02-cryptography-spec.md)) — **not** the
consensus hot key, because a TLS stack requires the raw private key and that would defeat the
remote-signer isolation of [ADR-0014](../adr/0014-validator-key-management.md) rule 3.

### 2.3 Verification — NORMATIVE

There is no CA, no trust store, no name checking, no revocation. Identity **is** the key.
A verifier MUST, in order:

1. Verify the certificate's ML-DSA-44 self-signature.
2. Compute `PeerId = SHAKE-256(SubjectPublicKeyInfo public key)[..32]`.
3. Require it to equal the `PeerId` the dialer intended to reach (for an inbound connection,
   record it as the peer's identity).
4. Abort the connection on any mismatch.

**Mutual authentication is mandatory.** The responder MUST send a `CertificateRequest`, and an
unauthenticated peer MUST NOT reach an application stream.

TLS's own `CertificateVerify` is an ML-DSA-44 signature over the handshake transcript, so peer
identity is bound to *this session* by a post-quantum signature. No additional application-level
binding step is needed or permitted.

### 2.4 Network separation via ALPN — NORMATIVE

ALPN is **`huxplex/{network}/1`** — `huxplex/mainnet/1`, `huxplex/testnet/1`. QUIC enforces ALPN
agreement, so a cross-network dial fails **before any Huxplex code executes**. This is the
transport-layer half of the §6 requirement.

### 2.5 Resumption

- 1-RTT session resumption is **enabled** — it omits the certificate, which is what makes the
  handshake cost acceptable in steady state on a long-lived validator mesh.
- **0-RTT early data is FORBIDDEN.** It reintroduces replay on the one path with no
  application-layer nonce to bind against.

### 2.6 Anti-amplification budget — NORMATIVE

RFC 9000 §8.1 caps the responder's pre-validation output at 3× bytes received.

| Flight | Bytes |
|---|---|
| Client Initial (ClientHello + `X25519MLKEM768`), **padded** | ≈ 2,700 |
| **Budget (3×)** | **≈ 8,100** |
| ServerHello | ≈ 1,220 |
| Certificate | ≈ 4,130 |
| CertificateVerify (ML-DSA-44) | ≈ 2,420 |
| EncryptedExtensions + CertificateRequest + Finished | ≈ 200 |
| **Responder first flight** | **≈ 7,970** |

The initiator MUST pad its Initial so the responder's first flight stays within 3×. Padding is
preferred to QUIC Retry, which costs a round trip on every first contact.

⚠️ **The margin is thin by design.** Anything added to the responder's first flight — a larger
parameter set, an extra certificate, an SLH-DSA identity proof (7,856 B alone) — breaks it.
Pinned by **G5-T6**.

### 2.7 Cross-protocol key separation

The `Transport` key and the protocol-signing keys are distinct purposes in one hierarchy, and
their signatures are further separated structurally: FIPS 204 encodes the context parameter's
length and bytes into the signed preimage, so a TLS `CertificateVerify` and a
`huxplex-{network}:…:v1` protocol signature have different preimages by construction. This MUST
be verified by test (**G5-T7**), never assumed. The exact context used by the TLS ML-DSA profile
is a conformance item to confirm against the published RFC.

## 3. Peer lifecycle (state machine)

```
        dial / inbound
  Disconnected ─────────► Connecting
                              │ QUIC established
                              ▼
                          Handshaking ── fail ──► Disconnected (backoff)
                              │ TLS mutual auth complete + PeerId match
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
- Records are `DhtEntry { key, value, network, sig, signer_pk }`, signed over `key‖value` with
  context `huxplex-{network}:dht:entry:v1` (crypto spec §6.3) 🟢.
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

### 5.1 GossipSub is not the only dissemination path — NORMATIVE

✅ *Decided 2026-09-22.* **This specification MUST NOT be read as fixing GossipSub as the
permanent transport for blocks and DAG batches.** Gossip lowers leader bandwidth at the cost of
hops, and hop count is what breaks a latency budget for large objects — a regime Huxplex enters
early because ML-DSA-44 signatures are 2,420 B. The 2026 state of the art for large single-source
objects is erasure-coded broadcast (ethp2p, RaptorCast, Turbine, Optimum P2P).

Requirements on implementations and on future revisions of this spec:

1. **Dissemination is selected per traffic shape, not globally.** GossipSub is normative for
   mempool, intents and control traffic, where its peer scoring and attack resilience are the
   reason it was chosen. Blocks and DAG batches are a separate path.
2. **v1/devnet MAY carry blocks over GossipSub** (the [v1 scope contract](06-v1-scope.md) permits
   it, and 3–5 nodes do not exercise the failure mode). Nothing above the transport may *assume*
   it.
3. **No consensus object's validity may depend on how it was disseminated.** A block MUST verify
   identically whether gossiped whole or reassembled from erasure-coded shards. Concretely: no
   gossip message-ID, topic, or hop metadata may enter a signed payload or a state transition.
4. The block path is specified by a future ADR (`adr/0020-*`, gate G6). Until it exists, §5's
   block-topic text is **provisional**.

## 6. Network separation
`mainnet` and `testnet` are isolated at every signed layer: handshake, gossip, DHT, and tx/vote
contexts all embed the network name, so no message from one network can be replayed on the other.
This is a hard requirement, verified by cross-network rejection tests.

✅ *Closed 2026-09-22:* the last implementation site that hard-coded `mainnet` (`DhtEntry`) is
network-parameterized, and cross-network replay rejection is now tested for DHT entries as well
as gossip (`test_dht_entry_cross_network_replay_fails`). "or will embed" no longer applies to any
implemented type; see [cryptography spec §5](02-cryptography-spec.md) rule 2.

---

### Open Questions
- Exact libp2p security-upgrade integration: implement the hybrid handshake as a custom
  `SecurityUpgrade`, or run it inside a Noise-XX-like pattern adapted for ML-KEM? (Security-
  critical; needs review + possibly an RFC. Note the ML-DSA authentication half is ours either
  way — upstream libp2p keeps authentication classical, so this is an integration choice, not an
  architecture one.)
- QC/vote propagation: dedicated topic vs. direct validator mesh — and how does 2420 B × (2f+1)
  QC size affect topic sizing? (Interacts with §5.1 and with [R-A1](../11-research/open-problems.md):
  an aggregating `QuorumCert` scheme would change the answer entirely.)
- Address privacy: should DHT values be encrypted to reduce network-topology surveillance?
- **Where does this handshake sit relative to QUIC's own TLS handshake**
  ([R-B12](../11-research/open-problems.md))? Replacing QUIC's crypto layer, or running
  application-level over a standard QUIC + rustls `X25519MLKEM768` connection? The second
  inherits the hybrid KEX from upstream but makes channel binding mandatory. QUIC's 3×
  anti-amplification limit binds only in the first case, and there the §2 first flight
  (`ServerHello` ≈ 2,500 B against a ~3,900 B budget) already fits — including at ML-DSA-65.
  ⏳ *Decision pending.*

# Networking (Layer 0)

## Current state (🟢 / 🟡)

The repository defines the *message and identity types* but **not a running network**:

- 🟢 `PeerId = SHAKE-256(ml_dsa44_pk)[..32]` (`network/peer.rs`).
- 🟢 `GossipMessage { topic, network, payload, sig, from }` with context-bound sign/verify.
- 🟢 `DhtEntry { key, value, network, sig, signer_pk }` with `huxplex-{network}:dht:entry:v1`.
- 🟢 Canonical topics: `huxplex/shard/{id}/blocks`, `…/mempool`, `huxplex/intents`.
- 🟢 `KeyPurpose::Transport` derivation for the TLS certificate key.
- 🟡 **No transport, no swarm, no peer state machine, no actual DHT, no handshake code.**

So the cryptographic envelope is real; the network engine is unbuilt. That's the right order.

## Target design

| Concern | Choice | Why |
|---|---|---|
| Library | **libp2p (Rust)** | Mature swarm, GossipSub, Kademlia, transport upgrades, used by Ethereum/Filecoin/Polkadot |
| Transport | **QUIC** (UDP) | Lower latency, multiplexed streams; ML-KEM-768 ciphertext (1,088 B) fits a datagram. 1-RTT resumption yes, **0-RTT early data no** |
| Key agreement | **`X25519MLKEM768`** hybrid, via the TLS stack | PQ confidentiality vs HNDL *and* classical safety if ML-KEM is broken (defense in depth) |
| Authentication | **Native ML-DSA-44 TLS certificates**, mutual ([ADR-0019](../adr/0019-transport-authentication.md)) | No classical key in the auth path; rotation is a `SignatureScheme` code point, not a redesign |
| Network separation | **ALPN `huxplex/{network}/1`** | QUIC enforces ALPN agreement *before* any Huxplex code runs |
| Session AEAD | TLS 1.3 cipher suite (AES-256-GCM or ChaCha20-Poly1305) | 256-bit for Grover margin; negotiated, not hand-rolled |
| Peer ID | SHAKE-256(pk)[..32] 🟢 | Self-certifying; binds identity to PQ key. **No X.509 chain** — a real advantage under the QUIC amplification limit (below) |
| Discovery | Kademlia DHT, ML-DSA-authenticated entries 🟢 | Decentralized peer/resource discovery |
| Propagation — mempool, intents, control | GossipSub per shard + intents overlay 🟢 | Topic-scoped, many-source, churn-tolerant; peer scoring is the point |
| Propagation — blocks, DAG batches | **Erasure-coded broadcast** 🔴 | Large single-source objects; gossip pays for low leader bandwidth in hops (below) |

### The handshake — standard TLS 1.3 with native ML-DSA certificates

Per [ADR-0019](../adr/0019-transport-authentication.md). QUIC's handshake **is** TLS 1.3
(RFC 9001) and is not replaceable; the only real question was how ML-DSA gets into it, and since
September 2026 the answer is *natively*.

```mermaid
sequenceDiagram
    participant A as Initiator
    participant B as Responder
    A->>B: ClientHello { X25519MLKEM768 key share, ALPN huxplex/{network}/1 }<br/>padded, for the 3× amplification budget
    B->>A: ServerHello { X25519MLKEM768 share } · EncryptedExtensions<br/>Certificate { SPKI = ML-DSA-44 pk, self-signed ML-DSA-44 }<br/>CertificateRequest · CertificateVerify (ML-DSA-44) · Finished
    A->>A: verify cert self-signature; SHAKE-256(spki)[..32] == expected PeerId
    A->>B: Certificate { ML-DSA-44 } · CertificateVerify (ML-DSA-44) · Finished
    Note over A,B: mutual auth; identity bound to THIS session by a PQ signature<br/>no classical key anywhere in the authentication path
```

**No bespoke handshake, no certificate extension, no application-level binding step.** TLS's own
`CertificateVerify` is an ML-DSA-44 signature over the handshake transcript, so the property a
custom design would have hand-rolled comes from the protocol. Enabled by
`draft-ietf-tls-mldsa-06` (`SignatureScheme` `mldsa44` = 0x0904) and rustls 0.23.44
(2026-09-07); ML-DSA certificates are unusable in the public Web PKI but supported for **private
hierarchies**, which is what a self-certifying `PeerId` network is.

The certificate key is the **`Transport`** key purpose (`m/44'/931931'/4'/0'/{i}'`), never the
consensus hot key — a TLS stack needs the raw private key, and that would defeat the
remote-signer isolation [ADR-0014](../adr/0014-validator-key-management.md) rule 3 requires.

> The previously specified bespoke flow (ClientHello/ServerHello/Finished with an ML-DSA
> transcript signature, over `…:tls:handshake:v1`) is **withdrawn**. `kem768_derive_session_key`
> and its directional `peer_a`/`peer_b` binding remain implemented and tested, and stay available
> for application-level session keys — but the transport KEX is rustls's.

### Why hybrid and not pure ML-KEM

ML-KEM is young. A hybrid X25519+ML-KEM secret is secure if *either* component holds: classical
(X25519) protects against a future ML-KEM cryptanalytic break, ML-KEM protects against a future
CRQC breaking X25519. This is current IETF/NIST transition guidance and is nearly free here.
The classical half can be dropped via the agility registry once ML-KEM is battle-tested.

> **Validated, September 2026.** The ecosystem converged on exactly this construction:
> `X25519MLKEM768` ships in Chrome, Cloudflare and rustls, IETF `draft-ietf-tls-ecdhe-mlkem`
> is at -05, and libp2p standardized `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`. The May
> 2026 Luo preprint claiming a quantum break of ML-KEM was refuted within eight days — but it
> is the reason the classical half stays until further notice, **not** a reason to drop it
> early. See [`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md) §1.1–1.2.

### The handshake byte budget (QUIC anti-amplification)

QUIC caps what a responder may send before validating the initiator's address at **3× the bytes
received** (RFC 9000 §8.1) — an anti-reflection measure, since an attacker can spoof a victim's
address in the first packet. It applies to the responder's **first flight**, and with native
ML-DSA certificates that flight now carries the certificate and `CertificateVerify`:

| Flight | Bytes |
|---|---|
| Client Initial (ClientHello + `X25519MLKEM768`), **padded** | ≈ 2,700 |
| **Budget (3×)** | **≈ 8,100** |
| ServerHello | ≈ 1,220 |
| Certificate (X.509 + ML-DSA pk 1,312 + ML-DSA self-sig 2,420) | ≈ 4,130 |
| CertificateVerify (ML-DSA-44) | ≈ 2,420 |
| EncryptedExtensions + CertificateRequest + Finished | ≈ 200 |
| **Responder first flight** | **≈ 7,970** |

The fix is **padding the client Initial**, which is cheaper than QUIC Retry (an extra round trip
on every first contact) and costs only upstream bytes on fresh handshakes. Session resumption
omits the certificate entirely, so steady-state cost on a long-lived validator mesh is near zero.

⚠️ **The margin is thin by design and will break silently.** Anything added to the responder's
first flight spends it: a larger parameter set (ML-DSA-65 adds ≈1.3 KB), a second certificate, or
an SLH-DSA-128s identity proof (7,856 B on its own). Pinned by **G5-T6**.

Huxplex is still structurally better placed than the wider Web here: self-certifying `PeerId`s
mean there is **no X.509 chain**, where a PQ certificate chain in public TLS reaches ~17.5 KB.
That is a benefit of the identity design, not an accident.

> ⚠️ *This section has been revised twice.* A first version miscounted the bespoke handshake's
> fourth flight as pre-validation and reported a false deficit; a second version costed a
> handshake design that [ADR-0019](../adr/0019-transport-authentication.md) then withdrew. The
> numbers above are for the accepted design.

### Block propagation: gossip is the wrong primitive for large objects 🔴

GossipSub reduces *leader* bandwidth and pays for it in **hops**, and hop count is what breaks a
latency budget for large objects. ML-DSA's 2,420-byte signatures put Huxplex squarely in that
regime. The field moved to erasure-coded broadcast during 2025–26:

| System | Approach |
|---|---|
| **ethp2p** | Reed–Solomon erasure-coded, object-specific broadcast — **scheduled to succeed GossipSub in late 2026** |
| **RaptorCast** (Monad) | Rateless Raptor codes + hierarchical leader → first-level validators → network |
| **Optimum P2P / Peer-Turbo** | RLNC-based broadcast |
| **Turbine** (Solana) | Erasure-coded fanout tree |

The design consequence is a **split by traffic shape**, not a wholesale replacement — GossipSub's
attack resilience and peer scoring are exactly what the mempool and intents overlay need:

| Traffic | Shape | Primitive |
|---|---|---|
| Block / DAG batch | large, single-source, latency-critical, known epoch validator set | **erasure-coded broadcast** |
| Mempool, intents, control | small, many-source, churn-tolerant, abuse-exposed | **GossipSub** 🟢 |
| DHT records | small, long-lived | Kademlia 🟢 |

Pending an ADR (see [review](../brainstorming/01-layer0-technology-review-2026.md) action A3).
This is cheap to plan now and a protocol change later.

## Design options (transport/discovery)

**Option A — Build on libp2p (recommended).** Mature, batteries-included; we add the PQ
handshake as a custom security upgrade and PQ-auth the DHT/gossip (envelopes already done).
*Cost*: must integrate PQ into libp2p's noise/tls slot. *Risk*: medium, well-trodden.

> **How much of this lands upstream (September 2026).** The answer is precise, and it is only
> half of what Huxplex needs:
>
> | | Upstream status | Huxplex can reuse? |
> |---|---|---|
> | **Confidentiality** — hybrid X25519+ML-KEM-768 | [libp2p/specs#727](https://github.com/libp2p/specs/pull/727) Stage-1 draft; [rust-libp2p#6481](https://github.com/libp2p/rust-libp2p/pull/6481) draft behind an off-by-default `mlkem-hfs` feature, blocked on ML-KEM in `snow`; four implementations interoperate | **Yes** — consume it, don't reimplement |
> | **Authentication / identity** — ML-DSA-44, `PeerId = SHAKE-256(pk)[..32]` | The spec states plainly: *"authentication stays classical: in libp2p the identity key signs the static key."* Identity stays Ed25519; no PQ identity work is planned | **No — never** |
>
> ✅ **Superseded 2026-09-22 — and the table's bottom-right cell turned out to be wrong.**
> The conclusion above ("QUIC inherits ML-DSA peer authentication from nowhere") held when
> written and was false two weeks later: **rustls 0.23.44 (2026-09-07) enables ML-DSA
> certificates by default**, and `draft-ietf-tls-mldsa-06` assigns `mldsa44` = `SignatureScheme`
> 0x0904. Authentication comes from TLS natively; Huxplex writes certificate generation and a
> custom verifier, not a security transport. libp2p's Noise PQ work is simply not on our path.
> See [ADR-0019](../adr/0019-transport-authentication.md).
>
> What remains of Option A's cost is **integration, not cryptography**: whether `libp2p-quic`
> accepts a custom rustls configuration, or whether quinn must be driven behind libp2p's
> transport trait. That is a G5 entry spike.

**Option B — Custom QUIC stack (`quinn`) + own overlay.** Maximum control over the PQ
handshake and datagram sizing. *Cost*: reinvent peer mgmt, NAT traversal, gossip, DHT. *Risk*:
high. *Verdict*: only if libp2p's security-upgrade extensibility proves inadequate.

**Option C — gRPC/QUIC mesh (validator-only) + libp2p for public.** Two-tier: tight authenticated
mesh among bounded validator set, libp2p gossip for the public. *Cost*: two networks to secure.
*Benefit*: validator path is simpler/faster. *Verdict*: attractive for the bounded-validator-set
consensus design; consider for Production.

**Recommendation**: Option A for the public network; evaluate Option C's validator mesh for the
consensus hot path in Production. Reject B unless forced.

## Security concerns specific to networking

- **Eclipse attacks**: enforce diverse peer selection, address buckets (Kademlia), inbound/
  outbound ratio limits, and validator mesh redundancy.
- **DDoS on leader**: mitigated at consensus layer by PQ-SSLE (hidden leader) — networking must
  not leak the next proposer.
- **Amplification via big PQ messages**: 2,420 B sigs make spam cheap-to-send/expensive-to-verify;
  require proof-of-work-lite or stake-gated gossip for unauthenticated peers, verify signatures
  lazily/batched, and rate-limit per peer with GossipSub scoring.
- **Traffic analysis** (nation-state): consider mixnet/onion options for the intents overlay in
  the privacy roadmap (see [`05-identity/privacy.md`](../05-identity/privacy.md)). 🔴
- **DHT poisoning**: entries are ML-DSA-signed 🟢; add S/Kademlia-style protections.

## MVP / Production / Future

- **MVP**: libp2p + QUIC, TLS 1.3 with native ML-DSA-44 certificates and mutual auth, ALPN-scoped
  per network, padded client Initial, GossipSub for blocks/mempool on a single shard, static
  bootstrap peers, signed gossip (reuse 🟢 envelopes). 3–5 node devnet.
- **Production**: Kademlia discovery, peer scoring/banning, eclipse resistance, validator mesh
  (Option C), per-shard topics, NAT traversal, metrics, **erasure-coded block broadcast**,
  session resumption tuning.
- **Future**: mixnet/onion for intents privacy, mobile/light-client transport, QUIC datagram
  tuning for PQ sizes, drop the classical half of the hybrid KEX when ML-KEM matures, and revisit
  referencing a known validator's key by on-chain index instead of sending the full certificate.

---

### Open Questions
- ~~Does libp2p's security-transport API cleanly accept a hybrid X25519+ML-KEM + ML-DSA upgrade, or do we need a fork?~~ ✅ **Closed 2026-09-22** — moot. ML-DSA enters TLS natively ([ADR-0019](../adr/0019-transport-authentication.md)); no security transport to write.
- ~~Which QUIC anti-amplification mitigation?~~ ✅ **Closed:** pad the client Initial.
- ~~Is QUIC still the right primary, or does libp2p's Noise path cost less?~~ ✅ **Closed:** QUIC, decisively — that is where native ML-DSA TLS lives.
- **Does `libp2p-quic` accept a custom rustls configuration** with an ML-DSA certificate and verifier, or must quinn be driven directly behind libp2p's transport trait? (G5 entry spike — the last open transport question.)
- How to rate-limit unauthenticated gossip cheaply given expensive PQ verification? (Batch verify? Stake-gated relays?)
- Is a separate validator mesh worth the second-network attack surface?
- Can an erasure-coded block broadcast and the DAG mempool's causal-batch traffic share one dissemination path, or do they want separate ones?
</content>

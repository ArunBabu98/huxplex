# 03 — G5 · Transport and the P2P layer

> **Entry:** G2 (canonical encoding). Runs **in parallel** with G3/G4 — it is the only meaningful
> parallel track before G7.
>
> Today `hux-network` defines message *types* only: no swarm, no transport, no peer state
> machine. Implements [ADR-0012](../adr/0012-network-transport.md) (libp2p/QUIC, Kademlia,
> GossipSub) and [ADR-0019](../adr/0019-transport-authentication.md) (native ML-DSA TLS
> certificates).

## 🔬 N0 — the entry spike (do this before anything else in G5)

**Question:** does `libp2p-quic` accept a custom rustls configuration carrying an ML-DSA-44
certificate and a custom certificate verifier — or must quinn be driven directly behind libp2p's
`Transport` trait, or `libp2p-tls` forked?

`libp2p_quic::Config` builds its TLS config internally via `libp2p-tls`, which generates an
Ed25519-identity certificate with the libp2p Public Key Extension. Huxplex needs a different
certificate entirely.

**Why it is first:** the answer changes how much of G5 is integration versus implementation, and
in the worst case it changes which crates are dependencies at all. Writing certificate code
against an integration that turns out to be impossible is the most expensive mistake available in
this gate.

**Timebox:** short. Possible outcomes, in descending order of preference:

| Outcome | Consequence |
|---|---|
| `libp2p-quic` accepts a custom rustls config | Best case — pure integration |
| A small `libp2p-tls` fork suffices | Acceptable; maintain as a patch, upstream if possible |
| quinn must be driven behind libp2p's `Transport` trait | More work; keeps GossipSub/Kademlia |
| None of the above | **Stop condition.** Fall back to ADR-0019's certificate-extension bridge — **never** the exporter-binding phase |

**Acceptance:** a written finding in this folder (append to this file), and if a fork or
direct-quinn path is chosen, an ADR amendment recording it.

## Tasks

### A. Certificates and authentication

| ID | Task | Acceptance |
|---|---|---|
| **N1** ⬜ | Generate a self-signed X.509 cert: SPKI = ML-DSA-44 public key, self-signature ML-DSA-44, `SignatureScheme` `mldsa44` = **0x0904** | Cert parses in rustls; key is the `Transport` purpose (`m/44'/931931'/4'/0'/{i}'`) 🟢 |
| **N2** ⬜ | Custom `ServerCertVerifier` / `ClientCertVerifier`: verify self-signature → `SHAKE-256(spki)[..32]` → compare to expected `PeerId` → abort on mismatch. **No CA, no trust store, no name checking, no revocation** | **G5-T1**, **G5-T2** |
| **N3** ⬜ | **Mutual** authentication — responder sends `CertificateRequest`; an unauthenticated peer never reaches an application stream | Part of G5-T1 |
| **N4** ⬜ | ALPN `huxplex/{network}/1`; QUIC refuses cross-network dials | Part of G5-T1 |
| **N5** ⬜ | Pin `rustls` ≥ 0.23.44 with the `aws-lc-rs` provider, **non-FIPS**; `deny.toml` entries | ADR-0019 conditions 1–2 |

### B. Transport behaviour

| ID | Task | Acceptance |
|---|---|---|
| **N6** ⬜ | Pad the client Initial so the responder's ≈7,970 B first flight stays inside RFC 9000 §8.1's 3× budget | **G5-T6**, measured on the wire |
| **N7** ⬜ | 1-RTT session resumption **enabled**; 0-RTT early data **disabled** | A test asserting early data is refused |
| **N8** ⬜ | Peer lifecycle state machine per [wire spec §3](../15-specifications/05-network-wire-protocol.md): `Disconnected → Connecting → Handshaking → Identified → Active`, with backoff and banning | A peer's messages are not processed before `Identified` |

### C. Discovery and messaging

| ID | Task | Acceptance |
|---|---|---|
| **N9** ⬜ | Kademlia DHT with signed `DhtEntry` records 🟢; DHT key = publisher's `PeerId`; verify before routing | **G5-T5** extended from struct-level to the live DHT |
| **N10** ⬜ | GossipSub for mempool / intents / control, reusing the 🟢 signed envelopes; message-ID dedup, no re-signing on forward | **G5-T3**, **G5-T4** |
| **N11** ⬜ | Peer scoring: GossipSub scoring plus penalties for invalid signatures, cross-context replay attempts, spam | **G5-T3** |

> **Do not** build erasure-coded block broadcast at this gate. [Wire spec §5.1](../15-specifications/05-network-wire-protocol.md)
> permits v1 to carry blocks over GossipSub; the guardrail is only that nothing above the
> transport may *assume* it. The block path is `adr/0020-*` at G6.

## 🎯 Gate tests

| ID | Property |
|---|---|
| **G5-T1** | **Authenticated handshake, no downgrade.** Classical-only key agreement rejected; a MITM substituting its own ML-DSA certificate fails the `PeerId` check; no client certificate ⇒ no application stream; cross-network ALPN refused by QUIC |
| **G5-T2** | **`PeerId` is bound to the key** — a peer cannot present a `PeerId` it does not hold the key for |
| **G5-T3** | **Gossip amplification is bounded** under a flood of malformed and unsigned messages; the offender is scored down and disconnected |
| **G5-T4** | **Propagation under partition** — 20% packet loss and a healed partition, all honest nodes converge |
| **G5-T5** | **Signed DHT entries reject forgery and replay**, including cross-network 🟢 |
| **G5-T6** | **Amplification limit respected** — the responder's *first flight* never exceeds 3× bytes received, re-asserted when the suite changes |
| **G5-T7** | **Transport and protocol signatures cannot be confused** — a TLS `CertificateVerify` must not verify as any Huxplex protocol signature, and vice versa, for every registry context |

> **G5-T6 and G5-T7 are the two new ones and the two most likely to be skipped.** T6 guards a
> margin of ~130 bytes that any future addition silently spends. T7 guards the only place where
> two ML-DSA keys from one hierarchy sign under two different disciplines.

## Open item carried into this gate

The exact context used by the TLS ML-DSA profile for `CertificateVerify` must be confirmed
against the published RFC (`draft-ietf-tls-mldsa` is Informational and in the RFC Editor queue).
FIPS 204 separates TLS and Huxplex signatures structurally either way, but G5-T7 should pin the
actual value rather than the assumption.

## G5 exit

- 5 nodes discover each other, mutually authenticate over QUIC with ML-DSA certificates, gossip,
  and sustain sessions.
- Abuse tests (G5-T3) green.
- G5-T6 and G5-T7 green.
- The N0 finding recorded, with an ADR amendment if the integration path changed.

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

---

### 🔬 N0 — FINDING, 2026-09-23

> **Run against:** `libp2p-quic` 0.14.0, `libp2p-tls` 0.7.0, `libp2p-identity` 0.3.0,
> `libp2p-core` 0.44.0, `rustls` 0.23.45, `quinn` 0.11.12 — read from the vendored crate sources,
> not from documentation.

#### Answer: outcome 3 — **quinn must be driven behind libp2p's `Transport` trait.**

Outcomes 1 and 2 are both ruled out, and 2 is ruled out for a different reason than expected.

**1. `libp2p-quic` does not accept a custom rustls config — confirmed, not inferred.**
`libp2p_quic::Config` holds `client_tls_config: Arc<QuicClientConfig>` and
`server_tls_config: Arc<QuicServerConfig>` as **private fields with no setter**.
`Config::new(keypair)` builds both internally:

```rust
QuicClientConfig::try_from(libp2p_tls::make_client_config(keypair, None).unwrap())
QuicServerConfig::try_from(libp2p_tls::make_server_config(keypair).unwrap())
```

The entire public builder surface is `mtu_upper_bound` and `disable_path_mtu_discovery`. There is
no injection point. (`QuinnConfig`, which wraps the quinn configs, is `pub(crate)`.)

**2. The "small `libp2p-tls` fork" is not small — the blocker is `libp2p-identity`, not TLS.**
`make_client_config` / `make_server_config` are public and return plain `rustls::{Client,Server}Config`,
so a `[patch.crates-io]` fork would be reached by `libp2p-quic`. But both take
`&libp2p_identity::Keypair`, and:

```rust
pub enum KeyType { Ed25519, RSA, Secp256k1, Ecdsa }   // libp2p-identity 0.3.0
```

There is no ML-DSA variant and no extension point. An ML-DSA key cannot travel through that
signature. Forking libp2p-tls alone therefore does not help; it cascades into forking
libp2p-identity, which owns `PeerId` encoding, the protobuf key format and the multihash — far
past "maintain as a patch, upstream if possible."

Two further hard-coded conflicts in `libp2p-tls`, each independently requiring a fork:
`const P2P_ALPN: [u8; 6] = *b"libp2p"` (Huxplex needs `huxplex/{network}/1`, and ALPN separation
before Huxplex code runs is part of **G5-T1**), and `Libp2pCertificateVerifier`, which enforces
the libp2p Public Key Extension that ADR-0019 deliberately does not use.

#### ✅ ADR-0019's load-bearing assumption is confirmed at the source

The ADR rests on rustls having shipped native ML-DSA. It has — `rustls` 0.23.45:

```rust
// draft-ietf-tls-mldsa … IANA considerations
ML_DSA_44 => 0x0904,   ML_DSA_65 => 0x0905,   ML_DSA_87 => 0x0906,
```

and the `aws_lc_rs` provider wires `webpki_algs::ML_DSA_{44,65,87}` into both its supported-schemes
and verification tables. The code point **0x0904 matches ADR-0019 exactly**. Better still,
`libp2p-tls` already depends on `rustls` with features `["aws-lc-rs", "prefer-post-quantum"]` and
calls `rustls::crypto::aws_lc_rs::default_provider()` — the provider carrying ML-DSA is already the
one in use.

**So the cryptography is available; only the plumbing is closed.** This is the good half of the
finding, and it means the **stop condition was not reached** — the certificate-extension bridge
fallback is not needed.

#### ⚠️ The deeper finding: two incompatible `PeerId` definitions

This did not appear in the original framing of the spike and matters more than the crate choice.

`libp2p-core` 0.44's upgrade pipeline produces `Boxed<(PeerId, StreamMuxerBox)>` — the swarm,
GossipSub and Kademlia are all typed on **`libp2p_identity::PeerId`**, a multihash over a
protobuf-encoded libp2p public key. Huxplex's is

```
PeerId = SHAKE-256(ML-DSA-44 public key)[..32]
```

([wire spec §4](../15-specifications/05-network-wire-protocol.md), `crates/hux-network/src/peer.rs`,
asserted by **G5-T2**). These are different identities over different key types with different
encodings. Driving quinn directly gives full control of the *transport* but does not by itself
reconcile the *identity* the libp2p behaviours are generic over.

**This is an architect decision, not an implementation detail.** Three options:

| Option | Consequence |
|---|---|
| **(a)** Adopt libp2p's `PeerId` | Keeps GossipSub + Kademlia unmodified. Contradicts ADR-0019, the wire spec, `peer.rs` and **G5-T2**; makes identity depend on Ed25519 in a PQ chain — self-defeating |
| **(b)** Huxplex `PeerId` end-to-end, own gossip + DHT | Fully consistent with ADR-0019. Abandons libp2p's battle-tested GossipSub scoring, which **G5-T3** (bounded amplification) leans on. Much the largest scope |
| **(c)** Dual identity with a proven binding — libp2p `PeerId` for the swarm, Huxplex `PeerId` at the application layer, bound by the ML-DSA certificate and verified at `Identified` | Pragmatic. Cost is a second identity and the binding proof; that binding becomes a security-critical invariant needing its own gate test |

**(c)** looks the most likely answer, but it is a genuine ADR, not a choice to make inside an
implementation PR. **Write it before N1.**

#### Consequences for the rest of G5

- **N1–N5 become implementation, not integration.** The upside: every ADR-0019 requirement —
  ALPN, mutual auth, the custom verifier, 0-RTT off, Initial padding — becomes *directly
  expressible*, because Huxplex owns the `rustls::{Client,Server}Config`. **G5-T6** (the ≈130-byte
  amplification margin) in particular is far easier to assert on a config we construct than one
  built for us.
- **Add `quinn` 0.11 as a direct dependency**; `libp2p-quic` is no longer the transport.
  `rustls` 0.23.45 (`aws-lc-rs`, non-FIPS), per ADR-0019 conditions 1–2.
- **ADR-0019 needs an amendment** recording outcome 3 and the reason outcome 2 failed
  (libp2p-identity, not libp2p-tls).
- **G0-7 (the C-toolchain pin) activates**: `aws-lc-rs` enters the tree with this work, so
  `scripts/check-reproducible.sh` must be re-verified as the first acceptance step — sequencing
  rule 3, and stop condition **R4** if it cannot be met.

#### Status

**N0 is closed.** N1 is blocked on the identity ADR above, not on further investigation.

---

## Tasks

### A. Certificates and authentication

| ID | Task | Acceptance |
|---|---|---|
> **Blocked on the identity ADR** from the N0 finding above — libp2p's `PeerId` and Huxplex's
> `SHAKE-256(spki)[..32]` are different identities, and which one the swarm carries decides the
> shape of N1–N11. Write that ADR first.

| **N0b** ⬜ | *(new, from the N0 finding)* Drive `quinn` 0.11 behind libp2p's `Transport` trait; add `quinn` + `rustls` 0.23.45 as direct dependencies. `libp2p-quic` is not the transport | A QUIC connection established with a Huxplex-constructed `rustls::{Client,Server}Config` |
| **N1** ⬜ | Generate a self-signed X.509 cert: SPKI = ML-DSA-44 public key, self-signature ML-DSA-44, `SignatureScheme` `mldsa44` = **0x0904** ✅ *confirmed present in rustls 0.23.45* | Cert parses in rustls; key is the `Transport` purpose (`m/44'/931931'/4'/0'/{i}'`) 🟢 |
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

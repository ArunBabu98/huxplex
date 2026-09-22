# ADR-0019: Transport authentication — native ML-DSA TLS certificates over QUIC

- Status: Accepted
- Date: 2026-09-22
- Deciders: Founding architect, networking, cryptography, security

## Context

[ADR-0012](0012-network-transport.md) chose rust-libp2p over QUIC with "a PQ-hybrid handshake
bound to the ML-DSA-44 identity", and [`15-specifications/05-network-wire-protocol.md`](../15-specifications/05-network-wire-protocol.md)
§2 specified a bespoke four-flight handshake (ClientHello / ServerHello / Finished ×2) with an
ML-DSA-44 signature over the transcript. ADR-0012 recorded the integration as its main negative
consequence: *"integrating a custom security upgrade into libp2p is non-trivial and must be
carefully reviewed (it is security-critical)."*

The September 2026 Layer-0 review sharpened that into a hard constraint: **upstream libp2p's
post-quantum work covers confidentiality only.** Its own draft states *"authentication stays
classical: in libp2p the identity key signs the static key"*, so `PeerId = SHAKE-256(ml_dsa_pk)`
will never be satisfied upstream. Huxplex carries custom transport authentication either way.

Three shapes were then considered (the full analysis is in
[`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md)):

- **1a — libp2p-style certificate extension.** A self-signed cert with an ephemeral *classical*
  key, carrying the ML-DSA key and an ML-DSA signature over the cert key in an X.509 extension.
  This is exactly how libp2p authenticates over QUIC today, with Ed25519.
- **2 — application-level handshake** over a standard QUIC + rustls connection, bound with a TLS
  exporter.
- **1a + 2 hybrid** — both, so that identity binds at handshake time *and* the binding is
  post-quantum.

### The fact that made all three obsolete

**QUIC's handshake is TLS 1.3 (RFC 9001) and cannot be replaced.** The real question was only
ever *how ML-DSA gets into that TLS handshake*. As of September 2026 it gets in natively:

- **`draft-ietf-tls-mldsa`** (*Use of ML-DSA in TLS 1.3*) is at **-06**, submitted to the IESG and
  in the RFC Editor queue, intended as Informational. It assigns IANA `SignatureScheme` code
  points: **`mldsa44` = 0x0904**, `mldsa65` = 0x0905, `mldsa87` = 0x0906.
- **rustls 0.23.44, released 2026-09-07, enables ML-DSA certificates by default** with the
  `aws-lc-rs` provider. The feature is explicitly unusable in the public Web PKI but supported
  for **private certificate hierarchies**.
- Other implementations: OpenSSL, BoringSSL, s2n-tls, wolfSSL, BouncyCastle, GnuTLS.

Huxplex *is* a private hierarchy — self-signed, self-certifying, no CA. The case that works today
is exactly ours.

### Forces

- **Principle 2 (temporal security).** Options 1a and 1a+2 leave an ephemeral **classical** key in
  the authentication path; a real-time CRQC could MITM. Only native ML-DSA removes it.
- **Principle 4 (agility over perfection).** A bespoke extension or handshake is a format Huxplex
  owns and must revise to rotate. A TLS `SignatureScheme` code point is a registry value.
- **Principle 12 (minimize the trusted base).** Every bespoke mechanism is security-critical code
  to specify, implement and audit.
- **Principle 9 (bounded state).** ML-DSA in certificates enlarges the first flight, which
  collides with QUIC's 3× anti-amplification limit.
- **[ADR-0014](0014-validator-key-management.md) rule 3** mandates an anti-double-sign guard in
  front of the consensus signer, "ideally a separate remote-signer process." **A TLS stack
  requires the raw private key.** A key handed to rustls cannot sit behind a remote signer.

## Options

- **A — Bespoke handshake** (wire spec §2 as written). *Advantages:* full control; no new
  dependency. *Disadvantages:* the largest possible volume of custom security-critical code;
  cannot reuse rustls's audited `X25519MLKEM768`; every rotation is a spec revision. Violates
  principles 4 and 12.
- **B — Certificate extension (1a), optionally plus exporter binding (2).** *Advantages:* mirrors
  libp2p exactly; small first flight (ECDSA `CertificateVerify`). *Disadvantages:* a classical
  ephemeral key remains load-bearing for session binding (principle 2); a Huxplex-owned extension
  format forever (principle 4); with phase 2 added, three bespoke mechanisms (principle 12).
- **C — Native ML-DSA TLS certificates.** *Advantages:* no classical component; standard
  negotiation; no custom protocol; TLS's `CertificateVerify` binds identity to the session with a
  PQ signature. *Disadvantages:* largest first flight (amplification); adds `aws-lc-rs`;
  `libp2p-quic` integration unverified.
- **D — AuthKEM / KEMTLS.** Signature-free KEM-based authentication; ~15% smaller
  (8,424 B vs 9,884 B). *Disadvantages:* `draft-celi-wiggers-tls-authkem-07` is an **individual
  draft, explicitly "not endorsed by the IETF" with "no formal standing in the IETF standards
  process"** — principle 4 forbids making that load-bearing. Requires a **long-term KEM key as
  identity**, breaking `PeerId = SHAKE-256(ml_dsa_pk)` and implying two identity keys. Provides
  **implicit authentication with no non-repudiation**, while the identity key must sign blocks,
  votes and DHT entries regardless. Extra round trip for client authentication. And the anti-
  principle applies verbatim: *"❌ Optimize the PQ parameters for size now."*

## Decision

**Option C.** Mutual-authentication TLS 1.3 over QUIC with native ML-DSA-44 certificates.

### 1. The certificate

```
self-signed X.509 certificate
  SubjectPublicKeyInfo : ML-DSA-44 public key   (1,312 B)
  signatureAlgorithm   : id-ML-DSA-44  (OID 2.16.840.1.101.3.4.3.17)
  self-signature       : ML-DSA-44               (2,420 B)
TLS SignatureScheme    : mldsa44 = 0x0904
```

Verification (a custom `ServerCertVerifier` / `ClientCertVerifier`, no CA, no trust store):

1. Verify the certificate's self-signature.
2. Compute `SHAKE-256(SubjectPublicKeyInfo public key)[..32]` and require it to equal the
   `PeerId` the dialer intended to reach.
3. Reject on any mismatch. There is no name checking, no expiry chain, no revocation — identity
   *is* the key.

**Both directions authenticate.** The server requests a client certificate; an unauthenticated
peer never reaches an application stream.

### 2. Network separation moves to ALPN

ALPN is **`huxplex/{network}/1`** (`huxplex/mainnet/1`, `huxplex/testnet/1`). QUIC enforces ALPN
agreement, so a mainnet node cannot complete a handshake with a testnet node **before any Huxplex
code runs**. This is stronger and cheaper than the context-string check it replaces, and it
satisfies the network-separation requirement of the [wire spec](../15-specifications/05-network-wire-protocol.md) §6
at the transport layer.

### 3. A dedicated `Transport` key purpose

The transport key is **`KeyPurpose::Transport` (4)** — `m/44'/931931'/4'/0'/{index}'` — not the
`Transaction` hot key.

This is a deliberate amendment to [ADR-0012](0012-network-transport.md) rule 5, and the reason is
operational, not cryptographic: **rustls needs the raw private key.** [ADR-0014](0014-validator-key-management.md)
rule 3 requires the consensus signer to sit behind an anti-double-sign guard, ideally in a
separate remote-signer process. A key that has been handed to a TLS stack cannot be isolated that
way. Separating them means the remote signer holds the consensus key and rustls never sees it.

ADR-0012 rule 5's *intent* is preserved: the transport identity is still an ML-DSA-44 key
deterministically derived from the same master seed, and `PeerId` is still
`SHAKE-256(that key)[..32]` — it is a **purposed** key in one hierarchy, not an ad-hoc second
identity. The validator registration record (`validator:registration:v1`) binds `PeerId` to the
validator identity, as it already does for session keys.

> This is the first exercise of [ADR-0018](0018-signature-role-profiles.md) rule V2 (roles and
> purposes are added, never renumbered) — and it worked as intended: a purely additive change.

### 4. Cross-protocol key separation is checked, not assumed

A TLS `CertificateVerify` signature and a Huxplex protocol signature are made by ML-DSA keys in
the same hierarchy. They are separated structurally, because FIPS 204 encodes the context
parameter's length and bytes into the signed preimage: TLS signs with the TLS profile's context,
Huxplex with `huxplex-{network}:{purpose}:v1`. **This MUST be tested, not assumed** (G5-T7), and
the exact context the TLS ML-DSA profile uses is a conformance item to confirm against the final
RFC.

### 5. Session resumption, but no 0-RTT early data

1-RTT resumption is **enabled**: it skips the certificate entirely, which is what makes the
handshake cost acceptable in steady state — a validator mesh holds long-lived connections, and
resumptions outnumber fresh handshakes heavily.

**0-RTT early data is forbidden.** It reintroduces exactly the replay class that principle 7's
domain-separation discipline exists to prevent, on the one path where Huxplex has no
application-layer nonce to bind.

### 6. Anti-amplification

| Flight | Bytes |
|---|---|
| Client Initial (ClientHello + X25519MLKEM768), **padded** | ≈ 2,700 |
| **Budget (3×)** | **≈ 8,100** |
| ServerHello | ≈ 1,220 |
| Certificate (X.509 + ML-DSA pk 1,312 + ML-DSA self-sig 2,420) | ≈ 4,130 |
| CertificateVerify (ML-DSA-44) | ≈ 2,420 |
| EncryptedExtensions + CertificateRequest + Finished | ≈ 200 |
| **Server first flight** | **≈ 7,970** |

The client MUST pad its Initial so that the responder's first flight stays inside 3×. Padding is
cheaper than QUIC Retry (which costs a round trip on every first contact) and costs only upstream
bytes on fresh handshakes. Pinned by **G5-T6**; the margin is thin by design and a test is the
only thing that will keep it.

## Consequences

- ➕ **No classical component in the authentication path.** Principle 2 is satisfied without
  qualification, which no other option achieved.
- ➕ **Three bespoke mechanisms deleted**: the custom handshake, the certificate extension, and
  the exporter-binding phase. The wire spec §2 flow is replaced by standard TLS 1.3.
- ➕ **Rotation is a code point.** ML-DSA-44 → -65 is `0x0904` → `0x0905` plus a registry row
  (ADR-0018), not a redesign of a Huxplex-owned format.
- ➕ **Network separation is enforced by QUIC itself**, before Huxplex code executes.
- ➕ The transport key is isolable behind the remote-signer boundary; a TLS-stack compromise does
  not reach the consensus key.
- ➕ Brings a second, independent ML-DSA implementation into the tree, which is what
  [`cryptography.md`](../02-architecture/cryptography.md) engineering rule 4 (multi-vendor) asks
  for.
- ➖ **`aws-lc-rs` enters the dependency tree.** It is C and assembly — a deliberate exception
  under principle 8's "vetted cryptographic primitive code" clause, and an audit and
  `cargo-deny` surface. Must be pinned and tracked.
- ➖ **Largest first flight of any option**, sitting close to the amplification ceiling. Mitigated
  by padding, enforced by G5-T6, and it will break silently if anything is added to the flight.
- ➖ **`libp2p-quic` integration is unverified.** `libp2p_quic::Config` builds its rustls config
  internally via `libp2p-tls`; supplying an ML-DSA certificate config may require driving quinn
  directly behind libp2p's transport trait, or a small fork of `libp2p-tls`. **This is the one
  open implementation risk and is a G5 entry spike.**
- ➖ The bespoke hybrid handshake retires from the transport path. `kem768_derive_session_key`
  and its directional derivation stay implemented, tested and available for application-level
  session keys, but rustls performs the transport KEX.
- ➖ Huxplex nodes cannot interoperate with vanilla libp2p nodes. Intended — network separation is
  already a hard requirement.
- ⚠️ **rustls 0.23.44 is two weeks old at the time of this decision.** Pin the exact version,
  track it closely, and hold Option B (certificate extension, without the exporter phase) as the
  **bridge** if the G5 spike finds integration blocked. Do not build the exporter phase under any
  circumstance — it exists only to compensate for a classical binding this decision removes.
- ⚠️ Risk accepted: `draft-ietf-tls-mldsa` is Informational and still in the RFC Editor queue. The
  code points are IANA-assigned and shipped in multiple implementations, so the practical risk is
  low, but it is not yet an RFC.

## Addendum — 2026-09-22: the `aws-lc-rs` dependency, on five conditions

The provider question was reviewed explicitly before accepting it, because it is the only part of
this decision that touches a stated principle.

**Why it is unavoidable.** rustls maintains two first-party providers: `rustls-aws-lc-rs`
(complete feature set, **including post-quantum**) and `rustls-ring` (easier to build,
**explicitly no post-quantum algorithms**). There is no native ML-DSA in TLS without `aws-lc-rs`.
`ring` would force the rejected certificate-extension bridge and its classical key — costing
principle 2, the principle this ADR exists to satisfy. Writing a libcrux-backed `CryptoProvider`
would keep one verified implementation and zero C, but means owning KEX, AEAD, hash and signature
handling in the TLS path — precisely what principle 12 says not to do.

**Correcting the framing.** Earlier drafts called this a *principle 8* exception. That is wrong.
Principle 8 permits `unsafe` in "vetted, audited cryptographic primitive code," and AWS-LC is
exactly that — it sits **inside** the carve-out, not outside it. What is genuinely new is not
unsafe code but **unverified** crypto where the project otherwise has **formally verified**
crypto: `libcrux`'s ML-DSA/ML-KEM core is machine-checked with hax and F* for panic freedom,
correctness and secret independence, and AWS-LC is not. The real tension is therefore with
**principle 12** (minimize the trusted base) and the reproducibility half of **principle 15** —
and it is recorded against those.

**Accepted on five conditions:**

1. **Non-FIPS builds only.** These require only a C/C++ compiler; `aws-lc-sys` ships
   pre-generated bindings for `aarch64-apple-darwin`, `aarch64-unknown-linux-gnu` and
   `aarch64-unknown-linux-musl`, so bindgen, CMake and Go are never invoked. A FIPS build would
   always require CMake and Go — do not enable one without revisiting this.
2. **Pin exact `aws-lc-rs` / `aws-lc-sys` versions** and add both to `deny.toml` review.
3. **Extend the G0-T2 reproducible-build recipe to pin the C toolchain**, not just
   `rust-toolchain.toml`. AWS-LC compiles C and assembly at build time, so byte-identical
   artifacts now depend on the C compiler version as well.
4. **CI runs a libcrux ↔ AWS-LC ML-DSA differential test.** FIPS 204 verification is
   deterministic, so the two implementations must agree byte-for-byte. This converts the cost
   into the multi-vendor coverage [`cryptography.md`](../02-architecture/cryptography.md)
   engineering rule 4 asks for. Note the `Transport` purpose means they never touch the same key.
5. **Revisit if a formally verified pure-Rust provider with ML-DSA appears.**

**Reversibility.** Swapping providers is a rustls configuration change — nothing on the wire
moves, no state migrates. That is exactly what this ADR's code-point-level agility buys, and it
makes the dependency a low-regret call rather than a lock-in.

## Links
- Amends [ADR-0012](0012-network-transport.md) rules 4 and 5 (does not supersede it — transport,
  discovery and messaging decisions stand)
- [ADR-0018](0018-signature-role-profiles.md) — the `Transport` role/purpose is added under rule V2
- [ADR-0014](0014-validator-key-management.md) — why the transport key is separate
- [ADR-0002](0002-cryptographic-parameter-set.md) — suite v1; agility is what makes the code-point
  rotation cheap
- Spec: [`15-specifications/05-network-wire-protocol.md`](../15-specifications/05-network-wire-protocol.md) §2,
  [`02-cryptography-spec.md`](../15-specifications/02-cryptography-spec.md) §1.1, §4.1, §5
- Tests: [`16-action-plan.md`](../16-action-plan.md) G5-T1, **G5-T6**, **G5-T7**
- Origin: [`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md) §3.2
- External: [draft-ietf-tls-mldsa-06](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/) ·
  [rustls 0.23.44 release](https://github.com/rustls/rustls/releases) ·
  [libp2p TLS spec](https://github.com/libp2p/specs/blob/master/tls/tls.md) (the rejected
  Option B pattern) ·
  [draft-celi-wiggers-tls-authkem](https://datatracker.ietf.org/doc/draft-celi-wiggers-tls-authkem/)
  (rejected Option D) · RFC 9000 §8.1 (amplification), RFC 9001 (QUIC/TLS)

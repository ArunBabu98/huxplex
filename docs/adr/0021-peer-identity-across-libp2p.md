# ADR-0021: Peer identity across the libp2p boundary — one identity, two encodings

- Status: Accepted
- Date: 2026-09-30
- Deciders: Founding architect, protocol, networking

## Context

[ADR-0012](0012-network-transport.md) rule 5 already decided what peer identity must be:

> *"the libp2p peer identity is derived from the node's **ML-DSA-44** key so it equals
> `PeerId = SHAKE-256(pk)[..32]` (ADR-0010); no separate transport identity key."*

That rule was written as a **requirement**, without establishing that it could be met. The
[N0 entry spike](../18-implementation-plan/03-g5-transport.md) (2026-09-23) found the obstacle,
reading the vendored sources rather than the documentation:

- `libp2p_identity::KeyType` is `{Ed25519, RSA, Secp256k1, Ecdsa}` — **no ML-DSA variant and no
  extension point.** An ML-DSA key cannot be represented as a libp2p key at all.
- `libp2p-core` 0.44's upgrade pipeline yields `Boxed<(PeerId, StreamMuxerBox)>`, so the swarm,
  **GossipSub and Kademlia are all typed on `libp2p_identity::PeerId`** — a multihash over a
  protobuf-encoded libp2p key.

So the question became live: is ADR-0012 rule 5 satisfiable, or does adopting libp2p force a
classical identity into a post-quantum chain?

This ADR answers that. It is not a new decision about *what* the identity is — ADR-0012 settled
that — it records the **mechanism** by which rule 5 is met, and closes the sub-decision ADR-0012's
own amendment deferred to the G5 entry spike.

### Why it cannot be left to implementation

`PeerId` is the Kademlia routing key, the GossipSub peer-scoring key, and the DHT record key
(*"the DHT key SHOULD be the publisher's `PeerId`"*, [wire spec §4](../15-specifications/05-network-wire-protocol.md)).
If two identities exist, every one of those has an ambiguous referent, and the ambiguity is
exactly the kind that is invisible until it is exploited. It is also asserted by **G5-T2**.

## Options

- **A — Adopt libp2p's `PeerId`.** Keeps GossipSub and Kademlia untouched at zero integration
  cost. *Cost:* peer identity in a PQ chain becomes anchored on Ed25519. A CRQC would not break
  consensus signatures but **would break Sybil resistance and DHT record authorisation** — the
  project's central claim failing at the one layer nobody inspects. Also contradicts ADR-0012
  rule 5, ADR-0019, the wire spec, `peer.rs` and G5-T2. **Rejected.**
- **B — Huxplex identity end-to-end; implement gossip and the DHT ourselves.** Fully consistent
  with every existing document. *Cost:* abandons libp2p's GossipSub — mesh maintenance,
  IHAVE/IWANT, flood publishing, and the peer scoring that **G5-T3** (bounded amplification)
  leans on — and Kademlia with it. The largest scope in the gate, and the largest new adversarial
  surface. **Rejected** on cost, not on principle; revisit only if C proves unworkable.
- **C — One identity, two encodings.** The libp2p `PeerId` is a *lossless re-encoding* of the
  Huxplex `PeerId`, not a second identity. **Accepted.**
- **D — Fork `libp2p-identity` to add an ML-DSA key type.** Would unify the two properly and
  could be upstreamed. *Cost:* the fork cascades into `PeerId` encoding, the protobuf key format
  and the multihash, and must be carried indefinitely until upstream accepts it. **Rejected as
  unnecessary** — option C achieves the same result with no fork.

## Decision

**Option C.** There is exactly one peer identity. libp2p carries an encoding of it.

```
Huxplex   PeerId = SHAKE-256(ML-DSA-44 public key)[..32]        // 32 bytes, unchanged
libp2p    PeerId = identity-multihash(Huxplex PeerId)
                 = 0x00 ‖ 0x20 ‖ <32 bytes>                      // 34 bytes
```

This is available **because** [N0 chose outcome 3](../18-implementation-plan/03-g5-transport.md) —
quinn is driven behind libp2p's `Transport` trait, so Huxplex constructs the
`(PeerId, StreamMuxerBox)` pair itself and decides what the swarm sees. Under `libp2p-quic` it
would not be: that crate builds the identity from its own keypair.

### Rules

| | Rule |
|---|---|
| **I1** | There is **one** identity. The libp2p form is an *encoding*, never a second identity, and must never be described as one. Nothing may hold a libp2p `PeerId` that is not a re-encoding of a Huxplex `PeerId`. |
| **I2** | The multihash code is **`0x00` (identity)**, not `0x12` (sha2-256). Identity-coding says *"these bytes are the identifier"*, which is true. `0x12` would assert a SHA-256 relationship to a libp2p key that does not exist. A SHAKE-256 code point is **not** an option: `PeerId::from_multihash` accepts only `0x00` and `0x12`. |
| **I3** | Conversion is **total and lossless in both directions**, and asserted by test in both directions. A one-way or fallible mapping reintroduces the two-identity problem through the back door. |
| **I4** | The Huxplex `PeerId` MUST stay **≤ 42 bytes** — libp2p's `MAX_INLINE_KEY_LENGTH`, above which identity-coded multihashes are rejected. It is 32 today. Assert this at compile time, so a future hash change fails the build rather than the network. |
| **I5** | The **authority is the TLS verifier** ([ADR-0019](0019-transport-authentication.md)): verify the certificate's self-signature, then check `SHAKE-256(spki)[..32] == expected PeerId`. The libp2p `PeerId` is *derived* from that verified value and is never trusted as received. |

### What this does not change

`peer.rs`, the wire spec's `PeerId` definition, ADR-0010's hash choice, ADR-0019's verifier, and
G5-T2 are all **unchanged**. That is the point: rule 5 is satisfied as written rather than amended.

## Verification

Run against `libp2p-identity` 0.3.0, 2026-09-30:

```
libp2p PeerId : 1AeFG5tBDEFVB4HGHZJPahwjnCeNzMpEHY4Yz3e7oFWCwR
round-trips   : true
recovers hux  : true
```

`PeerId::from_bytes(0x00 ‖ 0x20 ‖ hux)` is accepted, `to_bytes()` reproduces the input exactly,
and the Huxplex `PeerId` is recoverable verbatim from bytes `[2..]`. The `0x12` variant was also
tested and works; it is rejected here on semantics (I2), not capability.

### Re-verified at implementation — 2026-10-07

G5 was built on **`libp2p-identity` 0.2.14** (libp2p 0.56), not 0.3.0: 0.56 supports the pinned
rustc 1.85, so the toolchain bump this ADR anticipated was not needed. The mechanism is identical
— `PeerId::from_multihash` accepts identity-coded digests up to `MAX_INLINE_KEY_LENGTH = 42` — and
is now tested rather than spot-checked: **I3** both directions over 16 keys
(`i3_conversion_is_total_and_lossless_in_both_directions`), **I1** a sha2-coded `PeerId` refused,
**I4** a compile-time assertion in `peer.rs`, and **I5** the transport deriving the swarm's
`PeerId` only from the certificate the TLS verifier accepted.

## Consequences

- ➕ **ADR-0012 rule 5 is met as written.** Peer identity stays post-quantum, self-certifying, and
  exactly what the wire spec says it is.
- ➕ **GossipSub and Kademlia keep working**, on an identity that *is* the PQ identity. Both treat
  `PeerId` as an opaque identifier supplied by the transport; neither inspects a key.
- ➕ **No fork.** `libp2p-identity` is used unmodified, so there is no patch to carry and no
  upstream negotiation on the critical path.
- ➕ **No binding to prove.** The relationship is definitional — one value is a prefixed encoding
  of the other — rather than a cryptographic invariant that an attacker could attack. This is the
  main advantage over a genuine dual-identity design, which would have needed its own gate test.
- ➖ A reader who expects a libp2p `PeerId` to be derived from a libp2p key will find one that is
  not. Mitigated by I2: identity-coding claims nothing false, and the ambiguity is documented here
  and in the wire spec.
- ⚠️ **Depends on N0 outcome 3.** If the transport ever reverts to `libp2p-quic`, this mechanism is
  unavailable and the decision must be reopened. Recorded as a standing condition, not an
  assumption.
- ⚠️ **Toolchain.** `libp2p-identity` 0.3.0 requires **rustc 1.88**; `rust-toolchain.toml` pins
  **1.85.0**. Adopting the current libp2p stack means bumping the pinned toolchain, which is an
  input to the reproducible-build recipe — so **G0-T2 must be re-verified** as part of G5 entry,
  alongside the `aws-lc-rs` C-toolchain pin (G0-7). Two toolchain variables, one gate; do not
  conflate them.

## Links
- Satisfies [ADR-0012](0012-network-transport.md) rule 5; closes the sub-decision its 2026-09-22 amendment deferred to the G5 entry spike
- [ADR-0019](0019-transport-authentication.md) — the verifier that is the authority for I5
- [ADR-0010](0010-hash-function-domains.md) — SHAKE-256 as the identity hash
- N0 finding: [`18-implementation-plan/03-g5-transport.md`](../18-implementation-plan/03-g5-transport.md)
- [wire protocol spec §4](../15-specifications/05-network-wire-protocol.md)
- Tests: **G5-T2** (`PeerId` bound to the key); I3 and I4 need conversion tests at N0b
- Code (unchanged by this ADR): `crates/hux-network/src/peer.rs`

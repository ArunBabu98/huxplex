# 02 — Cryptography Specification (suite v1)

> Normative. This document is the conformance contract for Huxplex's cryptographic primitives. It
> is **derived directly from the implemented code** in `src/crypto/` and `src/network/` (🟢) and
> the canonical algorithm-suite decision in [ADR-0002](../adr/0002-cryptographic-parameter-set.md).
> Where this spec and the code disagree, that is a bug to be fixed in one of them.
>
> Keywords are per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Algorithm suite v1

Every signed or encrypted object is bound to **`(role, suite version)`** ([ADR-0002](../adr/0002-cryptographic-parameter-set.md),
[ADR-0018](../adr/0018-signature-role-profiles.md)). Verification MUST dispatch on both; neither
is optional and neither is inferred from the object type.

### 1.1 Signature roles — NORMATIVE

| Role | Objects | Suite v1 primitive | Standard | NIST cat |
|---|---|---|---|---|
| `Transaction` | `Transaction`, `Intent`, `GossipMessage`, `DhtEntry` | **ML-DSA-44** (Dilithium2) | FIPS 204 | 1 |
| `QuorumCert` | `Vote`, block certificate | **ML-DSA-44** | FIPS 204 | 1 |
| `Identity` | validator identity, `did:huxplex` | **SLH-DSA-128s** | FIPS 205 | 1 |
| `Governance` | Work Visa issuance, constitutional records, registry updates | **SLH-DSA-128s** | FIPS 205 | 1 |
| `Transport` | TLS 1.3 certificate + `CertificateVerify` ([ADR-0019](../adr/0019-transport-authentication.md)); `PeerId` derives from this key | **ML-DSA-44**, TLS `SignatureScheme` **0x0904** | FIPS 204 | 1 |

**SLH-DSA-128s is the SHAKE instantiation, SLH-DSA-SHAKE-128s.** ✅ *Decided 2026-10-07* (G1 · C7).
FIPS 205 defines the 128s parameter set over SHA-2 and over SHAKE; SHAKE-256 is already the
identity hash domain ([ADR-0010](../adr/0010-hash-function-domains.md)), so the root-of-trust
signature rests on the same hash assumption as the identities it signs for. Implemented on
`fips205`, cross-checked byte-for-byte against RustCrypto `slh-dsa` (C8).

Rules:
1. Roles are **added, never removed or renumbered.** An unknown role MUST fail closed with a
   distinct error (never be ignored, never fall back to a default).
2. A role's primitive changes **only** by a new suite version. Suite `vN` is immutable once any
   object has been signed under it, and every `(role, vN)` pair stays verifiable forever.
3. Roles version **independently**: bumping `QuorumCert` MUST NOT require re-signing or
   re-encoding any `Transaction` object.
4. A signature produced under one role MUST NOT verify under any other role, for every ordered
   pair (conformance: G1-T6).
5. The `(role, version) → primitive` table is governance-updatable data, not code.

### 1.2 Non-signature primitives (suite v1)

| Use | Primitive | Standard |
|---|---|---|
| Transport key agreement | **ML-KEM-768 + X25519** (hybrid) | FIPS 203 (+ RFC 7748) |
| Key derivation | **HKDF-SHA-256** | RFC 5869 |
| Identity / XOF hash | **SHAKE-256** | FIPS 202 |  <!-- impl: libcrux-sha3, see below -->
| Bulk state / Merkle hash | **BLAKE3** (256-bit) | — |

> Implemented (🟢, 2026-10-07): ML-DSA-44, SLH-DSA-SHAKE-128s, ML-KEM-768, the X25519 +
> ML-KEM-768 hybrid (§4.3), HKDF-SHA-256, SHAKE-256, BIP32 derivation, the `(role, version)`
> registry and the context registry (§5). Specified but not yet in code (🟡): BLAKE3 (G2b).
>
> **SHAKE-256 is implemented on `libcrux-sha3`** (2026-09-30), replacing RustCrypto `sha3`. The
> primitive is unchanged — FIPS 202 SHAKE-256 — and the swap was proven byte-neutral by KATs
> generated from the outgoing implementation before it was removed
> (`crates/hux-crypto/tests/kat_hashes.rs`). This matters because SHAKE-256 defines `PeerId`, so
> a byte change here is a network-wide identity change rather than a refactor. Rationale:
> [repository-structure § Dependency policy](../10-development/repository-structure.md).

> **v1 parameter note.** v1 keeps **ML-DSA-44** for both signing roles, per the
> [v1 scope contract](06-v1-scope.md) §1 — measuring its overhead is v1's research deliverable.
> ML-DSA-44 vs ML-DSA-65 ([R-A2](../11-research/open-problems.md)) is deferred to the G1
> benchmarks and is now a **per-role** question; because of ADR-0018 it is a registry row, not a
> redesign.

## 2. Exact sizes (bytes)

These are asserted by tests and MUST hold for suite v1.

### ML-DSA-44 (`src/crypto/signature.rs`, `publickey.rs`)
| Item | Size | Notes |
|---|---|---|
| Public (verification) key | **1312** | `PublicKey.bytes` |
| Secret (signing) key | **2560** | `PrivateKey.bytes` |
| Signature | **2420** | `Signature.bytes` |
| Seed (keygen input) | **32** | output of BIP32 derivation |

> Note: the executive summary's "2,560 B" refers to the **secret key**; the **signature is
> 2,420 B** (see ADR-0002 conflict #2). This spec uses the code's values, which are authoritative.

### SLH-DSA-SHAKE-128s (`crates/hux-crypto/src/sig/slh_dsa.rs`)
| Item | Size | Notes |
|---|---|---|
| Public key | **32** | `PK.seed ‖ PK.root` |
| Secret key | **64** | `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` |
| Signature | **7856** | |
| Seed (keygen input) | **48** | `SK.seed ‖ SK.prf ‖ PK.seed`, FIPS 205 Algorithm 18 order |
| Signing randomness | **16** | `opt_rand`; hedged, from the CSPRNG (§3) |

> There is no BIP32 path for a 48-byte seed yet: `Keypair::generate` (32 bytes) refuses
> SLH-DSA rather than stretching or truncating, and `Keypair::generate_from_seed` takes the 48.
> The `Identity` key's derivation is an open item.

### ML-KEM-768 (`src/crypto/kem.rs`)
| Item | Const | Size |
|---|---|---|
| Encapsulation key (public) | `EK_SIZE` | **1184** |
| Decapsulation key (secret) | `DK_SIZE` | **2400** |
| Ciphertext | `CT_SIZE` | **1088** |
| Shared secret | — | **32** |
| Keygen randomness | — | **64** |
| Encapsulation randomness | — | **32** |

### X25519 + ML-KEM-768 hybrid (`crates/hux-crypto/src/kem/hybrid.rs`)
| Item | Size | Layout |
|---|---|---|
| Encapsulation key | **1216** | `ek_mlkem (1184) ‖ pk_x25519 (32)` |
| Decapsulation key | **2432** | `dk_mlkem (2400) ‖ sk_x25519 (32)` |
| Ciphertext | **1120** | `ct_mlkem (1088) ‖ eph_pk_x25519 (32)` |
| Shared secret | **32** | §4.3 |
| Keygen seed | **96** | `d ‖ z (64) ‖ sk_x25519 (32)` |
| Encapsulation randomness | **64** | `m (32) ‖ eph_sk_x25519 (32)` |

### Hashes / identifiers
| Item | Size |
|---|---|
| `PeerId` (SHAKE-256 squeeze) | **32** (hex display **64** lowercase chars) |
| HKDF output (session key) | **32** |

## 3. Signing & verification (ML-DSA-44)

ML-DSA-44 is used with the **context** (domain-separation) parameter of the FIPS 204 signing API.

- **Sign:** `sign(signing_key, message, context, randomness)` where `randomness` is 32 fresh
  random bytes (hedged/randomized signing). A signer MUST use fresh randomness per signature.

> **Hedged signing is settled, not open.** ✅ *Decided 2026-09-22.* Deterministic lattice signing
> plus fault injection is a demonstrated key-recovery path (eprint 2025/2009, whose vulnerable
> pattern was found in PQM4, liboqs, PQClean and wolfSSL). Reproducibility is bought at the KAT
> layer instead (§7), never by making production signing deterministic.
>
> **Consequence for the API:** production signing MUST source randomness from the system CSPRNG
> and MUST NOT accept a caller-supplied value. A separate, test-only entry point takes explicit
> randomness so §7 fixtures stay byte-exact. These are two functions, not one function with a
> flag — a flag is a downgrade attack waiting for a misconfiguration.
- **Verify:** `verify(verification_key, message, context, signature)`.
- The `context` argument is the **domain-separation context string** from §5. When no context
  applies (raw test/low-level use only) it defaults to the empty slice; **all protocol-level
  signatures MUST supply a non-empty context** from the registry.
- A `PublicKey` MUST reject a `Signature` whose `scheme` differs from its own
  (`SchemeMismatch`), before any cryptographic check.
- Verification MUST enforce the exact byte sizes in §2; wrong-size keys/signatures are an error,
  not a `false` result.

## 4. Key derivation

### 4.1 BIP32 → ML-DSA seed (`src/crypto/bip32.rs`)
- Input: a **64-byte** master seed.
- Path (hardened at every level, **fixed**): **`m/44'/931931'/{purpose}'/0'/{index}'`** where
  `931931` is the Huxplex registered coin type, `{purpose}` is the **key purpose** (below), and
  `index` is a `u32` — the validator key epoch per [ADR-0014](../adr/0014-validator-key-management.md).
- Output: the **32-byte** BIP32 child private key, used directly as the ML-DSA-44 keygen seed.
- This derivation is deterministic: the same `(seed, purpose, index)` MUST always yield the same
  key.

**Key purposes — NORMATIVE.** ✅ *Decided 2026-09-22.* Discriminants are identical to the
signature roles of §1.1, so a key's purpose and the role it may sign under cannot drift apart.

| `{purpose}` | Purpose | Notes |
|---|---|---|
| `0'` | `Transaction` | Hot per-block / per-vote signing and user transactions |
| `1'` | `QuorumCert` | **Reserved.** Gives a future synchronized/aggregating scheme its own key tree (R-A1) without colliding with session keys |
| `2'` | `Identity` | Long-lived validator identity / root of trust |
| `3'` | `Governance` | Credential issuance, constitutional records, registry updates |
| `4'` | `Transport` | TLS certificate key; `PeerId = SHAKE-256(pk)[..32]`. **Separate from `Transaction` because the TLS stack requires the raw private key**, which would defeat the remote-signer isolation of [ADR-0014](../adr/0014-validator-key-management.md) rule 3 |

Rules:
1. Purposes are **added, never removed or renumbered** ([ADR-0018](../adr/0018-signature-role-profiles.md)
   V2) — a discriminant is part of the derivation path of every key ever issued under it.
2. Seeds for different purposes at the same `index` MUST be distinct (🟢
   `test_key_purposes_are_domain_separated_at_the_same_index`).
3. `purpose = 0'` reproduces the pre-ADR-0018 path byte-for-byte, so **no previously derived key
   or test vector changes** (🟢 `test_transaction_purpose_reproduces_the_original_path`).
4. A validator is **not** assumed to hold exactly one signing key. Registration records
   (`validator:registration:v1`) MUST be able to bind more than one purpose.

### 4.2 ML-KEM-768 session key (`src/crypto/kem.rs`)
After `decapsulate`/`encapsulate` produce a 32-byte shared secret `ss`, the directional session
key is:

```
session_key = HKDF-SHA-256(
    salt = <optional salt or none>,
    ikm  = ss,
    info = "ML-KEM-768-v1-DERIVE" || peer_a[32] || peer_b[32] || optional_protocol_label
) -> 32 bytes
```

- `peer_a` and `peer_b` are 32-byte peer fingerprints; their **order encodes direction** (so the
  initiator→responder key differs from responder→initiator).
- **Ordering rule — NORMATIVE.** ✅ *Decided 2026-09-22:* **initiator-first.** `peer_a` is the
  `PeerId` of the side that sent `ClientHello`; `peer_b` is the responder's. This is a property
  of the *connection*, not of the key values, so it never depends on byte comparison and cannot
  flip if a peer re-keys. Both sides know their role from the handshake, so no negotiation is
  required. A responder MUST NOT derive using its own `PeerId` as `peer_a`.
- `optional_protocol_label` SHOULD carry the protocol/context (e.g. the handshake context string)
  to bind the key to its use.

### 4.3 X25519 + ML-KEM-768 hybrid — NORMATIVE

✅ *Decided 2026-10-07* (G1 · B5). The application-level hybrid KEM, for session keys Huxplex
derives itself; the transport's own key exchange is TLS's `X25519MLKEM768` (ADR-0019). Byte
layout follows that TLS group — the ML-KEM part first in every value (§2).

```
shared_secret = HKDF-SHA-256(
    salt = none,
    ikm  = ss_mlkem (32) ‖ ss_x25519 (32),
    info = "X25519-MLKEM768-v1-COMBINE" ‖ ct_x25519 (32) ‖ pk_x25519 (32),
) -> 32 bytes
```

- **The X25519 values are bound into `info`.** ML-KEM is IND-CCA, so its secret already commits
  to its ciphertext; X25519's does not. Binding `ct_x25519` and `pk_x25519` keeps the construction
  IND-CCA when only ML-KEM holds (X-Wing, eprint 2024/039). ML-KEM's secret leads `ikm`.
- **A low-order X25519 share is rejected** (all-zero output), as TLS `X25519MLKEM768` requires.
- Directional session keys are then derived from `shared_secret` with §4.2's HKDF.
- **G1-T5:** with the X25519 output forced to a constant, session keys still differ, and every bit
  of the ML-KEM secret reaches the combined secret.

## 5. Context-string registry (domain separation) — NORMATIVE

Every protocol signature MUST be made over exactly one of these context strings. The scheme is
the project's core anti-replay mechanism: a signature valid in one context MUST NOT verify in any
other (cross-network, cross-shard, cross-phase, cross-purpose). All strings are ASCII; `{network}`
∈ {`mainnet`, `testnet`}; all carry a `:vN` version suffix for agility.

| Purpose | Context string | Role | Source |
|---|---|---|---|
| Transaction signing | `huxplex-{network}:tx:v1` | `Transaction` | code |
| Block phase — pre-prepare | `huxplex-{network}:block:preprepare:v1` | `QuorumCert` | code |
| Block phase — prepare | `huxplex-{network}:block:prepare:v1` | `QuorumCert` | code |
| Block phase — commit | `huxplex-{network}:block:commit:v1` | `QuorumCert` | code |
| Gossip message (per topic) | `huxplex-{network}:gossip:{topic}:v1` | `Transaction` | `src/network/topic.rs` 🟢 |
| DHT entry | `huxplex-{network}:dht:entry:v1` | `Transaction` | `src/network/topic.rs` 🟢 |
| ~~Transport handshake transcript~~ | ~~`huxplex-{network}:tls:handshake:v1`~~ | `Transport` † | **retired 2026-09-22** |
| Intent (agent economy) | `huxplex-{network}:intent:v1` | `Transaction` | code |
| Provenance record | `huxplex-{network}:provenance:v1` | `Transaction` | code |
| Validator registration | `huxplex-{network}:validator:registration:v1` | `Identity` | code |
| Verifiable credential / Work Visa | `huxplex-{network}:vc:v1` | `Governance` | code |
| ML-KEM HKDF info prefix | `ML-KEM-768-v1-DERIVE` | — | `src/crypto/kem.rs` |
| Hybrid KEM combiner info prefix | `X25519-MLKEM768-v1-COMBINE` | — | `src/kem/hybrid.rs` (§4.3) |

> **The registry is code** (2026-10-07): `hux_crypto::context` renders every string from a
> `Network` and a `Purpose`, binds each purpose to its role, and records retired strings so they
> are never reissued. `hux-network` builds its gossip and DHT contexts through it. **G1-T2**
> sweeps every ordered pair of its contexts on both networks — 650 pairs — rather than restating
> them.

Rules:
1. The gossip context is computed as `gossip_context(network, topic) =
   "huxplex-{network}:gossip:{topic}:v1"` where `{topic}` is the full topic string (§6). The DHT
   context is `dht_entry_context(network) = "huxplex-{network}:dht:entry:v1"`.
2. **Every context is network-parameterized. `{network}` is never hard-coded.** ✅ *Decided
   2026-09-22.* A context literal that bakes in a network name is a spec violation, because it
   makes cross-network replay rejection untestable for that object. `DhtEntry` was the last
   implementation site and is fixed (`src/network/message.rs`, `topic.rs`); the remaining
   `mainnet` literals live only in test fixtures for types that do not exist yet, and MUST be
   network-parameterized when those types are implemented.
3. Adding or changing any context string is a consensus-affecting change (§ change control in the
   [section README](README.md)) and MUST bump `:vN`.
4. † **The transport handshake context is retired.** [ADR-0019](../adr/0019-transport-authentication.md)
   replaced the bespoke handshake with standard TLS 1.3, whose `CertificateVerify` binds identity
   to the session under TLS's own transcript and context. Transport signatures are therefore made
   under the **`Transport`** role and TLS's context, not a Huxplex context string; **network
   separation for the transport moves to ALPN** (`huxplex/{network}/1`), which QUIC enforces
   before any Huxplex code runs. The context string is not reused for anything else — retired
   entries are never recycled. *(This was the first exercise of
   [ADR-0018](../adr/0018-signature-role-profiles.md) rule V2: adding the `Transport` role was a
   pure addition, exactly as the rule predicted.)*
5. Each context belongs to exactly one signature **role** (§1.1). The role and the context are
   independent separation axes and both MUST be enforced — a `tx:v1` signature must fail under
   `block:commit:v1` (context separation) *and* a `Transaction`-role signature must fail
   `QuorumCert`-role verification (role separation).

### 5.1 Required cross-context rejection properties (conformance)
The implementation MUST guarantee (these are covered by existing tests in
`src/network/mod.rs` and `src/crypto/mod.rs`):
- A mainnet signature MUST NOT verify under a testnet context, and vice versa — for **every**
  signed object type, DHT entries included (🟢 `test_dht_entry_cross_network_replay_fails`).
- A shard-`i` gossip signature MUST NOT verify under a shard-`j` (`i≠j`) context.
- A `blocks`-topic signature MUST NOT verify under the `mempool` topic, and an `intents`
  signature MUST NOT verify under a shard topic.
- A block `prepare`-phase signature MUST NOT verify under `preprepare` or `commit`.
- Tampering with any signed byte (payload, key, value) MUST cause verification to fail.

## 6. Network identifiers

### 6.1 PeerId (`src/network/peer.rs`)
```
PeerId = SHAKE-256(ml_dsa44_verification_key_bytes) squeezed to 32 bytes
hex(PeerId) = 64 lowercase hex chars
```
- Deterministic: the same ML-DSA-44 key MUST always yield the same `PeerId`.
- Distinct keys MUST yield distinct `PeerId`s (collision-resistant).
- The `PeerId` derivation MUST NOT collide with the ML-KEM EK fingerprint (different role,
  different size).
- The same digest construction anchors `did:huxplex` ids ([ADR-0013](../adr/0013-did-huxplex-method.md)).

### 6.2 GossipSub topics (`src/network/topic.rs`)
| Topic | String |
|---|---|
| Shard blocks | `huxplex/shard/{shard_id}/blocks` |
| Shard mempool | `huxplex/shard/{shard_id}/mempool` |
| Intent overlay | `huxplex/intents` |

`shard_id` is a `u16`. All topics in a deployment MUST be unique (no cross-shard leakage).

### 6.3 Signed message envelopes
- **GossipMessage** = `{ topic, network, payload, sig, from }`. `sig` is ML-DSA-44 over `payload`
  with context `gossip_context(network, topic)`. `verify()` recomputes the context from the
  message's own `topic`/`network`, so tampering with either invalidates the signature.
- **DhtEntry** = `{ key, value, network, sig, signer_pk }`. `sig` is ML-DSA-44 over the
  **length-framed** payload

  ```text
  u64_be(len(key)) ‖ key ‖ u64_be(len(value)) ‖ value
  ```

  with context `dht_entry_context(network)` = `huxplex-{network}:dht:entry:v1`. The DHT key
  SHOULD equal the signer's `PeerId`.

> ⚠️ **Corrected 2026-09-23 — this was a live forgery, not a style concession.** The payload was
> specified and implemented as the bare concatenation `key || value`, described below as "the
> grandfathered primitive encoding." Concatenation does not encode the field boundary, so
> `("abc","XY")` and `("ab","cXY")` produce identical signed bytes. `DhtEntry::verify`
> recomputes the payload from its own fields, so it **accepted** a record whose key had been
> re-split — letting an attacker republish a publisher's signature under a different DHT key
> without any key material. Because the key decides routing, that is routing-table poisoning by
> a peer that holds nothing.
>
> This falsified **G5-T5** and is precisely the ambiguity **G2-T2** forbids: two distinct values
> must never share one encoding. Framing both fields fixes it; it is normative, and it changes
> the signed bytes (free now, since no network exists — expensive after one does). Pinned by
> `test_dht_entry_key_value_boundary_is_unambiguous` and
> `test_dht_entry_empty_key_and_empty_value_are_distinguishable`.
>
> **The general lesson:** ad-hoc concatenation of variable-length fields is never a neutral
> shortcut — it is an encoding decision, and an ambiguous one. Per
> [ADR-0011](../adr/0011-canonical-serialization.md), structured objects (tx, block, resource)
> MUST use the canonical `Codec` (postcard) — see
> [01-data-model-and-encoding](01-data-model-and-encoding.md). Where a primitive encoding
> genuinely predates the codec, it MUST still frame every variable-length field.

## 7. Test vectors (Known-Answer Tests)

Deterministic inputs already exercised by the in-repo tests; these are the **executable KATs**
until byte-exact fixtures are committed (see task below).

> **Committed 2026-09-30 — `crates/hux-crypto/tests/kat_hashes.rs`.** Byte-exact vectors for
> **SHAKE-256** (including all three at the 1,312-byte ML-DSA-44 key length, the only length that
> occurs when deriving a `PeerId`) and for **HKDF-SHA-256 session-key derivation**, generated
> from the outgoing implementation and asserted against the incoming one.
>
> The empty-input SHAKE-256 vector is the published FIPS 202 value —
> `46b9dd2b…6ed5762f` — so it is checkable against an external authority rather than only
> against this project's own history. The rest pin *our* history, which is what a migration
> needs.
>
> **Why these could land before task C9.** C10 was recorded as blocked on C9 (splitting
> deterministic signing). That dependency was too broad: C9 blocks **signature** KATs, which need
> pinned randomness to reproduce. Hashes and KDFs take no randomness, so their vectors were
> always committable. Still outstanding for full C10: ML-DSA-44 and ML-KEM-768 vectors (keygen is
> deterministic and could land now; signature vectors need C9), SLH-DSA-128s (C7), BLAKE3 (G2b).

### 7.1 Key derivation KAT
```
master_seed (hex, 64 B):
  75ca70e0863b97e3e5cde1bc9b6eae8101158802cf7e916e7afc03f241941996
  dd0d391e42f36345af6079f35003270390a4a958492b5f9563fa629e89262177
index: 0
=> derive_mldsa_seed(master_seed, 0) -> 32-byte seed
=> Keypair::generate(Dilithium2, seed):
     public_key.len()  == 1312
     private_key.len() == 2560
   (same seed MUST reproduce identical pk and sk)
```

### 7.2 Sign/verify KAT
```
seed = [99u8; 32]
message = "Transfer 100 HUX to Alice"
context = none
=> signature.len() == 2420
=> verify(message, signature) == true
=> verify("Transfer 999 HUX to Alice", signature) == false   (tamper)
=> verify under a different key == false
```

### 7.3 Overhead reference (informative)
```
PeerId            : 32 B
ML-DSA-44 PK      : 1312 B
ML-DSA-44 Sig     : 2420 B   (≈ 37.8× an Ed25519 64 B signature)
```

> ✅ **Done 2026-10-07 (R-CRYPTO-KAT, G1 · C10).** Byte-exact fixtures are committed in
> `crates/hux-crypto/tests/kat/`, each recording the crate versions that produced it, in a
> dependency-free text format any reimplementation can read:
>
> | File | Vectors | Independently reproduced by |
> |---|---|---|
> | `ml_dsa_44.kat` | §7.1 BIP32 → keypair; keygen + pinned-randomness signatures (incl. §7.2) | RustCrypto `ml-dsa`; aws-lc-rs (empty-context ones) |
> | `ml_kem_768.kat` | keygen, encapsulate, decapsulate | RustCrypto `ml-kem` |
> | `slh_dsa_shake_128s.kat` | keygen + pinned-`opt_rand` signatures | RustCrypto `slh-dsa` |
> | `hybrid_x25519_ml_kem_768.kat` | the §4.3 composition | halves pinned separately; X25519 against RFC 7748 §6.1 |
>
> Signature vectors are reproduced through the test-only signing entry point (§3); the public API
> can only verify them.

## 8. Dependencies pinned (suite v1 provenance)
```
libcrux-ml-dsa = 0.0.10, libcrux-ml-kem = 0.0.10, libcrux-sha3 = 0.0.10 (SHAKE-256)
libcrux-curve25519 = 0.0.9 (X25519, HACL*)
fips205 = 0.4.1 (SLH-DSA-SHAKE-128s only)
hkdf = 0.13, sha2 = 0.11 (SHA-256)
bip32 = 0.5
dev-only oracles: ml-dsa 0.1.1, ml-kem 0.3.2, slh-dsa 0.2.0-rc.5, aws-lc-rs 1.18
```
A change to any of these is a potential KAT-affecting change and MUST re-verify §7.

---

### Open Questions

*All three of this document's standing questions were closed on 2026-09-22 — see §5 rule 2
(network-generalized contexts), §3 (hedged signing) and §4.2 (initiator-first ordering).*

- ~~Must the §7 KAT fixtures pin the signing randomness, and where does the test-only entry point
  live?~~ ✅ *Closed 2026-10-07.* Yes — every signature fixture records its randomness. Signing
  randomness is a `SigningRandomness` only `hux-crypto` can construct; the explicit-bytes
  constructor and `Keypair::sign_with_randomness` exist only under `cfg(test)`, and `compile_fail`
  doctests prove neither is reachable from the public API.
- ~~**Which context does the TLS ML-DSA profile use?**~~ ✅ *Closed 2026-10-07.* **Empty**, per
  `draft-ietf-tls-mldsa`. Pinned by `g5_t7_the_tls_context_is_pinned_empty`; separation from every
  registry context, in both directions, by `g5_t7_tls_and_protocol_signatures_never_verify_as_each_other`.

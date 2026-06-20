# 02 — Cryptography Specification (suite v1)

> Normative. This document is the conformance contract for Huxplex's cryptographic primitives. It
> is **derived directly from the implemented code** in `src/crypto/` and `src/network/` (🟢) and
> the canonical algorithm-suite decision in [ADR-0002](../adr/0002-cryptographic-parameter-set.md).
> Where this spec and the code disagree, that is a bug to be fixed in one of them.
>
> Keywords are per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Algorithm suite v1

Every signed or encrypted object is bound to a suite version (ADR-0002). **Suite v1** is:

| Role | Primitive | Standard | NIST cat |
|---|---|---|---|
| Hot-path signing (tx, vote, gossip, DHT) | **ML-DSA-44** (Dilithium2) | FIPS 204 | 1 |
| Long-lived validator identity / root | **SLH-DSA-128s** | FIPS 205 | 1 |
| Transport key agreement | **ML-KEM-768 + X25519** (hybrid) | FIPS 203 (+ RFC 7748) | 3 (+ classical) |
| Key derivation | **HKDF-SHA-256** | RFC 5869 | — |
| Identity / XOF hash | **SHAKE-256** | FIPS 202 | — |
| Bulk state / Merkle hash | **BLAKE3** (256-bit) | — | — |

> ⚠️ Implemented today (🟢): ML-DSA-44, ML-KEM-768, HKDF-SHA-256, SHAKE-256, BIP32 derivation.
> Specified but not yet in code (🟡): SLH-DSA-128s, X25519 hybrid leg, BLAKE3.

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

### ML-KEM-768 (`src/crypto/kem.rs`)
| Item | Const | Size |
|---|---|---|
| Encapsulation key (public) | `EK_SIZE` | **1184** |
| Decapsulation key (secret) | `DK_SIZE` | **2400** |
| Ciphertext | `CT_SIZE` | **1088** |
| Shared secret | — | **32** |
| Keygen randomness | — | **64** |
| Encapsulation randomness | — | **32** |

### Hashes / identifiers
| Item | Size |
|---|---|
| `PeerId` (SHAKE-256 squeeze) | **32** (hex display **64** lowercase chars) |
| HKDF output (session key) | **32** |

## 3. Signing & verification (ML-DSA-44)

ML-DSA-44 is used with the **context** (domain-separation) parameter of the FIPS 204 signing API.

- **Sign:** `sign(signing_key, message, context, randomness)` where `randomness` is 32 fresh
  random bytes (hedged/randomized signing). A signer MUST use fresh randomness per signature.
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
- Path (hardened, **fixed**): `m/44'/931931'/0'/0'/{index}'` where `931931` is the Huxplex
  registered coin type and `index` is a `u32` (the account/key index — also the validator key
  epoch per [ADR-0014](../adr/0014-validator-key-management.md)).
- Output: the **32-byte** BIP32 child private key, used directly as the ML-DSA-44 keygen seed.
- This derivation is deterministic: the same `(seed, index)` MUST always yield the same key.

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
  initiator→responder key differs from responder→initiator). Implementations MUST agree on the
  ordering convention (defined alongside the handshake in
  [05-network-wire-protocol](05-network-wire-protocol.md)).
- `optional_protocol_label` SHOULD carry the protocol/context (e.g. the handshake context string)
  to bind the key to its use.

## 5. Context-string registry (domain separation) — NORMATIVE

Every protocol signature MUST be made over exactly one of these context strings. The scheme is
the project's core anti-replay mechanism: a signature valid in one context MUST NOT verify in any
other (cross-network, cross-shard, cross-phase, cross-purpose). All strings are ASCII; `{network}`
∈ {`mainnet`, `testnet`}; all carry a `:vN` version suffix for agility.

| Purpose | Context string | Source |
|---|---|---|
| Transaction signing | `huxplex-{network}:tx:v1` | code |
| Block phase — pre-prepare | `huxplex-mainnet:block:preprepare:v1` | code |
| Block phase — prepare | `huxplex-mainnet:block:prepare:v1` | code |
| Block phase — commit | `huxplex-mainnet:block:commit:v1` | code |
| Gossip message (per topic) | `huxplex-{network}:gossip:{topic}:v1` | `src/network/topic.rs` |
| DHT entry | `huxplex-mainnet:dht:entry:v1` | `src/network/message.rs` |
| Transport handshake transcript | `huxplex-{network}:tls:handshake:v1` | code |
| Intent (agent economy) | `huxplex-mainnet:intent:v1` | code |
| Provenance record | `huxplex-mainnet:provenance:v1` | code |
| Validator registration | `huxplex-{network}:validator:registration:v1` | code |
| Verifiable credential / Work Visa | `huxplex-mainnet:vc:v1` | code |
| ML-KEM HKDF info prefix | `ML-KEM-768-v1-DERIVE` | `src/crypto/kem.rs` |

Rules:
1. The gossip context is computed as `gossip_context(network, topic) =
   "huxplex-{network}:gossip:{topic}:v1"` where `{topic}` is the full topic string (§6).
2. Several contexts are currently hard-coded to `mainnet` in the primitives
   (`dht:entry`, `intent`, `provenance`, `vc`, block phases). Generalizing them to `{network}`
   is tracked as a follow-up; until then `testnet` deployments MUST NOT reuse those mainnet
   contexts for non-mainnet data.
3. Adding or changing any context string is a consensus-affecting change (§ change control in the
   [section README](README.md)) and MUST bump `:vN`.

### 5.1 Required cross-context rejection properties (conformance)
The implementation MUST guarantee (these are covered by existing tests in
`src/network/mod.rs` and `src/crypto/mod.rs`):
- A mainnet signature MUST NOT verify under a testnet context, and vice versa.
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
- **DhtEntry** = `{ key, value, sig, signer_pk }`. `sig` is ML-DSA-44 over `key || value` (byte
  concatenation) with context `huxplex-mainnet:dht:entry:v1`. The DHT key SHOULD equal the
  signer's `PeerId`.

> Note ([ADR-0011](../adr/0011-canonical-serialization.md)): the `key || value` concatenation is
> the grandfathered primitive encoding. Structured objects (tx, block, resource) MUST use the
> canonical `Codec` (postcard) instead — see [01-data-model-and-encoding](01-data-model-and-encoding.md).

## 7. Test vectors (Known-Answer Tests)

Deterministic inputs already exercised by the in-repo tests; these are the **executable KATs**
until byte-exact fixtures are committed (see task below).

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

> **Task (R-CRYPTO-KAT):** commit byte-exact fixtures (the resulting 1312/2560-byte keys for the
> §7.1 seed, and the 2420-byte signature for §7.2) as test data so any reimplementation can prove
> conformance offline. Generate them from the current `libcrux` versions pinned in `Cargo.toml`
> (`libcrux-ml-dsa = 0.0.7`, `libcrux-ml-kem = 0.0.7`) and record those versions with the
> fixtures, since pre-1.0 libcrux output may change between versions.

## 8. Dependencies pinned (suite v1 provenance)
```
libcrux-ml-dsa = 0.0.7
libcrux-ml-kem = 0.0.7
hkdf = 0.12, sha2 = 0.10 (SHA-256), sha3 = 0.10 (SHAKE-256)
bip32 = 0.5
```
A change to any of these is a potential KAT-affecting change and MUST re-verify §7.

---

### Open Questions
- Should the `mainnet`-hard-coded contexts (`dht:entry`, `intent`, `provenance`, `vc`, block
  phases) be generalized to `{network}` now, before more code depends on the literals?
- Is randomized (hedged) ML-DSA signing the right default, or do we want deterministic signing for
  reproducibility in tests/consensus replay? (Affects §3 and KAT stability.)
- What is the canonical `peer_a`/`peer_b` ordering rule for §4.2 directional derivation?

# 01 — Data Model & Encoding Specification

> Normative. Defines the canonical types every node serializes, hashes, and signs, and the rules
> that make those bytes **deterministic and non-malleable**. Justified by
> [ADR-0011](../adr/0011-canonical-serialization.md) (postcard + `Codec`),
> [ADR-0010](../adr/0010-hash-function-domains.md) (hashing), and
> [ADR-0003](../adr/0003-state-model-hrm.md) (HRM).
>
> Keywords per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119). Status: 🟡 specified; only the
> primitive crypto/network types exist in code today.

## 1. Encoding rules (the determinism contract)

1. **Codec.** All consensus objects (anything hashed, signed, gossiped, or stored in state) MUST
   be encoded via the internal `Codec` trait, backed by **postcard** in suite v1. Application code
   MUST NOT call a serializer directly on a consensus object.
2. **Canonical decode.** Decoding MUST verify that re-encoding the decoded value reproduces the
   exact input bytes. Non-canonical encodings MUST be rejected (anti-malleability). 
3. **No floats.** Floating-point types MUST NOT appear in any consensus object.
4. **Fixed-width integers.** All integers are explicitly sized (`u8/u16/u32/u64/u128`); postcard
   varint encoding is used as defined by the library, and the width is part of the type.
5. **Deterministic collections.** Maps/sets MUST be encoded as length-prefixed sequences sorted by
   the canonical byte order of their keys. No hash-map iteration order may leak into bytes.
6. **Explicit optionals & enums.** `Option`/enum tags are encoded explicitly; `#[serde(flatten)]`,
   untagged enums, and aliasing that breaks 1:1 round-tripping are FORBIDDEN.
7. **Versioning.** Every top-level signed object begins with a 1-byte (or varint) **algorithm-suite
   id** (ADR-0002). Decoders MUST reject unknown suite ids rather than guessing.

## 2. Primitive types (exist in code, 🟢)

| Type | Definition | Encoding |
|---|---|---|
| `PublicKey` | `{ scheme, bytes }` | scheme tag + 1312-byte ML-DSA-44 key |
| `PrivateKey` | `{ scheme, bytes }` | never serialized to chain; local custody only |
| `Signature` | `{ scheme, bytes }` | scheme tag + 2420-byte ML-DSA-44 sig |
| `SignatureSchemeId` | enum `{ Dilithium2 }` | suite tag (extensible under agility) |
| `PeerId` | `[u8; 32]` | raw 32 bytes; hex display 64 lowercase chars |
| `GossipTopic` | newtype `String` | UTF-8 topic string (§ crypto spec §6.2) |
| `GossipMessage` | `{ topic, network, payload, sig, from }` | see crypto spec §6.3 |
| `DhtEntry` | `{ key, value, sig, signer_pk }` | signs `key‖value` (grandfathered) |

## 3. Consensus types (to be built, 🟡)

These are specified here as the canonical shapes; field-exact layouts are frozen as each is
implemented. All hashes are per [ADR-0010](../adr/0010-hash-function-domains.md) (BLAKE3 for
state/Merkle, SHAKE-256 for identity).

### 3.1 HRM Resource
The unit of state ([ADR-0003](../adr/0003-state-model-hrm.md)); eUTXO is the special case.
```
Resource {
    suite:        SuiteId,          // agility version byte
    logic_ref:    Hash32,           // hash of the controlling logic/validator (HuxVM)
    label:        Hash32,           // asset/kind discriminator
    quantity:     u128,             // fungible amount (0 for pure-data resources)
    data:         Bytes,            // opaque application datum (canonical-encoded)
    nonce:        u64,              // uniqueness / replay separation
    ephemeral:    bool,             // consumed-within-tx vs persisted
}
ResourceCommitment = BLAKE3-256(Codec(Resource))
Nullifier          = BLAKE3-256("huxplex:nullifier:v1" || Codec(Resource) || spender_binding)
```
See [03-hrm-state-transition](03-hrm-state-transition.md) for semantics.

### 3.2 Transaction
```
Transaction {
    suite:        SuiteId,
    consumed:     [ResourceCommitment],   // inputs (referenced by commitment)
    nullifiers:   [Nullifier],            // one per consumed resource
    created:      [ResourceCommitment],   // outputs
    proofs:       [LogicProof],           // satisfaction of each resource's logic
    witnesses:    [Signature],            // ML-DSA-44, context huxplex-{network}:tx:v1
    weight:       TxWeight,               // multi-dimensional capacity (see §3.4)
}
TxId = BLAKE3-256(Codec(Transaction without witnesses))   // witnesses excluded from id (SegWit-style)
```
Witnesses are excluded from `TxId` so that signatures can be **pruned after finality** without
changing transaction identity (a core readme goal). The signed message for each witness is the
canonical encoding of the transaction body (commitments, nullifiers, created, proofs, weight).

### 3.3 Block
```
BlockHeader {
    suite:        SuiteId,
    height:       u64,
    shard_id:     u16,
    parent:       Hash32,
    state_root:   Hash32,            // root of the Jellyfish/Merkle state (BLAKE3)
    tx_root:      Hash32,            // Merkle root over TxIds
    causal_stamp: CausalStamp,       // vector-clock / HLC stamp (anti-grinding)
    proposer:     PeerId,
    timestamp:    u64,               // HLC physical component (advisory, not consensus-trusted)
}
Block { header, body: [Transaction], qc: QuorumCertificate }
BlockId = BLAKE3-256(Codec(BlockHeader))
```
Block-phase signatures use the `block:{preprepare,prepare,commit}:v1` contexts
([04-consensus-spec](04-consensus-spec.md)).

### 3.4 TxWeight (multi-dimensional capacity)
From the readme's capacity model; a vector, not a scalar:
```
TxWeight { bytes: u32, inputs: u32, outputs: u32, wasm_gas: u64, causal_complexity: u32 }
scalar_weight = bytes*1 + inputs*10 + outputs*5 + wasm_gas*2 + causal_complexity*3
```
The coefficients are governance parameters (genesis values in [06-v1-scope](06-v1-scope.md));
the *formula shape* is consensus-fixed.

### 3.5 CausalStamp
```
CausalStamp {
    vclock: Map<ShardId|NodeId, u64>,   // vector clock (causal order)
    hlc:    u64,                         // hybrid logical clock (anti-grinding)
}
```
Encoded with the sorted-map rule (§1.5). Causal-regression (a stamp that violates observed
causality) is a slashing condition ([04-consensus-spec](04-consensus-spec.md)).

## 4. Common scalar types

| Name | Type | Notes |
|---|---|---|
| `Hash32` | `[u8; 32]` | BLAKE3-256 or SHAKE-256 output per domain (ADR-0010) |
| `SuiteId` | `u8` (varint) | algorithm-suite version (ADR-0002) |
| `ShardId` | `u16` | matches gossip topic shard id |
| `Bytes` | length-prefixed `Vec<u8>` | canonical postcard sequence |
| `Amount` | `u128` | no floats, ever |

## 5. Versioning & migration
- Each top-level object carries `suite: SuiteId`. A node MUST refuse objects with an unknown or
  unsupported suite id.
- Adding a field is a new object version (and likely a new `:vN` context for any signature over
  it). Removing/reordering fields is a breaking change requiring an RFC + ADR.
- The `Codec` trait isolates the wire format so the underlying library (postcard) can be replaced
  under agility without touching call sites.

---

### Open Questions
- Final field ordering and exact integer widths for `Transaction`/`Block` — freeze per type as
  built; this spec fixes shapes and rules, not yet every byte offset.
- Do nullifiers need a separate accumulator (sparse Merkle / Verkle) spec, or is the Jellyfish
  Merkle state sufficient? (Ties to [02-architecture/state-management](../02-architecture/state-management.md).)
- Should `TxWeight` coefficients be in-state governance params from genesis, or compile-time
  constants for v1 devnet? (See [06-v1-scope](06-v1-scope.md).)

# 05 — G2b · Consensus encoding

> **Entry:** G1 (the `(role, version)` registry) and G2a (the one `Codec`). **Unblocks:** G3.
> Outside Layer 0 — [ADR-0022](../adr/0022-g2-split-wire-and-consensus-encoding.md) puts G2b
> before G3 and after the wire half.
>
> Implements [data-model spec §3](../15-specifications/01-data-model-and-encoding.md) and the
> `Vote` / `QuorumCertificate` shapes of [consensus spec §3](../15-specifications/04-consensus-spec.md)
> on the **existing** `hux_types::codec`. ADR-0022 forbids a second encoder: every type below
> encodes through `to_canonical` / `from_canonical`, and nothing else in the workspace names
> `postcard`.
>
> **Status: plan, 2026-10-08 — not started.** Confirm the open decisions (§ *Decisions needed*)
> before E3.

## Why this gate is load-bearing

Two nodes that encode one transaction differently will fork, and two byte strings that decode to
one transaction give an attacker two `TxId`s for it. G2a closed that for the two wire envelopes;
G2b closes it for everything that lives in state. It is also where **witness exclusion** is
decided, and that decision cannot be revisited after G3 starts storing `TxId`s: post-finality
signature pruning — the answer to PQ signature bloat (risk #2) — depends on `TxId` never
covering a signature.

## The shape to build

```
crates/hux-crypto/src/
├── hash/blake3.rs          # the ONLY file permitted to name `blake3`  (E1)
└── traits.rs               # + Hasher                                   (E1)

crates/hux-types/src/
├── codec.rs                # unchanged — the one encoder
├── wire.rs                 # unchanged — WireSuite, WireSignature, …
└── consensus/
    ├── mod.rs              # Hash32, ShardId, Amount, size bounds       (E2)
    ├── resource.rs         # Resource, ResourceCommitment, Nullifier    (E3)
    ├── transaction.rs      # TxWeight, LogicProof, TxBody, Transaction, TxId  (E4)
    ├── block.rs            # CausalStamp, BlockHeader, BlockId, Block   (E5)
    └── vote.rs             # VotePhase, Vote, QuorumCertificate         (E6)

crates/hux-types/tests/consensus_encoding.rs   # G2-T1…T4, golden vectors (E7)
fuzz/                                           # cargo-fuzz targets, outside the workspace (E8)
```

`hux-types` already depends on `hux-crypto`; nothing new crosses the layering rule. BLAKE3 goes
into `hux-crypto`, not `hux-types`, because a hash is a primitive and C4 confines primitives to
the registry crate.

## Rules every type follows

These are the G2a rules, restated as acceptance criteria so no type quietly skips one.

1. **One wire struct per type, `serde`-derived, private.** The public type converts to and from it,
   as `GossipMessage` ↔ `GossipWire` does. Field order in the wire struct **is** the frozen layout.
2. **Identifiers by registry code.** The descriptor is `WireSuite`, signatures are
   `WireSignature`, keys `WirePublicKey` — never a serde variant index.
3. **Fixed widths, frozen per type in this file's § *Layouts* as each lands** (data-model open
   question #1). Changing one after its golden vector is committed is a new object version.
4. **Collections:** sequences keep their order (it is meaningful: `consumed[i]` ↔ `nullifiers[i]`).
   Maps are `BTreeMap`, which postcard writes sorted; `from_canonical`'s re-encode check then
   rejects unsorted or duplicate keys with no extra code.
5. **A `MAX_*_LEN` per top-level type**, checked by `from_canonical` before decoding.
6. **Every hash is domain-separated** (see decision D1).

## Tasks

| ID | Task | Acceptance |
|---|---|---|
| **E1** | `Hasher` trait and **BLAKE3** in `hux-crypto` (`hash/blake3.rs`), deferred to this gate by G1 decision (2) because BLAKE3 is the second hash. `blake3` added to `check-primitive-encapsulation.sh`. | BLAKE3 official test vectors as a KAT (`tests/kat/`), reproduced by a second implementation; the encapsulation check **fails on an injected `blake3::` call** outside `hash/blake3.rs`; SHAKE-256 also served through `Hasher` with no change to its KATs |
| **E2** | Scalars: `Hash32`, `ShardId = u16`, `Amount = u128`, `SuiteId` → **`WireSuite`** (see D2) | Unit tests: each round-trips; `Hash32` refuses any length but 32 |
| **E3** | `Resource`; `ResourceCommitment = H_commit(Codec(Resource))`; `Nullifier = H_null(Codec(Resource) ‖ spender_binding)` | G2-T1/T2 over `Resource`; commitment and nullifier are fixed functions pinned by golden vectors; changing any one field changes both |
| **E4** | `TxWeight`, `LogicProof`, `TxBody`, `Transaction { body, witnesses }`; `TxId = H_tx(Codec(TxBody))`; witness signing over `Codec(TxBody)` under `huxplex-{network}:tx:v1` | **G2-T3**; a witness verifies under `tx:v1` and under no other context; `|nullifiers| == |consumed|` is **not** checked here (that is the STF, G3) |
| **E5** | `CausalStamp`, `BlockHeader`, `Block { header, body, qc }`; `BlockId = H_block(Codec(BlockHeader))` | G2-T1/T2 incl. an unsorted and a duplicate-key `vclock`, both refused as `NonCanonical` |
| **E6** | `VotePhase`, `Vote`, `QuorumCertificate`; vote signatures under the `block:{phase}:v1` context of the vote's own phase | G2-T1/T2; a `Prepare` vote's signature does not verify relabelled as `Commit` (the phase is in the signed bytes **and** selects the context); QC `signers`/`sigs` length mismatch refused at decode |
| **E7** | Gate tests over **every** type, and golden encodings | G2-T1…T4 below; one golden vector per top-level type, committed, decoded and re-encoded byte for byte |
| **E8** | `cargo-fuzz` targets — one per `Codec::decode`, wire types included — and a CI job running each for a bounded time | G2 exit: *fuzz target in CI*. The job runs on nightly in its own directory, so the 1.85 pin of the workspace is untouched; a seeded crash input proves the target reaches the decoder |
| **E9** | Freeze the layouts in the specs | Data-model §3 and consensus §3 rewritten from *shapes* to *layouts*, field by field, with the widths; open question #1 closed |

### Sequencing

E1 → E2 → E3 → E4 → (E5 ∥ E6) → E7 → E8 → E9. E1 first because three of the four hashes depend on
it, and a hash added after its first golden vector is a re-freeze. E7's golden vectors are
committed **per type as it lands**, not at the end — the freeze is the point.

## 🎯 Gate tests

| ID | Property | Over |
|---|---|---|
| **G2-T1** | `decode(encode(x)) == x` **and** `encode(decode(b)) == b` | every top-level consensus type, generated and golden |
| **G2-T2** | Non-canonical encodings refused: trailing bytes, overlong varints, every truncation, unregistered ids, unsorted / duplicate map keys, oversize | every top-level type |
| **G2-T3** | **`TxId` excludes witnesses** — mutate, add, remove or reorder witnesses: `TxId` unchanged. Mutate any body field: `TxId` changes | `Transaction` |
| **G2-T4** | 10⁶ random byte strings and 2×10⁴ mutations of valid encodings per type: never panic, never two distinct inputs decoding to one value | every decoder |

> **G2-T3 is the one most likely to be satisfied vacuously.** A test that flips a witness byte and
> sees `TxId` unchanged also passes if `TxId` hashes nothing at all. Its second half — every body
> field *does* move `TxId` — is what makes the first half mean something.

## Decisions needed before E3

The specs fix shapes, not these. Each is a protocol decision; recorded here so it is made once,
before a golden vector freezes it.

| # | Question | Proposed | Why |
|---|---|---|---|
| **D1** | Domain separation. Spec: `ResourceCommitment`, `TxId`, `BlockId` are bare `BLAKE3(Codec(x))`; only `Nullifier` has a tag | **Every** BLAKE3 use in BLAKE3's `derive_key` mode with its own context (`huxplex:commitment:v1`, `:nullifier:v1`, `:txid:v1`, `:blockid:v1`) | Without it, any byte string that is a valid encoding of two types has one hash in two roles. Cheap now; a re-hash of state later |
| **D2** | Descriptor width. Data-model §3 says `suite: SuiteId (u8)`; §1 rule 7 and ADR-0011 rule 3′ require the full `(role, version)` | **`WireSuite`**, as G2a did; spec §3/§4 corrected | The u8 is the pre-ADR-0018 shape; freezing it would recreate the migration trap ADR-0022 §3 names |
| **D3** | `proofs` vs `witnesses`. For signature logic (the v1 default) the proof *is* an ML-DSA signature, so a signature in `proofs` would be inside `TxId` | v1 `LogicProof = { Signature { witness: u16 } \| Program { bytes } }` — a signature proof **references** a witness by index; signatures live only in `witnesses` | Otherwise G2-T3 passes on `witnesses` while `TxId` still covers signatures through `proofs`, and pruning breaks |
| **D4** | `spender_binding` in `Nullifier` is undefined (HRM spec open question) | G2b takes it as an opaque `Hash32` argument; G3 defines what is bound | The encoding can be frozen without deciding the semantics; the hash input layout cannot change later |
| **D5** | Whose QC does `Block.qc` carry, and does `voter` / `signers` hold a transport `PeerId`? | `qc` certifies the **parent** (HotStuff-2 shape, ADR-0004); `voter` is a `ValidatorId = SHAKE-256(QuorumCert pk)[..32]`, not the transport `PeerId` | A transport `PeerId` derives from the `Transport` key; votes are signed by the `QuorumCert` key. Using the transport id repeats the DHT role/purpose drift (open item 1) in consensus |

## G2b exit

- `Resource`, `Transaction`, `Block`/`BlockHeader`, `Vote`, `QuorumCertificate` encode through the
  one `Codec`, with golden vectors.
- BLAKE3 behind `Hasher`, KAT-pinned, confined by the encapsulation check.
- G2-T1…T4 green over every consensus type; **G2-T3 proven**, both halves.
- A fuzz target in CI (G2 exit criterion, shared with G2a's decoders).
- Data-model §3 and consensus §3 state layouts, not shapes.
- Green in CI on the three-architecture matrix (standing rule #1).

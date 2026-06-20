# 03 — HRM State-Transition Specification

> Normative (🟡 specified, unbuilt). Defines the operational semantics of the Huxplex Resource
> Machine: what state is, what a valid transition is, and the exact validity predicate a node
> applies. Justified by [ADR-0003](../adr/0003-state-model-hrm.md) (HRM as canonical, eUTXO as a
> subset). Types are in [01-data-model-and-encoding](01-data-model-and-encoding.md).
>
> Keywords per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. State

The global state is the pair `(CommitmentSet, NullifierSet)`:

- **CommitmentSet** — the set of `ResourceCommitment`s that have been *created* and not yet
  *consumed*. Stored in a Jellyfish Merkle Tree (JMT); `state_root` is its BLAKE3 root.
- **NullifierSet** — the set of `Nullifier`s that have been *spent*. A nullifier is the
  one-way, unlinkable spend-marker of a resource. Membership = "already spent."

A resource is **live** iff its commitment ∈ CommitmentSet and its nullifier ∉ NullifierSet.

> eUTXO mapping (ADR-0003): a UTXO is a Resource with `quantity>0` and a signature-based logic;
> "spending an output" = "publishing its nullifier + consuming its commitment."

## 2. The transition function

A block applies an ordered list of transactions to state: `apply(state, [tx]) -> state'`.
For a single transaction `tx`:

```
STF(state, tx):
  1. decode-canonical(tx)                       # ADR-0011; reject non-canonical
  2. suite(tx) is supported                      # ADR-0002
  3. |tx.nullifiers| == |tx.consumed|            # one nullifier per input
  4. for each consumed c_i:
        c_i ∈ state.CommitmentSet               # input exists & is live
        tx.nullifiers[i] == Nullifier(resource_i) # nullifier well-formed
        tx.nullifiers[i] ∉ state.NullifierSet    # no double-spend
  5. nullifiers within tx are pairwise distinct  # no in-tx double-spend
  6. for each consumed resource: its logic predicate is satisfied
        by tx.proofs[i] (HuxVM eval / signature check)  # see §3
  7. balance: for every fungible label L,
        Σ quantity(consumed with L) == Σ quantity(created with L)
        (mint/burn only via a resource whose logic authorizes it)
  8. weight(tx) within per-tx and per-block limits  # §3.4 data-model
  9. causal validity: tx.causal stamp does not regress observed causality  # §4
 => state' = state
        with NullifierSet  ∪= tx.nullifiers
        with CommitmentSet (−= tx.consumed) (+= tx.created)
```

If **any** check fails, the transaction is invalid and MUST NOT be applied; a block containing an
invalid transaction is itself invalid. All checks are deterministic.

## 3. Resource logic (validity predicates)

Each resource names a `logic_ref` (hash of its controlling program). Consuming or creating a
resource requires showing its logic is satisfied:

- **Signature logic (eUTXO subset):** the proof is an ML-DSA-44 signature over the transaction
  body with context `huxplex-{network}:tx:v1` ([crypto spec §5](02-cryptography-spec.md)) by the
  key the logic designates. This is the v1 default and needs no VM.
- **Program logic (full HRM):** the proof is a HuxVM (deterministic WASM,
  [ADR-0008](../adr/0008-vm-engine.md)) execution that MUST return `accept` given `(resource,
  tx_context, witness)`. Execution is metered by `wasm_gas`; non-termination/out-of-gas = reject.

Logic evaluation MUST be a pure function of on-chain data and the provided witness — no clocks,
no network, no randomness outside the protocol-provided beacon.

## 4. Causal validity (anti-grinding)

Each transaction/block carries a `CausalStamp` (vector clock + HLC). A node MUST reject a stamp
that:
- claims to have observed an event it cannot have (vector clock entry exceeds known frontier), or
- regresses below the causal frontier established by its declared parents.

Causal regression by a validator is a **slashing condition**
([04-consensus-spec](04-consensus-spec.md)). The novelty/"sentience" metric is **NOT** part of
the STF — per [ADR-0007](../adr/0007-sentience-framing.md) it is opt-in and off the
consensus-critical path. The STF uses causality only for *ordering integrity*, never for scoring.

## 5. Determinism requirements
- The STF MUST be a pure function; given the same `(state, block)` every node computes the same
  `state'` and the same `state_root`.
- Iteration over sets/maps MUST follow the canonical ordering ([01 §1.5](01-data-model-and-encoding.md)).
- No floating point, no wall-clock dependence, no nondeterministic allocation-order effects in
  hashing.

## 6. Pruning
Because witnesses are excluded from `TxId` ([01 §3.2](01-data-model-and-encoding.md)), after a
block is final its signatures MAY be pruned: the `(CommitmentSet, NullifierSet)` transition is
fully determined by the non-witness body, and finality is attested by the `QuorumCertificate`.
This is the mechanism behind the readme's "signature pruning after finality."

## 7. Sharding (forward-compatible, single-shard in v1)
Per [ADR-0006](../adr/0006-sharding-strategy.md) v1 runs a single shard. The model is shard-ready:
resources carry enough information to be assigned to a shard (S-EUTXO), and cross-shard atomicity
(two-phase, with nullifier reservation) is specified later. v1 implementations MUST NOT assume
more than one shard but MUST NOT hard-code assumptions that block sharding (e.g. global mutable
singletons keyed without `shard_id`).

---

### Open Questions
- Exact nullifier derivation binding (`spender_binding`) — what prevents nullifier
  precomputation/grinding while keeping spends unlinkable?
- Is the balance rule (§2.7) per-label sufficient, or do we need typed resource conservation laws
  for non-fungible/data resources?
- Cross-shard atomic commit protocol — defer to a dedicated spec; what is the minimal v1 stub that
  stays forward-compatible?

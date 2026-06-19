# State Management — The Huxplex Resource Machine (HRM)

> Resolves the readme ("eUTXO") vs. essay ("HRM") conflict: **HRM is the canonical model;
> eUTXO is a special case of HRM.** See [ADR-0003](../adr/0003-state-model-hrm.md).

## The model

Huxplex state is a set of **resources**. A resource is the atomic unit of state and can
represent a token balance, a verifiable credential (Work Visa), a vault, a provenance record,
a DAO share — *anything*, with uniform mechanics. Inspired by Anoma's Resource Machine.

```
Resource {
  kind: Hash,            // the "type" — fungibility class / token id / credential type
  quantity: u128,        // amount of this kind
  value: bytes,          // arbitrary application data (datum)
  logic: Hash,           // hash of the validator script that authorizes consume/create
  nullifier_key: Hash,   // derives the nullifier when consumed
  nonce: [u8; 32],       // uniqueness + sharding input
  ephemeral: bool,       // true = exists only within a tx (for intents/balancing)
}
```

A **transaction** consumes a set of resources and creates a set of resources. It is valid iff:

1. **Balance**: for every `kind`, `Σ consumed.quantity == Σ created.quantity` (unless the
   kind's `logic` authorizes minting/burning — e.g., the HUX fee burn, SNTNC minting).
2. **Logic**: every consumed and created resource's `logic` script accepts the transaction
   context (runs in HuxVM).
3. **Authorization**: required ML-DSA-44 signatures over `huxplex-{net}:tx:v1` 🟢 are present.
4. **No double-spend**: each consumed resource's **nullifier** is not already in the nullifier
   set; consuming adds it.

## Why HRM (vs account, vs pure UTXO)

| Property | Account (Ethereum) | Pure UTXO (Bitcoin) | eUTXO (Cardano) | **HRM (Huxplex)** |
|---|---|---|---|---|
| Parallelism | Hard (global mutable state) | Natural | Natural | **Natural** (disjoint resources) |
| Expressive smart logic | Yes | No | Yes (datum+validator) | **Yes (logic script + value)** |
| Agent reasoning ("what can I do with what I hold") | Awkward | Simple | Simple | **First-class (intents + resources)** |
| Sharding | Hard (account locality) | Good | Good | **Good (resource → shard by nonce)** |
| Privacy/ZK friendliness | Poor | Medium | Medium | **Good (nullifier model ≈ shielded)** |
| Determinism for VM | Medium | High | High | **High** |

HRM keeps eUTXO's parallelism, determinism, and clean pruning, *and* adds a uniform resource
abstraction that makes credentials, intents, and tokens the same kind of object — which is what
makes the agent economy (intents/solvers, Work Visas) expressible without bolt-ons.

> **eUTXO as a subset.** An eUTXO output `(asset, amount, datum_hash, validator_hash)` is
> exactly an HRM resource with `kind=asset, quantity=amount, value=datum, logic=validator`.
> The readme's eUTXO design is preserved, not discarded.

## Intents and the balance invariant

An **intent** is an *unbalanced* transaction: it consumes resources the author holds and
declares created resources they *want*, leaving the kind-balance non-zero. A **solver** (an
agent) supplies the balancing half (and claims a fee), producing a valid balanced transaction.
This is how "I want X for Y" becomes settlement without the author specifying execution. Detail
in [`04-ai-economy/autonomous-commerce.md`](../04-ai-economy/autonomous-commerce.md).

```mermaid
graph LR
    I[Intent: consume 10 HUX, want 5 SNTNC ephemeral] --> SOLV[Solver matches]
    SOLV --> TX[Balanced tx: 10 HUX ↔ 5 SNTNC + solver fee]
    TX --> VAL[Logic scripts accept] --> COMMIT[Commit + nullify inputs]
```

## Causal state: vector clocks + HLC

Beyond value-balance, Huxplex tracks **causal** advancement. Each resource/agent action can
carry vector-clock metadata so the protocol can:

- order asynchronous cross-shard messages causally,
- detect **causal regression** (an actor referencing state "before" what it already
  acknowledged) — a slashable fault and an anti-grinding signal,
- compute research metrics (novelty delta, entropy contribution).

⚠️ **Keep causal scoring off the consensus-critical path.** Consensus validity depends only on
balance + logic + nullifiers + signatures. Vector-clock *novelty/merit* is an
application-layer/research overlay, not a block-validity rule (ADR-0007). This is a deliberate
narrowing of the readme's more ambitious "Proof of Sentience as consensus" framing.

## Sharding the state

Resources map to shards by `shard_id = SHAKE-256(nonce ‖ epoch_seed) mod NUM_SHARDS`. Because
resources are independent, this is clean — the hard part is a transaction touching resources in
multiple shards (cross-shard), handled by a two-phase commit with vector-clock ordering
(Phase-4 gated; see [layer1.md](layer1.md)).

## Design options for state representation

**Option A — HRM resources over JMT (recommended).** Uniform, parallel, shard-ready, ZK-friendly.
*Con*: more abstract than accounts; tooling/devx must be built; intents add a solver dependency.

**Option B — Account/balance model (Ethereum-like).** Familiar devx, huge ecosystem.
*Con*: poor parallelism, poor sharding locality, awkward for agent capabilities/intents,
exposes public keys constantly (HNDL). *Verdict*: rejected — fights every Huxplex goal.

**Option C — Pure eUTXO (Cardano-like).** Parallel, deterministic.
*Con*: less uniform than HRM (credentials/intents need bolt-ons). *Verdict*: HRM strictly
generalizes it; adopt HRM, keep eUTXO compatibility as a subset.

## MVP / Production / Future

- **MVP**: single-shard HRM, fungible-token + simple-logic resources, nullifier set in RocksDB,
  no intents/solvers yet (just balanced txs). Reuse 🟢 tx signing context.
- **Production**: full logic-script execution in HuxVM, intents/solver mempool, Work Visa &
  provenance resources, witness pruning, nullifier filter.
- **Future**: cross-shard 2PC, shielded/ZK resources, nullifier accumulators, formal model of
  the balance/nullifier invariants.

---

### Open Questions
- Exact nullifier derivation (must be unlinkable for privacy yet verifiable) — design with ZK in mind from day one.
- How much of the Anoma resource-machine semantics to adopt vs. simplify for v1?
- Should `logic` scripts be Turing-complete (HuxVM/WASM) or a restricted predicate language for safety? (Leaning restricted for v1.)
</content>

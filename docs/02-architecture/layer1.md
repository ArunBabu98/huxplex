# Layer 1 Design

## What "Layer 1" means here

The L1 is the part of Huxplex that is *consensus-critical*: the rules every honest node must
agree on bit-for-bit. It comprises the **state model (HRM)**, the **sharding layout
(S-EUTXO)**, the **state commitment (Jellyfish Merkle Trees)**, the **DAG mempool**, and the
**Q-BFT** finality engine. Detailed specs are split across
[consensus](consensus.md), [state-management](state-management.md), and [storage](storage.md);
this document ties them together and states the global L1 invariants.

## L1 invariants (must always hold)

1. **PQ-only authentication.** Every consensus object (block, vote, certificate) is signed
   with a PQ scheme from the algorithm registry. No classical signatures on the critical path.
2. **Deterministic state transition.** `apply(state, block) → state'` is a pure function;
   identical on every node.
3. **Conservation.** For every resource *kind*, Σ(consumed.quantity) = Σ(created.quantity) in
   a valid transaction (the HRM balance invariant). No value created from nothing except via
   explicitly authorized minting logic.
4. **No double-spend.** Each resource is consumed at most once, enforced by **nullifiers**
   (see [state-management](state-management.md)).
5. **Finality is irreversible.** Once Q-BFT commits a block (2f+1), it is never reverted
   (BFT safety under ≤ f Byzantine).
6. **Bounded active state.** Witness/signature data is prunable post-finality; the active
   state set a node must hold does not grow without bound.

## Scaling model: shard the *state*, not the trust

The central L1 scaling decision is **S-EUTXO**: resources are partitioned across `NUM_SHARDS`
by a deterministic function of their nonce and an epoch randomness seed:

```
shard_id = SHAKE-256(resource.nonce ‖ epoch_randomness_seed) mod NUM_SHARDS
```

Each shard maintains its own Jellyfish Merkle Tree; the **global state root** is the hash of
the ordered vector of shard roots. This gives parallel state access and parallel execution
(via TCHAO), at the cost of **cross-shard transactions**, which are the hard part.

### Design options for the L1 scaling architecture

**Option A — Single chain, no sharding (start here).**
- *Advantages*: simplest; no cross-shard complexity; easiest to make correct and audit; fine
  for testnet/early mainnet throughput.
- *Disadvantages*: throughput ceiling; does not match the "trillion-agent" vision.
- *Complexity*: low. *Security*: highest (least surface). *Scalability*: limited.

**Option B — State sharding with synchronous cross-shard (S-EUTXO + 2-phase commit).** *(vision)*
- *Advantages*: parallel state + execution; matches the agent-economy throughput story; HRM
  resources map naturally to shards.
- *Disadvantages*: cross-shard atomicity (2PC) adds latency and liveness risk; PQ signature
  size makes cross-shard messages heavy; shard reorg/availability is subtle.
- *Complexity*: high. *Security*: medium (cross-shard is the soft spot). *Scalability*: high.

**Option C — Rollup-centric / modular (L1 settles, execution on L2s).**
- *Advantages*: defers execution scaling to rollups; smaller L1 surface; leverages ZK.
- *Disadvantages*: PQ-friendly rollup proofs (zk-STARK) are heavy; fragments the agent
  economy across L2s; cross-rollup UX is poor; not what the vision describes.
- *Complexity*: high (different shape). *Security*: depends on proof system. *Scalability*: high.

### Recommendation

**Phase the decision.** Ship **Option A (single chain)** for devnet → early mainnet — this is
the only way to get a correct, audited chain in a realistic timeframe and it is sufficient for
the research goals. Design every L1 data structure (HRM resources, JMT, nullifier set) to be
**shard-ready** (resources already carry a nonce; the sharding function is pure) so that
**Option B (S-EUTXO)** can be activated at a later phase *without* re-architecting state.
Treat full cross-shard atomicity as a Phase-4 research-gated feature, not a launch requirement.
Reject Option C as the primary path (it dilutes the agent-economy and adds PQ-proof cost) but
keep STARK-based proofs in the toolbox for specific verifiable-compute use cases. See
[ADR-0006](../adr/0006-sharding-strategy.md).

> **Why not shard at launch?** Sharding multiplies every other risk (consensus, state,
> execution, networking) by the cross-shard problem, and PQ signature bloat makes cross-shard
> bandwidth the binding constraint. A single correct chain that *can* shard later beats a
> sharded chain that is never quite correct.

## Block structure (logical)

```
Block {
  header {
    parent_hash, height, epoch,
    global_state_root,        // hash of shard roots (single root in Option A)
    tx_root,                  // commitment to included txs
    timestamp_hlc,            // hybrid logical clock value (anti-grinding)
    proposer_id,              // revealed leader (PQ-SSLE)
    algo_suite_version,       // crypto-agility: which suite signed this
  }
  body {
    transactions[],           // ordered, TCHAO-grouped
    causal_metadata,          // vector clock summary
  }
  certificate {
    commit_votes[],           // 2f+1 ML-DSA-44 signatures over commit context
  }
  // witness/signatures separable & prunable post-finality (SegWit-style)
}
```

## Throughput & the PQ overhead problem (quantified)

ML-DSA-44 verification is roughly **38× more expensive** than Ed25519, and signatures are
**2,420 bytes** vs 64. With thousands of tx/block each carrying a 2,420 B signature, **state
and bandwidth — not CPU — are the first walls.** L1 mitigations, in priority order:

1. **Signature/witness separation + post-finality pruning** (largest win on state).
2. **TCHAO parallel execution** to absorb verification CPU across cores.
3. **DAG mempool** (Narwhal-style) to decouple data dissemination from consensus, so big
   signatures are spread before voting, not during.
4. **Signature aggregation research** — there is no standardized efficient ML-DSA aggregation
   today; this is a top open problem ([`11-research/open-problems.md`](../11-research/open-problems.md)).

## Relationship to the rest of the stack

- L1 hands *finalized, ordered* blocks up to L2 (HuxVM) — actually execution happens *before*
  commit (execute-then-finalize), so L1 finalizes a state root the executor produced.
- L1 depends on L0 for authenticated, PQ-secure dissemination.
- L1 exposes the state root and nullifier set to identity/governance (L3) read-only.

---

### Open Questions
- Execute-then-finalize vs. order-then-execute? (Leaning execute-then-finalize for determinism + fast finality; revisit with DAG mempool.)
- What `NUM_SHARDS` and what resharding/rebalancing policy when load is skewed across kinds?
- Can the global-root-of-shard-roots design support light clients cheaply under PQ proof sizes?
</content>

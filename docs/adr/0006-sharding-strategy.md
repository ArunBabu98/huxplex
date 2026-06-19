# ADR-0006: Single chain first, S-EUTXO shard-ready

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect

## Context

The vision specifies S-EUTXO sharding (resources → shards by `SHAKE-256(nonce ‖ epoch_seed) mod
NUM_SHARDS`, per-shard JMT, global root of shard roots, cross-shard 2PC). Sharding multiplies the
difficulty of every other subsystem, and PQ signature size makes cross-shard bandwidth the binding
constraint. But the "trillion-agent" vision eventually needs horizontal scale.

## Options

- **A — Single chain, no sharding.** Simplest, most auditable; throughput-limited.
- **B — Shard at launch (S-EUTXO + cross-shard 2PC).** Matches the vision; high complexity, soft
  cross-shard safety, PQ bandwidth pressure.
- **C — Rollup-centric / modular.** L1 settles, execution on L2s. PQ-friendly proofs (STARK) are
  heavy; fragments the agent economy; not the vision's shape.

## Decision

**Phase the decision: Option A now, Option B later, reject C as primary.**

- Ship a **single chain** for devnet → early mainnet (correct, audited, sufficient for research).
- Design **all L1 data structures to be shard-ready**: resources already carry a `nonce`; the
  shard function is pure; the state root is defined as a (degenerate, single-element) vector of
  shard roots. Activating S-EUTXO later requires *no re-architecture*.
- Treat full cross-shard atomicity (2PC + vector-clock ordering + DA) as a **Phase-4
  research-gated** feature (R-B6).
- Keep zk-STARK proofs in the toolbox for specific verifiable-compute, but not as the primary
  scaling path.

## Consequences

- ➕ A correct chain ships years sooner; sharding risk doesn't block mainnet.
- ➕ No throwaway work — single chain is the `NUM_SHARDS=1` case of the sharded design.
- ➖ Throughput is capped until sharding activates (mitigated by parallel execution + DAG mempool;
  may even prove sufficient without sharding — see R-B-open).
- ➖ Cross-shard atomicity remains the hardest unsolved systems problem for Phase 4.

## Links
- [layer1](../02-architecture/layer1.md), [storage](../02-architecture/storage.md), [phase4](../09-roadmap/phase4-global-scale.md)
</content>

# ADR-0009: Block-STM optimistic parallelism, HAOT as a hint

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect, execution

## Context

PQ verification + execution are CPU-heavy (ML-DSA verify ~38× Ed25519). HRM resources are
naturally independent, so parallel execution can recover throughput. The vision proposes TCHAO:
predict access sets via a Historical Access Object Table (HAOT), build a conflict graph, color it
into parallel groups. The risk: prediction misses cause incorrect "parallel" execution.

## Options

- **A — Pessimistic / declared access sets (Solana/Sui-style).** Transactions declare touched
  resources; scheduler trusts declarations. Simple, sound. *Cons*: less flexible; declaration
  burden; violators must be rejected.
- **B — Optimistic STM (Aptos Block-STM).** Execute in parallel speculatively, detect read/write
  conflicts, re-execute conflicting txs. No declarations. *Cons*: more complex.
- **C — HAOT prediction + fallback (the vision).** Predict access sets, validate, re-run on miss.
  Correctness depends on getting the fallback right.

## Decision

**Block-STM optimistic parallelism (B) as the production engine**, with **HAOT (C) used only as a
scheduling *hint*** to reduce re-execution — never as a correctness dependency. **Start serial**
in the MVP (correctness first), then parallelize.

Reasoning: Block-STM is proven (Aptos), needs no perfect prediction, and fits HRM's disjoint-
resource model exactly. Using HAOT as an optimization (not a correctness requirement) keeps the
vision's insight (historical access patterns reduce conflicts) without betting correctness on
prediction accuracy. The deterministic merge is the crux and must be order-independent + tested.

## Consequences

- ➕ Correctness independent of prediction accuracy; throughput recovers PQ overhead across cores.
- ➕ HAOT still adds value (fewer re-executions) without risk.
- ➖ Block-STM is non-trivial; the deterministic merge must be proven order-independent
  (differential + property tested — T27 adjacency).
- ➖ Serial MVP leaves throughput on the table early (acceptable; correctness first).
- Follow-on: benchmark Block-STM vs declared-access under HRM + PQ load (R-B2).

## Links
- [execution-engine](../02-architecture/execution-engine.md), [testing-strategy](../10-development/testing-strategy.md)
</content>

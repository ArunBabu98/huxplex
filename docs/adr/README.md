# Architecture Decision Records (ADRs)

ADRs capture **significant, hard-to-reverse decisions** with their context and consequences, so
future maintainers inherit the *reasoning*, not just the conclusion (Principle #15).

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-canonical-architecture-reconciliation.md) | Reconcile readme vs. essay architecture | Accepted |
| [0002](0002-cryptographic-parameter-set.md) | Cryptographic parameter set + agility-first | Accepted |
| [0003](0003-state-model-hrm.md) | HRM as the canonical state model (eUTXO as subset) | Accepted |
| [0004](0004-consensus-selection.md) | Q-BFT: HotStuff-derived BFT over a DAG mempool | Accepted |
| [0005](0005-build-strategy.md) | Custom Rust workspace, not Substrate | Accepted |
| [0006](0006-sharding-strategy.md) | Single chain first, S-EUTXO shard-ready | Accepted |
| [0007](0007-sentience-framing.md) | "Sentience" as a bounded, off-consensus proxy metric | Accepted |
| [0008](0008-vm-engine.md) | HuxVM: wasmi → wasmtime, behind a `Vm` trait | Accepted |
| [0009](0009-parallel-execution.md) | Block-STM optimistic parallelism, HAOT as hint | Accepted |

## Process

- Number sequentially; never delete an ADR — supersede it (status `Superseded by ADR-XXXX`).
- Status: `Proposed` → `Accepted` / `Rejected` → (later) `Superseded` / `Deprecated`.
- Significant changes go through an [RFC](../rfc/) first; the resulting decision is recorded as an ADR.
- Template below.

## Template

```markdown
# ADR-XXXX: <title>
- Status: Proposed | Accepted | Rejected | Superseded by ADR-YYYY
- Date: YYYY-MM-DD
- Deciders: <roles>

## Context
What problem/forces are at play? What constraints?

## Options
A / B / C with advantages, disadvantages, complexity, security & scalability implications.

## Decision
What we chose and why (which forces won).

## Consequences
Positive, negative, and follow-on work / risks accepted.

## Links
Related docs, RFCs, open problems.
```
</content>

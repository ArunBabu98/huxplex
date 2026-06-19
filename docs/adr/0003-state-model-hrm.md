# ADR-0003: HRM as the canonical state model (eUTXO as subset)

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect

## Context

The readme specifies an eUTXO ledger; the essays specify the Huxplex Resource Machine (HRM), a
resource-oriented model inspired by Anoma. We need one state model that supports parallelism,
sharding, ZK/privacy, and — critically — the agent economy (intents, Work Visas, provenance as
first-class objects).

## Options

- **A — Account model (Ethereum-like).** Familiar, huge ecosystem. *Cons*: poor parallelism/
  sharding locality, awkward for agent capabilities/intents, exposes public keys constantly (HNDL).
- **B — Pure/extended UTXO (eUTXO).** Parallel, deterministic, prunable. *Cons*: less uniform —
  credentials/intents need bolt-ons.
- **C — HRM resource model.** Uniform atomic resources (tokens, VCs, vaults, provenance) with a
  kind-balance invariant + nullifiers; intents are unbalanced resources solvers complete. *Cons*:
  more abstract; tooling/devx must be built; intents add a solver dependency.

## Decision

**Option C (HRM)**, with **eUTXO as a strict subset**: an eUTXO output
`(asset, amount, datum, validator)` is exactly an HRM resource
`{kind, quantity, value, logic}`. The readme's eUTXO design is preserved, not discarded.

HRM is chosen because it keeps eUTXO's parallelism/determinism/pruning **and** makes the agent
economy expressible natively (intents/solvers, Work Visas, provenance are all just resources),
and its nullifier model is ZK/shielding-ready.

## Consequences

- ➕ One uniform abstraction for tokens, credentials, intents, provenance.
- ➕ Natural parallelism (disjoint resources → TCHAO/Block-STM) and shard-readiness (resource →
  shard by nonce).
- ➕ Privacy-ready (nullifiers ≈ shielded-pool model).
- ➖ Steeper learning curve; must build SDK/tooling and a (possibly restricted) logic language.
- ➖ Intent settlement depends on a solver market (Phase 3).
- Follow-on: nullifier derivation must be designed unlinkable-yet-fast from day one (R-B7/R-B8).

## Links
- [state-management](../02-architecture/state-management.md), [transaction-model](../02-architecture/transaction-model.md)
</content>

# 04 — Consensus Specification (Q-BFT)

> Normative (🟡 specified, unbuilt). Defines the Q-BFT messages, phase machine, quorum rules, and
> slashing conditions. Justified by [ADR-0004](../adr/0004-consensus-selection.md) (HotStuff-
> derived, PQ-authenticated BFT over a DAG mempool). Signatures and contexts are from the
> [cryptography spec](02-cryptography-spec.md); types from
> [01-data-model-and-encoding](01-data-model-and-encoding.md).
>
> Keywords per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Model

- **Validators.** A known set of `n` validators, each identified by `PeerId` and an ML-DSA-44
  hot-signing key bound to an SLH-DSA identity ([ADR-0014](../adr/0014-validator-key-management.md)).
- **Fault tolerance.** Byzantine threshold `f` with `n ≥ 3f + 1`; a **quorum** is `≥ 2f + 1`
  validators (by stake weight in the staked deployment; by count on devnet).
- **Authentication.** Every consensus message is ML-DSA-44–signed over a phase-specific context
  (§3). There is no unauthenticated consensus traffic.
- **Mempool.** A DAG mempool (Narwhal/Bullshark-style) disseminates transactions; the commit rule
  is HotStuff-2/Jolteon-style (ADR-0004). v1 MAY start with a simpler linear mempool and a
  classical-randomness leader fallback (ADR-0002 R-A3), upgrading later under agility.

## 2. Phases (per height/round)

Q-BFT proceeds in three signed phases, mirroring the context strings already in the codebase:

```
PRE-PREPARE : leader proposes a block         -> sign ctx huxplex-mainnet:block:preprepare:v1
PREPARE     : validators vote to prepare       -> sign ctx huxplex-mainnet:block:prepare:v1
COMMIT      : validators vote to commit         -> sign ctx huxplex-mainnet:block:commit:v1
```

A **QuorumCertificate (QC)** for a phase is an aggregate of `≥ 2f+1` valid signatures over the
same `(BlockId, height, round, phase)`. A block is **final** once a COMMIT QC exists for it (plus
the pipeline rule from ADR-0004). Finality is irreversible; forks below a finalized block are
invalid.

> Naming note: these strings currently use `mainnet` literally. Generalizing the phase contexts to
> `huxplex-{network}:block:{phase}:v1` is the same follow-up flagged in
> [crypto spec §5](02-cryptography-spec.md).

## 3. Messages

```
Vote {
    suite:    SuiteId,
    height:   u64,
    round:    u32,
    phase:    enum { PrePrepare, Prepare, Commit },
    block_id: Hash32,
    voter:    PeerId,
    sig:      Signature,   // ML-DSA-44 over (height,round,phase,block_id) with the phase context
}

QuorumCertificate {
    height, round, phase, block_id,
    signers: [PeerId],     // >= 2f+1 distinct
    sigs:    [Signature],  // matching; aggregation is a future optimization (R: ML-DSA agg)
}
```

A validator MUST verify, for every received vote: suite supported; signer ∈ validator set;
signature valid under the correct phase context; `(height, round)` not stale; and the vote does
not conflict with one it has already counted from that signer.

## 4. Leader election

- v1 / devnet: round-robin or classical-randomness leader (ADR-0002 fallback).
- Target: **LB-VRF**-based election with **PQ-SSLE** (single secret leader election) and epoch
  rotation (system-overview). These are less mature (R-A3) and sit behind agility; the consensus
  spec treats leader selection as a pluggable oracle returning a `PeerId` per `(height, round)`.

## 5. Slashing conditions (NORMATIVE)

A validator's stake is slashed (and identity penalized) for provable misbehavior. Each condition
is a deterministic, on-chain-verifiable predicate over signed evidence:

| Condition | Evidence | Severity |
|---|---|---|
| **Double-sign / equivocation** | two validly-signed votes by the same validator for the same `(height, round, phase)` with different `block_id` | severe |
| **Conflicting commit** | COMMIT votes for two different blocks at the same height | severe |
| **Causal regression** | a proposed/voted stamp violating observed causality ([03 §4](03-hrm-state-transition.md)) | moderate |
| **Invalid proposal** | a leader's PRE-PREPARE block fails the STF | moderate |

Anti-double-sign is also enforced *preventively* at the signer via the high-water-mark guard
([ADR-0014](../adr/0014-validator-key-management.md)) — slashing is the on-chain backstop, not the
only defense.

## 6. Safety & liveness (argument sketch)

- **Safety (no two conflicting finalized blocks):** a COMMIT QC needs `≥ 2f+1` signers; two
  conflicting QCs at one height would require a validator in both quorums (quorum intersection ≥
  `f+1`), i.e. ≥ 1 honest validator double-signing — contradiction, and that double-sign is
  slashable evidence. Inherited from the HotStuff family (ADR-0004).
- **Liveness (progress under partial synchrony):** after GST, a correct leader within a round
  collects a quorum and drives PREPARE→COMMIT; round timeouts rotate the leader so a faulty leader
  cannot stall progress indefinitely. PQ signature size affects *latency/bandwidth*, not the
  safety argument — but is the binding performance constraint (risk #2), handled by DAG mempool +
  signature aggregation research.

A full formal treatment (TLA+/Ivy or a written proof) is a Phase-0 deliverable, tracked in
[11-research](../11-research/).

## 7. Determinism
All consensus checks are deterministic functions of signed messages and on-chain state. No
wall-clock value is consensus-trusted; the HLC timestamp is advisory and bounded, never a tiebreak
that honest nodes could disagree on.

---

### Open Questions
- Concrete commit rule: HotStuff-2 vs Jolteon vs Bullshark commit — pick and pin for v1
  (ADR-0004 leaves the family chosen, the exact variant open).
- ML-DSA signature **aggregation** for QCs — without it, a QC is `(2f+1) × 2420 B`; is that
  tolerable at the v1 validator count, and what is the aggregation research path?
- LB-VRF / PQ-SSLE maturity — what is the precise classical fallback for devnet, and the
  migration trigger to the PQ construction?

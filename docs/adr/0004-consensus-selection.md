# ADR-0004: Q-BFT — HotStuff-derived BFT over a DAG mempool

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect, distributed systems

## Context

Consensus must give deterministic finality (escrow/settlement need it), be PQ-authenticated, and
survive the bandwidth pressure of 2,420 B signatures. The vision names "Q-BFT" but only specifies
"PBFT + PQ signatures." We evaluated Tendermint/CometBFT, HotStuff/HotStuff-2/Jolteon, Narwhal+
Bullshark, Avalanche-family, Substrate (BABE+GRANDPA), Cosmos SDK (CometBFT), and a custom build.
Full comparison: [consensus](../02-architecture/consensus.md).

## Options (summarized)

- **A — CometBFT/Tendermint as-is.** Proven deterministic finality; sig-agnostic. *Cons*: couples
  data dissemination with voting (bad under big PQ sigs); known leader (DDoS target).
- **B — HotStuff/Jolteon with BLS aggregation.** Linear comms. *Cons*: its advantage *depends on*
  signature aggregation — **PQ has no efficient aggregation**, so the headline benefit evaporates.
- **C — Pure Avalanche/metastable DAG.** Great scale/liveness. *Cons*: probabilistic finality —
  unacceptable for escrow/cross-shard atomicity.
- **D — HotStuff-derived BFT over a Narwhal-style DAG mempool, custom Rust, PQ-authenticated.**

## Decision

**Option D.** Q-BFT = a HotStuff/Jolteon-style 2-chain commit (deterministic finality) running
over a **Narwhal-style DAG mempool**, PQ-authenticated with ML-DSA-44 over domain-separated phase
contexts (already implemented + tested), leader election via **LB-VRF + PQ-SSLE** (hidden leader).
Built as a custom Rust crate that *reuses* the algorithms/engineering of CometBFT/HotStuff-2/
Bullshark rather than inventing a new protocol.

Key reasoning: the **DAG mempool** is the answer to PQ-signature bloat — it disseminates the heavy
tx+signature data *before and independent of* the voting path, so the consensus hot path moves
small references, not 2,420 B blobs. Deterministic finality is preserved for settlement.

## Consequences

- ➕ Deterministic finality + PQ auth + bandwidth-resilience together.
- ➕ Phase-context replay already provably prevented (existing tests).
- ➖ Without PQ aggregation, a quorum cert = 2f+1 separate 2,420 B sigs → **validator set must be
  bounded** (≤~100–150) (ADR drives [staking](../06-tokenomics/staking.md)).
- ➖ Custom consensus is high-effort/high-risk — mitigated by copying proven protocols + formal
  verification of safety (top assurance target).
- Follow-on: STARK-compressed quorum certificates (R-A1) could later relax the set-size bound.

## Links
- [consensus](../02-architecture/consensus.md), [staking](../06-tokenomics/staking.md), open problem R-A1
</content>

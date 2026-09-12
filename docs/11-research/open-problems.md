# Open Problems Register

The canonical, consolidated list of unresolved questions across the blueprint. Each doc's
**Open Questions** block feeds this register. When one is resolved, write an ADR and update both
places. Items are tagged by severity: 🔴 (blocks a phase / could invalidate a core assumption),
🟠 (significant), 🟡 (refinement).

## A. Cryptography & post-quantum

| ID | Problem | Sev | Owner doc |
|---|---|---|---|
| R-A1 | **No efficient PQ signature aggregation** → consensus quorum-certificate bloat; can a STARK-compressed certificate fix it affordably? | 🔴 | [consensus](../02-architecture/consensus.md), [zk-proofs](../05-identity/zk-proofs.md) |
| R-A2 | ML-DSA-44 (Cat 1) vs ML-DSA-65 (Cat 3) for the hot path — security/perf/bandwidth tradeoff | 🟠 | [pq-cryptography](../03-post-quantum/pq-cryptography.md) |
| R-A3 | Audited Rust LB-VRF + PQ-SSLE constructions — do they exist, or must we build/commission them? | 🔴 | [cryptography](../02-architecture/cryptography.md) |
| R-A4 | Decentralized, bias-resistant randomness beacon to replace trusted QRNG | 🟠 | [quantum-era-risks](../01-vision/quantum-era-risks.md) |
| R-A5 | Trigger criteria that reliably indicate a PQ scheme is being broken before catastrophic loss | 🔴 | [quantum-threats](../08-security/quantum-threats.md) |
| R-A6 | Hybrid *signatures* (not just KEX) — worth the doubled size as insurance? | 🟡 | [pq-cryptography](../03-post-quantum/pq-cryptography.md) |
| R-A7 | Threshold/MPC ML-DSA signing — practical audited construction? | 🟠 | [key-management](../03-post-quantum/key-management.md) |
| R-A8 | Migrate shielded/ZK state across a crypto-suite change without breaking unlinkability | 🔴 | [migration-strategy](../03-post-quantum/migration-strategy.md), [privacy](../05-identity/privacy.md) |

## B. Consensus, state & execution

| ID | Problem | Sev | Owner doc |
|---|---|---|---|
| R-B1 | Execute-then-finalize vs order-then-execute with a DAG mempool, under HuxVM determinism | 🟠 | [consensus](../02-architecture/consensus.md), [execution-engine](../02-architecture/execution-engine.md) |
| R-B2 | Optimistic (Block-STM) vs declared-access parallelism under HRM + PQ load — benchmark | 🟠 | [execution-engine](../02-architecture/execution-engine.md) |
| R-B3 | Deterministic, ungameable definition of `causal_complexity` (fee + anti-grinding) | 🔴 | [transaction-model](../02-architecture/transaction-model.md) |
| R-B4 | Can "causal regression" be a deterministic, false-positive-free slashable fault? | 🟠 | [staking](../06-tokenomics/staking.md) |
| R-B5 | Optimal active validator-set size vs decentralization vs certificate size | 🟠 | [staking](../06-tokenomics/staking.md) |
| R-B6 | Cross-shard atomicity + data availability under PQ message sizes | 🔴 | [layer1](../02-architecture/layer1.md), [storage](../02-architecture/storage.md) |
| R-B7 | Nullifier set bounded over decades (accumulators?) while supporting fast double-spend checks | 🟠 | [storage](../02-architecture/storage.md), [state-management](../02-architecture/state-management.md) |
| R-B8 | Unlinkable nullifier derivation compatible with fast membership tests (privacy) | 🟠 | [state-management](../02-architecture/state-management.md), [privacy](../05-identity/privacy.md) |
| R-B9 | Light-client viability under PQ proof/signature sizes | 🟠 | [storage](../02-architecture/storage.md) |
| R-B10 | Restricted predicate language vs full WASM for resource `logic` | 🟡 | [state-management](../02-architecture/state-management.md) |

## C. AI economy & mechanism design

| ID | Problem | Sev | Owner doc |
|---|---|---|---|
| R-C1 | **Does any novelty metric converge rather than inflate under adversarial agents?** | 🔴 | [agent-reputation](../04-ai-economy/agent-reputation.md) |
| R-C2 | Can soulbound merit provably resist Sybil amplification given personhood-gated controllers? | 🔴 | [agent-reputation](../04-ai-economy/agent-reputation.md) |
| R-C3 | Independence test for peer attestations that defeats collusion rings at scale | 🔴 | [agent-reputation](../04-ai-economy/agent-reputation.md) |
| R-C4 | MEV-resistant intent matching over a public gossip overlay | 🟠 | [agent-marketplace](../04-ai-economy/agent-marketplace.md) |
| R-C5 | Practical on-chain zk-STARK verification cost for real agent tasks | 🔴 | [autonomous-commerce](../04-ai-economy/autonomous-commerce.md) |
| R-C6 | Dispute mechanism that resists agent collusion without bottlenecking on scarce humans | 🟠 | [autonomous-commerce](../04-ai-economy/autonomous-commerce.md) |
| R-C7 | Bounding the SNTNC flywheel so machine economic power stays under the human veto in practice | 🔴 | [agent-governance](../04-ai-economy/agent-governance.md) |
| R-C8 | Should controller-less autonomous agents exist, and under what bond/constitutional gate? | 🟠 | [ai-identity](../05-identity/ai-identity.md) |
| R-C9 | Is `log2` the right machine-vote curve, or capped/quadratic-cost? | 🟡 | [agent-governance](../04-ai-economy/agent-governance.md) |

## C2. Connectors & external evidence

Opened by [ADR-0015](../adr/0015-connector-architecture.md) and
[ADR-0016](../adr/0016-evidence-and-attestation.md). Owner doc for all:
[connector protocol](../15-specifications/07-connector-protocol.md).

| ID | Problem | Sev |
|---|---|---|
| R-K1 | **Connector-session evidence chains are detailed purchase records in consensus state.** Can projections be committed with selective disclosure instead of plaintext? This may decide whether HCP is usable at all in regulated jurisdictions | 🔴 |
| R-K2 | **`Notarized` may be weaker than it looks.** *k*-of-*n* connectors may all wrap the same upstream API; independence is hard to verify and easy to fake. Related to R-C3 | 🔴 |
| R-K3 | **Reconciliation without connector cooperation.** If a connector goes dark mid-`Unknown`, who determines the truth? A second connector on the same external system is the obvious answer — and another argument for R-K2 | 🟠 |
| R-K4 | Can Profile 1+ connectors ever be permissionless? The bridge precedent argues for permanent governance gating, which conflicts with the neutrality criterion in [mission](../01-vision/mission.md) | 🟠 |
| R-K5 | Session rent pricing: too low invites state-growth spam, too high makes long-horizon intents (the 8-day delivery case) uneconomic | 🟡 |
| R-K6 | Is `Cryptographic` evidence reachable for ordinary commerce, or is `FirstParty` the realistic ceiling outside a few rails? | 🟡 |
| R-K7 | Can `Compensate` semantics be standardized per action class, or is compensation necessarily external-system-specific? | 🟡 |
| R-K8 | Liability allocation: who is merchant-of-record when a connector executes, and does recording legal operator + jurisdiction actually discharge anything under the EU AI Act? Needs legal review, not research | 🟠 |

## D. Identity, privacy & governance

| ID | Problem | Sev | Owner doc |
|---|---|---|---|
| R-D1 | **Personhood that is strong + decentralized + inclusive** enough to make the SVRGN veto meaningful (assumption A4) | 🔴 | [human-identity](../05-identity/human-identity.md) |
| R-D2 | Coercion-resistant ZK voting with auditable tallies at scale | 🟠 | [voting](../07-governance/voting.md) |
| R-D3 | Is a 33% veto threshold right given expected low human turnout? | 🟠 | [governance-model](../07-governance/governance-model.md) |
| R-D4 | Exact minimal constitutional invariant set | 🔴 | [constitutional-layer](../07-governance/constitutional-layer.md) |
| R-D5 | Reconcile "no retroactive seizure" with fraud/personhood-revocation needs | 🟠 | [constitutional-layer](../07-governance/constitutional-layer.md) |
| R-D6 | Transparent-default vs private-default for an *agent* economy | 🟠 | [privacy](../05-identity/privacy.md) |
| R-D7 | Bootstrap legitimate SVRGN distribution before personhood infra is strong | 🔴 | [governance-model](../07-governance/governance-model.md) |
| R-D8 | Prevent agent→human class spoofing without an invasive biometric registry | 🔴 | [human-identity](../05-identity/human-identity.md) |

## E. Economics

| ID | Problem | Sev | Owner doc |
|---|---|---|---|
| R-E1 | **Does the burn-based fee model self-stabilize?** (measure, don't assume) | 🔴 | [incentives](../06-tokenomics/incentives.md) |
| R-E2 | Long-term security budget when emission decays — fees sufficient at realistic usage? | 🔴 | [incentives](../06-tokenomics/incentives.md) |
| R-E3 | SNTNC decay rate bounding inflation without erasing legitimate merit | 🟠 | [incentives](../06-tokenomics/incentives.md) |
| R-E4 | Right PQ-signature weight multipliers in the fee vector (measure on testnet) | 🟠 | [fee-model](../06-tokenomics/fee-model.md) |
| R-E5 | Treasury diversification without bridge/custodial risk | 🟠 | [treasury](../06-tokenomics/treasury.md) |

## F. Strategy (meta) {#strategy}

| ID | Problem | Sev | Owner doc |
|---|---|---|---|
| R-F1 | **Sovereign L1 vs exportable module suite** — which is the higher-value endgame? | 🔴 | [00-executive-summary](../00-executive-summary.md), [phase4](../09-roadmap/phase4-global-scale.md) |
| R-F2 | Solo vs funded team — is a civilization-scale L1 deliverable at current staffing? | 🔴 | [phase0](../09-roadmap/phase0-research.md) |
| R-F3 | If novelty/reputation proves hopelessly gameable, ship weakened or cut? (pre-commit criteria) | 🟠 | [phase3](../09-roadmap/phase3-ai-economy.md) |

## How this register is used

- Reviewed at **every phase gate**; 🔴 items in the relevant phase must be resolved or explicitly
  deferred-with-justification before proceeding.
- Each 🔴 should map to a research task in [future-research](future-research.md) and/or a backlog
  epic ([`../backlog/`](../backlog/)).
- Resolution = an ADR + updates to the owning doc + this register.

---

*This register is the honest core of the blueprint: a protocol foundation's value is as much in
knowing what it doesn't know as in what it has decided.*
</content>

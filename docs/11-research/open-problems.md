# Open Problems Register

The canonical, consolidated list of unresolved questions across the blueprint. Each doc's
**Open Questions** block feeds this register. When one is resolved, write an ADR and update both
places. Items are tagged by severity: 🔴 (blocks a phase / could invalidate a core assumption),
🟠 (significant), 🟡 (refinement).

## A. Cryptography & post-quantum

| ID | Problem | Sev | Owner doc |
|---|---|---|---|
| R-A1 | **PQ quorum-certificate aggregation — which candidate, at what cost to the key lifecycle?** Candidates now exist (Chipmunk ~20 KB @ 1,024 signers; Lemur+ ~56 KB @ 10⁶; STARK-compressed O(1)), but **all are synchronized/stateful**, so the choice constrains ADR-0014's key hierarchy. Reframed 2026-09-22 from "does anything exist?". The answer now has somewhere to land: the `QuorumCert` role ([ADR-0018](../adr/0018-signature-role-profiles.md)), adoptable by version bump without touching transactions | 🔴 | [consensus](../02-architecture/consensus.md), [cryptography](../02-architecture/cryptography.md), [zk-proofs](../05-identity/zk-proofs.md) |
| R-A2 | ML-DSA-44 (Cat 1) vs ML-DSA-65 (Cat 3) — **per signature role** ([ADR-0018](../adr/0018-signature-role-profiles.md)). ✅ **v1 decided 2026-09-22: ML-DSA-44 for all roles**, because measuring its overhead *is* v1's research deliverable. Open for **mainnet**: Sui chose 65, CNSA 2.0 mandates 87, against a measured 40–50% TPS cost at 44 (BSC); genesis also pairs a Cat-1 signature with a Cat-3 KEX. Now a registry row, not a redesign | 🟡 | [pq-cryptography](../03-post-quantum/pq-cryptography.md), [cryptography](../02-architecture/cryptography.md) |
| R-A3 | ~~LB-VRF~~ **iVRF** + PQ-SSLE — does iVRF's modified uniqueness hold for a *bounded, known* Q-BFT validator set, or only for Algorand-style open sortition? Is there an audited Rust PQ-SSLE construction? | 🔴 | [cryptography](../02-architecture/cryptography.md) |
| R-A4 | Decentralized, bias-resistant randomness beacon to replace trusted QRNG | 🟠 | [quantum-era-risks](../01-vision/quantum-era-risks.md) |
| R-A5 | Trigger criteria that reliably indicate a PQ scheme is being broken before catastrophic loss | 🔴 | [quantum-threats](../08-security/quantum-threats.md) |
| R-A6 | Hybrid *signatures* (not just KEX) — worth the doubled size as insurance? | 🟡 | [pq-cryptography](../03-post-quantum/pq-cryptography.md) |
| R-A7 | Threshold/MPC ML-DSA signing — practical audited construction? | 🟠 | [key-management](../03-post-quantum/key-management.md) |
| R-A8 | Migrate shielded/ZK state across a crypto-suite change without breaking unlinkability | 🔴 | [migration-strategy](../03-post-quantum/migration-strategy.md), [privacy](../05-identity/privacy.md) |
| R-A9 | ✅ **Cadence decided 2026-09-22** ([ADR-0014](../adr/0014-validator-key-management.md) amendment): rotate a `Transaction` session key after **50,000 signatures or 7 days**, ≈4× margin under the 190,000-signature sign-leakage bound (eprint 2026/1366). *Still open:* reconciling that cadence with the multi-year committed key lifetimes synchronized aggregation (R-A1) requires — the substance of `adr/0021-*` | 🟠 | [ADR-0014](../adr/0014-validator-key-management.md), [key-management](../03-post-quantum/key-management.md) |
| R-A10 | Side-channel and fault-injection test methodology beyond FIPS KATs, given that the vulnerable seed-pointer pattern (eprint 2025/2009) is present in PQM4, liboqs, PQClean and wolfSSL — and `libcrux-*` is still `0.0.x` | 🟠 | [cryptography](../02-architecture/cryptography.md), [testing-strategy](../10-development/testing-strategy.md) |

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
| R-B11 | **Erasure-coded block broadcast vs GossipSub** under PQ object sizes — can one dissemination path serve both the block/DAG-batch traffic and the DAG mempool's causal batches, or do they want separate ones? (ethp2p, RaptorCast, Optimum P2P) | 🟠 | [networking](../02-architecture/networking.md), [consensus](../02-architecture/consensus.md) |
| ~~R-B12~~ | ✅ **Resolved 2026-09-22 by [ADR-0019](../adr/0019-transport-authentication.md).** Neither a bespoke handshake nor an application-level binding: ML-DSA-44 enters TLS 1.3 **natively** as `SignatureScheme` 0x0904 (`draft-ietf-tls-mldsa-06`, rustls 0.23.44). *Residual:* the responder's ≈7,970 B first flight sits close to QUIC's 3× budget and is held by client-Initial padding — pinned by G5-T6, and the `libp2p-quic` integration spike is a G5 entry task | — | [ADR-0019](../adr/0019-transport-authentication.md), [wire spec §2](../15-specifications/05-network-wire-protocol.md) |

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

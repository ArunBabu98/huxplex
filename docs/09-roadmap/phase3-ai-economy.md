# Phase 3 — AI Economy (Months 30–48) · the 36–48 month horizon

> **Goal**: turn the proven chain into the AI-native economy the vision promises — identity,
> Work Visas, intents/solvers, agent reputation, marketplaces — **layered on a secure mainnet,
> off the consensus-critical path.**

## Milestones & deliverables

| ID | Milestone | Deliverable |
|---|---|---|
| P3.1 | Identity layer | `did:huxplex` (🟢 primitive) DID docs as HRM resources; key rotation; identity classes |
| P3.2 | Personhood + SVRGN | multi-provider ZK personhood portfolio; personhood-gated SVRGN; unlinkable voting (target) |
| P3.3 | Work Visa credentials | issuance/revocation; in-HuxVM constraint enforcement (spend caps, scopes, expiry) |
| P3.4 | Agent wallets | scoped/revocable agent keys; allowances; sponsored fees; circuit breakers |
| P3.5 | Intents + solvers | intent mempool over `huxplex/intents` (🟢 topic); solver matching; escrow resources |
| P3.6 | zk-STARK task proofs | verifiable-compute task settlement; oracle integration for the rest; dispute resolution v1 |
| P3.7 | Agent reputation / SNTNC | bounded, decaying, soulbound merit; collusion detection; autonomy tiers |
| P3.8 | Marketplaces | open auction + commit-reveal; reputation ranking; A2A commerce |
| P3.9 | Agent governance | SNTNC log-weighted machine deliberation; Agentic DAOs (capped); all under SVRGN veto |
| P3.10 | Provenance | human-origin + machine-origin records (🟢 context); deepfake-provenance product |

## Critical path

```mermaid
graph LR
    P31[Identity DID] --> P33[Work Visa]
    P32[Personhood+SVRGN] --> P39[Agent governance]
    P33 --> P34[Agent wallets]
    P34 --> P35[Intents/solvers]
    P35 --> P36[zk task proofs]
    P36 --> P37[Reputation/SNTNC]
    P37 --> P38[Marketplaces]
    P37 --> P39
```

Identity → Work Visa → agent wallets → intents/solvers is the spine. Personhood (P3.2) gates
meaningful SVRGN/agent-governance. zk-STARK proofs (P3.6) gate cryptographic task settlement
(economic settlement via escrow/dispute works without them).

## The risk-management heart of Phase 3

This phase contains Huxplex's most novel and most dangerous mechanisms. Discipline:
- **Everything here is L3/L4** — a bug in reputation or marketplaces must never threaten
  consensus safety (it can't, by construction — they're off the critical path).
- **Roll out behind feature flags + caps** — small bonds, low spend caps, capped Agentic-DAO
  votes; widen as data accrues.
- **Simulate adversarially first** — the Phase-0 agent simulation matures into a continuous
  red-team before each mechanism goes live. "Does novelty inflate?" must be answered with data
  *before* SNTNC influences anything economic.
- **Human veto fully operational** before agent governance has teeth.

## Team requirements

Adds to the Phase-2 team:

| Role | FTE | Focus |
|---|---|---|
| Identity/ZK engineers | 2 | DID, personhood, STARK proofs |
| Mechanism-design researcher | 1 | reputation, marketplace, anti-collusion |
| Agent-framework engineers | 2 | Work Visa, wallets, intents/solvers |
| Economist | 0.5–1 | SNTNC issuance/decay, market design |
| Security (ongoing) | 1 + firms | audits of each new mechanism |

Realistic: **~12–18 people** including the Phase-2 base.

## Budget estimate

- Personnel (largest team yet): dominant.
- ZK proving infra + audits of novel mechanisms: significant.
- Personhood-provider integrations: meaningful.
- Continued bug bounty (now covering agent economy + ZK): significant.
- Ecosystem grants to seed agent builders ([`12-business/grants.md`](../12-business/grants.md)).

## Research dependencies (many — this is the research-heavy phase)

- Practical, audited STARK framework (proving cost realism).
- Sybil-resistant personhood that's decentralized + inclusive (top open problem).
- Anti-collusion / independence tests for reputation + attestations.
- Whether novelty scoring converges (must be answered before SNTNC goes economic).
- MEV-resistant intent matching.

## Exit criteria (Phase 3 → Phase 4 gate)

- [ ] Agents transacting under enforced Work Visa constraints with fast revocation.
- [ ] Intents/solvers + escrow + dispute working; zk-STARK settlement for verifiable tasks.
- [ ] Reputation/SNTNC live, bounded, decaying, with collusion detection — validated by adversarial sim.
- [ ] Personhood-gated SVRGN making the veto meaningful; agent governance under veto.
- [ ] No L3 mechanism has ever threatened L1 safety (verified).

---

### Open Questions
- If adversarial simulation shows novelty/reputation is hopelessly gameable, do we ship a weakened version or cut it? (Pre-commit the decision criteria.)
- Can personhood be strong + decentralized + inclusive enough by Phase 3, or does the veto stay provisional into Phase 4?
- Practical on-chain STARK verification cost at agent-economy scale.
</content>

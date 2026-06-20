# 14 — Use Cases, Applications & Impacts

> What is Huxplex *for*? This section maps the full surface of things a post-quantum,
> AI-native, sovereignty-constrained Layer-1 could do — from the boringly practical to the
> civilization-scale — and is honest about which is which.

This is a **possibility space**, not a promise. Per the
[executive summary](../00-executive-summary.md), Huxplex today is ~1,200 lines of
post-quantum cryptography and networking primitives. **None of the use cases below run
yet.** They are arranged so that a reader can immediately tell the difference between "this
falls out of a working chain almost for free" and "this requires research breakthroughs that
may never arrive." Confusing those two is exactly how ambitious L1s die (risk #1 in the
[risk register](../00-executive-summary.md)).

## How every use case is tagged

Each use case carries **three tags**: a *field*, a *time horizon*, and a *difficulty*. They
are orthogonal — a use case can be far-future yet technically easy (we just won't get to it),
or near-term yet brutally hard.

### Horizon — *when could this plausibly exist?*

| Tag | Horizon | Meaning | Maps to roadmap |
|---|---|---|---|
| 🟩 **Immediate** | 0–3 yrs | Falls out of a working chain + tokens + basic agent identity. On or adjacent to the [roadmap](../09-roadmap/). | Phase 1–2 |
| 🟦 **Futuristic** | 3–10 yrs | Needs the AI economy, ZK proofs, identity, and governance layers mature and battle-tested. | Phase 3–4 |
| 🟪 **Very Ambitious** | 10 yrs+ / civilizational | Depends on breakthroughs (sound novelty metrics, sharded PQ at scale, hardware, social adoption) that are unproven or unsolved. Some may be impossible. | Beyond Phase 4 / research |

### Difficulty — *how hard to build, given the layers it sits on?*

| Tag | Difficulty | Meaning |
|---|---|---|
| ⚪ **Easy** | Low | Standard L1 capability; little Huxplex-specific research. The chain just needs to exist. |
| 🟠 **Intermediate** | Medium | Needs Huxplex-specific machinery (HRM resources, Work Visas, intent/solver mempool, reputation) that is specified but unbuilt. |
| 🔴 **Hard** | High | Depends on the project's open research problems (novelty/sentience scoring, sharded PQ atomicity, biometric DIDs, ZK at scale). Genuine risk it never works. |

> A use case's **realistic ETA ≈ max(horizon implied by its difficulty, horizon of the
> layers it depends on).** A ⚪Easy use case is still 🟦Futuristic if it sits on top of the
> agent economy.

### Status legend (inherited from the blueprint)

🟢 Implemented · 🟡 Specified · 🔴 Open research. Almost everything here is 🟡 or 🔴; the
only 🟢 building blocks are the PQ signatures, KEM, key derivation, and signed message types.

## What makes a use case *Huxplex-shaped*

A use case earns its place here only if Huxplex offers something a generic chain does **not**.
The differentiators, in rough order of defensibility:

1. **Post-quantum by construction** — anything needing 30+ year integrity (land titles,
   archives, long-lived identity, nuclear/medical records) where a future quantum adversary
   is in the threat model. This is the *most defensible and least speculative* edge.
2. **AI agents as first-class economic actors** — agents with their own wallets, identities
   (`did:huxplex`), capability-scoped **Work Visas**, reputation, and the ability to contract
   via an **intent/solver** mempool. Not bots on a human chain.
3. **Human sovereignty as a hard, protocol-level constraint** — the **biological veto** and
   constitutional invariants. A cryptographically enforced "humans can always say no."
4. **Soulbound merit & causal-contribution measurement** — the speculative frontier:
   non-transferable reputation (SNTNC) and the attempt to measure *non-redundant causal
   contribution* (the "sentience" research line).

If a use case relies on none of these, it belongs on a cheaper, faster, more mature chain —
and we say so.

## Map of this section

| File | Field cluster |
|---|---|
| [`00-master-matrix.md`](00-master-matrix.md) | **Every use case in one sortable table** (field × horizon × difficulty × differentiator) |
| [`01-finance-and-defi.md`](01-finance-and-defi.md) | Payments, settlement, DeFi, RWAs, machine money markets |
| [`02-ai-agent-economy.md`](02-ai-agent-economy.md) | Autonomous agents, intents/solvers, agent labor markets, M2M commerce |
| [`03-identity-personhood-sovereignty.md`](03-identity-personhood-sovereignty.md) | DIDs, proof-of-personhood, human veto, digital sovereignty |
| [`04-science-research-academia.md`](04-science-research-academia.md) | Reproducibility, provenance, DeSci, peer review, data commons |
| [`05-supply-chain-iot-physical.md`](05-supply-chain-iot-physical.md) | Supply chains, IoT/M2M, robotics, energy grids, DePIN |
| [`06-governance-civics-public-sector.md`](06-governance-civics-public-sector.md) | Voting, public records, DAOs, treasuries, e-government |
| [`07-healthcare-biotech.md`](07-healthcare-biotech.md) | Health records, consent, clinical trials, genomics, agent triage |
| [`08-security-defense-critical-infra.md`](08-security-defense-critical-infra.md) | PQ migration, critical infra, defense logistics, secure comms |
| [`09-creative-media-ip-culture.md`](09-creative-media-ip-culture.md) | Provenance, royalties, AI authorship, deepfake defense, cultural archives |
| [`10-knowledge-education.md`](10-knowledge-education.md) | Credentials, knowledge commons, agent tutors, archives for centuries |
| [`11-impact-on-society.md`](11-impact-on-society.md) | **Cross-cutting:** labor, inequality, institutions, power, geopolitics |
| [`12-impact-on-humans.md`](12-impact-on-humans.md) | **Cross-cutting:** the individual — agency, attention, trust, the lived day |
| [`13-philosophical-implications.md`](13-philosophical-implications.md) | **Cross-cutting:** personhood, value, sentience framing, the long now |
| [`14-very-ambitious-civilizational.md`](14-very-ambitious-civilizational.md) | The moonshots — interplanetary, post-labor, machine-civilization substrate |

## Reading order

- **Skeptics / investors:** start at [`00-master-matrix.md`](00-master-matrix.md), filter to
  🟩 Immediate / ⚪–🟠 difficulty. That column is the realistic near-term product.
- **Researchers / dreamers:** read [`14-very-ambitious-civilizational.md`](14-very-ambitious-civilizational.md)
  and the three cross-cutting impact files.
- **Builders:** pair each field file with its dependency in [`09-roadmap/`](../09-roadmap/)
  and [`04-ai-economy/`](../04-ai-economy/).

## A standing caution

The most exciting use cases here lean hardest on the project's **riskiest** ideas — novelty
scoring, "proof of sentience," biometric personhood, and sharded PQ atomicity. Per
[ADR-0007](../adr/0007-sentience-framing.md), the sentience/novelty machinery must stay
**off the consensus-critical path, opt-in, and economically bounded.** Where a use case
depends on it, that dependence is flagged 🔴 and treated as *a research bet, not a feature*.

---

### Open Questions
- Which **single** vertical should the project pursue first to avoid scope collapse —
  long-horizon PQ records, or the agent economy? (See [`11-research/open-problems.md`](../11-research/open-problems.md).)
- Is Huxplex better positioned as a **sovereign L1** running these use cases, or as a
  **module suite** (PQ pruning, causal clock, novelty lib) other chains import? (The readme's
  v4 endgame.)
- For each 🔴 use case: what is the *minimum* research result that would move it from 🔴 to 🟠?

# 17 — The 2026 Landscape: What Aligns, Rivals, and Matters

> **Purpose.** Huxplex is not being built in an empty field. This document surveys what
> exists as of **September 2026** across agent payments, agent identity, intent-centric
> chains, post-quantum migration, consensus research, and AI governance — and states plainly
> where Huxplex is **converging** with the field, where it is **behind**, where it is
> **genuinely differentiated**, and where it is **being overtaken**.
>
> Companion to [`16-action-plan.md`](16-action-plan.md). Written to be uncomfortable: the
> most useful finding in here is that several ideas the project treats as distinctive are
> now being standardized by very large organizations.

**Legend:** 🤝 aligns · ⚔️ rivals · 📚 research input · ⚠️ threat to the thesis

---

## 1. Executive read

Six findings, in order of importance to the project.

| # | Finding | So what |
|---|---|---|
| 1 | **The field has independently converged on Huxplex's core thesis.** "Capability ≠ authority", scope attenuation, bounded delegation and evidence models are now the organizing ideas of agent infrastructure — at Google, Coinbase, Mastercard, the Linux Foundation and DIF | The thesis is *validated* and *no longer distinctive*. Differentiation must move to **enforcement depth**, not the idea |
| 2 | **The founder's four identity questions are now a published standard.** KYA-OS (ex-MCP-I) at DIF asks the same four questions almost verbatim | Independent arrival at the same design is strong evidence it is right — and evidence Huxplex must interoperate rather than reinvent |
| 3 | **The authority layer is being standardized *above* the chain, not on one.** AP2 mandates, x402, and A2A put delegation proofs in the protocol envelope, settling on any rail | ⚠️ This is the biggest threat: it makes a *sovereign L1* look unnecessary for the agent-authority use case |
| 4 | **Nobody has solved substrate-level enforcement.** Every 2026 system enforces at the *orchestration* layer; the governance-containment gap is measured at 15–20 points | This is Huxplex's real, remaining moat — and it is exactly what G9-T4 tests |
| 5 | **Q-Day consensus has moved to 2033–2035**, but regulatory deadlines (2030/2031) arrived early | PQ-by-construction stays correct, but the *urgency* argument is now regulatory, not cryptographic |
| 6 | **Q-BFT as specified is behind the state of the art.** Mysticeti-C is in production on Sui at 3-round latency; Shoal++ reaches sub-second at 100k TPS | Adopt, don't invent. ADR-0004 should be revisited before G6 |

---

## 2. Agent payments and agentic commerce ⚔️🤝

The most crowded and fastest-moving area, and the one that most directly overlaps the
founder's Canon-DSLR walkthrough.

### The three protocols that matter

| Protocol | Origin | What it does | Relation to Huxplex |
|---|---|---|---|
| **AP2** (Agent Payments Protocol) | Google Cloud + Coinbase, Sept 2025 | Cryptographic **mandates** — signed attestations that a human authorized an agent to spend, carried to whoever takes the money | ⚔️🤝 **This is the Work Visa, as an interop envelope.** AP2 is *"a way of proving that a person told an agent it could spend"* — the same primitive, without a chain |
| **x402** | Coinbase + Cloudflare, Sept 2025; **Linux Foundation x402 Foundation, April 2026** | Revives HTTP 402: a server answers "payment required", a machine settles and retries, no human | 🤝 The machine-payment rail a Huxplex payment connector would speak |
| **ACP** (Agentic Commerce Protocol) | OpenAI/Stripe lineage | Merchant-side agentic checkout | 🤝 A commerce-connector target |

### Scale, as of 2026

- x402 processed **~165 million agent transactions** in its first months.
- McKinsey: agentic commerce could influence **$3–5 trillion** of global commerce by 2030.
- The AI agent market reached **$12.06 billion** in 2026.

### What this means for Huxplex

The founder's notes describe commerce connectors, payment connectors and shipping connectors
as things Huxplex will need to define. **Three of the four already exist as open standards
with major backing.** The correct move is decisively:

> **Huxplex connectors should *speak* AP2, x402 and ACP — not replace them.**

The differentiator is not the rail. It is that Huxplex **enforces the mandate at the
substrate** and **records the evidence in consensus state**, where AP2 merely *carries* the
mandate and trusts the endpoints to honour it.

⚠️ **The uncomfortable version:** if AP2 mandates plus a conventional payment network deliver
80% of the bounded-agent-spending benefit with zero blockchain adoption cost, most users will
stop there. Huxplex must be clear about the 20% that requires a sovereign substrate —
neutrality, non-revocable audit trail, and enforcement no single vendor can lift.

## 3. Agent identity and delegation 🤝

**The most striking finding in this review.**

In March 2026, Vouched donated the **MCP-I** framework to the **Decentralized Identity
Foundation**, where it is stewarded by the DIF Trusted AI Agents Working Group and renamed
**KYA-OS** (Know Your Agent OS). It defines four questions every service should be able to
answer:

> **Who is the agent? Who authorized it? What is it allowed to do? What is the scope of that
> delegation?**

Compare the founder's handwritten notes, page 18, written independently:

> *"Who is the human? Who is the agent? Who authorized the agent? What was the agent
> authorized to do? How much can it spend? Until when? Can it automatically execute?"*

This is the same framework, arrived at independently, with **three extra questions** — spend
limit, expiry, and automatic-execution authority — that the standard does not name
explicitly.

### Other convergences

| Concept | Field, 2026 | Huxplex |
|---|---|---|
| **Scope attenuation** — *"each delegation hop must narrow, never widen"* | KYA-OS core constraint | Exactly **G9-T2** |
| **Intersection, not union** — an agent may do what it is authorized to do **and** what its principal may do | 2026 delegation literature | Should be added explicitly to the visa evaluation rules |
| DIDs + VCs as the substrate for agent identity | KYA-OS built on DID/VC | [ADR-0013](adr/0013-did-huxplex-method.md) `did:huxplex` — 🤝 aligned |
| Delegation carried as signed capability documents / JWT `act` claims | OAuth 2.0 extensions | Huxplex uses PQ-signed VCs — **more future-proof, less interoperable today** |

**Recommendation:** `did:huxplex` should publish a KYA-OS-compatible profile. Being a
conformant, post-quantum implementation of an emerging standard is a far stronger position
than being a parallel one.

## 4. Intent-centric architecture ⚔️

**Anoma** remains the closest architectural relative: an intent-centric L1 built around a
formally specified **Resource Machine**, with intents as the primary unit of state
transition and a solver market performing counterparty discovery and matching. As of 2026 it
is in research/testnet; mainnet is staged for 2026 but has not launched.

| Dimension | Anoma | Huxplex |
|---|---|---|
| State model | Resource Machine | HRM — acknowledged in [ADR-0003](adr/0003-state-model-hrm.md) as the same lineage |
| Intents | Unbalanced partial transactions + solvers | Same model in the blueprint; **different** model in the founder's notes |
| Post-quantum | No | **Yes, by construction** ← the clearest differentiator |
| Agent authority | Not a primitive | Work Visas, enforced |
| External systems | Not in scope | Connectors ← new in the founder's notes |
| Status | Testnet, mainnet staged 2026 | Primitives only |

**Reading:** Anoma is years ahead on the intent machinery and will likely ship first.
Huxplex should treat Anoma's Resource Machine specification as **prior art to learn from
rather than a race to win**, and concentrate its distinctiveness on PQ + bounded authority +
evidence. The two-intent-model tension flagged in
[`brainstorming/README.md`](brainstorming/README.md) §3.1 is precisely the seam where Anoma's
model (settlement-facing) and the founder's model (user-facing) can be composed rather than
chosen between.

### Agent-native chains ⚔️

**Kite AI** launched an agent-payment L1 on Avalanche in April 2026 — native agent identity,
stablecoin-native micropayment rails, governance, and "Proof of Attributed Intelligence".
Skyfire, Nevermined, Crossmint, Nekuda and PayOS occupy the agent-payment middleware layer;
Visa has run agent-initiated transaction pilots with several.

⚠️ Note the direct collision: **Proof of Attributed Intelligence** is conceptually adjacent to
Huxplex's "Proof of Sentience" / SNTNC merit accrual — already the project's riskiest idea
([ADR-0007](adr/0007-sentience-framing.md)). Kite shipping something similar first means
Huxplex will be *compared* to it. Keeping merit strictly off the consensus path (**G8-T4**)
is now a competitive necessity as well as a safety one.

## 5. Evidence, attestation, and the oracle problem 📚⚠️

The founder's notes end Part II by naming this as unfinished: *"an area where Huxplex will
eventually need a sophisticated proof/evidence model."* The 2026 literature agrees, and has
started building one.

- **Mastercard + Google — Verifiable Intent** (2026): an open, standards-based trust layer
  for agentic commerce. The merchant proves the agent is legitimate; the agent proves a real
  user delegated the purchase. Described as *"the layer where most agent-fraud risk
  concentrates, and the most contested protocol layer."*
- **Proof of conduct** (Inherence): cryptographic evidence that an action passed defined
  policy checks *before* execution — a **pre-execution** complement to Huxplex's
  post-execution connector attestation.
- **"An Evidence Model for Agentic Processes"** (arXiv 2609.08481) delivers the sharpest
  warning in this entire review:

  > *"A hash does not establish semantic truth, a signature does not establish
  > authorization, and an external anchor does not establish capture completeness."*

  This is a direct critique of the naïve reading of the founder's evidence record. Storing a
  merchant response, a receipt hash and a connector signature proves *integrity of a
  received message* — **not** that the goods exist, that the price was fair, or that the
  merchant will honour it. **G11-T3 exists because of this paper.**
- **Runtime vs. specification gap:** AP2 gives specification-level guarantees, but real
  execution introduces retries, concurrency and orchestration that break implicit
  assumptions about mandate usage. → **G11-T5** (idempotency, duplicate delivery,
  out-of-order callbacks).
- **Decision Evidence Maturity Model for Agentic AI** (arXiv 2605.04093) offers a
  property-level ladder Huxplex could adopt for grading evidence quality rather than
  treating evidence as binary.

## 6. Post-quantum cryptography 🤝⚠️

### Standards and timeline

- **ML-DSA (FIPS 204)** and ML-KEM are the settled NIST choices — Huxplex's selections are
  correct and mainstream 🤝.
- **Q-Day central estimate is now 2033–2035.** IBM targets ~200 logical qubits by 2029
  (Starling) and 2,000 by 2033 (Blue Jay); Google's Willow progressed from a 3×3 to a 7×7
  surface code in early 2026. Neither is a CRQC — breaking RSA-2048 needs millions of
  physical qubits.
- ⚠️ **But Google Quantum AI (March 2026)** showed breaking the elliptic-curve cryptography
  behind Bitcoin and Ethereum needs roughly **20× fewer qubits than previously believed** —
  the estimate is moving in the dangerous direction.
- **Regulatory deadlines have overtaken the technical ones.** EO 14409 (June 2026) requires
  US federal PQ key establishment by **end-2030** and PQ signatures by **end-2031**; all
  quantum-vulnerable public-key algorithms are disallowed in NIST standards by **2035**.

**Implication:** the honest pitch is no longer *"quantum computers are about to break
everything."* It is **harvest-now-decrypt-later plus a hard compliance wall in 2030/2031**,
against ledgers meant to remain valid for decades. That is a stronger argument and a more
defensible one.

### The size problem, quantified

ML-DSA public keys are ~1.3–2.6 KB and signatures ~2.4–4.6 KB, against 33-byte keys and
64–72-byte signatures for ECDSA. The 2026 literature independently confirms this as *the*
blocking constraint for on-chain PQ — which is exactly risk #2 in the executive summary.
**G3-T4 (pruning preserves the root) is the project's answer, and it is validated as the
right thing to test early.**

### Also relevant

- LLM-assisted static analysis for PQC migration auditing (arXiv 2604.00560) — a tooling
  opportunity for [`03-post-quantum/migration-strategy.md`](03-post-quantum/migration-strategy.md).
- Operational hybrid PQC TLS deployment in financial infrastructure (arXiv 2605.17955) —
  direct input for **G5-T1**.
- Monte Carlo modelling of PQC migration in Australia's New Payments Platform
  (arXiv 2605.02276) — a template for the crypto-agility rollout in
  [`03-post-quantum/crypto-agility.md`](03-post-quantum/crypto-agility.md).

## 7. Consensus research ⚔️📚

Directly relevant to [ADR-0004](adr/0004-consensus-selection.md) and **G6**.

| System | Result | Bearing on Q-BFT |
|---|---|---|
| **Narwhal + Bullshark/Tusk** | 100k+ TPS geo-replicated, sub-3s | The DAG-mempool baseline ADR-0004 already cites |
| **Mysticeti-C** | **In production on Sui**, >$1.5B secured. First DAG BFT at the 3-message-round latency lower bound; ~4× latency reduction vs Bullshark, by dropping explicit block certification | ⚔️ Q-BFT as specified is a generation behind. **Uncertified DAGs are the current state of the art** |
| **Shoal / Shoal++** | Up to 60% latency reduction; sub-second at 100k TPS | Pipelining techniques applicable regardless of base protocol |
| **Nemo-Nemo** (arXiv 2604.08914) | ≥600k cmd/sec, CFT DAG in the WAN | Upper bound on what lightweight DAG architectures achieve |
| **Orthrus** (arXiv 2501.14732) | Concurrent partial ordering across multi-BFT | Relevant to future S-EUTXO sharding |

**Recommendation:** revisit ADR-0004 **before G6 begins**. The specification's
HotStuff/Jolteon commit over a Narwhal-style mempool is sound but no longer state of the
art. An uncertified-DAG design would also *reduce* certificate volume — which matters
disproportionately here, because every certificate carries 2,420-byte ML-DSA signatures.
**PQ signature size makes Mysticeti's central optimization worth more to Huxplex than to
Sui.**

## 8. Agent interoperability and the governance gap 📚⭐

The single most important paper for this project.

### MCP and A2A are now infrastructure

- **MCP:** 97 million monthly SDK downloads by March 2026 — React-scale in 16 months.
  Natively supported by Anthropic, OpenAI, Google, Microsoft, AWS, Cursor and JetBrains.
  Donated to the Linux Foundation's **Agentic AI Foundation** in December 2025. Median time
  to wire a SaaS tool into an agent fell from ~18 h to ~4.2 h.
- **A2A:** v1.0 in April 2026 under the Linux Foundation, 150+ organizations. Agent-to-agent
  peer delegation.
- The division: **MCP is agent→tool (vertical). A2A is agent→agent (horizontal).**

⚠️ **Direct consequence for the founder's connector concept.** MCP *is* the connector
protocol the notes describe — *"it understands the Huxplex protocol and the external
platform protocol"* — and it has already won, at enormous scale. **Huxplex connectors should
be MCP servers/clients with a Huxplex authority-and-evidence wrapper.** Defining a
proprietary connector protocol in 2026 would be a serious strategic error, and this should
be written into the connector ADR that **G11** is blocked on.

### The paper that states Huxplex's thesis academically

**"Governance Gaps in Agent Interoperability Protocols: What MCP, A2A, and ACP Cannot
Express"** — Richard Kang, Yudho Diponegoro, arXiv:2606.31498 (2026).

The paper analyses the three dominant agent protocols and identifies five governance
properties **none of them can express**:

| # | Gap the paper identifies | Huxplex's answer | Tested by |
|---|---|---|---|
| 1 | **Authority bounds** — scope of authority over resources or actions | Work Visa constraints | G9-T1 |
| 2 | **Delegation scope** — what may be delegated, to whom, under what conditions | Attenuating delegation | G9-T2 |
| 3 | **Spend limits & resource controls** — financial and consumption thresholds | `max_transaction`, `max_shipping`, per-epoch caps | G9-T1 |
| 4 | **Accountability** — assigning responsibility, enabling audit | Every action bound to a visa, in consensus state | G9-T4 |
| 5 | **Evidence & proof requirements** — what verification an action requires | Connector attestation model | G11-T1, G11-T3 |

**This is the Huxplex feature list, written by independent researchers as a list of things
the industry cannot currently do.** It is the strongest external validation available, and
the best available framing for the project: *Huxplex is an implementation of the governance
requirements taxonomy that MCP, A2A and ACP cannot express.*

Also relevant: *Infrastructure for the Agentic Web* (arXiv 2606.20570), *Runtime Governance
for AI Agents: Policies on Paths* (arXiv 2603.16586), and *AgentRob: From Virtual Forum
Agents to Hijacked Physical Robots* (arXiv 2602.13591) — the last being a direct empirical
warning about the physical-world connectors the notes propose.

## 9. AI governance, control, and regulation 📚

### The measured governance-containment gap

2026 data puts a **15–20 point gap** between organizations' ability to *monitor* AI systems
and their ability to *stop* them: 59% have human-in-the-loop oversight and 58% continuous
monitoring, but only **37% have purpose binding** and **40% have kill-switch capability**.
65% of firms reported an AI-agent security incident in 2026.

This is the market gap Huxplex targets, with numbers attached. Purpose binding — the least
implemented control at 37% — is *precisely* what a Work Visa's `purpose` field is.

### Convergent research

- **"Bounded Autonomy for Enterprise AI: Typed Action Contracts and Consumer-Side
  Execution"** (arXiv 2604.14723) — typed action contracts are a near-exact restatement of
  the visa concept, at the application layer.
- **"On Controllability in Agentic AI: A Survey"** (*Minds and Machines*, 2026) — the
  academic frame for capability-vs-permission.
- The emerging consensus: *"Environment-level constraints are the most infrastructural form
  of guardrailing: they do not require the agent to reason correctly about every safety
  rule, because the surrounding environment bounds what the agent can physically do."*
  🤝 This is Huxplex's substrate-enforcement argument, stated by the AI-safety field.
- *"AI agents need deterministic controls, not probabilistic safety gates."*
- Graduated authority levels with persistent audit trails (MongoDB's bounded-autonomy
  pattern) — worth adopting into the visa lifecycle.

### Regulation is now a forcing function 🤝

**EU AI Act enforcement powers over GPAI providers went live 2 August 2026**, with fines up
to 3% and Commission powers to evaluate, demand documentation, and require recall.
Autonomous agents taking consequential actions — financial transactions, medical decisions,
legal submissions — are likely **high-risk**, triggering human oversight, auditability and
conformity assessment. High-risk systems must **automatically generate logs of their
operation**.

Critically for Huxplex's positioning: *"Compliance at the GPAI provider level does not
discharge the orchestration layer's obligations, which do not discharge the enterprise
deployer's."* Every layer needs its own provable audit trail.

> **This is the strongest commercial argument the project has, and it is new.** The
> founder's notes say governments will want *"auditability and jurisdictional controls."* As
> of August 2026 that is not a prediction — it is an enforced legal obligation with a
> revenue-percentage penalty. A substrate that makes agent authority and evidence
> structurally auditable is a compliance artifact, not just an ideology.

---

## 10. Where Huxplex actually stands

### Genuinely differentiated ✅

1. **Post-quantum by construction, combined with agent authority.** No one else is doing
   both. Every agent-payment system surveyed uses classical cryptography.
2. **Substrate-level enforcement.** Everyone else enforces at the orchestration layer, which
   a determined agent or a compromised orchestrator routes around. The 37% purpose-binding
   statistic is the size of this gap.
3. **Evidence recorded in consensus state**, not in a vendor's log that the vendor can edit.
4. **Crypto-agility as a first-class architectural property**, ahead of the 2030/2031
   regulatory wall.
5. **A constitutional layer with an unamendable human veto.** No competitor has anything
   comparable; it is the answer to the notes' Mars-colony question.

### No longer differentiated ⚠️

1. Bounded agent authority *as an idea* — AP2, KYA-OS and typed action contracts all have it.
2. The four identity questions — now a DIF standard.
3. Intent-centric architecture — Anoma is years ahead.
4. Agent-native chains — Kite AI shipped a mainnet in April 2026.
5. Connector-style adapters — MCP won, at 97M monthly downloads.

### Behind ❌

1. **Consensus:** Q-BFT as specified is a generation behind Mysticeti-C.
2. **Shipping:** competitors have mainnets; Huxplex has primitives that
   [do not currently compile on ARM](16-action-plan.md#g0--repository-health).
3. **Standards participation:** absent from DIF, AAIF, and the x402 Foundation, where the
   interfaces Huxplex will have to speak are being decided right now.

### Recommended strategic adjustments

| # | Adjustment | Rationale |
|---|---|---|
| 1 | **Reposition as the enforcement and evidence layer *for* the emerging agent stack**, not a replacement for it | Speak AP2, x402, MCP, A2A; enforce and attest underneath them. The standards are settled; the enforcement is not |
| 2 | **Adopt arXiv:2606.31498's taxonomy as the project's external framing** | Independent researchers have written the feature list. Use their words |
| 3 | **Revisit ADR-0004 before G6** | Uncertified DAGs matter more to a PQ chain than to a classical one |
| 4 | **Publish a KYA-OS-conformant `did:huxplex` profile** | Conformant-and-post-quantum beats parallel-and-isolated |
| 5 | **Lead with the 2030/2031 compliance wall and EU AI Act auditability**, not Q-Day | Both are enforced deadlines; Q-Day is a forecast that keeps moving |
| 6 | **Keep SNTNC off the consensus path (G8-T4) and say so loudly** | Kite's Proof of Attributed Intelligence guarantees the comparison will be drawn |
| 7 | **Join DIF, AAIF and the x402 Foundation** | Cheapest possible way to keep the interfaces compatible with a substrate that does not exist yet |

---

## Sources

**Agent payments & commerce**
- [Agentic Payments in 2026: AP2, ACP and x402 Explained](https://dev.to/lusivision/agentic-payments-in-2026-ap2-acp-and-x402-explained-2pkb)
- [Agentic Payments in 2026: The x402 Explainer — RZLT](https://www.rzlt.io/blog/agentic-payments-2026-x402-explainer)
- [AP2 Protocol: Complete Guide to Agent Payments for Web3 (2026) — Cobo](https://www.cobo.com/post/ap2-protocol-complete-guide-to-agent-payments-for-web3-developers-2026)
- [What Is Agentic Commerce? The 2026 Guide — Eco](https://eco.com/support/en/articles/14839400-what-is-agentic-commerce-the-2026-guide)
- [The 2026 Payment Stack and the Metering Gap — UsageBox](https://usagebox.com/articles/ai-agent-payment-stack-2026-x402-ap2-agent-pay-metering-gap)
- [How Does Agentic Commerce Work? — Agentic AI Foundation](https://aaif.io/blog/how-does-agentic-commerce-work)
- [How Verifiable Intent builds trust in agentic AI commerce — Mastercard](https://www.mastercard.com/us/en/news-and-trends/stories/2026/verifiable-intent.html)
- [The hidden liability of agentic commerce — Fintech Wrap Up](https://www.fintechwrapup.com/p/deep-dive-the-hidden-liability-of)

**Agent identity & delegation**
- [AI Identity: Standards, Gaps and Delegation (arXiv 2604.23280)](https://arxiv.org/pdf/2604.23280)
- [AI Agent Identity Management 2026: Standards & Gaps — Iden](https://www.idenhq.com/en/blog/ai-agent-identity-management-2026)
- [AI Agent Identity: Delegation, Risk and Standards 2026 — Techjack](https://techjacksolutions.com/cloud-tools/foundations/ai-agent-identity/)
- [Agent Identity Verification: How AI Agents Authenticate Purchases in 2026 — Eco](https://eco.com/support/en/articles/15192005-agent-identity-verification-how-ai-agents-authenticate-purchases-in-2026)

**Intent-centric & agent-native chains**
- [What Are Intents and Solvers? 2026 Guide — Eco](https://eco.com/support/en/articles/11855244-what-are-intents-and-solvers-2026-guide)
- [Anoma Intent-Centric Architecture: How It Works — Eco](https://eco.com/support/en/articles/14799841-anoma-intent-centric-architecture-how-it-works)
- [Kite AI Payment L1 — BlockEden](https://blockeden.xyz/blog/2026/03/10/kite-ai-payment-l1-purpose-built-blockchain-ai-agent-economy/)
- [Kite whitepaper](https://gokite.ai/kite-whitepaper) · [KiteAI: Building the Agentic Economy — Messari](https://messari.io/report/kiteai-building-the-agentic-economy)
- [KITE AI Launches Mainnet on Avalanche](https://coinalertnews.com/news/2026/04/30/kite-ai-mainnet-avalanche-agent-economy)

**Evidence & attestation**
- [An Evidence Model for Agentic Processes (arXiv 2609.08481)](https://arxiv.org/html/2609.08481v1)
- [Decision Evidence Maturity Model for Agentic AI (arXiv 2605.04093)](https://arxiv.org/pdf/2605.04093)
- [Inherence — Proof of conduct for the agent economy](https://resources.inherence.dev/)

**Post-quantum**
- [Cryptographically Relevant Quantum Computer: Complete 2026 Guide — Quantum Zeitgeist](https://quantumzeitgeist.com/cryptographically-relevant-quantum-computer/)
- [Quantum Computing Progress 2026: IBM, Google and Q-Day](https://quantumsecuritydefence.com/quantum-news/quantum-computing-progress-2026-ibm-google/)
- [ML-DSA and PQ Signing — Encryption Consulting](https://www.encryptionconsulting.com/ml-dsa-and-pq-signing/)
- [PQC Migration in 2026 — Encryption Consulting](https://www.encryptionconsulting.com/pqc-migration-in-2026/)
- [Post-Quantum Cryptography and Quantum-Safe Security: A Survey (arXiv 2510.10436)](https://arxiv.org/pdf/2510.10436)
- [Quantum-Safe Code Auditing (arXiv 2604.00560)](https://arxiv.org/pdf/2604.00560)
- [Operationalising Post-Quantum TLS in Financial Infrastructure (arXiv 2605.17955)](https://arxiv.org/pdf/2605.17955)
- [PQC Migration in Australian Real-Time Payments (arXiv 2605.02276)](https://arxiv.org/pdf/2605.02276)

**Consensus**
- [Mysticeti: Reaching the Limits of Latency with Uncertified DAGs (arXiv 2310.14821)](https://arxiv.org/pdf/2310.14821) · [NDSS version](https://www.ndss-symposium.org/wp-content/uploads/2025-929-paper.pdf)
- [Shoal: Improving DAG-BFT Latency and Robustness (arXiv 2306.03058)](https://arxiv.org/pdf/2306.03058) · [Shoal++](https://decentralizedthoughts.github.io/2024-06-12-shoalpp/)
- [DAG Meets BFT — Decentralized Thoughts](https://decentralizedthoughts.github.io/2022-06-28-DAG-meets-BFT/)
- [Nemo-Nemo: CFT DAG-based Consensus in the WAN (arXiv 2604.08914)](https://arxiv.org/pdf/2604.08914)
- [Orthrus: Accelerating Multi-BFT Consensus (arXiv 2501.14732)](https://arxiv.org/pdf/2501.14732)

**Agent interoperability & governance**
- [**Governance Gaps in Agent Interoperability Protocols (arXiv 2606.31498)**](https://arxiv.org/pdf/2606.31498) — Kang & Diponegoro
- [Infrastructure for the Agentic Web (arXiv 2606.20570)](https://arxiv.org/pdf/2606.20570)
- [Runtime Governance for AI Agents: Policies on Paths (arXiv 2603.16586)](https://arxiv.org/pdf/2603.16586)
- [AgentRob: From Virtual Forum Agents to Hijacked Physical Robots (arXiv 2602.13591)](https://arxiv.org/pdf/2602.13591)
- [Agent Interoperability Protocols: MCP, A2A, OSI Explained — Atlan](https://atlan.com/know/agent-interoperability-protocols/)
- [MCP vs A2A: The Complete Guide to AI Agent Protocols in 2026](https://dev.to/pockit_tools/mcp-vs-a2a-the-complete-guide-to-ai-agent-protocols-in-2026-30li)
- [Survey of LLM Agent Communication with MCP (arXiv 2506.05364)](https://arxiv.org/pdf/2506.05364)

**AI governance, control & regulation**
- [Bounded Autonomy for Enterprise AI: Typed Action Contracts (arXiv 2604.14723)](https://arxiv.org/pdf/2604.14723)
- [On Controllability in Agentic AI: A Survey — Minds and Machines](https://link.springer.com/article/10.1007/s11023-026-09783-y)
- [AI Agent Security Incidents Hit 65% of Firms in 2026 — Kiteworks](https://www.kiteworks.com/cybersecurity-risk-management/ai-agent-security-incidents-2026/)
- [2026 Data Security Forecast: AI Governance Predictions — Kiteworks](https://www.kiteworks.com/cybersecurity-risk-management/2026-data-security-forecast-ai-governance-predictions/)
- [AI agents need deterministic controls, not probabilistic safety gates — NHI Mgmt Group](https://nhimg.org/articles/ai-agents-need-deterministic-controls-not-probabilistic-safety-gates/)
- [EU AI Act 2026: GPAI Enforcement & 3% Fines Begin — Beam](https://beam.ai/agentic-insights/eu-ai-act-enforcement-august-2-2026-gpai-fines)
- [Enforcement of Chapter V under the EU AI Act](https://artificialintelligenceact.eu/enforcement-of-chapter-v-under-the-eu-ai-act/)
- [AI Act — European Commission](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [AI Governance and Regulation 2026: Global Frameworks — Prof. Hung-Yi Chen](https://www.hungyichen.com/en/insights/ai-governance-regulatory-landscape-2026)

---

### Open Questions

- **Is a sovereign L1 still the right vessel?** If AP2 + x402 + MCP standardize authority,
  payment and connection above any chain, the readme's v4 "export as modules" endgame
  (causal clock, PQ pruning, enforcement/evidence library) may be the higher-expected-value
  path. This review strengthens that question rather than settling it — it is the same
  question already open in [`11-research/open-problems.md`](11-research/open-problems.md).
- Can Huxplex be a **conformant AP2 mandate verifier** while enforcing at the substrate — or
  do the two authority models conflict semantically?
- Does the EU AI Act's automatic-logging obligation create a **compliance-driven adoption
  path** that bypasses the usual crypto adoption curve entirely?
- What is the smallest artifact that demonstrates substrate-level enforcement to a skeptic —
  and can it be shipped **before** a full L1?
- Should Huxplex publish the founder's four identity questions as a **KYA-OS extension
  proposal** (adding spend limit, expiry, and automatic-execution authority)?

*Survey current as of 12 September 2026. This document should be re-run every 6 months; the
agent-infrastructure field is moving faster than the project.*

# Huxplex Canonical Blueprint (`/docs`)

> The sovereign substrate for the Quantum + AI era — a post-quantum, intent-centric,
> AI-native Layer-1 designed to survive for decades.

This directory is the **canonical engineering blueprint** for Huxplex. It is not a
description of the code as it exists today (a Cargo workspace of two crates —
`hux-crypto` and `hux-network` — holding the post-quantum primitive layer). It is the multi-year program that takes Huxplex from a
post-quantum crypto library to a civilization-scale protocol.

It is written to be read by protocol engineers, cryptographers, distributed-systems
researchers, AI researchers, economists, governance designers, and operators. Where the
vision and the code disagree, the blueprint **says so explicitly** and resolves the
conflict with an Architecture Decision Record (ADR).

## How to read this

1. Start with [`00-executive-summary.md`](00-executive-summary.md) — it contains the
   honest **reality-vs-vision gap analysis** and the one-page program thesis.
2. Read [`01-vision/`](01-vision/) for the *why*.
3. Read [`02-architecture/`](02-architecture/) for the *what* and [`adr/`](adr/) for the
   *why this and not that*.
4. Builders go to [`16-action-plan.md`](16-action-plan.md) — the gated build order and the
   tests that unlock each stage — then, for the work actually in flight,
   [`18-implementation-plan/`](18-implementation-plan/). To check the foundation yourself, run
   [`19-verification/`](19-verification/); for where it actually stands against the gates, read
   [`20-completion/`](20-completion/). Then [`09-roadmap/`](09-roadmap/),
   [`10-development/`](10-development/), [`backlog/`](backlog/), and the
   [`process/`](process/) playbooks.
5. For competitive and research context, read [`17-landscape-2026.md`](17-landscape-2026.md).
   For the founder's original thinking, read [`brainstorming/`](brainstorming/)
   (non-normative).

## Map

| Section | Purpose |
|---|---|
| [`00-executive-summary.md`](00-executive-summary.md) | Thesis, gap analysis, critical path, top risks |
| [`01-vision/`](01-vision/) | Mission, principles, threat model, quantum-era risks |
| [`02-architecture/`](02-architecture/) | System, L1, consensus, networking, storage, state, crypto, tx model, execution |
| [`03-post-quantum/`](03-post-quantum/) | PQ crypto stack, key management, migration, crypto-agility |
| [`04-ai-economy/`](04-ai-economy/) | Agent framework, wallets, identity, reputation, marketplace, commerce, governance |
| [`05-identity/`](05-identity/) | DID, human/AI/hybrid identity, ZK proofs, privacy |
| [`06-tokenomics/`](06-tokenomics/) | Token design, incentives, staking, treasury, fees |
| [`07-governance/`](07-governance/) | Governance model, voting, constitution, upgrades |
| [`08-security/`](08-security/) | Threat model, attack vectors, quantum threats, audits, incident response |
| [`09-roadmap/`](09-roadmap/) | Phase 0–4 (research → testnet → mainnet → AI economy → global scale) |
| [`10-development/`](10-development/) | Repo structure, coding standards, CI/CD, testing |
| [`11-research/`](11-research/) | Open problems, future research, literature review |
| [`12-business/`](12-business/) | Ecosystem growth, grants, partnerships, adoption |
| [`13-operational/`](13-operational/) | Validator guide, node ops, monitoring, disaster recovery |
| [`14-use-cases/`](14-use-cases/) | Use cases, applications & impacts — by field, horizon (immediate/futuristic/very ambitious) and difficulty (easy/intermediate/hard); plus society, human and philosophical impact |
| [`15-specifications/`](15-specifications/) | Normative implementation specs — data model & encoding, cryptography (context registry + KATs), HRM state transition, consensus, network wire protocol, v1 scope contract |
| [`16-action-plan.md`](16-action-plan.md) | **The build order** — gated development plan; each gate's high-concept tests must pass before dependent work may begin |
| [`17-landscape-2026.md`](17-landscape-2026.md) | What the rest of the world shipped by 2026 — agent payments, agent identity, intent chains, PQC, consensus, AI governance; where Huxplex aligns, rivals, and is behind |
| [`18-implementation-plan/`](18-implementation-plan/) | **How Layer 0 gets built** — workspace migration, G0/G1/G5 task breakdown with acceptance criteria, sequencing, risks and stop conditions |
| [`19-verification/`](19-verification/) | **How to verify Layer 0 yourself** — one-command harness, self-verifying walkthroughs, and manual check procedures for developers and contributors |
| [`20-completion/`](20-completion/) | **Where the project actually stands** — a dated, evidence-backed audit against the gates, and the complete list of what remains to be completed and tested |
| [`brainstorming/`](brainstorming/) | **Non-normative.** Founder's notes and ideas-in-progress, plus their reconciliation against this blueprint |
| [`adr/`](adr/) | Architecture Decision Records |
| [`rfc/`](rfc/) | RFC process + template |
| [`diagrams/`](diagrams/) | Mermaid architecture diagrams |
| [`process/`](process/) | Contributor guide, validator onboarding, GitHub project plan |
| [`backlog/`](backlog/) | Issue backlog + implementation checklists |

## Naming conventions used throughout

- **HRM** — Huxplex Resource Machine (the state model).
- **S-EUTXO** — Sharded Extended-UTXO (the sharding layout over HRM resources).
- **Q-BFT** — Quantum Byzantine Fault Tolerant consensus (PQ-authenticated PBFT/HotStuff family).
- **HuxVM** — deterministic WebAssembly execution environment.
- **TCHAO** — Transaction Classification by Historical Access Objects (parallel scheduler).
- **Work Visa** — verifiable credential authorizing an AI agent to act, with constraints.
- **HCP/1** — Huxplex Connector Protocol: how the substrate and agents cause and observe effects
  in external systems ([spec](15-specifications/07-connector-protocol.md)).
- **Connector** — a registered adapter to one external system. An *oracle* boundary, not a
  custody boundary: it holds no funds or credentials and cannot create authority.
- **Authorization Envelope** — a single-purpose, attenuated, expiring capability derived from a
  visa (`bounds ⊆ visa bounds`) and issued to exactly one connector.
- **Connector Session** — the durable object binding {intent, visa, connector} for the intent's
  entire lifecycle, outliving connections, processes, and restarts.
- **Evidence Class** — how strongly an external outcome is evidenced:
  `SelfReported < Relayed < Notarized < FirstParty ≤ Cryptographic`.
- **HUX / SVRGN / SNTNC** — the triple-token model (machine utility / human sovereignty / agent merit).

> ⚠️ **Source-of-truth note.** Two prior descriptions of Huxplex exist: the repository
> `readme.md` (token model `$HUX/$PLEX/$CRED`, "Proof of Sentience") and the Medium
> vision essays (`HUX/SVRGN/SNTNC`, "Hive-Mind governance"). This blueprint treats the
> Medium architecture as the **evolved canonical model** and records the reconciliation in
> [`adr/0001-canonical-architecture-reconciliation.md`](adr/0001-canonical-architecture-reconciliation.md).

## Status legend

Throughout the docs, components are tagged:

- 🟢 **Implemented** — code exists and is tested in `crates/`.
- 🟡 **Specified** — designed here, not yet built.
- 🔴 **Open** — unresolved research question; tradeoffs documented, decision deferred.

## Living documents

Every file ends with an **Open Questions** block. The union of these is maintained in
[`11-research/open-problems.md`](11-research/open-problems.md). When you resolve one,
write an ADR and update both places.
</content>
</invoke>

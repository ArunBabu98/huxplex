# Huxplex Canonical Blueprint (`/docs`)

> The sovereign substrate for the Quantum + AI era — a post-quantum, intent-centric,
> AI-native Layer-1 designed to survive for decades.

This directory is the **canonical engineering blueprint** for Huxplex. It is not a
description of the code as it exists today (that code is ~1,200 lines of cryptographic
and networking primitives). It is the multi-year program that takes Huxplex from a
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
4. Builders go to [`09-roadmap/`](09-roadmap/), [`10-development/`](10-development/),
   [`backlog/`](backlog/), and the [`process/`](process/) playbooks.

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
- **HUX / SVRGN / SNTNC** — the triple-token model (machine utility / human sovereignty / agent merit).

> ⚠️ **Source-of-truth note.** Two prior descriptions of Huxplex exist: the repository
> `readme.md` (token model `$HUX/$PLEX/$CRED`, "Proof of Sentience") and the Medium
> vision essays (`HUX/SVRGN/SNTNC`, "Hive-Mind governance"). This blueprint treats the
> Medium architecture as the **evolved canonical model** and records the reconciliation in
> [`adr/0001-canonical-architecture-reconciliation.md`](adr/0001-canonical-architecture-reconciliation.md).

## Status legend

Throughout the docs, components are tagged:

- 🟢 **Implemented** — code exists and is tested in `src/`.
- 🟡 **Specified** — designed here, not yet built.
- 🔴 **Open** — unresolved research question; tradeoffs documented, decision deferred.

## Living documents

Every file ends with an **Open Questions** block. The union of these is maintained in
[`11-research/open-problems.md`](11-research/open-problems.md). When you resolve one,
write an ADR and update both places.
</content>
</invoke>

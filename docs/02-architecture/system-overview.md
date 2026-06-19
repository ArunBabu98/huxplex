# System Overview

## Purpose

This is the map of the whole machine: the layers, how data flows from a user/agent intent to
a finalized state transition, and where each subsystem's detailed spec lives.

## Layered architecture

Huxplex is organized as a clean stack. Each layer depends only on the layers below it, and
every cross-layer object is **domain-separated and PQ-signed**.

```mermaid
graph TD
    subgraph L4["Layer 4 — Applications & Agent Economy"]
        AGENT[AI agents / solvers]
        WALLET[Wallets / clients]
        DAPP[dApps, marketplaces, DAOs]
    end
    subgraph L3["Layer 3 — Identity, Credentials, Governance"]
        DID[did:huxplex identities]
        VISA[Work Visa VCs]
        GOV[Hive-Mind governance]
        PROV[Provenance records]
    end
    subgraph L2["Layer 2 — Execution & Economy"]
        VM[HuxVM deterministic WASM]
        TCHAO[TCHAO parallel scheduler]
        FEES[Burn-based fee market]
        TOK[HUX / SVRGN / SNTNC]
    end
    subgraph L1["Layer 1 — Consensus & State"]
        QBFT[Q-BFT consensus]
        DAGMP[DAG mempool]
        HRM[HRM resource state]
        SEUTXO[S-EUTXO sharding]
        JMT[Jellyfish Merkle state]
    end
    subgraph L0["Layer 0 — Networking & Crypto"]
        P2P[libp2p / QUIC + PQ-TLS]
        GOSSIP[GossipSub + Kademlia DHT]
        CRYPTO[PQ crypto suite 🟢]
    end

    L4 --> L3 --> L2 --> L1 --> L0
```

| Layer | Subsystems | Spec | Status |
|---|---|---|---|
| L0 Crypto/Net | PQ suite, transport, gossip, DHT, peer ID | [cryptography](cryptography.md), [networking](networking.md), [`03-post-quantum/`](../03-post-quantum/) | crypto 🟢 / net 🟡 |
| L1 Consensus/State | Q-BFT, DAG mempool, HRM, S-EUTXO, JMT | [consensus](consensus.md), [state-management](state-management.md), [storage](storage.md), [layer1](layer1.md) | 🟡 |
| L2 Execution/Economy | HuxVM, TCHAO, fees, tokens | [execution-engine](execution-engine.md), [transaction-model](transaction-model.md), [`06-tokenomics/`](../06-tokenomics/) | 🟡 |
| L3 Identity/Gov | DID, Work Visa, governance, provenance | [`05-identity/`](../05-identity/), [`07-governance/`](../07-governance/) | 🟡 |
| L4 Apps/Agents | agents, solvers, wallets, marketplaces | [`04-ai-economy/`](../04-ai-economy/) | 🟡 |

## End-to-end lifecycle of a transaction/intent

```mermaid
sequenceDiagram
    participant U as User/Agent
    participant W as Wallet (HD keys 🟢)
    participant M as DAG Mempool
    participant S as Solver (agent)
    participant SCH as TCHAO Scheduler
    participant VM as HuxVM
    participant C as Q-BFT
    participant ST as State (JMT/RocksDB)

    U->>W: declare intent or build full tx
    W->>W: sign with ML-DSA-44 + context 🟢
    alt full transaction
        W->>M: submit balanced tx
    else intent (unbalanced)
        W->>M: submit intent
        S->>M: discover intent
        S->>S: construct balancing half + solver fee
        S->>M: submit completed tx
    end
    M->>SCH: ordered/causal batch (vector clocks)
    SCH->>SCH: build conflict graph, color into parallel groups
    SCH->>VM: execute groups in parallel
    VM->>VM: meter gas, mutate via typed host fns
    VM->>C: state-transition candidate
    C->>C: PrePrepare/Prepare/Commit (ML-DSA sigs, 2f+1)
    C->>ST: commit finalized block
    ST->>ST: prune witness/signature data post-finality
```

## Core data objects

| Object | Role | Signed with context |
|---|---|---|
| **Resource** (HRM) | atomic state unit: tokens, VCs, vaults, provenance | logic script validates |
| **Intent** | unbalanced partial tx (a goal) | `huxplex-{net}:intent:v1` |
| **Transaction** | balanced set of consumed+created resources | `huxplex-{net}:tx:v1` 🟢 |
| **Block** | ordered batch + consensus certificate | `…:block:{phase}:v1` 🟢 |
| **Vote** | PrePrepare/Prepare/Commit | `…:block:{phase}:v1` 🟢 |
| **GossipMessage** | propagation envelope | `…:gossip:{topic}:v1` 🟢 |
| **DhtEntry** | authenticated DHT record | `…:dht:entry:v1` 🟢 |
| **Work Visa** | agent capability credential | issuer-signed VC |
| **Provenance record** | human-origin attestation | creator-signed |

(🟢 = context string already defined and tested in `src/`.)

## Design stance: monolith first, modular always

Huxplex is built as a **single Rust workspace of cohesive crates** (a "modular monolith"),
*not* a generic framework (Substrate) and *not* a fragmented microservice mesh.

- We *use* mature libraries (`libp2p`, `wasmtime`/`wasmi`, `rocksdb`, `libcrux`) but own the
  consensus, state, and execution glue — the parts where Huxplex's differentiation lives.
- Crate boundaries mirror the layers above so subsystems can be tested and swapped
  independently (and so the v4 "export as modules" endgame stays possible).
- See [`10-development/repository-structure.md`](../10-development/repository-structure.md) and
  [ADR-0005](../adr/0005-build-strategy.md) (build on Substrate vs. custom Rust).

## Cross-cutting concerns

- **Crypto-agility** threads through every layer (algorithm IDs on every signed object).
- **Determinism** is enforced at L2 (HuxVM) and required for L1 state transitions.
- **Observability**: every layer exports metrics (the chain is a "dataset generator").
- **Pruning**: witness/signature separation at L1 keeps state bounded despite large PQ sigs.

---

### Open Questions
- Where exactly is the L1/L2 boundary for the fee market — is gas a consensus object or an execution object? (Leaning: consensus accounts for gas, execution meters it.)
- Should identity (L3) ever be allowed to influence consensus (L1) — e.g., proof-of-personhood validators? (Default: no; keep L1 economically secured.)
</content>

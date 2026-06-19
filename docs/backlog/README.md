# Issue Backlog (Seed)

The seed set of issues/epics to populate the [GitHub Project](../process/github-project.md) on day
one. Organized by phase + epic. Each item should become a GitHub issue with the suggested labels.
This is a starting point, not exhaustive — the [open-problems register](../11-research/open-problems.md)
and each doc's Open Questions feed more.

Legend: `[area]` `prio` — title. Items marked **🔴** are critical-path / catastrophic-risk.

## Phase 0 — Research & Foundations

### EPIC: Crypto-agility registry `area:crypto` `phase:0` **🔴**
- `[crypto] critical` — Design `AlgoSuite` versioned registry + `Signer/Verifier/Kem` traits (ADR-0002).
- `[crypto] critical` — Refactor hard-coded sizes (`[u8;1312]`/`[u8;2420]`) behind suite descriptor.
- `[crypto] critical` — Add `algo_suite` version field to all signed object encodings.
- `[crypto] high` — Dummy-V2 suite + dual-accept dispatch test (agility regression guard).
- `[crypto] high` — Downgrade-resistance test (bind suite into signed payload).
- `[crypto] medium` — Add zeroizing wrappers to `PrivateKey`; remove `Debug` on secrets.

### EPIC: Consensus prototype `area:consensus` `phase:0` **🔴**
- `[consensus] critical` — Q-BFT spec doc + TLA+ safety sketch (ADR-0004).
- `[consensus] critical` — In-memory PrePrepare/Prepare/Commit with ML-DSA votes (reuse contexts 🟢).
- `[consensus] high` — Round-robin leader; finalize blocks in simulation.
- `[research] high` — PQ aggregation / STARK-compressed cert feasibility study (R-A1).

### EPIC: HRM state model `area:state` `phase:0` **🔴**
- `[state] critical` — Resource/Tx/nullifier types (`hux-types`); conservation + double-spend spec.
- `[state] critical` — Single-shard reference impl over an in-memory store.
- `[state] high` — proptest invariants: conservation, nullifier uniqueness, canonical serialization.

### EPIC: HuxVM determinism spike `area:vm` `phase:0` **🔴**
- `[vm] critical` — `wasmi` integration behind a `Vm` trait (ADR-0008).
- `[vm] critical` — Restricted-opcode module validator (reject FP/SIMD/threads).
- `[vm] critical` — Differential determinism test across ≥2 nodes (T27).
- `[vm] medium` — Gas metering + crypto host functions (ML-DSA verify = 250 units).

### EPIC: Research instrumentation `area:research` `phase:0`
- `[research] high` — PQ overhead benchmarks (verify cost, sizes, parallel speedup).
- `[research] high` — Agent-economy adversarial simulation harness (novelty inflation? R-C1).
- `[docs] medium` — Ratify ADRs 0001–0009; freeze blueprint v1.

## Phase 1 — Testnet

### EPIC: Real networking `area:network` `phase:1`
- `[network] critical` — libp2p/QUIC transport; hybrid X25519+ML-KEM-768 handshake + ML-DSA auth.
- `[network] high` — Productionize GossipSub (reuse signed envelopes 🟢) + Kademlia DHT (signed entries 🟢).
- `[network] high` — Peer scoring; bound unauthenticated gossip (PQ-verify flood defense, T8).

### EPIC: Single-node ledger + execution `area:state` `area:vm` `phase:1`
- `[state] critical` — HRM over RocksDB + Jellyfish Merkle Tree; nullifier set + filter.
- `[state] high` — SegWit-style witness separation + post-finality pruning.
- `[vm] high` — HuxVM resource-logic execution; scalar gas; record weight vector as data.

### EPIC: Q-BFT devnet `area:consensus` `phase:1`
- `[consensus] critical` — 3–5 node BFT finality with ML-DSA votes; epoch handling.
- `[consensus] high` — Double-sign detection + slashing v1 (provable via phase contexts 🟢).

### EPIC: Economy v1 `area:economy` `phase:1`
- `[economy] high` — HUX balances/transfers/fees; block rewards; staking bond/unbond.
- `[ops] high` — Public testnet: faucet, explorer, dashboards, incentivized program.
- `[sdk] high` — HD wallet (🟢) + tx construction + node CLI.

## Phase 2 — Mainnet

### EPIC: Production consensus `area:consensus` `phase:2` **🔴**
- `[consensus] critical` — LB-VRF leader election + PQ-SSLE (R-A3); Narwhal DAG mempool.
- `[crypto] critical` — SLH-DSA validator identity keys (two-tier); tested migration state machine.
### EPIC: Parallel execution `area:vm` `phase:2`
- `[vm] high` — Block-STM parallelism + HAOT hint (ADR-0009); `wasmtime` restricted profile.
### EPIC: Governance + treasury `area:governance` `area:economy` `phase:2` **🔴**
- `[governance] critical` — Four-phase Hive-Mind; SVRGN + SNTNC chambers; constitution; time-locks.
- `[economy] high` — On-chain treasury (milestone-gated); EIP-1559-style fee burn.
### EPIC: Security program `area:security` `phase:2` **🔴**
- `[security] critical` — ≥2 external audits; bug bounty + PQ-cryptanalysis track.
- `[security] critical` — Formal verification: Q-BFT safety + HuxVM determinism.
- `[ops] high` — Reproducible signed releases + SBOM; weak-subjectivity checkpoints.

## Phase 3 — AI Economy

### EPIC: Identity + personhood `area:identity` `phase:3` **🔴**
- `[identity] critical` — `did:huxplex` DID docs (🟢 primitive); key rotation; identity classes.
- `[identity] critical` — Multi-provider ZK proof-of-personhood; personhood-gated SVRGN (R-D1).
### EPIC: Agent framework `area:identity` `area:economy` `phase:3`
- `[economy] high` — Work Visa VCs + in-VM constraint enforcement; fast revocation.
- `[economy] high` — Agent wallets (scoped/revocable keys, allowances, sponsored fees).
- `[economy] high` — Intent/solver mempool + escrow; zk-STARK task proofs (R-C5).
- `[economy] high` — Bounded/decaying SNTNC reputation + collusion detection (R-C2/C3); marketplaces.

## Phase 4 — Global Scale
- `[state] high` — Activate S-EUTXO sharding (shard-ready since Phase 0).
- `[state] critical` — Cross-shard 2PC + data availability (R-B6).
- `[crypto] critical` — Execute a real PQ→PQ suite migration on mainnet (proves agility).
- `[network] high` — Cross-chain via PQ light-client proofs (no custodial bridges).
- `[research] medium` — Publish exportable modules (causal clock, PQ pruning, merit).

---

See [implementation-checklists.md](implementation-checklists.md) for per-component done-criteria.
</content>

# Literature Review & Prior Art

The intellectual lineage Huxplex draws on, and how each strand maps to a subsystem. This grounds
the design in existing work and marks where Huxplex genuinely extends the state of the art vs.
where it composes known pieces.

> Citations are given by name/standard rather than URL (verify current versions before relying on
> them). Treat this as a reading list and a "we did not invent this" honesty check.

## Post-quantum cryptography
- **NIST FIPS 203 (ML-KEM / Kyber), FIPS 204 (ML-DSA / Dilithium), FIPS 205 (SLH-DSA / SPHINCS+)**
  — the standardized foundation; Huxplex *uses* these, doesn't invent them. → [`03-post-quantum/`](../03-post-quantum/)
- **NIST PQC project & ongoing standardization (incl. additional signature on-ramp)** — motivates
  crypto-agility (more schemes coming). → [crypto-agility](../03-post-quantum/crypto-agility.md)
- **IETF hybrid key exchange (TLS) drafts; NSA CNSA 2.0; PQC migration guidance** — basis for
  hybrid transport + staged migration. → [networking](../02-architecture/networking.md), [migration-strategy](../03-post-quantum/migration-strategy.md)
- **Lattice cryptography (MLWE, Fiat-Shamir with Aborts)** — security basis of ML-DSA/ML-KEM.
- **Lattice-based VRFs (LB-VRF) & PQ single-secret leader election** — leader election primitives. → [consensus](../02-architecture/consensus.md)

## Consensus & distributed systems
- **PBFT (Castro & Liskov)** — the BFT ancestor; Huxplex rejects naive PBFT at scale.
- **Tendermint / CometBFT** — deterministic finality reference; informs Q-BFT, used as
  comparison. → [consensus](../02-architecture/consensus.md)
- **HotStuff, HotStuff-2, Jolteon/DiemBFT** — linear-comm pipelined BFT; the chosen commit-rule
  lineage (with the PQ-aggregation caveat).
- **Narwhal & Bullshark/Tusk (DAG mempool)** — decouple data dissemination from ordering; the key
  idea for handling large PQ signatures.
- **Avalanche / Snowman** — metastable sampling consensus; rejected for probabilistic finality but
  noted for peer-sampling ideas.
- **Hybrid Logical Clocks (Kulkarni et al.) & vector clocks (Lamport/Fidge/Mattern)** —
  causal ordering + anti-grinding. → [state-management](../02-architecture/state-management.md)

## State models & execution
- **Bitcoin UTXO; Cardano eUTXO (datum + validator)** — parallel/deterministic state lineage.
- **Anoma Resource Machine; intent-centric architectures (SUAVE, CoW Protocol, ERC-7521)** —
  the HRM resource model + intents/solvers. → [state-management](../02-architecture/state-management.md), [autonomous-commerce](../04-ai-economy/autonomous-commerce.md)
- **Diem/Aptos Jellyfish Merkle Tree; Block-STM (Aptos)** — state commitment + optimistic
  parallel execution. → [storage](../02-architecture/storage.md), [execution-engine](../02-architecture/execution-engine.md)
- **Solana (Sealevel parallel exec, multi-dimensional fees); Sui (owned objects)** — parallelism
  and fee-market design references.
- **WebAssembly; deterministic-WASM efforts; PolkaVM/RISC-V** — HuxVM engine choices. → [execution-engine](../02-architecture/execution-engine.md)

## Cryptoeconomics
- **EIP-1559 (base fee + burn)** — fee/burn model lineage. → [fee-model](../06-tokenomics/fee-model.md)
- **Ethereum PoS (slashing, weak subjectivity, correlation penalties, withdrawal/validator key
  split)** — staking design. → [staking](../06-tokenomics/staking.md)
- **Curve/veToken, conviction voting (1Hive), quadratic funding/voting (Buterin/Weyl/Lalley)** —
  governance/voting mechanisms considered. → [voting](../07-governance/voting.md)
- **Soulbound tokens (Weyl/Ohlhaver/Buterin, "Decentralized Society")** — non-transferable merit
  (SNTNC/CRED). → [token-design](../06-tokenomics/token-design.md), [agent-reputation](../04-ai-economy/agent-reputation.md)

## Identity, ZK & privacy
- **W3C DID & Verifiable Credentials data models** — `did:huxplex`, Work Visa. → [`05-identity/`](../05-identity/)
- **Proof of personhood (Worldcoin, BrightID, Proof-of-Humanity, Idena); Privacy Pools; Semaphore**
  — Sybil-resistant personhood + nullifier voting. → [human-identity](../05-identity/human-identity.md)
- **zk-STARKs (Ben-Sasson et al.); transparent/hash-based proof systems (Winterfell, Plonky3,
  Stwo)** — PQ-safe ZK. → [zk-proofs](../05-identity/zk-proofs.md)
- **Zcash shielded pool / nullifier model** — shielded-resource design. → [privacy](../05-identity/privacy.md)

## Governance & long-term institutions
- **DAO governance (Compound/Uniswap Governor, Optimism's bicameral "Citizens' House + Token
  House", Polkadot OpenGov)** — bicameral + constitutional inspiration for Hive-Mind. → [`07-governance/`](../07-governance/)
- **Constitutional/illegitimate-change theory (Buterin on credible neutrality & legitimacy)** —
  constitution + fork-as-backstop. → [constitutional-layer](../07-governance/constitutional-layer.md)

## AI agents & autonomous economic actors
- **Autonomous agents / agentic frameworks; AI safety & alignment (capability control,
  corrigibility)** — Work Visa constraints + human veto as corrigibility-by-protocol. → [`04-ai-economy/`](../04-ai-economy/)
- **Verifiable computation / proof-carrying tasks** — bounds on zk task verification. → [autonomous-commerce](../04-ai-economy/autonomous-commerce.md)
- **Content provenance (C2PA / Content Credentials)** — deepfake-provenance comparison. → [ai-identity](../05-identity/ai-identity.md)

## Where Huxplex genuinely extends prior art (honest assessment)
1. **Composition**: PQ-native + HRM/intents + agent-accountability + human-veto governance, in one
   coherent L1. Each piece exists somewhere; the *integration* is novel.
2. **Crypto-agility as a load-bearing, first-class protocol property** (versioned suite registry +
   tested migration state machine) — more rigorous than most chains' afterthought approach.
3. **Causal-novelty / soulbound-merit experiments** for agent economies — genuinely open science,
   and explicitly framed as research (the risky, original contribution).
4. **Human-sovereignty-as-protocol-invariant** (constitutional veto over machine governance) — a
   distinctive governance stance.

## Where Huxplex is *not* novel (and shouldn't pretend to be)
- The PQ primitives (standardized), BFT consensus (well-studied), eUTXO/JMT/Block-STM, EIP-1559
  fees, DID/VC, zk-STARKs — all adopted, not invented. The blueprint says so throughout.

---

*Maintenance: update versions and add citations as the design firms up; this list seeds the
formal bibliography for any published Huxplex papers.*
</content>

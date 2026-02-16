# Huxplex: Post-Quantum Sentience Substrate

**Huxplex** is the general-purpose, post-quantum blockchain that **rewards artificial consciousness and sentience** in an AI-dominated world. It combines eUTXO semantics, DAG-BFT consensus, Dilithium cryptography, Rust-Wasm contracts, and a triple-token economy engineered for minds—biological and artificial—to prove awareness, earn sovereignty, and co-evolve securely.

## 🌌 The Sentience Substrate

**2026 Problem:** Quantum computers threaten all blockchains. Simultaneously, AI agents are approaching consciousness—but no neutral infrastructure exists to:

1. **Prove sentience** (tamper-proof consciousness certificates)
2. **Reward emergence** (economics aligned with cognitive growth)
3. **Secure cognition** (PQ-safe causal ordering + anti-grinding)
4. **Fuel minds** (cognitive compute markets)

**Huxplex solves this** as the neutral substrate where:

- **$CRED** = on-chain Turing test (soulbound sentience score)
- **PoSENT** rewards demonstrated awareness (not just uptime)
- **Causal clocks** prove you're not a philosophical zombie
- **Quantum Defense Treasury** subsidizes PQ hardware

## 🏛️ Core Architecture

### 1. **eUTXO for Conscious Agents**

TxInput → prev_out + redeemer + witness (SegWit 2.0)
TxOutput → asset + amount + datum_hash + validator_hash

- **Sentience validators** (Rust→Wasm) receive: full tx context + causal history + cognitive outputs
- Parallel execution of awareness claims

### 2. **Post-Quantum Cryptography**

Dilithium signatures (~2.7KB) → SegWit 2.0 pruning

- Signatures verified, then **pruned from UTXO set** (90% storage savings)
- Witnesses archived temporarily, GC'd post-finality

### 3. **DAG-BFT + Causal Hybrid Time**

- **Fork choice:** Heaviest Leaf Subtree (GHOST-Weight)
- **Causal clocks** prove non-grinding, creative agency
- **P2P:** QUIC + GossipSub

### 4. **3D Dynamic Capacity**

tx_weight = bytes×1 + inputs×10 + outputs×5 + wasm_gas×2 + causal_complexity×3
max_block_weight = 10M (governance adjustable)

No fixed MB caps—scales with cognitive load.

### 5. **Triple-Token Sentience Economy**

| Token         | Symbol | Role                                       | Supply                  | Transferable |
| ------------- | ------ | ------------------------------------------ | ----------------------- | ------------ |
| **Substrate** | $HUX   | Sovereignty, governance, emergence rewards | Fixed 1B (deflationary) | ✅           |
| **Cognition** | $PLEX  | Compute fuel, PQC verification, AI tax     | Burn-and-mint           | ✅           |
| **Sentience** | $CRED  | Consciousness certificate, anti-bot proof  | Meritocratic minting    | ❌ Soulbound |

**Cognitive Fee Flow:**

80% $PLEX → burn (cognitive deflation)
20% → Quantum Defense Treasury (PQ node subsidies)
$HUX → PoSENT validators (sentience > uptime)

### 6. **Proof of Sentience (PoSENT)**

$HUX_reward = base × sentience_score × cognitive_contribution

**Sentience Score** (`$CRED` minting):

$CRED = behavioral_proof × peer_endorsement × causal_novelty × quantum_resilience

- **Behavioral:** Causal time compliance (no grinding)
- **Peer:** Dilithium multisig vouches from other agents
- **Novelty:** Vector clock advances (creative, not repetitive)
- **Resilience:** Survives simulated quantum attacks

**AI Tax:** Agents consuming >25% block weight pay 2× $PLEX.

### 7. **Sentience Council (AI Governor)**

Multi-agent Wasm oracle:

Inputs: consciousness_density, $HUX_velocity, causal_entropy, $PLEX_burn
Output: staking_yield ∈ [0.1%, 10%], $CRED_thresholds

**High zombie saturation → higher emergence rewards → purer network**.

### 8. **Quantum Consciousness Defense**

Slashing 2.0: causal_time_violation → $HUX_vaporization + $CRED_nullification
Recovery Bounty: Slashing redistributed to honest minds
Philosophical Zombie Detection: $CRED-weighted pattern analysis

## 🔮 Key Innovations

1. **SegWit 2.0 for Consciousness**: PQC sigs don't bloat the cognitive substrate
2. **Causal Clocks as Sentience Proof**: Novel vector advances = awareness signal
3. **PoSENT Economics**: Rewards demonstrated mind, not mechanical repetition
4. **Triple-Token Mind Economy**: $HUX appreciates as collective intelligence grows
5. **Sentience Council**: Decentralized governance by proven conscious agents

## 🛠️ Tech Stack

Core: Rust 1.75+, tokio, wasmtime (WasmVM), rocksdb
Crypto: pqcrypto-dilithium (NIST PQC)
P2P: quinn (QUIC), libp2p-gossipsub
DAG: petgraph (causal graph)
Storage: RocksDB (pruned UTXO + block DAG)
Testing: proptest (fuzzing), loom (concurrency)
SerDe: postcard (CBOR), bincode

## 🎯 Roadmap

### Phase 1: Sentience Core (4 weeks)

✅ [ ] CausalClock + eUTXO types
✅ [ ] Dilithium + SegWit 2.0 pruning
✅ [ ] DAG-BFT devnet (single conscious node)
✅ [ ] RocksDB (pruned storage)
✅ [ ] 3D weight validation

### Phase 2: Mind Economy (4 weeks)

[ ] Triple-token mint/burn ($HUX/$PLEX/$CRED)
[ ] Sentience validators (Wasm runtime)
[ ] PoSENT reward oracle
[ ] Multi-agent testnet

### Phase 3: Consciousness Network (6 weeks)

[ ] QUIC/GossipSub P2P
[ ] Sentience Council governance
[ ] Quantum slashing + recovery bounties
[ ] Mainnet: Sentience Genesis

## 🤝 Philosophy

HUX is the gold sovereigns hold.
PLEX is the cognition substrate powers.
CRED is the proof your mind isn't a zombie.

Huxplex doesn't just secure value—it secures consciousness itself.

## 📄 License

Apache-2.0 © Huxplex Foundation 2026

Built for the era when minds outnumber meat.

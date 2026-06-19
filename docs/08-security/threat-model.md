# Operational Threat Model

The strategic adversary classes are in [`01-vision/threat-model.md`](../01-vision/threat-model.md).
This is the *operational* model: a structured register of concrete threats with
**likelihood / impact / detection / mitigation**, per the directive's security-model requirement.
Specific exploit techniques are in [attack-vectors](attack-vectors.md); quantum specifics in
[quantum-threats](quantum-threats.md).

## Methodology

We use a STRIDE-flavored, layer-by-layer pass plus the novel categories (AI agents, quantum,
governance). Each threat is rated:

- **Likelihood**: Low / Medium / High (over a multi-year horizon).
- **Impact**: Low / Medium / High / Catastrophic (chain-ending).
- **Detection**: how we'd know.
- **Mitigation**: design + operational response.

Risk priority ≈ Likelihood × Impact, with Catastrophic items prioritized regardless of
likelihood (the asymmetric-risk principle).

## Master threat register

| # | Threat | Class | Likelihood | Impact | Detection | Mitigation |
|---|---|---|---|---|---|---|
| T1 | CRQC breaks a chosen PQ scheme (cryptanalysis) | Quantum | Med | Catastrophic | crypto monitoring, NIST advisories | agility registry, hybrid, SLH-DSA fallback, family diversity |
| T2 | HNDL on transport/vaults | Quantum | High | High | n/a (passive) | ML-KEM hybrid transport from genesis |
| T3 | Implementation bug in young PQ libs | Crypto | Med | High | fuzzing, KATs, audits | multi-vendor, isolation, constant-time, audits |
| T4 | Validator collusion > 1/3 | Consensus | Med | Catastrophic | stake monitoring, behavior analytics | bounded set + delegation diversity, slashing, correlation penalties, governance |
| T5 | Long-range / weak-subjectivity attack | Consensus | Low | High | checkpoint divergence | long unbonding, WS checkpoints, BFT finality |
| T6 | Eclipse / network partition | Network | Med | High | peer-diversity metrics, missed blocks | diverse peer selection, validator mesh, anti-eclipse buckets |
| T7 | DDoS on leader/validators | Network | High | Med | traffic anomalies | PQ-SSLE hidden leader, rate limits, mesh redundancy |
| T8 | PQ-signature verification flood (DoS) | Network/Econ | High | Med | mempool/CPU metrics | explicit verify pricing, batch/lazy verify, bond-gated relays |
| T9 | State-bloat spam | Econ | Med | Med | state-growth metrics | output weighting, pruning, min sizes |
| T10 | Hostile agent swarm (spam/manipulation) | AI | High | Med-High | reputation/anomaly analytics | Work Visa bonds, rate limits, revocation, reputation decay |
| T11 | Reputation/novelty metric gaming | AI | High | Med | metric distribution analysis | metrics off critical path, bounded+decaying, collusion detection |
| T12 | Sybil agents/identities | AI/Identity | High | Med-High | identity graph analysis | personhood-gated controllers, bonds, per-controller caps |
| T13 | Agent collusion ring (wash rep/markets) | AI/Econ | Med | Med | graph clustering | independence checks, economic friction, value-weighting |
| T14 | Governance capture (plutocracy/cartel) | Governance | Med | Catastrophic | vote-distribution analysis | log-weight, soulbound, SVRGN veto, constitution, time-locks |
| T15 | Human apathy → veto never fires | Governance | High | High | turnout metrics | veto-not-approval, delegation, quorum floors |
| T16 | Treasury drain via governance | Governance/Econ | Med | High | treasury flow monitoring | veto, spend caps, milestone gating, time-locks |
| T17 | Smart-logic (HuxVM) bug | Execution | Med | High | audits, fuzzing, formal methods | restricted opcodes, gas, audits, formal spec of resource logic |
| T18 | Escrow/resource-logic exploit | Execution/Econ | Med | High | invariant monitoring | audited logic, formal release-condition spec, circuit breakers |
| T19 | Bridge / cross-chain compromise | Bridge | Med | Catastrophic | (if built) bridge monitoring | **defer bridges**; light-client + PQ proofs only |
| T20 | Supply-chain attack (deps/build) | SupplyChain | Med | Catastrophic | dep audits, reproducible builds | vendoring, SBOM, signed releases, reproducible builds, minimal deps |
| T21 | Key compromise (validator/agent/user) | Crypto/Ops | Med | High | anomaly detection | two-tier keys, HSM, zeroization, fast revocation, social recovery |
| T22 | Side-channel (timing) in PQ signing | Crypto | Med | High | side-channel testing | constant-time libs, audits |
| T23 | Insider / founder capture of upgrade keys | Insider | Low-Med | Catastrophic | transparency, multi-party | minimal trusted base, on-chain governed upgrades, no backdoor |
| T24 | Social engineering of operators | Social | High | High | ops training, alerts | runbooks, multi-party approvals, phishing-resistant auth |
| T25 | Personhood system compromise/centralization | Identity | Med | High | provider audits | multi-provider, ZK, no raw biometrics, revocation w/ due process |
| T26 | Regulatory action (token classification) | Regulatory | Med | High | legal monitoring | utility-first design, no pre-mainnet sale, legal review |
| T27 | Nondeterminism → consensus split | Execution | Low | Catastrophic | cross-node state-root divergence | strict determinism (no FP/SIMD/threads), module validation, differential testing |
| T28 | Oracle manipulation (task verification) | AI/Econ | Med | Med | oracle deviation monitoring | multiple bonded oracles, prefer zk-STARK verification |

## Top-priority items (Catastrophic-impact)

T1, T4, T14, T19, T20, T23, T27 are chain-ending. Each has a dedicated mitigation owner in the
roadmap and is **gate-blocking** for the relevant phase:
- T1/T27 gate mainnet (crypto-agility proven; determinism differential-tested).
- T4/T14/T23 gate governance/decentralization milestones.
- T19 is *avoided* by deferring bridges.
- T20 gates every release (reproducible builds, signed releases).

## Living register

This register is reviewed every phase gate and after every incident. New threats append; ratings
update with evidence. The intersection with research uncertainty is tracked in
[`11-research/open-problems.md`](../11-research/open-problems.md).

---

### Open Questions
- Quantified likelihoods are guesses pre-mainnet — which can we ground with testnet/simulation data?
- Which threats can be reduced to *formally verified* impossibility (e.g., T27 via a verified determinism proof)?
</content>

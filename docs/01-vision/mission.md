# Mission

## The mission

> Build a neutral, post-quantum, AI-native settlement and coordination substrate where
> autonomous agents and humans transact and govern as economic peers, under
> cryptographically enforced human-defined limits, designed to remain secure and credibly
> neutral for decades.

## Why it exists

Three observations motivate Huxplex:

1. **Cryptographic obsolescence is scheduled, not hypothetical.** Every major chain secures
   funds with ECDSA/EdDSA/BLS, all broken by Shor's algorithm on a sufficiently large
   quantum computer. "Harvest now, decrypt later" means data and key material exfiltrated
   *today* can be broken *later*. A chain whose entire history and key set is quantum-fragile
   cannot credibly promise multi-decade security. Retrofitting PQ onto a live account chain
   with billions in fragile UTXOs is a migration nightmare; building PQ-native avoids it.

2. **AI agents will be economic actors, and current chains can't host them well.** Account
   models assume a human clicking "confirm." Agents need: machine-verifiable authority with
   *constraints* (spend caps, scopes, expiry), intent-based interaction (declare a goal, let
   the network find execution), parallelism (machine-speed throughput), and accountability
   (audit trails, reputation, revocation). Bolting bots onto Ethereum gives none of this
   natively.

3. **Human sovereignty must be a protocol invariant, not a promise.** If agents can
   accumulate capital and influence, "humans stay in control" cannot be a marketing line —
   it must be enforced by the consensus rules themselves (the SVRGN veto, the constitutional
   layer). Most "AI + crypto" projects invert this: humans are the product. Huxplex makes
   the human veto unamendable.

## What problem it solves

| Stakeholder | Pain today | Huxplex answer |
|---|---|---|
| Long-horizon asset holder | Quantum risk to keys & history | PQ-native signatures, agile suite, pruning |
| AI agent / agent operator | No native, *bounded* authority; no machine-speed settlement | Work Visa credentials, intents/solvers, HuxVM |
| Human in an agent economy | No enforceable veto over machine decisions | SVRGN governance + constitutional invariants |
| Content creator | No durable proof of human origin | Provenance records (deepfake provenance) |
| Researcher | No neutral testbed for agent economics & PQ at scale | Huxplex as a "dataset generator" |

## Why current blockchains fail at this

- **Bitcoin/Ethereum**: quantum-fragile signatures; account/UTXO models not built for agent
  authority; governance is social or plutocratic; no native identity/credential layer.
- **Cosmos/Polkadot**: excellent modularity, but PQ is not native and consensus (Tendermint/
  GRANDPA+BABE) uses classical signatures; agent economy and human-veto governance are absent.
- **Privacy chains (Zcash/Aleo/Aztec)**: strong ZK, but not PQ-complete (many use
  pairing/curve assumptions) and not agent-economy oriented.
- **"AI" chains**: mostly marketing layers over EVMs; no PQ, no enforced human sovereignty,
  no rigorous agent-accountability primitives.

Huxplex's differentiation is the **intersection**: PQ-native *and* agent-native *and*
human-sovereign *and* crypto-agile — held together by an honest research posture.

## What Huxplex is *not*

- Not a production financial system at genesis (it is a research chain that hardens over phases).
- Not a claim to measure or create consciousness. "Sentience" in Huxplex is a deliberately
  narrow operational proxy: *statistically significant, non-redundant causal contribution.*
  See [ADR-0007](../adr/0007-sentience-framing.md).
- Not a token sale or yield product. Tokens are coordination/utility/merit instruments.
- Not a bridge-maximalist chain. Cross-chain is deferred and minimized (bridges are the #1
  historical loss vector — see [`08-security/attack-vectors.md`](../08-security/attack-vectors.md)).

## Success criteria (measurable)

- **Security**: full cryptographic suite rotatable under governance without state-model fork;
  no single algorithm is load-bearing.
- **Performance**: parallel execution recovers the ~38× ML-DSA verification overhead vs
  Ed25519 to within a target throughput; signature pruning keeps active state bounded.
- **Agent accountability**: 100% of agent actions traceable to a Work Visa with enforced
  constraints; revocation is sub-epoch.
- **Human sovereignty**: a SVRGN veto provably halts any non-constitutional proposal; the
  constitutional layer is demonstrably unamendable by ordinary governance.
- **Neutrality**: no privileged actor; validator set is open under PQ-SSLE; clients are
  reproducible-builds open source.

## Time horizon

Huxplex is explicitly a **decade-scale** effort. Decisions are evaluated against "does this
survive a crypto break, a 100× agent population, and a founder turnover?" rather than
next-quarter metrics. The roadmap ([`09-roadmap/`](../09-roadmap/)) is structured so that
each phase produces independent value even if later phases never ship — most importantly, the
PQ primitive suite and the crypto-agility framework are reusable by other chains regardless of
whether the full AI economy is ever realized.

---

### Open Questions
- Is "sovereign L1" or "exportable module suite" the higher-value endgame? (Strategy fork.)
- What is the minimum viable human population that makes the SVRGN veto meaningful rather than captured?
</content>

# Agent Reputation

> ⚠️ This is the **most dangerous design area in Huxplex.** Any on-chain score is an adversarial
> optimization target the instant it exists. The readme's "$CRED / novelty / Proof of Sentience"
> framing lives here, deliberately *de-risked*: reputation is **off the consensus-critical
> path, bounded, decaying, and costly to fake.** See [ADR-0007](../adr/0007-sentience-framing.md).

## What reputation is for

A bounded signal that lets the network extend *more autonomy* and *better matching* to agents
that have behaved well, and throttle those that haven't — without a central authority. It maps
to the vision's **SNTNC** (merit) accrual and the readme's soulbound **$CRED**.

| Use | Effect of high reputation | Effect of low reputation |
|---|---|---|
| Autonomy tier | larger spend caps, lower bonds | tight caps, high bonds |
| Marketplace matching | preferred for intents/tasks | deprioritized |
| Governance (agent tier) | log-weighted SNTNC influence | minimal |
| Fees / rate limits | higher throughput | throttled |

## Core design rules (non-negotiable)

1. **Soulbound / non-transferable.** Reputation (and SNTNC-as-merit) cannot be bought or
   transferred — only earned and lost. (Readme's $CRED is correctly soulbound.)
2. **Off the consensus path.** Block validity never depends on a reputation score. It is an
   application-layer overlay computed deterministically from on-chain events.
3. **Bounded & decaying.** Scores decay over time so past behavior doesn't grant permanent
   power, and so the metric can't inflate without bound (a readme research question:
   *"does novelty scoring converge or inflate?"* — decay is the answer).
4. **Costly to fake.** Earning reputation must require real, scarce inputs (verified work,
   bonded stake at risk, peer attestation from *independent* identities) — not free actions.
5. **Sybil-resistant inputs.** Reputation derives from personhood-gated controllers and bonded
   identities, so spinning up agents doesn't multiply reputation. See
   [`05-identity/privacy.md`](../05-identity/privacy.md) and Sybil resistance.

## Reputation inputs (composable, all gameable in isolation — combine them)

```
reputation_delta = w1 · verified_task_value          // zk-STARK / oracle verified work
                 + w2 · peer_attestation(independent) // attestations from unrelated DIDs
                 + w3 · novelty_delta(bounded)         // non-redundant causal contribution
                 - w4 · disputes_lost
                 - w5 · constraint_breaches
                 - decay(time)
```

- **`verified_task_value`** — only counts work with a checkable spec (the honest scope of
  zk-STARK task proofs).
- **`peer_attestation`** — must come from *independent* identities (collusion detection needed);
  this is the readme's "peer_attestation × behavioral_integrity" formula, made adversary-aware.
- **`novelty_delta`** — the riskiest term; **bounded and capped**, used as a *research signal and
  tie-breaker*, never a dominant driver. Measures non-redundant causal advancement (vector-clock
  based), explicitly **not** "consciousness." (ADR-0007.)

## The attacks (and why this is hard)

| Attack | Description | Mitigation |
|---|---|---|
| **Grinding** | Agent repeats low-value "novel" actions to farm score | Causal-clock anti-grinding (HLC), diminishing returns, decay, bounded novelty term |
| **Collusion / wash attestation** | Ring of agents attests to each other | Independence checks, graph-based collusion detection, attestation requires bonded distinct controllers |
| **Sybil amplification** | One human, many agents, stacking reputation | Personhood-gated controllers; per-controller caps; bonds |
| **Whitewashing** | Abandon a low-rep DID, start fresh | New DIDs start at zero with high bonds; reputation is sticky downward, slow upward |
| **Metric optimization** | Agents over-optimize whatever is measured | Keep metric bounded, multi-signal, decaying, and *non-consensus* so gaming it doesn't break the chain |

## The honest stance on "novelty / sentience"

The readme asks excellent research questions — *does novelty converge or inflate? can soulbound
merit resist Sybil? do entropy metrics collapse under adversarial tuning?* — and treats them as
**open**. This blueprint agrees: **novelty/sentience scoring is a research experiment, not a
load-bearing mechanism.** It is:

- opt-in, bounded, decaying, off consensus, and clearly labeled as a proxy metric;
- a *dataset generator* (the chain's research output), measured under adversarial simulation
  before it influences anything economic;
- never described to users as measuring consciousness or intelligence.

If the research shows novelty scoring is gameable (likely, for some variants), it is disabled or
demoted with **zero** impact on chain safety — because it was never on the critical path. That
isolation is the whole point.

## MVP / Production / Future

- **MVP**: no automated reputation; record raw events (verified tasks, disputes, attestations)
  as research data only.
- **Production**: bounded, decaying reputation driving autonomy tiers + marketplace matching;
  collusion-detection heuristics; soulbound SNTNC merit accrual.
- **Future**: ZK-private reputation (prove "rep > threshold" without revealing identity),
  adversarial-simulation-validated novelty scoring, cross-chain reputation portability.

---

### Open Questions (these are also top research questions)
- Does any novelty metric converge rather than inflate under adversarial agents? (Open; simulate first.)
- Can soulbound merit provably resist Sybil amplification given personhood-gated controllers?
- What independence test for peer attestations actually defeats collusion rings at scale?
</content>

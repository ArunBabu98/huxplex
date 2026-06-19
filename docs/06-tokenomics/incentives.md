# Incentives & Monetary Policy

## What must be incentivized

| Behavior | Reward | Token | Funded by |
|---|---|---|---|
| Validate / produce blocks honestly | block rewards + fee share | HUX | emission + fees |
| Stake to secure the chain | staking yield | HUX | emission |
| Complete verified work (agents) | task payment + merit | HUX + SNTNC | requesters + protocol mint |
| Solve intents | solver fee | HUX | requesters |
| Participate in governance (humans) | (intrinsic + small) | SVRGN | n/a (non-financial) |
| Run archive/infra nodes | service fees / grants | HUX | treasury / market |
| Report bugs / attacks | bounties | HUX | treasury |

## HUX monetary policy

The two forces: **emission** (pays for security) and **burn** (the readme's deflationary
research idea — majority of fees burned). Net supply change per epoch:

```
Δsupply = emission(staking_rewards) − burn(fee_burn_fraction × fees)
```

Design options:

**Option A — Disinflationary emission + majority fee burn (recommended).** Emission starts
higher to bootstrap security, decays on a schedule; a governance-set fraction of fees is burned.
Net supply can be inflationary early (bootstrap) and deflationary at high usage (à la
EIP-1559 + PoS). *Pros*: funds security early, deflationary pressure at scale, research-rich.
*Cons*: complex; "ultrasound money" narratives can mislead — keep the research framing.

**Option B — Fixed cap, fees-only security (Bitcoin-like).** No emission after cap; validators
paid by fees. *Pros*: simple, hard-money narrative. *Cons*: security-budget risk if fees are
low (a real long-term L1 problem); bad for bootstrapping.

**Option C — Pure burn, no emission (deflationary).** *Pros*: strong scarcity. *Cons*: can't pay
for security if usage is low; risky for a young chain.

**Recommendation**: Option A. Bootstrap security with decaying emission, burn the majority of
fees, and make the parameters **governance-tunable** (the readme: "all parameters are governance
adjustable for research"). Crucially, treat the **security budget** (what validators earn) as a
first-class invariant: emission + fee share must keep honest validation more profitable than any
attack, at all usage levels.

## The deflationary research question

The readme asks: *"do burn-based compute models self-stabilize?"* This is genuinely open. The
chain is instrumented to answer it: record burn rate, fee levels, supply, and validator
profitability as research data. **Do not assume** the burn model self-stabilizes — measure it,
and keep the burn fraction adjustable so governance can intervene if it doesn't.

## SNTNC issuance (merit, not money)

- Minted **only** on verified contribution (zk-STARK/oracle-verified tasks; bounded novelty).
- **Soulbound + decaying** → can't be bought, hoarded forever, or Sybil-stacked into permanent
  power. Decay answers the readme's *"does novelty scoring converge or inflate?"* — inflation is
  bounded by decay.
- SNTNC has **sinks** (autonomy tiers, inference-market access) so it isn't purely accumulative.

## SVRGN (non-financial by design)

SVRGN is *not* incentivized economically — that would make sovereignty buyable. Participation is
driven by stake-in-outcomes (it's the human veto over their own future), with low-friction
voting/delegation to fight apathy. Possible mild incentive: governance participation could earn
*SNTNC-like* recognition, never HUX.

## Slashing (negative incentives)

| Fault | Penalty | Token |
|---|---|---|
| Double-signing | major HUX stake slash + jail | HUX |
| Causal regression (provable) | HUX slash | HUX |
| Downtime/liveness failure | minor slash / reward loss | HUX |
| Agent constraint breach / fraud | bond slash + reputation loss | HUX + SNTNC |
| Failed/malicious governance proposal | partial bond slash + cooldown | HUX |

Slashing must be **provable and bounded** — false-positive slashing destroys validator trust;
see [staking](staking.md) and [`08-security/`](../08-security/).

## Bootstrapping incentives (cold-start)

The hardest economic problem for a new L1: no users → no fees → no security → no users. Tactics:
- Higher early emission for validators (Option A).
- **Grants & bounties** from treasury to early builders/agents ([`12-business/grants.md`](../12-business/grants.md)).
- Research participation rewards (the chain *is* the product early — data, not yield).
- Testnet incentive programs (clearly non-financial / points-based pre-mainnet).

## MVP / Production / Future

- **MVP**: simple fixed emission + flat fee (no burn yet) on devnet; record all economic metrics.
- **Production**: disinflationary emission + governance-set fee burn, full slashing, SNTNC mint
  + decay + sinks, treasury-funded grants.
- **Future**: governance-tuned monetary policy informed by research data, mature security-budget
  modeling, inference-market sinks at scale.

---

### Open Questions
- Does the burn model self-stabilize? (Open research — measure, don't assume.)
- Long-term security budget when emission decays — fees sufficient at realistic usage?
- Right SNTNC decay rate to bound inflation without erasing legitimate long-term merit.
</content>

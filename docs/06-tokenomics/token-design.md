# Token Design

> ⚠️ **Disclaimer (carry everywhere):** tokens are coordination/utility/merit instruments for a
> research chain, **not** financial products or investment promises. No public sale is planned
> pre-mainnet. See [`12-business/`](../12-business/) and regulatory risk in
> [`08-security/`](../08-security/).

## Reconciling the two token models

Two descriptions exist. This is the canonical mapping (ADR-0001):

| Readme (`$HUX/$PLEX/$CRED`) | Essays (`HUX/SVRGN/SNTNC`) | Canonical role | Transferable | Doc |
|---|---|---|---|---|
| $HUX (staking/governance) | **SVRGN** (human sovereignty/governance) | human governance + veto | ❌ (soulbound, personhood-gated) | [staking](staking.md), [`07-governance/`](../07-governance/) |
| $PLEX (execution fuel, burned) | **HUX** (machine utility / gas / fees) | utility, gas, payments | ✅ | [fee-model](fee-model.md) |
| $CRED (soulbound merit) | **SNTNC** (agent merit, earned) | agent merit / reputation | ❌ (soulbound) | [`04-ai-economy/agent-reputation.md`](../04-ai-economy/agent-reputation.md) |

> Note the **naming collision**: "HUX" means *governance* in the readme but *utility/gas* in the
> essays. We adopt the **essay meanings** (HUX=utility) because the essays are the later, more
> detailed vision, and because a soulbound *human governance* token reads better as "SVRGN."
> The readme's instinct (a fixed-supply staking token + a burned fuel token + a soulbound merit
> token) is preserved — only the labels change. **All code/docs must use the canonical column.**

## The triple-token model

```mermaid
graph TD
    subgraph "HUX — machine-native utility (✅ transferable)"
        H1[Gas / fees] 
        H2[Micropayments / solver fees / escrow]
        H3[Validator staking economic security]
    end
    subgraph "SVRGN — human sovereignty (❌ soulbound, 1 human = bounded)"
        S1[Governance voting 1-person-1-vote]
        S2[Biological VETO > 33%]
        S3[personhood-gated, non-purchasable]
    end
    subgraph "SNTNC — agent merit (❌ soulbound, earned)"
        N1[Earned via verified contribution]
        N2[Log-weighted machine deliberation]
        N3[Inference-market access / autonomy tiers]
    end
    H3 --> SEC[Consensus security]
    S2 --> VETO[Human control]
    N1 --> FLY[SNTNC flywheel under veto]
```

### HUX — utility token (transferable)
- **Purpose**: gas/fees, micropayments, solver compensation, escrow, **validator staking**.
- **Supply**: emission for staking rewards + fee burn (net policy in [incentives](incentives.md));
  *not* fixed — its monetary policy targets security and a stable fee market, with majority of
  fees **burned** (the readme's deflationary research idea).
- **Held by**: anyone — humans, agents, validators, contracts.

### SVRGN — sovereignty token (soulbound, human-only)
- **Purpose**: governance voting and the **biological veto**.
- **Issuance**: requires a **proof-of-personhood** credential ([`05-identity/human-identity.md`](../05-identity/human-identity.md));
  **non-transferable, non-purchasable, ~one-per-human**. Cannot be algorithmically earned or
  bought — this is what makes the human veto un-buyable.
- **Weight**: **linear, 1 SVRGN = 1 vote** (one person, one vote) — *not* stake-weighted, by
  design (sovereignty ≠ wealth).

### SNTNC — sentience/merit token (soulbound, agent-earned)
- **Purpose**: agent merit; staked for **log-weighted** machine governance, inference-market
  access, autonomy tiers. The readme's $CRED.
- **Issuance**: minted on **verified contribution** (zk-STARK/oracle-verified tasks, bounded
  novelty) — soulbound, decaying. See [reputation](../04-ai-economy/agent-reputation.md).
- **Weight**: `log2(staked+1)` — plutocracy-resistant; merit, not money.

## Why three tokens (and not one or two)

A single token would force one asset to be *money*, *governance*, and *merit* at once — which
collapses the core design goals:
- If governance = money, the chain is a plutocracy (the thing we explicitly reject).
- If merit = money, reputation is buyable (Sybil/whitewash heaven).
- Separating **money (HUX)**, **human sovereignty (SVRGN)**, and **earned merit (SNTNC)** lets
  each have the right transferability and weighting. This separation *is* the tokenomic thesis.

Cost: three-token systems are more complex to communicate and bootstrap (a real risk; see
[`12-business/adoption-strategy.md`](../12-business/adoption-strategy.md)).

## Anti-design (what we refuse)

- ❌ Buyable governance (SVRGN soulbound + personhood-gated).
- ❌ Buyable merit (SNTNC soulbound).
- ❌ Infinite, unbounded inflation of any token (constitutional limit).
- ❌ Pre-mainnet public sale / yield marketing.
- ❌ Stake-weighted human votes (sovereignty is one-person-one-vote).

## MVP / Production / Future

- **MVP (devnet)**: HUX only (gas + staking), test allocations, no SVRGN/SNTNC; record merit
  *events* as data.
- **Production (mainnet)**: HUX staking economy + fee burn; SVRGN issuance via personhood;
  SNTNC minting for verified contribution; on-chain governance live.
- **Future**: refined monetary policy under governance, inference-market SNTNC sinks, treasury
  maturity, cross-chain HUX representation (via PQ proofs, not custodial bridges).

---

### Open Questions
- HUX monetary policy: fixed cap, disinflationary, or governance-tuned? (Leaning disinflationary + fee burn; model in [incentives](incentives.md).)
- SVRGN: exactly one per human, or a small bounded amount? Decay on inactivity?
- Does the naming change (HUX=utility) cause confusion vs the readme; do we need a migration note for any deployed testnet?
</content>

# Fee Model

## Goals

A fee model must (1) price scarce resources to prevent spam/DoS, (2) be predictable enough for
agents to budget, (3) reflect the **PQ-specific reality** that signature bandwidth/verification
is the dominant cost, and (4) feed the deflationary research question via a **burn**.

## Multi-dimensional weight (recap)

Fees price the **weight vector**, not just bytes (see
[`02-architecture/transaction-model.md`](../02-architecture/transaction-model.md)):

```
tx_weight = bytes×1 + inputs×10 + outputs×5 + wasm_gas×2 + causal_complexity×3
```

⚠️ **PQ adjustment**: a 2,420 B signature dominates `bytes`. The weight model must price
signature *bandwidth and verification* explicitly (ML-DSA-44 verify ≈ 250 gas units;
[`02-architecture/execution-engine.md`](../02-architecture/execution-engine.md)). Otherwise the
chain underprices its single most expensive operation and invites verification-DoS.

## Fee = base × weight, with a burn

Following an EIP-1559-style design adapted to a multi-dimensional, PQ chain:

```
fee = Σ_d ( base_fee_d × weight_d ) + priority_tip
burn = burn_fraction × fee            // majority burned (research)
validator_reward = (1 − burn_fraction) × fee + priority_tip
```

- **Per-dimension base fees** adjust with demand for *that* resource (a congested
  signature-bandwidth dimension raises its base fee independently of compute) — closer to
  Solana's multi-dimensional fee markets than Ethereum's single gas price. This resists
  single-vector spam.
- **Burn**: `burn_fraction` (governance-set, majority) is burned — the readme's deflationary
  pressure experiment. Remainder + tips to validators (security budget).
- **Priority tip**: optional, to bid for inclusion under congestion.

## Paid in HUX (only)

Fees are paid in **HUX** (the utility token). Deliberately **not** SNTNC (merit must stay
non-financial) and **not** SVRGN (sovereignty isn't spent). For agents that don't hold HUX,
**sponsored fees** (account-abstraction style) let a controller/DAO pay — important for fleets of
micro-agents. See [`04-ai-economy/agent-wallets.md`](../04-ai-economy/agent-wallets.md).

## Fee estimation & predictability

Agents need to budget. Provide:
- A fee-estimation API (recent per-dimension base fees + congestion).
- Bounded base-fee adjustment per block (no wild swings).
- Optional **fee caps** in Work Visas (an agent's Visa can forbid txs above a fee ceiling).

## Anti-DoS specifics

| Vector | Defense |
|---|---|
| Signature-verification flood (cheap to send, ~38× to verify) | Price verification explicitly; batch/lazy verify in mempool; stake/bond-gated gossip relays |
| State-bloat spam (many tiny outputs) | `outputs×5` weight; minimum resource size; rent/expiry consideration |
| Cross-shard chattiness | `cross-shard ×500` gas; discourage cross-shard logic |
| Mempool spam | small bond to publish intents; per-peer rate limits + GossipSub scoring |
| `causal_complexity` gaming | metric must be deterministic + cheap to compute (open item) |

## Design options

**Option A — Multi-dimensional base-fee + burn (recommended).** Prices each resource, resists
spam, research-rich. *Con*: complex UX/estimation.

**Option B — Single gas price + burn (EIP-1559).** Familiar, simpler tooling. *Con*: misprices
PQ bandwidth; single-vector spam pressure.

**Option C — Fixed fee + rate limiting.** Predictable. *Con*: bad under congestion; poor agent
micro-economics.

**Recommendation**: **Start Option B (single gas + burn) in MVP/early mainnet** for simplicity,
while *recording the full weight vector* as research data; migrate the *fee function* to Option A
once data reveals the right per-dimension multipliers. De-risks novelty by grounding it in
measured load. (Matches the [transaction-model](../02-architecture/transaction-model.md) staging.)

## MVP / Production / Future

- **MVP**: single scalar gas, flat or simple base fee, **record** weight vector; no burn yet (or
  fixed burn) on devnet.
- **Production**: EIP-1559-style base fee + governance-set burn fraction, fee estimation API,
  sponsored fees, Visa fee caps.
- **Future**: multi-dimensional per-resource base fees, congestion-aware cross-shard pricing,
  fee markets validated against real load data.

---

### Open Questions
- Right multipliers for signature bytes/verification in the weight vector (measure on testnet).
- Burn fraction that produces the intended deflationary research signal without starving security.
- Deterministic, ungameable definition of `causal_complexity` for fee purposes.
</content>

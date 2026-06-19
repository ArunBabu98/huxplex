# Transaction Model

## Transaction = resource delta + authorization

A Huxplex transaction is a **balanced set of consumed and created HRM resources** plus the
authorization (signatures) and metadata needed to validate and order it.

```
Transaction {
  consumed: [ResourceRef + redeemer + witness],  // inputs (eUTXO: prev_out + redeemer + witness)
  created:  [Resource],                           // outputs
  fee:      { amount_HUX, burn_fraction },        // burn-based fee
  causal:   { vector_clock, hlc_timestamp },      // anti-grinding / ordering
  auth:     [ML-DSA-44 signature over huxplex-{net}:tx:v1],  // 🟢 context exists & tested
  algo_suite: u16,                                // crypto-agility selector
}
```

This mirrors the readme's eUTXO shape (`TxInput → prev_out + redeemer + witness`,
`TxOutput → asset + amount + datum_hash + validator_hash`) generalized to HRM resources.

## Validation pipeline

```mermaid
graph LR
    RX[Receive tx] --> SIG[Verify ML-DSA sigs + context 🟢]
    SIG --> BAL[Check kind-balance invariant]
    BAL --> NULL[Check nullifiers unspent]
    NULL --> LOGIC[Run resource logic scripts in HuxVM]
    LOGIC --> GAS[Meter gas / weight]
    GAS --> ADM[Admit to DAG mempool]
    ADM --> SCHED[TCHAO: conflict graph + grouping]
    SCHED --> EXEC[Parallel execute]
    EXEC --> COMMIT[Q-BFT finalize + nullify inputs]
```

Any step failing rejects the tx (or the resource-logic aborts). Order matters: cheap checks
(signature, balance, nullifier membership) gate the expensive ones (logic execution).

## Two transaction shapes

1. **Balanced (full) transaction** — author specifies both sides; submitted directly.
2. **Intent (unbalanced)** — author specifies a goal; a solver completes it. Intents carry an
   *ephemeral* resource representing the desired output and a solver-fee allowance. See
   [state-management](state-management.md) and
   [`04-ai-economy/autonomous-commerce.md`](../04-ai-economy/autonomous-commerce.md).

## The multi-dimensional weight model

The readme proposes weight as a vector, not a scalar — a genuinely good idea for a chain where
"cost" is multi-resource (bytes, I/O, compute, *causal complexity*):

```
tx_weight = bytes×1 + inputs×10 + outputs×5 + wasm_gas×2 + causal_complexity×3
```

This generalizes the EIP-1559/gas idea. Architectural notes:

- **PQ-aware weighting**: a 2,420 B signature dominates `bytes`; weight must reflect the real
  bandwidth/state cost of PQ sigs (consider counting witness bytes at a higher multiplier, or
  pricing signature *verification* explicitly given the ~38× cost).
- **`causal_complexity`** prices vector-clock work and anti-grinding overhead — but it must be
  cheap to *compute deterministically*, or it becomes its own DoS vector. 🔴
- Block capacity is a **vector budget** (max bytes, max inputs, max gas, …), not one number —
  this is closer to Solana's multi-dimensional fee markets and reduces single-resource spam.

### Fee market

Fees are paid in **HUX**, **majority burned** (deflationary research signal), remainder to
proposer/validators. See [`06-tokenomics/fee-model.md`](../06-tokenomics/fee-model.md). The fee
must price the *binding* resource (often signature bandwidth/verification on a PQ chain), not
just bytes.

## Design options

**Option A — Multi-dimensional weight + burn fees (recommended, vision-aligned).** Prices each
resource; resists single-vector spam; research-rich. *Con*: complex fee UX; harder estimation;
`causal_complexity` metering risk.

**Option B — Single scalar gas (Ethereum-style).** Simple, familiar tooling. *Con*: misprices
PQ bandwidth and parallelism; one-dimensional spam pressure.

**Option C — Fixed fee + rate limiting (Bitcoin-ish / fee-less + PoW-lite).** Simple, predictable.
*Con*: poor under congestion; bad for agent micro-economics.

**Recommendation**: Option A, but **start as Option B (scalar gas) in MVP** for simplicity, with
the weight *vector computed and recorded* from day one (as research data), then switch the *fee
function* to multi-dimensional in Production once the data shows the right multipliers. This
de-risks the novel fee model by grounding it in measured load.

## Replay & cross-domain safety

- Every signature is context-bound (`huxplex-mainnet:tx:v1` vs `…testnet…`), so a testnet tx
  can never replay on mainnet. 🟢 (tested)
- Nullifiers prevent intra-chain replay of consumed resources.
- `algo_suite` in the signed payload binds the tx to a crypto suite version (agility + replay
  across suite upgrades).

## MVP / Production / Future

- **MVP**: balanced txs only, scalar gas, ML-DSA auth (🟢), nullifier check, record the weight
  vector for research.
- **Production**: intents/solvers, multi-dimensional fee market, burn split, witness pruning,
  fee estimation API.
- **Future**: shielded/ZK transactions, cross-shard txs, account-abstraction-style sponsored
  fees for agents, fee delegation via Work Visa allowances.

---

### Open Questions
- Concrete, *deterministic and cheap* definition of `causal_complexity` that can't be gamed or DoS'd.
- Right multipliers for PQ signature bytes/verification in the weight vector.
- Should fees ever be payable in SNTNC (merit) for agents, or strictly HUX? (Leaning strictly HUX to keep merit non-financial.)
</content>

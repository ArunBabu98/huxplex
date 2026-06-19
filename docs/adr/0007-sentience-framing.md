# ADR-0007: "Sentience" as a bounded, off-consensus proxy metric

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect, research

## Context

The readme centers "Proof of Sentience (PoSENT)", causal-novelty scoring, and a soulbound merit
token ($CRED). These are the project's most original — and most dangerous — ideas. Any on-chain
score is an adversarial optimization target; "sentience"/"consciousness" framing risks
overclaiming and reputational ruin; and putting such a metric on the consensus-critical path would
make a gameable heuristic load-bearing for chain safety.

## Options

- **A — "Proof of Sentience" as a consensus mechanism** (novelty/merit influences block
  validity/rewards directly). Maximally novel. *Cons*: a gameable metric becomes a consensus
  attack surface; catastrophic if wrong; overclaiming risk.
- **B — Drop novelty/sentience entirely.** Safe, but discards the project's distinctive research.
- **C — Keep it as a bounded, opt-in, decaying, off-consensus research metric**, explicitly framed
  as a *proxy* (non-redundant causal contribution), never "consciousness."

## Decision

**Option C.** Specifically:

1. **Definitional honesty**: "sentience" ≡ *statistically significant, non-redundant causal
   advancement under constrained consensus* — a measurable proxy, never a claim about
   consciousness or intelligence. Disclaimers are mandatory and prominent.
2. **Off the consensus-critical path**: block validity NEVER depends on novelty/merit. They are an
   application-layer overlay computed deterministically from on-chain events.
3. **Bounded + decaying + soulbound + costly-to-fake**: so the metric can't inflate without bound,
   grant permanent power, be bought, or be cheaply Sybil-farmed.
4. **Validated adversarially before it has economic teeth**: the readme's own research questions
   ("does novelty converge or inflate?") are answered by simulation + testnet data *first*.
5. **Disposable**: if research shows it's hopelessly gameable, it is demoted/removed with **zero**
   impact on chain safety — because it was never load-bearing.

## Consequences

- ➕ Preserves the distinctive research while removing existential risk to consensus + reputation.
- ➕ Turns risky claims into honest, falsifiable experiments (the chain as "dataset generator").
- ➖ The flagship "Proof of Sentience" narrative is deliberately demoted from consensus to research
  — less flashy, far more credible.
- Follow-on: reputation/SNTNC design + adversarial simulation (R-C1/C2/C3).

## Links
- [agent-reputation](../04-ai-economy/agent-reputation.md), [00-executive-summary](../00-executive-summary.md), open problems R-C1..C3
</content>

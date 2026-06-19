# RFC-XXXX: <title>

- **Status**: Draft
- **Author(s)**: <name / DID>
- **Created**: YYYY-MM-DD
- **Tracking issue**: <link>
- **Affected subsystems**: <e.g., consensus, HRM state, tokenomics>
- **Requires**: governance? audit? crypto-suite change? formal verification?

## Summary

One paragraph: what is being proposed and why, in plain language.

## Motivation

- What problem does this solve? Who is affected?
- Why now? What breaks or is missed if we don't do this?
- Link to the relevant [open problem](../11-research/open-problems.md) or doc.

## Design

The detailed proposal. Include data structures, diagrams (Mermaid), context strings (remember
domain separation!), and how it interacts with existing subsystems.

### Options considered (required)

| Option | Advantages | Disadvantages | Complexity | Security impact | Scalability impact |
|---|---|---|---|---|---|
| A | | | | | |
| B | | | | | |
| C | | | | | |

**Chosen**: <which, and why the deciding forces won>.

## Crypto-agility & determinism review (required for protocol changes)

- Does any new signed/encrypted object carry an `algo_suite` version? (It must.)
- Does this introduce any nondeterminism (FP, map iteration, time, RNG, threads)? (It must not, on
  consensus paths.)
- New domain-separation context string(s)? List them: `huxplex-{net}:...:v1`.

## Security analysis (required)

- New attack surface? Map to the [threat register](../08-security/threat-model.md).
- Likelihood / impact / detection / mitigation for new risks.
- Does it touch the consensus-critical path? (Prefer designs that don't.)

## Economic / governance impact

- Incentive changes, new sinks/sources, who gains/loses, capture risk.

## Migration & compatibility

- Backward compatibility; state migration; activation strategy (height + time-lock).
- Does old finalized history stay valid? (It must.)

## Testing & verification plan

- Unit / property / fuzz / differential / adversarial tests required.
- Formal verification needed? (For catastrophic-impact properties.)
- Testnet rehearsal plan.

## Drawbacks & alternatives

- Why might we *not* do this? What are we accepting?

## Unresolved questions

- What's deferred to implementation or future RFCs? (Add to the open-problems register.)

## References

- Related RFCs, ADRs, docs, prior art.
</content>

# Voting

Mechanics of casting and counting votes across the two chambers.

## Two voting systems, by design

| | Human chamber (SVRGN) | Machine chamber (SNTNC) |
|---|---|---|
| Eligibility | personhood-gated SVRGN holders | SNTNC-staked agents |
| Weight | **1 person = 1 vote** (linear) | **`log2(staked+1)`** (sub-linear) |
| Transferable power | no (soulbound) | no (soulbound merit) |
| Privacy | unlinkable (ZK) target | pseudonymous |
| Primary role | **veto** + approval | deliberation + signal |

Different weighting is intentional: human governance is about *people* (equality), machine
governance is about *earned merit with anti-plutocracy* (diminishing returns).

## How a vote is cast

A vote is a domain-separated, PQ-signed transaction:

```
Vote {
  proposal_id,
  choice: For | Against | Abstain | Veto,   // Veto only valid for SVRGN
  voter: did:huxplex:…,
  weight_proof: (SVRGN personhood / SNTNC stake),
  sig: ML-DSA-44 over huxplex-{net}:governance:vote:v1,   // new context string
}
```

This reuses the existing context-binding discipline (🟢) — a governance vote can't be replayed as
a transaction or across networks. (Add `…:governance:vote:v1` to the canonical context inventory.)

## Counting & finalization

- Votes are tallied deterministically at phase boundaries (epoch increments).
- **Human veto**: if `Σ Veto-weight > 33% of participating SVRGN`, proposal dies — checked
  *after* machine deliberation, so machines can't out-vote a human veto.
- **Quorum**: tiered minimum participation (higher for upgrades/constitution); fail-closed if not
  met.
- Tallies and evidence are on-chain and auditable.

## Anti-manipulation

| Attack | Mitigation |
|---|---|
| Vote buying (SVRGN) | soulbound + personhood-gated → can't transfer/sell the vote |
| Vote buying (SNTNC) | soulbound merit; log-weight blunts whale influence |
| Sybil voting | personhood (SVRGN) / bonded distinct controllers (SNTNC) |
| Last-minute vote sniping | commit-reveal option for high-stakes votes; fixed phase windows |
| Coercion | privacy/unlinkability (ZK) reduces coercibility; abstain option |
| Bribery markets / dark DAOs | unlinkable voting makes proof-of-vote (needed to pay bribes) hard |

## Privacy: unlinkable voting (target)

A human's SVRGN vote should not deanonymize their economic life, and should resist
**bribery/coercion** (which require *proving* how you voted). ZK voting:
- prove eligibility (valid SVRGN/personhood) and cast a weight-1 vote, without revealing identity;
- a nullifier prevents double-voting;
- no receipt → no provable vote → bribery markets break.

This is a Production/Future target; MVP uses transparent voting with the tradeoffs noted. See
[`05-identity/zk-proofs.md`](../05-identity/zk-proofs.md).

## Delegation (liquid democracy)

- SVRGN holders may **delegate** their veto/vote weight to a representative DID (revocable).
- Raises effective turnout (fighting apathy) while preserving one-person-one-vote (you delegate
  *your one vote*, you don't accumulate purchased votes).
- Delegation graphs must prevent cycles and cap re-delegation depth.

## Voting methods considered

**Option A — Simple weighted (recommended for v1).** For/Against/Abstain + SVRGN Veto. Clear,
auditable. *Con*: no preference intensity.

**Option B — Quadratic voting.** Captures intensity, anti-whale. *Con*: requires strong Sybil
resistance (have it for SVRGN via personhood, weak for agents); complex; cost mechanics.

**Option C — Conviction voting.** Time-weighted support; good for continuous funding. *Con*:
complex UX; better suited to treasury streams than discrete proposals.

**Recommendation**: Option A for v1 (with the SVRGN veto), evaluate **conviction voting for
treasury** and **quadratic for personhood-gated human votes** as Future refinements once turnout
data exists.

## MVP / Production / Future

- **MVP**: transparent weighted voting, SVRGN veto, fixed phase windows; no privacy/delegation.
- **Production**: delegation (liquid democracy), commit-reveal for high-stakes votes, quorum
  tiers, governance vote context (🟢-style).
- **Future**: ZK unlinkable + coercion-resistant voting, conviction voting for treasury,
  quadratic human votes.

---

### Open Questions
- Coercion-resistant ZK voting that still allows public auditability of tallies — feasible at scale?
- Re-delegation depth/cycle limits for liquid democracy.
- Quadratic voting for SVRGN — does personhood give *enough* Sybil resistance to make it safe?
</content>

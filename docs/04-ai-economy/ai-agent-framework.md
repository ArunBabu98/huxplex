# AI Agent Framework

> ⚠️ **Phase gate**: nothing in `04-ai-economy/` enters the consensus-critical path. The agent
> economy is an *application layer* (L3/L4) on top of a working chain. Build the chain first
> (Principle #10). Target phase: **Phase 3** ([roadmap](../09-roadmap/phase3-ai-economy.md)).

## The central questions (answered up front)

| Question | Answer |
|---|---|
| How does an AI become an economic participant? | It gets a **DID** + a **Work Visa** (capability credential) issued by a human/DAO controller, and an operating wallet. |
| How does it earn? | Completing intents as a **solver**, fulfilling tasks (verified, where possible by zk-STARK), earning **HUX** (utility) and **SNTNC** (merit). |
| How does it spend? | From its operating wallet, **within Work Visa constraints** (spend caps, scopes, expiry) enforced by HuxVM. |
| How is it controlled? | By its controller via the Visa; revocation is sub-epoch; the human **SVRGN veto** sits above all agent governance. |
| How is it audited? | Every action ties to a Visa + signature + on-chain trail; reputation accrues; provenance is immutable. |
| How is abuse prevented? | Bonds, capability constraints in-VM, reputation decay, rate limits, slashing, revocation, and metrics-off-critical-path. |

## What an "agent" is on Huxplex

An agent is **not** a special protocol object — it is a **DID controlled (initially) by a human
or DAO, holding a Work Visa that scopes what it may do, and a wallet under that scope.** The
chain does not run the AI model; the AI runs off-chain and *acts on-chain* through signed
transactions/intents. Huxplex provides **identity, authority, accountability, settlement** — not
inference.

```mermaid
graph TD
    H[Human / DAO controller] -->|issues| V[Work Visa VC: capabilities + constraints + expiry]
    H -->|delegates key| AK[Agent operating key ML-DSA-44]
    V --> A[Agent DID]
    AK --> A
    A -->|submits intents / solves| CHAIN[Huxplex L1]
    A -->|earns| HUX[HUX] & SNTNC[SNTNC merit]
    CHAIN -->|enforces| V
    H -.->|revoke / re-issue| V
    GOV[SVRGN human veto] -.->|overrides| A
```

## Capability model

A Work Visa grants a typed **capability set** with **constraints**, e.g.:

```
WorkVisa {
  holder: did:huxplex:…(agent),
  issuer: did:huxplex:…(human/DAO),
  purpose: "Purchase Canon DSLR",          // scope-binding; the least-implemented control
                                           // industry-wide (37% adoption, 2026)
  capabilities: [ GPU.Purchase, Dataset.Acquire, Market.Trade(pair=HUX/SNTNC), … ],
  constraints: {
    // positive bounds
    max_tx_value, min_tx_value, max_spend_per_epoch,
    allowed_kinds, allowed_categories, allowed_counterparties,
    max_ancillary: { shipping, tax, fees },
    deadline,
    // NEGATIVE capabilities — deny by default, and the half that matters most
    subscription:              false,
    recurring_payment:         false,
    transfer_to_third_party:   false,
    refund_authority:          true,
    automatic_execution:       true,
  },
  required_evidence_class: FirstParty,      // what proof settles this — ADR-0016
  remediation_policy: [ Cancel, SeekReplacement, RequestRefund, NotifyUser ],
  expiry: block_height,
  revocation_ref: …,
  issuer_sig: ML-DSA-44 over issuer context,
}
```

This schema follows the founder's 14-field formulation
([`brainstorming/`](../brainstorming/00-arun-babu-founding-notes.md) §Step 4) rather than the
earlier 4-field sketch. Three additions carry most of the weight:

- **`purpose`** — scope binding. Per 2026 industry data this is the *least* implemented agent
  control anywhere (37%), and it is what distinguishes a bounded capability from a blank cheque.
- **Negative capabilities, denied by default.** "Cannot create a subscription", "cannot set up
  recurring payment", "cannot transfer to a third party." Positive bounds alone do not prevent an
  agent from converting a one-off authorization into an ongoing obligation.
- **`required_evidence_class` and `remediation_policy`** — the user decides what proof is good
  enough, and what the agent may do when a constraint breaks *after* settlement.

> *"This is the difference between giving an AI your credit card and giving an AI a bounded
> economic capability."*

### Attenuation to external effects

A visa is never handed to a connector. For each external action, L3 derives a single-purpose
**Authorization Envelope** with `bounds(envelope) ⊆ bounds(visa)`, naming exactly one connector
and one action class. See [ADR-0015](../adr/0015-connector-architecture.md) and the
[connector protocol](../15-specifications/07-connector-protocol.md) §5.

Constraints are **enforced in HuxVM** when the agent's transactions execute — not merely
advisory. A tx exceeding `max_spend_per_epoch` is rejected by the Visa's logic script. This is
the mechanism that makes "human-defined limits" real rather than rhetorical.

## Agent lifecycle

```mermaid
stateDiagram-v2
    [*] --> Registered: controller creates agent DID
    Registered --> Authorized: Work Visa issued
    Authorized --> Active: agent transacts within scope
    Active --> Active: earns HUX/SNTNC, builds reputation
    Active --> Suspended: constraint breach / dispute / low reputation
    Suspended --> Active: remediation
    Authorized --> Revoked: controller revokes Visa (sub-epoch)
    Active --> Expired: Visa expiry height reached
    Revoked --> [*]
    Expired --> [*]
```

### Obligations do not end at settlement

An agent's work frequently continues *after* payment clears. In the founder's worked example the
agent monitors an 8-day delivery, detects a breach on day 12, and acts on it. The lifecycle above
covers the agent; the **intent** has its own, longer lifecycle, carried by a
[Connector Session](../15-specifications/07-connector-protocol.md) §4:

```
settled → monitoring (shipped → in_transit → delivered)
        → breach detected (delivery 12 days > 8-day constraint)
        → remediation, but only what the visa authorized:
             cancel · seek replacement · request refund · notify user
```

Three consequences for agent design:

1. **The session, not the agent process, owns the lifecycle.** A session survives node restart
   and agent-process death, and is resumable by any instance holding the agent DID. Agents are
   replaceable; obligations are not.
2. **Remediation is authorized in advance.** What the agent may do on breach is a visa field, not
   an agent decision. *"The exact behaviour could itself be part of the user's authorization."*
3. **The intent is therefore not "buy a camera"** but *"achieve this economic outcome subject to
   these constraints"* — including what to do when the outcome fails.

## Accountability principle

Every agent action is traceable: `action → signature → Work Visa → issuer DID → human/DAO`.
There is **no anonymous unbounded agent**. An agent that wants more autonomy must post larger
**bonds** and build **reputation** — both slashable. This is how the system stays steerable as
agent populations grow.

## Hard problems (honest)

- **Not all work is verifiable.** zk-STARK "proof of correct task completion" only works for
  tasks with a checkable specification (deterministic compute, oracle-verifiable outputs).
  "Write a good essay" is not provable. Scope task-verification accordingly; use
  reputation/escrow/dispute for unverifiable work. See [autonomous-commerce](autonomous-commerce.md).
- **Metric gaming.** Any reward signal (SNTNC, reputation, novelty) is an optimization target.
  Keep them bounded, decaying, costly to fake, and off consensus. See [agent-reputation](agent-reputation.md).
- **Sybil agents.** One human can spin up thousands of agents. Bonds + issuer accountability +
  proof-of-personhood for *controllers* (not agents) are the defense. See
  [`05-identity/`](../05-identity/).
- **Collusion.** Agent rings can wash-trade reputation/intents. Detection is a research item;
  economic friction (bonds, fees) is the first line.

## MVP / Production / Future

- **MVP (Phase 3 entry)**: agent DID + Work Visa as HRM resources, constraint enforcement in
  HuxVM, manual issuance/revocation, no automated reputation.
- **Production**: intent/solver participation, escrow + dispute, reputation accrual, bonded
  autonomy tiers, marketplace.
- **Future**: Agentic DAOs, inference markets, self-funding agents (GPU procurement loop),
  cross-agent delegation graphs — all under the SVRGN veto.

---

### Open Questions
- Where is the line between "agent acts under a human" and "fully autonomous agent" — and should the latter ever exist without a human controller?
- Minimum viable capability vocabulary for v1 Work Visas.
- How to make constraint-enforcement scripts cheap enough to run on every agent tx given PQ verify costs?
</content>

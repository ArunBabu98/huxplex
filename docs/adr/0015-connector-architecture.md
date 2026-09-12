# ADR-0015: Connector architecture — wrap MCP, never widen authority

- Status: Accepted
- Date: 2026-09-12
- Deciders: Founding architect, protocol, security

## Context

The blueprint describes Huxplex as a self-contained L1: agents transact in on-chain HRM
resources, and the outside world does not appear. The founder's brainstorming notes
([`brainstorming/00-arun-babu-founding-notes.md`](../brainstorming/00-arun-babu-founding-notes.md)
§Steps 7–11) introduce a concept absent from the entire blueprint — the word "connector" appeared
**zero times across all 111 doc files** — and it changes what Huxplex is:

> *"Huxplex is a substrate, Amazon is an external system. Therefore we need a bridge … A
> connector is essentially an external system adapter. It understands the Huxplex protocol and
> the external platform protocol … This makes Huxplex much bigger than a cryptocurrency system."*

This forces a decision that had never been posed: **is Huxplex a closed economy, or an
orchestration and trust substrate over existing systems?**

### Forces

- **A closed agent economy has nothing to do.** Agents transacting only in on-chain resources form
  a loop with no contact with real economic value. Making it useful requires the whole economy to
  move on-chain first — a bootstrapping problem that has failed repeatedly for fifteen years.
- **Empirical evidence favours connection.** USDC is, structurally, a connector: an off-chain
  asset attested by an off-chain issuer — an oracle boundary. It is the most-used object on every
  chain that has it. The connected design beat the self-contained one decisively.
- **Adoption asymmetry.** With connectors, the counterparty need not know Huxplex exists.
  Self-contained requires every counterparty to adopt first.
- **The plumbing is already standardized and we cannot win it.** MCP reached ~97M monthly SDK
  downloads by March 2026, is natively supported by every major AI vendor, and was donated to the
  Linux Foundation's Agentic AI Foundation. x402 (Linux Foundation, April 2026) covers machine
  payment; A2A v1.0 covers agent↔agent. Defining a proprietary connector protocol in 2026 would be
  a strategic error.
- **But the standards cannot express governance.** Kang & Diponegoro, *"Governance Gaps in Agent
  Interoperability Protocols"* (arXiv:2606.31498, 2026) show MCP, A2A and ACP cannot express
  authority bounds, delegation scope, spend limits, accountability, or evidence requirements —
  precisely the five things Huxplex exists to provide.
- **Human sovereignty is a protocol invariant** ([`mission.md`](../01-vision/mission.md)). Any
  external pathway that could widen agent authority would destroy the project's core claim.
- **Bridges are risk #9** ([`attack-vectors.md`](../08-security/attack-vectors.md)) and are
  deferred indefinitely. The relationship between connectors and bridges must be settled, not
  assumed.

### The classification question

An earlier draft of this analysis treated connectors as bridge-like and gated them accordingly.
**That was wrong**, and correcting it is central to this ADR:

| | Cross-chain bridge | Connector |
|---|---|---|
| Holds funds or credentials | Yes | **No** — the notes forbid it (§Step 8) |
| Can create authority | Yes — its signature mints | **No** — the visa resolves at L3 before invocation |
| Worst-case compromise | Unbounded theft up to TVL | Lies about an external fact, inside a bounded envelope |
| Independent recourse | None | Merchant records, chargebacks, external audit trails |
| Classification | **Custody** boundary | **Oracle** boundary — the author's own term (§Step 11) |

Further, the trust boundary exists with or without Huxplex: if an agent shops for a user, someone
is trusting the merchant. A connector under a visa does not create that exposure — it bounds and
attests it. Against the realistic alternative (the agent holds the user's card with unbounded API
access) a connector is a strict security **improvement**.

## Options

- **A — Self-contained substrate.** No external pathway; agents transact only in on-chain
  resources. *Advantages:* no oracle problem, fully verifiable, smallest attack surface, cleanest
  story. *Disadvantages:* no day-one utility; requires universal on-chain migration to become
  useful; loses to connected competitors on adoption; makes the founder's worked examples
  (§Steps 1–19) unimplementable.
- **B — Proprietary Huxplex connector protocol.** Define our own tool-invocation, discovery and
  transport layer. *Advantages:* total control; exact fit. *Disadvantages:* competes with MCP at
  ~97M monthly downloads and loses; every integrator must implement a bespoke protocol; we absorb
  the full API-rot maintenance cost that MCP amortizes across an entire ecosystem.
- **C — Wrap MCP: borrow the invocation plane, build the authority and evidence planes.**
  *Advantages:* zero-cost integration with an ecosystem that already exists; we build only the
  differentiator (the five governance properties MCP structurally cannot express); the maintenance
  treadmill is shared. *Disadvantages:* dependency on an external standard's evolution; MCP cannot
  carry long-running events, canonical bytes, or server identity, so three gaps must be filled
  ourselves.
- **D — Connectors as full protocol participants** (connectors run nodes, submit directly, hold
  value). *Advantages:* stronger evidence, direct settlement. *Disadvantages:* makes connectors
  custody-shaped, i.e. bridges; no merchant will run a validator; catastrophically raises the
  blast radius.

## Decision

**Option C.** Huxplex adopts a **three-plane connector architecture**, specified as HCP/1 in
[`15-specifications/07-connector-protocol.md`](../15-specifications/07-connector-protocol.md).

1. **Authority plane (ours, L3, before any external contact).** A connector never receives the
   visa and never receives credentials. It receives an **Authorization Envelope**: single-purpose,
   nonce'd, expiring, naming exactly one connector and one action class, with
   `bounds(envelope) ⊆ bounds(visa)` as an on-chain decidable subset check.
2. **Invocation plane (borrowed).** MCP for tool invocation and discovery; x402 for machine
   payment on HTTP rails; AP2 mandates as the external representation of a payment envelope; A2A
   for agent↔agent (out of connector scope). MCP never learns Huxplex exists.
3. **Evidence plane (ours, L2, after the effect).** Typed, classed, connector-signed attestations
   recorded in state — see [ADR-0016](0016-evidence-and-attestation.md).
4. **Connectors are not validators.** They hold a `did:huxplex` identity with SLH-DSA root +
   ML-DSA-44 operational keys, sign off-chain, and their attestations MAY be submitted on-chain by
   the agent. A merchant integrates an endpoint, not consensus.
5. **Four conformance profiles shipped in order** — 0 Observer (read-only), 1 Effector, 2 Settler,
   3 Custodial. **Profile 3 is custody-shaped and MUST be gated as a bridge.** Profiles 1–3 are
   governance-gated at launch.
6. **The exploration/execution split.** An agent's candidate search is plain MCP, off-chain,
   unbounded, requiring no envelope and no session. Only *effects* cross into HCP. The protocol
   governs effects, not reasoning.

### The invariants that make this safe

| | Invariant |
|---|---|
| **A1** | No invocation without a valid, unexpired, unspent envelope — structurally, not by check |
| **A2** | Nothing from the invocation or evidence plane can create, widen, or extend authority |
| **A3** | `bounds(envelope) ⊆ bounds(visa)`; attenuation is monotonic |
| **A4** | Connectors MUST NOT issue envelopes. Only L3 may |
| **A7** | Huxplex MUST NOT accept, store, forward, or proxy user credentials for any external system |
| **A8** | Commerce and payment are disjoint action classes; neither connector can perform the other's |

**The decisive property:** with the agent *and* the connector fully compromised and colluding, the
loss is still bounded above by the visa the human signed (test G11-T6). This is what makes
"connectors must not override bounded authority" a theorem rather than a promise.

## Consequences

- ➕ Day-one utility. The founder's Canon-DSLR walkthrough becomes implementable against real
  merchants, real payment rails, real carriers.
- ➕ Adoption requires no counterparty to adopt Huxplex.
- ➕ We build only the differentiator. The five governance gaps in arXiv:2606.31498 become the
  product; the plumbing is free.
- ➕ Repositions Huxplex as the enforcement and evidence layer *for* the emerging agent stack
  rather than a competitor to it — see [`17-landscape-2026.md`](../17-landscape-2026.md) §10.
- ➕ The audit trail is a compliance artifact under the EU AI Act's logging obligations.
- ➖ **Scope expands materially.** Mitigated by the profile ladder and "one category done
  completely before the next," not by good intentions.
- ➖ Dependency on MCP's evolution and governance. Accepted: the alternative is worse.
- ➖ Three gaps MCP cannot fill must be built and maintained ourselves — long-running events,
  canonicalization, connector identity (HCP §8, §7.4, §6).
- ➖ **Liability, not theft, is the real long-run cost.** Merchant-of-record and fraud liability
  are now protocol concerns; the registry records legal operator and jurisdiction (HCP §12).
- ➖ API rot is a permanent operating cost. Mitigated by adapter/schema separation and continuous
  conformance testing as a registry requirement (HCP §11.2).
- ➖ Privacy: session evidence chains are detailed purchase records in consensus state. Unresolved
  — see [`open-problems.md`](../11-research/open-problems.md).
- ⚠️ Risk accepted: a `Relayed` connector can lie about occurrence. Bounded by evidence classes,
  bonding and corroboration; **not eliminated**.

### Relationship to the bridge deferral

This ADR does **not** reverse the bridge deferral (risk #9). Profiles 0–2 are oracle boundaries
and are not bridges. **Profile 3 (Custody) is a bridge in all but name and inherits the deferral
in full** — governance super-majority, and no earlier than Phase 4.

## Links
- Spec: [`15-specifications/07-connector-protocol.md`](../15-specifications/07-connector-protocol.md)
- Evidence model: [ADR-0016](0016-evidence-and-attestation.md)
- Origin: [`brainstorming/00-arun-babu-founding-notes.md`](../brainstorming/00-arun-babu-founding-notes.md) §Steps 7–11, and the reconciliation in [`brainstorming/README.md`](../brainstorming/README.md) §2.1
- Landscape: [`17-landscape-2026.md`](../17-landscape-2026.md) §2, §8
- Build gate: [`16-action-plan.md`](../16-action-plan.md) G11
- Related: [ADR-0005](0005-build-strategy.md) (leverage mature stacks), [ADR-0013](0013-did-huxplex-method.md) (connector DIDs), [ADR-0002](0002-cryptographic-parameter-set.md) (hybrid key model)
- External: Kang & Diponegoro, *Governance Gaps in Agent Interoperability Protocols*, arXiv:2606.31498 (2026)

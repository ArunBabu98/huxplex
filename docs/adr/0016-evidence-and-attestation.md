# ADR-0016: Evidence model — typed claims, classed trust, no truth by signature

- Status: Accepted
- Date: 2026-09-12
- Deciders: Founding architect, protocol, security, research

## Context

[ADR-0015](0015-connector-architecture.md) admits external effects into Huxplex. That creates a
question the blueprint has never answered: **when the chain records that something happened in
the outside world, what exactly has been established?**

The founder's notes reach this question and correctly mark it unfinished
([`brainstorming/00-arun-babu-founding-notes.md`](../brainstorming/00-arun-babu-founding-notes.md)
§Step 11):

> *"Instead of believing the agent's claims of buying the camera, an authorized connector receives
> an order confirmation from Amazon … The external connector is an oracle/trust boundary. This is
> an area where Huxplex will eventually need a sophisticated proof/evidence model."*

The notes propose recording connector identity, order ID, merchant response, timestamp,
transaction reference, payment reference, hash of external receipt, delivery information, and a
connector signature.

### The trap

A naïve implementation of that record would treat it as proof that *"the camera was bought."* It
is not. It is *"a connector claims it received this from something it believes is Amazon."* The
2026 literature states the failure precisely — *An Evidence Model for Agentic Processes*
(arXiv:2609.08481):

> *"A hash does not establish semantic truth, a signature does not establish authorization, and an
> external anchor does not establish capture completeness."*

Three distinct conflations are available to get wrong, and systems routinely get all three wrong:

1. **Signature ⇒ truth.** A signature proves *receipt by the signer*, nothing about the world.
2. **Signature ⇒ authorization.** Evidence is frequently read as though it justified the action.
   Authority came from the visa, before the action; evidence cannot retroactively supply it.
3. **A record exists ⇒ the record is complete.** An anchored log says nothing about what was
   omitted.

### Further forces

- **Provenance differs enormously in strength.** A merchant signing its own order record and a
  third party wrapping that merchant's public API are not interchangeable, yet both produce "a
  signed attestation."
- **Determinism.** External payloads are free-form JSON, HTML, or worse. They cannot enter
  consensus — two nodes would hash them differently.
- **The blueprint's existing treatment is thin.** [`autonomous-commerce.md`](../04-ai-economy/autonomous-commerce.md)
  mentions "oracle attestation" as an escrow release condition. There is no evidence object, no
  provenance model, and no evidence reference in any state transition.
- **Human sovereignty.** If the protocol decides unilaterally what evidence is good enough, it has
  made a trust decision on the user's behalf — inconsistent with the project's thesis.

## Options

- **A — Binary evidence.** An attestation is either present or absent. *Advantages:* trivial.
  *Disadvantages:* treats a scraper and a merchant as equals; makes the three conflations above
  unavoidable; the protocol silently decides how much trust is enough.
- **B — Reputation-weighted evidence.** Score connectors; weight attestations by score.
  *Advantages:* adaptive, no taxonomy needed. *Disadvantages:* reputation is an adversarial
  optimization target (the same objection as [ADR-0007](0007-sentience-framing.md)); it conflates
  *how reliable a connector has been* with *what kind of claim this is* — orthogonal axes; and a
  reputable connector relaying a lie still produces a `Relayed` claim.
- **C — Typed claims + a provenance class lattice, with the required class set by the user.**
  Separate *what is established* from *how strongly*, and let the visa/intent declare the minimum.
  *Advantages:* makes the three conflations type errors; puts the trust decision with the human;
  supports graduated strength. *Disadvantages:* more machinery; requires a schema registry;
  connectors must be honestly classified at registration.
- **D — Cryptographic proof only** (zk / TLS-transcript proofs for everything). *Advantages:*
  trust-minimal. *Disadvantages:* unavailable for the overwhelming majority of real commerce in
  2026; would reduce the connector system to almost nothing. Same overclaiming failure the project
  already rejected for zk-STARK task proofs.

## Decision

**Option C.** Specified in [`15-specifications/07-connector-protocol.md`](../15-specifications/07-connector-protocol.md)
§7.

### 1. Five separated evidence claims

Every attestation carries these **independently**. They MUST NOT be collapsed.

| Claim | Established by | Never established by |
|---|---|---|
| `integrity` | payload hash | signature alone |
| `receipt` | connector signature | payload hash |
| `authorization` | **the envelope — never the evidence** | any signature |
| `occurrence` | `FirstParty` / `Cryptographic` / `Notarized` | `Relayed` |
| `completeness` | gapless `seq` + unbroken heartbeat | any single record |

**Invariant A5.** `authorization` is never an evidence claim. An attestation asserting it is
malformed and MUST be rejected. This makes conflation #2 a type error.

### 2. The Evidence Class lattice

```
SelfReported  <  Relayed  <  Notarized  <  FirstParty  ≤  Cryptographic
```

| Class | Meaning | Signed by |
|---|---|---|
| `SelfReported` | The agent asserts it | agent — **never sufficient for settlement** |
| `Relayed` | A third-party connector received this response | connector |
| `Notarized` | *k*-of-*n* independent connectors relayed consistent results | k connectors |
| `FirstParty` | The external system signed its own record | the external system |
| `Cryptographic` | Verifiable without trusting any connector | verifiable |

A connector declares its maximum class at registration and **cannot assert above it**. A
third-party API wrapper is registered `Relayed` and structurally cannot emit `FirstParty`,
whatever it claims. This makes conflation #1 unrepresentable.

### 3. The user sets the bar

The intent — and therefore the visa and the envelope — declares `required_evidence_class`. A
session MUST NOT reach `Fulfilled` on evidence below it.

> *"Settle only on `FirstParty` or better"* for a ₹1,00,000 camera; `Relayed` is fine for a ₹200
> one.

This is the decision's most important property: **the trust decision is made by the human, at
authorization time**, which is exactly where the project's thesis says authority belongs.

### 4. Typed Evidence Schemas; raw payloads stay off-chain

1. The connector receives a raw external response.
2. It **projects** it into a registered, versioned `EvidenceSchema` — a typed struct encoded per
   [ADR-0011](0011-canonical-serialization.md).
3. The **typed projection** and `H(raw_payload)` go on-chain. **The raw payload does not.**
4. The raw payload remains retrievable off-chain for a declared window and MUST hash to the
   committed value.

The schema registry is versioned and governance-updatable, mirroring the algorithm registry of
[ADR-0002](0002-cryptographic-parameter-set.md).

### 5. Completeness is structural, not asserted

`completeness` is earned only by a **gapless per-session sequence** plus an unbroken heartbeat
(HCP §8). A withheld event is detectable as a gap; a silent connector is indistinguishable from a
gap. This makes conflation #3 a checkable property rather than an assumption.

## Consequences

- ➕ The three standard conflations become type errors or unrepresentable states.
- ➕ Users control their own trust threshold, per intent, at authorization time.
- ➕ Directly implements the fifth governance gap of arXiv:2606.31498 ("evidence & proof
  requirements") that MCP, A2A and ACP cannot express.
- ➕ Creates a clear incentive to recruit **first-party** connectors: a merchant-operated,
  Huxplex-signing endpoint is a categorically better artifact than a scraper, and the class
  lattice makes that difference legible and economically meaningful.
- ➕ Consensus stays deterministic — no free-form external bytes ever enter it.
- ➕ Slashing becomes tractable: a `Relayed` attestation contradicted by `FirstParty` or
  `Cryptographic` evidence is *provably* false, and only provable falsehood is slashable.
- ➖ More machinery: a schema registry, projections and adapters per external system.
- ➖ Honest classification depends on correct registration; misregistration is a governance
  failure, not a cryptographic one.
- ➖ `Notarized` is weaker than it looks — independent connectors may all wrap the same upstream
  API, and independence is hard to verify. Flagged as an open problem.
- ➖ Evidence chains are detailed purchase records in consensus state. **Privacy is unresolved**
  and may require committed rather than plaintext projections with selective disclosure.
- ⚠️ Risk accepted: `Relayed` connectors can lie about `occurrence`. Bounded and attributable;
  not eliminated. Stated explicitly in HCP §13.2 rather than hidden.

## Links
- Spec: [`15-specifications/07-connector-protocol.md`](../15-specifications/07-connector-protocol.md) §7, §8
- Connector architecture: [ADR-0015](0015-connector-architecture.md)
- Origin: [`brainstorming/00-arun-babu-founding-notes.md`](../brainstorming/00-arun-babu-founding-notes.md) §Step 11
- Related: [ADR-0011](0011-canonical-serialization.md) (canonical encoding), [ADR-0007](0007-sentience-framing.md) (why not reputation-weighted), [`autonomous-commerce.md`](../04-ai-economy/autonomous-commerce.md) (escrow release conditions)
- Tests: [`16-action-plan.md`](../16-action-plan.md) G11-T1, T3; HCP §16 G11-T3, T8, T12
- External: *An Evidence Model for Agentic Processes*, arXiv:2609.08481 (2026); *Decision Evidence Maturity Model for Agentic AI*, arXiv:2605.04093 (2026)

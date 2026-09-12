# `brainstorming/` — Ideas, notes, and thinking-in-progress

> **Everything in this folder is non-normative.**
>
> This is where raw ideas live before they earn their way into the canonical blueprint. No
> file here is a specification, a decision, or a commitment. Where anything here conflicts
> with [`/docs`](../README.md) and the [ADRs](../adr/), **the blueprint wins** until an RFC
> changes it.

## Why this folder exists

The canonical blueprint is deliberately conservative: it records what has been decided and
why. But the reasoning that *produced* those decisions — the founder's raw thinking, the
worked examples, the "what if" branches — is valuable and easy to lose. This folder
preserves it, clearly quarantined from normative content.

## Contents

| File | What it is | Author |
|---|---|---|
| [`00-arun-babu-founding-notes.md`](00-arun-babu-founding-notes.md) | The substrate walkthrough — layer stack, intents, visas, connectors, evidence, and the full Canon-DSLR worked example. Transcribed from 50 handwritten pages. | **Arun Babu**, creator of Huxplex (Sept 2026) |

## Status of ideas in this folder

| Legend | Meaning |
|---|---|
| 🟩 **Aligned** | Already in the canonical blueprint; the notes restate or sharpen it |
| 🟦 **New** | Genuinely new to the project; not present in `/docs` at all |
| 🟨 **Tension** | Conflicts with, or materially extends, something the blueprint already decided |

---

# Reconciliation with the canonical blueprint

This section is the transcriber's analysis, **not** the author's. It cross-checks the
founding notes against all 111 files in `/docs` and `src/`.

## 1. What already aligns 🟩

The notes and the blueprint agree on more than they disagree on, which is a good sign for
the project's internal coherence.

| Idea in the notes | Where the blueprint already has it |
|---|---|
| The five-layer stack L0→L4, with those exact responsibilities | [`02-architecture/system-overview.md`](../02-architecture/system-overview.md) — the layer diagram matches almost exactly, including the L4 = agents / L3 = identity+governance / L2 = execution+economy / L1 = consensus+state / L0 = networking+crypto split |
| Intents as goals rather than steps; agents supply the "how" | [`04-ai-economy/autonomous-commerce.md`](../04-ai-economy/autonomous-commerce.md), [`02-architecture/transaction-model.md`](../02-architecture/transaction-model.md) |
| Agent authority delegated by a human via a credential | Work Visa — [`04-ai-economy/ai-agent-framework.md`](../04-ai-economy/ai-agent-framework.md) |
| Constraints enforced by the machine, not by convention | Same; "enforced in HuxVM … not merely advisory" |
| The four identity questions (who is the human / the agent / who authorized / what may it do) | [`05-identity/`](../05-identity/), [`adr/0013-did-huxplex-method.md`](../adr/0013-did-huxplex-method.md) |
| Q-BFT at L1 for finality | [`15-specifications/04-consensus-spec.md`](../15-specifications/04-consensus-spec.md) |
| PQ crypto and secure propagation at L0 | [`02-architecture/cryptography.md`](../02-architecture/cryptography.md) — and 🟢 implemented in `src/crypto/` |
| Agent lifecycle with revocation and expiry | [`04-ai-economy/ai-agent-framework.md`](../04-ai-economy/ai-agent-framework.md) lifecycle state machine |
| "Capability with responsibility"; human sovereignty as invariant | [`01-vision/mission.md`](../01-vision/mission.md), [`07-governance/constitutional-layer.md`](../07-governance/constitutional-layer.md) |

## 2. What is genuinely new 🟦

These ideas appear **nowhere** in the current blueprint and are the notes' main
contribution.

### 2.1 Connectors — the single biggest gap

The word **"connector" appears zero times across all 111 files in `/docs`.**

The notes introduce connectors as first-class architecture: typed adapters that translate
between the Huxplex protocol and an external platform's protocol, so that *"Huxplex should
not need to understand Amazon's internal implementation — it only needs to understand the
connector protocol."*

This is a **structural change to what Huxplex is**. The blueprint currently describes a
self-contained L1 whose agent economy transacts in on-chain resources. The notes describe an
**orchestration and trust substrate** that reaches into commerce, payment, shipping,
physical-world and civic systems. The notes state this explicitly: *"This makes Huxplex much
bigger than a cryptocurrency system."*

**Connectors are not bridges, and the distinction is load-bearing.** A cross-chain bridge is
a *custody and authority* boundary: it holds value, and its signature mints value on the far
side, so compromising it is unbounded theft up to TVL. That is why bridges are risk #9 in
[`08-security/attack-vectors.md`](../08-security/attack-vectors.md).

A connector as the notes define it is an *effect and evidence* boundary:

| | Cross-chain bridge | Huxplex connector |
|---|---|---|
| Holds user funds or credentials | Yes | **No** — *"Huxplex should not automatically possess the user's bank credentials"* (notes §Step 8) |
| Can create authority | Yes — its signature mints | **No** — the visa is evaluated at L3 *before* the connector is invoked (§Step 9) |
| Worst-case compromise | Unbounded theft up to TVL | Bounded by the visa of each intent routed through it; lies about external facts |
| Independent recourse | None; funds are gone | Yes — merchant records, chargebacks, the external system's own audit trail |
| Correct classification | Custody boundary | **Oracle boundary** — the author's own term (§Step 11) |

The failure mode is *"the ledger records something false about the outside world"* — the
oracle problem — not *"the attacker drained the protocol."* That still requires rigour, but a
different kind: attribution, bonding and evidence typing rather than custody minimization.

Two further points that cut in connectors' favour:

- **The trust boundary exists with or without Huxplex.** If an agent shops on the user's
  behalf, someone is trusting Amazon. A connector under a visa does not create that exposure
  — it *bounds and attests* it. Against the realistic alternative (the agent holds the user's
  card and unbounded API access), a connector is a strict security **improvement**.
- **One exception deserves bridge-grade caution:** a connector that settles *on-chain* value
  (stablecoins, or any rail where the connector itself custodies) is custody-shaped and
  should be treated as a bridge. Commerce, shipping, status-reporting and
  external-rail-payment connectors are not.

The real long-run costs of connectors are **liability, scope and maintenance**, not theft.
See [`../16-action-plan.md`](../16-action-plan.md) G11. **This needs an ADR.**

### 2.2 A first-class evidence model

The notes specify a concrete evidence record returned by a connector — connector identity,
order ID, merchant response, timestamp, transaction reference, payment reference, hash of
external receipt, delivery information, and a connector signature over all of it — and give
the reason: *"instead of believing the agent's claim of buying the camera, an authorized
connector receives an order confirmation."*

The blueprint mentions "oracle attestation" in escrow release conditions but has **no
evidence object, no connector attestation, and no evidence reference in any state
transition**. The notes correctly flag this as unfinished: *"an area where Huxplex will
eventually need a sophisticated proof/evidence model."*

### 2.3 Separation of payment authority from commerce authority

*"Huxplex should not automatically possess the user's bank credentials. Instead there must
be a separate payment authorization."* Two connectors — commerce and payment — cooperate to
fulfil one intent, each under its own bounded delegation.

The blueprint's [`agent-wallets.md`](../04-ai-economy/agent-wallets.md) covers on-chain
wallets only. External payment rails, and the two-authority split, are new.

### 2.4 Hard constraints vs. soft preferences

A clean, implementable rule: *"Hard constraints must never be violated. Soft preferences let
the agent optimize."* Hard constraints are visa-enforced and binary; soft preferences turn
the intent into an optimization problem the agent solves. The blueprint does not make this
distinction.

### 2.5 "The policy wins"

Stated as *"one of the fundamental principles of the Huxplex architecture"*: when the agent's
judgement and the visa disagree, the visa wins — even when the agent believes it is right
(the ₹1,25,000 example). This is a crisper, testable invariant than the blueprint's more
general "human veto", and belongs in
[`01-vision/principles.md`](../01-vision/principles.md).

### 2.6 "The app is not Huxplex"

An explicit application/substrate boundary: apps are built *on top of* Huxplex and are not
part of it. The blueprint has no application-layer boundary statement.

### 2.7 Post-settlement agent obligations

In the notes the agent keeps working *after* payment settles — monitoring delivery, and on a
constraint breach cancelling, seeking replacement, requesting a refund, or notifying the
user, with *"the exact behaviour … itself part of the user's authorization."*

The blueprint's agent lifecycle ends at settlement. Long-running intents with remediation
policies are new, and they imply state and scheduling machinery that does not currently
exist in any spec.

## 3. Tensions to resolve 🟨

| # | Tension | Detail | Suggested resolution |
|---|---|---|---|
| 1 | **Two different intent models** | Blueprint: an intent is an *unbalanced partial transaction* completed by a solver (Anoma-style). Notes: an intent is an *objective + constraints + execution policy* evaluated against a visa. These are not the same object. | They are complementary, not exclusive — the notes' intent is the *user-facing* declaration; the blueprint's is the *settlement-facing* encoding. Needs an ADR defining the lowering from one to the other. |
| 2 | **Visa schema depth** | Blueprint visa has 4 constraint fields. Notes' visa has 14, including refund authority, subscription, recurring payment, and transfer-to-another-person — all defaulting to deny. | Adopt the notes' richer schema as the design target; it is far closer to implementable. The deny-by-default negative capabilities are the valuable part. |
| 3 | **Scope vs. v1** | [`15-specifications/06-v1-scope.md`](../15-specifications/06-v1-scope.md) explicitly forbids the agent economy, Work Visa enforcement, intents/solvers and oracles from v1. The notes are almost entirely L3/L4 content. | **No conflict if labelled correctly.** These notes are a north-star document, not a v1 plan. Treat them as the target the v1 chain must not foreclose — see [`../16-action-plan.md`](../16-action-plan.md). |
| 4 | **Scale of ambition** | The connector list (commerce → payment → shipping → robots → drones → government) is a wish list, not a roadmap. The cost is liability, scope and API maintenance, not theft. | Sequence, don't forbid: **one category done completely** before the next. Physical-world and civic connectors are Phase 4, behind their own ADR. |
| 5 | Spelling: notes say "QBFT" | Blueprint uses **Q-BFT** throughout. | Cosmetic; blueprint spelling stands. |

## 4. What the notes tell us about mission framing

The notes contain a sharper one-line statement of the project than
[`01-vision/mission.md`](../01-vision/mission.md) currently has:

> *"A sovereign substrate where humans and machines can interact economically **without
> conflating intelligence with authority**."*

That phrase — *capability is not permission* — is the whole thesis in four words, and it is
also, independently, where the 2026 research literature has converged (see
[`../17-landscape-2026.md`](../17-landscape-2026.md)). It is worth promoting into the
mission doc.

## 5. Actions arising

| Action | Target | Status |
|---|---|---|
| ADR: connector architecture + trust boundary | [`adr/0015`](../adr/0015-connector-architecture.md) | ✅ Accepted |
| ADR: evidence & attestation model | [`adr/0016`](../adr/0016-evidence-and-attestation.md) | ✅ Accepted |
| Normative connector protocol | [`15-specifications/07`](../15-specifications/07-connector-protocol.md) | ✅ Specified (HCP/1) |
| Promote "the policy wins" to a named principle | [`01-vision/principles.md`](../01-vision/principles.md) #11 | ✅ Done |
| Adopt the 14-field visa schema as design target | [`ai-agent-framework.md`](../04-ai-economy/ai-agent-framework.md) | ✅ Done |
| Add the application/substrate boundary statement | [`system-overview.md`](../02-architecture/system-overview.md) | ✅ Done |
| Add post-settlement / long-running intent obligations | [`ai-agent-framework.md`](../04-ai-economy/ai-agent-framework.md) | ✅ Done |
| Correct the connector risk classification (oracle, not custody) | [`attack-vectors.md`](../08-security/attack-vectors.md) §8b | ✅ Done |
| Connector profile ladder on the roadmap | [`phase3-ai-economy.md`](../09-roadmap/phase3-ai-economy.md) | ✅ Done |
| New research questions R-K1…R-K8 | [`open-problems.md`](../11-research/open-problems.md) §C2 | ✅ Done |
| **ADR: reconcile the two intent models** | `adr/0017-*` | ⬜ **Open — blocks G10** |
| Adopt the sharper mission sentence | `01-vision/mission.md` | ⬜ Low |

These are tracked as gate items in [`../16-action-plan.md`](../16-action-plan.md).

---

## Contributing to this folder

- One idea per file; prefix with a number.
- Always state **who** the idea came from and **when**.
- Always state that it is non-normative.
- When an idea graduates, write the ADR or RFC and link back to the note here — do not
  delete the note. The reasoning trail is the point.

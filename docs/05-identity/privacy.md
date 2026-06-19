# Privacy

## The privacy thesis

"Sovereignty by cryptographic proof" implies privacy: if any party can surveil all activity,
sovereignty is hollow. But Huxplex also requires **accountability** (agents traceable to
controllers, personhood for veto, provenance for content). Privacy and accountability are in
tension; the resolution is **selective disclosure via ZK** — reveal exactly what a context needs,
nothing more.

## Privacy by layer

| Layer | Default visibility | Privacy mechanism |
|---|---|---|
| Network (L0) | metadata (who talks to whom) | PQ-TLS encryption (🟢 primitives); mixnet/onion for intents (future) |
| State (L1) | resources/amounts public by default | shielded resources via ZK (nullifier model is shielded-ready) |
| Identity (L3) | DID ↔ activity linkable | ZK selective disclosure, unlinkable nullifiers |
| Governance | votes/holdings | unlinkable SVRGN voting (ZK) |
| Agent economy | agent ↔ controller linkable | accountable-anonymous agents (ZK) |

## What's private, what's not (design choices)

- **Transparent by default, shielded by choice.** Like most chains, the base ledger is public
  (auditable, simple). Users/agents *opt into* shielded resources for confidential amounts/
  parties. This is a deliberate tradeoff: full-privacy-by-default chains are harder to audit,
  reason about for compliance, and bootstrap. Revisit if the agent economy demands default
  privacy.
- **Identity is pseudonymous by default** (a DID is not a legal name), with ZK to break the
  *linkage* between a DID's actions where needed.
- **Provenance is intentionally public** (the point is verifiable origin) — but the *creator's
  other activity* stays unlinkable.

## The shielded-resource design

HRM's **nullifier** model is structurally similar to Zcash's shielded pool: consuming a resource
publishes a nullifier (preventing double-spend) without revealing *which* resource, and a ZK
proof attests the transaction is valid (conservation + ownership). To realize it:

- Nullifiers must be **unlinkable** to the resource and to each other (design the nullifier
  derivation with this from day one — a state-management open question).
- A ZK circuit proves: inputs exist in the state tree, owner authorized, kind-balance holds,
  nullifiers correctly derived — all without revealing amounts/owners.
- Uses zk-STARKs (PQ-safe). Cost is significant; shielded txs are heavier than transparent ones.

## Metadata privacy (often forgotten)

Encrypting payloads doesn't hide *who talks to whom* — a nation-state adversary does traffic
analysis. Mitigations (roadmap):

- **Intent overlay privacy**: route the `huxplex/intents` overlay through a mixnet/onion layer so
  agent demand isn't trivially mappable. 🔴
- **Dummy traffic / batching** for high-sensitivity flows.
- **DID rotation** to limit long-term linkability.

## Privacy vs. the regulatory reality

Strong privacy invites regulatory scrutiny (and strong surveillance invites the opposite). The
stance: **privacy is a user right, not a mandatory default**; shielded usage is opt-in;
selective-disclosure proofs let users *voluntarily* prove compliance (e.g., "this counterparty
is personhood-verified and in good standing") without blanket transparency. See
[`12-business/`](../12-business/) and [`08-security/`](../08-security/) for the regulatory risk
treatment.

## Design options

**Option A — Transparent base + opt-in ZK shielding (recommended).** Auditable, bootstrappable,
privacy where it matters. *Con*: most activity is public; metadata leakage.

**Option B — Private by default (Aleo/Aztec-like).** Strong privacy. *Con*: hard to audit/
bootstrap, heavy ZK cost on every tx, worse regulatory optics, harder agent-economy debugging.

**Option C — No on-chain privacy (transparent only).** Simple, auditable. *Con*: fails the
sovereignty thesis; surveillance-friendly. Rejected as an end state.

## MVP / Production / Future

- **MVP**: transparent ledger; PQ-encrypted transport (🟢); pseudonymous DIDs; design nullifiers
  to be shielding-ready.
- **Production**: opt-in shielded resources (ZK-STARK), unlinkable SVRGN voting, selective-
  disclosure credentials.
- **Future**: mixnet intent overlay, accountable-anonymous agents, dummy-traffic options,
  ZK-private reputation.

---

### Open Questions
- Transparent-default vs private-default for an *agent* economy — do machines need confidentiality more than humans?
- Unlinkable nullifier derivation that still supports fast double-spend checks — feasible at scale?
- How to migrate the crypto suite or ZK system without breaking shielded-pool unlinkability?
</content>

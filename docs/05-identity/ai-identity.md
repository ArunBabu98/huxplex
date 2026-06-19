# AI Identity

> Companion to [`04-ai-economy/agent-identity.md`](../04-ai-economy/agent-identity.md). That doc
> covers the agent-economy mechanics; this one covers the *identity-layer* design: how machine
> identity differs from human identity and what guarantees the protocol makes about it.

## Machine identity is delegated and accountable

The defining property: an AI identity is **not sovereign by default**. It is rooted in a human
or DAO **controller** and scoped by credentials. This is the opposite of human identity (which
*is* sovereign). The asymmetry is intentional — it is how the protocol keeps machine actors
steerable.

| Dimension | Human identity | AI identity |
|---|---|---|
| Root of trust | self + personhood | controller DID |
| Sovereignty | full | delegated, revocable |
| Governance | SVRGN (veto) | SNTNC (log-weighted, vetoable) |
| Provenance role | can create human-origin content | can create *machine-origin* content (labeled) |
| Identity proof | proof-of-personhood | proof-of-controllership + Work Visa |

## Machine provenance (the inverse of deepfake provenance)

Just as humans register **human-origin** content, agents register **machine-origin** content.
This is the deepfake-provenance use case from both directions:

- A human creator stamps content as human-made (provenance record, personhood-gated).
- An agent stamps content as machine-made (machine provenance, controller-attributed).

Together they let the world cryptographically distinguish biological from synthetic origin —
arguably one of Huxplex's most immediately useful features in an AI-saturated information
ecosystem. Both are immutable HRM resources (`quantity=1`, never consumed), signed with
ML-DSA-44 over a provenance context.

```
ProvenanceRecord {
  content_hash: SHAKE-256(content),
  creator: did:huxplex:…,
  origin: human | machine,
  timestamp_block,
  media_type,
  creator_sig: ML-DSA-44 over huxplex-{net}:provenance:v1,  // 🟢 context already defined
}
```

Note `huxplex-mainnet:provenance:v1` is **already among the tested context strings** — the
provenance primitive's signing discipline is in place.

## Identity for autonomous (controller-less) agents — the hard frontier

The vision gestures at fully autonomous agents. Identity-wise, an agent with *no* human
controller breaks the accountability chain. Options if/when this is allowed:

- **Bonded autonomy**: an agent posts a large slashable bond and operates under
  constitutional limits, with the bond as the accountability root instead of a human. 🔴
- **DAO-rooted**: the "controller" is a chartered DAO (which is human-rooted), not a single
  human — accountability is diffuse but present.
- **Never**: the conservative stance — every agent always has a human/DAO root. (Default for
  the foreseeable roadmap.)

**Recommendation**: default to controller-rooted; treat controller-less autonomy as a
constitutional question requiring SVRGN approval, not an engineering default.

## Class integrity (anti-spoofing)

The protocol must guarantee an agent cannot present as a human (to grab SVRGN/provenance-human).
Enforcement:

- `identityClass` in the DID document is **bound** to how the identity was created — human class
  requires a personhood proof the agent can't produce.
- SVRGN issuance and human-origin provenance both **check the personhood gate**, not a
  self-asserted flag.
- Cross-checks: an identity claiming `human` without a valid personhood nullifier is rejected.

## Privacy with accountability (ZK)

Linking every agent to a controller is great for accountability, bad for privacy. The
reconciliation is ZK: prove "this agent is controlled by a personhood-verified human in good
standing, with a valid non-revoked Work Visa" **without** revealing which human or which Visa.
Revocation/slashing still function via nullifiers. This "accountable anonymity" is the ideal end
state and a research item. See [zk-proofs](zk-proofs.md).

## MVP / Production / Future

- **MVP**: agent DID + explicit controller + class flag; machine provenance records (🟢 context);
  no privacy layer; no controller-less agents.
- **Production**: personhood-gated class integrity, machine vs human provenance, bounded
  sub-delegation, fast revocation.
- **Future**: ZK accountable-anonymity for agents, bonded controller-less autonomy under
  constitutional approval, cross-chain machine identity.

---

### Open Questions
- Should controller-less autonomous agents ever exist, and if so under what bond/constitutional gate?
- How to make machine-origin provenance robust against an agent laundering content through a human DID?
- Standard for ZK "good-standing controllership" proofs.
</content>

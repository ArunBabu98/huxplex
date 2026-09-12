# Principles

These are the load-bearing design principles. When a decision is hard, decide in the order
listed: earlier principles win ties.

## The three founding axioms (from the vision)

1. **Sovereignty by cryptographic proof.** Authority over identity, assets, and data derives
   from possession of keys and validity of proofs — never from a permissioned party who can
   revoke or decrypt. Security is *mathematical*, not *policy*.

2. **Temporal security.** Defend against "harvest now, decrypt later." PQ algorithms are a
   *baseline requirement at genesis*, not a future upgrade. Anything that touches long-lived
   secrets must assume a future CRQC adversary.

3. **Biological–machine parity with asymmetric veto.** Humans and AI agents participate as
   economic equals, but humans hold a non-negotiable, protocol-level veto. Machine
   acceleration must remain steerable by biological intelligence.

## Engineering principles (how we build)

4. **Crypto-agility over cryptographic perfection.** PQ standards are young and will evolve.
   No single algorithm may be load-bearing; every primitive is referenced through a versioned
   registry and can be rotated under governance. We would rather ship a "good enough" suite we
   can replace than the "perfect" suite we cannot. (This directly follows current NIST/IETF
   migration guidance favoring staged, agile PQ adoption.) See
   [`03-post-quantum/crypto-agility.md`](../03-post-quantum/crypto-agility.md).

5. **Determinism everywhere it touches consensus.** No floating point, no wall-clock
   nondeterminism, no unbounded loops in execution. Same inputs ⇒ same state, on every node,
   forever. This is what makes the chain auditable and the VM safe.

6. **Honest framing.** Never claim more than we can prove. "Sentience" is a narrow proxy
   metric. "Novelty" is a research signal, not truth. Disclaimers are features, not weakness.
   Overclaiming is an existential reputational risk for a chain that wants to last decades.

7. **Domain separation by default.** Every signature is bound to a context string
   (`huxplex-{net}:{purpose}:v{n}`). This is already implemented and tested in the codebase;
   it is the cheapest, highest-leverage defense against cross-protocol replay and confused-
   deputy attacks. Extend it to every new signed object.

8. **`#![forbid(unsafe_code)]` outside the crypto core.** Memory safety is a security
   property. The only place `unsafe` is tolerated is vetted, audited cryptographic primitive
   code, and even there it is isolated and minimized.

9. **Pruning and bounded state are first-class.** PQ signatures are large (2,420 B each).
   Witness/signature data must be separable (SegWit-style) and prunable after finality, or the
   chain's state and bandwidth grow until it dies. State growth is a security property.

10. **Build the chain before the economy.** The AI economy, identity, and governance layers
    are *applications of* a working chain. They do not enter the consensus-critical path until
    the chain is solid. Phase gates enforce this (see [`09-roadmap/`](../09-roadmap/)).

11. **The policy wins.** When an agent's judgement and its authorization disagree, the
    authorization wins — *including* when the agent is right. Authority is resolved **before**
    an effect is attempted, never negotiated during it, and no downstream component (executor,
    connector, external system) can widen it. Capability is not permission: an agent may be
    arbitrarily capable and still be unable to act outside its visa, because it was never given
    a capability that reaches there. This is the founder's formulation
    ([`brainstorming/`](../brainstorming/00-arun-babu-founding-notes.md) §Step 9) and the
    project's defining invariant — tested by
    [`16-action-plan.md`](../16-action-plan.md) G9-T1 and G11-T6.

## Governance & social principles (how we last)

12. **Minimize the trusted base.** Fewer privileged roles, fewer multisig escape hatches,
    fewer "the foundation can…" clauses. Every privilege is a future capture vector and an
    attacker's first target.

13. **Constitution over majoritarianism.** A small set of invariants (PQ-only, human veto
    exists, no infinite inflation, no retroactive seizure) sit above ordinary governance and
    cannot be amended by a simple vote. Decades-survival requires limits on what any
    momentary majority can do.

14. **Plutocracy resistance.** Machine governance weight is sub-linear (e.g. `log2(stake+1)`)
    and human governance (SVRGN) is one-person-one-vote and non-purchasable. Concentration of
    tokens must not equal concentration of control.

15. **Reproducibility and openness.** Reproducible builds, open specs, public research data,
    permissive license (Apache-2.0). Neutrality requires verifiability.

16. **Document the tradeoff, not the certainty.** When uncertain, write down options A/B/C
    with costs, pick one, and record an ADR. Future maintainers inherit reasoning, not just
    conclusions.

## Anti-principles (things we explicitly refuse)

- ❌ "Move fast and break consensus." Consensus changes are slow, audited, and ADR-gated.
- ❌ "Trust us, the foundation will…" Any design that requires trusting the team long-term is wrong.
- ❌ "We measure consciousness/sentience." We measure a proxy and say so loudly.
- ❌ "Add a bridge to bootstrap liquidity." Bridges are deferred and minimized.
- ❌ "Optimize the PQ parameters for size now." Agility first; parameters are swappable later.

---

### Open Questions
- Should principle 10 (chain-before-economy) ever be relaxed to attract early agent-builder mindshare? (Currently: no.)
- What exactly belongs in the unamendable constitution vs. ordinary governance? See [`07-governance/constitutional-layer.md`](../07-governance/constitutional-layer.md).
</content>

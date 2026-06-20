# 15 — Normative Specifications

> The precision layer between the blueprint and the compiler. Where [`02-architecture/`](../02-architecture/)
> says *what and why* in prose, these documents say *exactly how* — byte layouts, context
> strings, state-transition rules, wire formats, and the frozen v1 scope — at a level two
> independent engineers could implement against and get **byte-identical** results.

## Why this section exists

The blueprint is complete as narrative but under-specified for implementation. Consensus requires
that every node agree on exact bytes; "approximately the same encoding" is a chain split. This
section is the **conformance contract**: when code and a spec here disagree, that is a bug in one
of them, and the discrepancy MUST be resolved (not papered over).

## Normative language

These documents use [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / RFC 8174 keywords:
**MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **MAY**. A lowercase "must" is
prose, not a normative requirement.

## Status of each spec

| Spec | Covers | Grounding |
|---|---|---|
| [01 — Data model & encoding](01-data-model-and-encoding.md) | Canonical types, postcard codec, versioning, determinism rules | 🟡 specified; primitive types exist in code |
| [02 — Cryptography](02-cryptography-spec.md) | ML-DSA-44 / ML-KEM-768 / HKDF / SHAKE / BIP32, the **context-string registry**, key sizes, test vectors | 🟢 mostly implemented — this spec is derived from `src/crypto` and `src/network` |
| [03 — HRM state transition](03-hrm-state-transition.md) | Resources, nullifiers, validity predicates, the transition function | 🟡 specified, unbuilt |
| [04 — Consensus](04-consensus-spec.md) | Q-BFT messages, phases, the block-phase context strings, slashing conditions | 🟡 specified, unbuilt |
| [05 — Network wire protocol](05-network-wire-protocol.md) | Handshake sequence, peer lifecycle, gossip/DHT framing | 🟡 message types exist; transport unbuilt |
| [06 — v1 scope contract](06-v1-scope.md) | The frozen "Definition of Done" for v1 — what is in, what is explicitly out | 🟡 the anti-scope-creep contract |

## Relationship to ADRs

A spec says *what the rule is*; an [ADR](../adr/) says *why we chose it*. Each spec links the ADRs
that justify it. The specs most relevant ADRs:

- [ADR-0002](../adr/0002-cryptographic-parameter-set.md) — crypto suite & agility
- [ADR-0010](../adr/0010-hash-function-domains.md) — which hash where
- [ADR-0011](../adr/0011-canonical-serialization.md) — canonical encoding
- [ADR-0012](../adr/0012-network-transport.md) — transport
- [ADR-0013](../adr/0013-did-huxplex-method.md) — `did:huxplex`
- [ADR-0014](../adr/0014-validator-key-management.md) — validator keys

## Change control

Any change to a byte layout, context string, key size, or state-transition rule is a
**consensus-affecting change**: it MUST go through an [RFC](../rfc/), be recorded in an
[ADR](../adr/) if it reverses a prior decision, bump the relevant `:vN` version, and update both
the spec and the conformance tests in the same PR (enforced by the
[PR checklist](../../.github/pull_request_template.md)).

---

### Open Questions
- Which spec should be frozen first? (Recommendation: 02-cryptography, since it is already 🟢 in
  code and only needs byte-exact KAT fixtures committed.)
- Do we need a machine-readable schema (e.g. a `.proto`-like IDL) for the data model, or is the
  Rust `Codec` trait + this prose sufficient for a single implementation?

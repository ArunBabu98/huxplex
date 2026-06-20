# ADR-0013: The `did:huxplex` identity method

- Status: Accepted
- Date: 2026-06-21
- Deciders: Founding architect, identity

## Context

The identity docs ([`05-identity/`](../05-identity/)) and the AI-economy docs assume a
`did:huxplex` method (for human, AI-agent, and hybrid identities, and as the anchor for Work Visa
credentials), but the method itself is unspecified — there is no definition of the DID syntax,
how a DID resolves, or how it binds to the ML-DSA-44 keys the chain already uses. Before any
identity or credential code is written, the method needs a canonical definition consistent with
W3C DID Core and the existing crypto.

Forces:
- **Reuse existing key material** — identities must bind to ML-DSA-44 keys and the `PeerId`
  derivation already in the codebase, not introduce a parallel key system.
- **Post-quantum** — verification methods must be PQ (ML-DSA-44 hot, SLH-DSA for long-lived
  roots per ADR-0002); no Ed25519/secp256k1 verification methods.
- **Crypto-agility** — a DID's keys must be rotatable and the method must survive a suite
  migration (ADR-0002).
- **Decentralization** — resolution should not depend on a single registry; prefer
  self-certifying identifiers anchored on-chain.
- **Privacy** — must support pairwise/peer DIDs and selective disclosure; never require putting
  personal data on-chain (ties to risk #8 and the ZK-personhood line).

## Options

- **A — Reuse an existing method (`did:key`, `did:web`, `did:peer`).** No new spec. *Cost:*
  none of them natively model on-chain anchoring + governance-rotatable PQ keys + agent/human
  distinction the way Huxplex needs.
- **B — Define `did:huxplex` as a self-certifying, on-chain-anchored method** whose identifier is
  derived from an initial ML-DSA-44 key (reusing the `PeerId` hash), with the DID Document stored/
  resolved via chain state. Supports key rotation, multiple verification relationships, and a
  subject-type (human / agent / org / hybrid).
- **C — Centralized registry method.** Simple resolution. *Cost:* a single point of control/
  failure; contradicts the sovereignty thesis.

## Decision

**Option B — `did:huxplex`, a self-certifying, chain-anchored DID method.**

Syntax:
```
did:huxplex:<network>:<id>
# <network> ∈ { main, test }   (omit for main once stable, TBD in the spec)
# <id> = base32(SHAKE-256(initial_ML-DSA-44_verification_key)[..32])   — same digest as PeerId
```

Key points:
1. **Self-certifying genesis:** the initial `<id>` is the SHAKE-256 digest (ADR-0010) of the
   bootstrap ML-DSA-44 verification key — so a fresh DID is verifiable offline before any
   on-chain record exists, exactly mirroring `PeerId`.
2. **DID Document** lives in chain state (an HRM resource): it lists verification methods
   (ML-DSA-44 / SLH-DSA), their relationships (authentication, assertion, capabilityInvocation,
   keyAgreement via ML-KEM-768), services, and a `huxSubjectType` ∈ {`human`,`agent`,`org`,
   `hybrid`}. Update operations are themselves signed and chain-anchored, enabling **key
   rotation** without changing the identifier.
3. **Agent vs human:** agent DIDs MUST reference a controlling principal DID; Work Visa
   credentials ([04-ai-economy](../04-ai-economy/)) are Verifiable Credentials issued from a
   principal DID to an agent DID, signed over context `huxplex-{network}:vc:v1` (already reserved
   in the context registry).
4. **Privacy:** pairwise DIDs (no on-chain doc, `did:peer`-style) are supported for private
   relationships; proof-of-personhood is attached as a ZK credential, never raw biometrics
   on-chain (risk #8).
5. **Agility:** verification-method entries carry the algorithm-suite id (ADR-0002); a suite
   migration rotates keys via a normal signed update.

Full normative method spec (operations, resolution, ABNF) goes in `05-identity/` and references
this ADR.

## Consequences

- ➕ One identity system reusing ML-DSA-44 + the `PeerId` digest; a node's `PeerId` and its
  `did:huxplex` id share a derivation, reducing concepts.
- ➕ Offline-verifiable genesis + on-chain rotation + agent/principal modeling in one method.
- ➕ W3C DID Core-compatible, so standard VC tooling can interoperate.
- ➖ Requires chain state to exist for full resolution (DID Docs are HRM resources) — until then
  only self-certifying `did:peer`-style use works.
- ➖ Another spec surface to maintain and eventually register in the W3C DID method registry.

## Links
- [decentralized-identity](../05-identity/decentralized-identity.md),
  [human-identity](../05-identity/human-identity.md), [ai-identity](../05-identity/ai-identity.md)
- [ADR-0002](0002-cryptographic-parameter-set.md), [ADR-0003 (HRM)](0003-state-model-hrm.md), [ADR-0010 (hash)](0010-hash-function-domains.md)
- W3C DID Core 1.0; context `huxplex-{network}:vc:v1`

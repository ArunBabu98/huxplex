# Decentralized Identity

## The `did:huxplex` method

Every entity — human, agent, validator, DAO — anchors a self-certifying identity:

```
did:huxplex:{chain_id}:{ SHAKE-256(ml_dsa44_pk)[0..32] as hex }
```

This **reuses the exact primitive already implemented** for PeerId
(`SHAKE-256(pk)[..32]`, 🟢 `network/peer.rs`) — identity, peer id, and address are the same
construction. The DID is self-certifying: the identifier *is* a commitment to the controlling
PQ public key, verifiable without a registry.

### DID document

```
DID Document {
  id: did:huxplex:…,
  controller: did:…,                 // self for humans; controller for agents
  verificationMethod: [              // ML-DSA-44 keys (algo_suite-versioned)
    { id, type: MlDsa44VerificationKey, publicKeyMultibase, algo_suite } ],
  authentication: [ #key-1 ],
  capabilityDelegation: [ … ],        // Work Visa delegation references
  service: [ … ],                     // endpoints
  alsoKnownAs: [ … ],                 // cross-chain / linked identities
  identityClass: human | agent | validator | dao,
}
```

The document is itself an HRM resource (or anchored by one), updated by controller-signed
transactions. Key rotation = add/retire a `verificationMethod` — the same mechanism that carries
identity across a crypto-suite migration ([`03-post-quantum/migration-strategy.md`](../03-post-quantum/migration-strategy.md)).

## Why W3C DID/VC, not a bespoke scheme

- **Interoperability**: W3C DIDs/VCs are the emerging standard; aligning eases wallet,
  credential, and cross-chain tooling.
- **Separation of identity from keys**: a DID outlives any single key (rotation, migration).
- **Credentials as first-class**: Work Visas and provenance records are Verifiable Credentials.

We adapt the standards' crypto suites to PQ (ML-DSA verification methods) — the data model is
standard, the cryptography is post-quantum.

## Identity classes & their roots of trust

```mermaid
graph TD
    subgraph Humans
      H[Human DID] --> HP[Root: self + proof-of-personhood]
      HP --> SV[Eligible for SVRGN]
    end
    subgraph Agents
      A[Agent DID] --> AC[Root: controller DID]
      AC --> WV[Work Visa scopes authority]
    end
    subgraph Validators
      V[Validator DID] --> VC[Root: SLH-DSA cold key]
    end
    subgraph DAOs
      D[DAO DID] --> DC[Root: multi-key / charter]
    end
```

The class is consequential: only **human** DIDs (personhood-verified) can hold SVRGN and create
human-origin provenance; only **agent** DIDs carry Work Visas; only **validator** DIDs join
consensus. Class must be hard to forge — see [human-identity](human-identity.md).

## Credentials anchored to identity

| Credential | Subject | Issuer | Doc |
|---|---|---|---|
| **Work Visa** | agent | human/DAO | [`04-ai-economy/ai-agent-framework.md`](../04-ai-economy/ai-agent-framework.md) |
| **Provenance record** | content | human creator | [privacy](privacy.md) §provenance |
| **Personhood credential** | human | personhood protocol | [human-identity](human-identity.md) |
| **Validator registration** | validator | self (SLH-DSA) + stake | [`13-operational/validator-guide.md`](../13-operational/validator-guide.md) |

## Cross-chain identity

`alsoKnownAs` + signed attestations let a `did:huxplex` link to identities on other chains/
systems. Cross-chain *proofs* (not bridges) — a light client + PQ-signed attestation — are
preferred over custodial bridges (bridges are the #1 loss vector; see
[`08-security/attack-vectors.md`](../08-security/attack-vectors.md)). Cross-chain identity is a
Future item.

## Design options

**Option A — `did:huxplex` reusing SHAKE-256(pk) (recommended).** Self-certifying, zero new
crypto, aligned with existing PeerId. *Con*: rotating keys needs a DID-doc indirection (handled).

**Option B — Registry/namespace DIDs (did:web-like).** Human-readable names. *Con*: introduces a
naming authority / centralization; defer human-readable names to an optional naming layer.

**Option C — Pure key-as-identity (no DID doc).** Simplest. *Con*: no rotation, no migration, no
credentials — fails the decade-survival and agent-control requirements. Rejected.

## MVP / Production / Future

- **MVP**: `did:huxplex` = SHAKE-256(pk) (🟢), minimal DID doc as an HRM resource, controller
  field, single key.
- **Production**: full DID doc with rotation + capabilityDelegation, Work Visa & provenance VCs,
  identity classes with personhood gate.
- **Future**: cross-chain identity via PQ light-client proofs, optional human-readable naming,
  ZK selective disclosure of credentials.

---

### Open Questions
- Anchor DID docs as a dedicated system resource or general HRM resources with a reserved kind?
- Human-readable naming without reintroducing a central authority?
- VC format: adopt W3C VC-DATA-MODEL 2.0 verbatim with PQ suites, or a leaner on-chain encoding?
</content>

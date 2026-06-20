# 06 — v1 Scope Contract ("Definition of Done")

> Normative for *scope*, not bytes. This is the frozen contract for what **v1** is — and, just as
> importantly, what it is **not**. Its single job is to make scope creep (risk #1, "scope
> collapse") cost something: if work isn't in the "In" list, it is out of v1 by definition, and
> moving it in requires editing this file via RFC. Aligned with the readme's v1 and
> [09-roadmap/phase1-testnet](../09-roadmap/phase1-testnet.md).

## 1. The one-sentence definition

> **v1 is a 3–5 node devnet that produces blocks under Q-BFT, signing every block and vote with
> ML-DSA-44 over domain-separated contexts, executing transactions against a single-shard HRM
> ledger with post-finality signature pruning, and exporting research metrics — with ZERO
> AI-economy or "sentience" features on the consensus-critical path.**

This restates the executive summary's "what good looks like in 12 months." Everything below
elaborates it into a checklist.

## 2. In scope for v1 (the Definition of Done)

A v1 release is "done" when **all** of these are true and tested:

### Cryptography & encoding (mostly 🟢 today)
- [x] ML-DSA-44 sign/verify with context strings (exists)
- [x] ML-KEM-768 + HKDF session derivation (exists)
- [x] BIP32 → ML-DSA seed derivation (exists)
- [ ] Byte-exact KAT fixtures committed (crypto spec §7 task R-CRYPTO-KAT)
- [ ] Canonical `Codec` (postcard) + canonical-decode for all consensus types ([ADR-0011](../adr/0011-canonical-serialization.md))
- [ ] Hash domains wired per [ADR-0010](../adr/0010-hash-function-domains.md)

### Ledger & execution
- [ ] HRM single-shard state: CommitmentSet + NullifierSet with JMT `state_root` ([03](03-hrm-state-transition.md))
- [ ] Transaction STF with signature-logic (eUTXO subset); HuxVM program-logic MAY be stubbed
- [ ] Post-finality signature pruning (witnesses excluded from `TxId`)
- [ ] Multi-dimensional `TxWeight` accounting

### Consensus & networking
- [ ] Q-BFT three-phase commit with QCs over the block-phase contexts ([04](04-consensus-spec.md))
- [ ] Anti-double-sign signer guard + slashing for double-sign and causal regression
- [ ] Round-robin / classical-randomness leader (LB-VRF deferred)
- [ ] libp2p/QUIC transport + PQ-hybrid handshake + signed gossip/DHT ([05](05-network-wire-protocol.md))
- [ ] 3–5 nodes produce and finalize blocks on a local devnet

### Economy (minimal, on-chain but simple)
- [ ] Basic staking with HUX; slashing wired to the conditions above
- [ ] Burn-based fee accounting (the $PLEX/HUX burn research instrument)
- [ ] Soulbound merit (SNTNC) accrual MAY exist **only** as an off-critical-path, opt-in record
      ([ADR-0007](../adr/0007-sentience-framing.md)) — it MUST NOT affect consensus

### Operability & research output
- [ ] Validator key custody per [ADR-0014](../adr/0014-validator-key-management.md)
- [ ] Metrics export: PQ signature overhead, block time, parallel-execution speedup, state growth
- [ ] Basic governance parameter voting (param changes only)

## 3. Explicitly OUT of scope for v1

These are real project goals but are **forbidden in v1** to protect the schedule and the
consensus-critical path:

- ❌ The AI agent economy: intents/solvers marketplace, Work Visa enforcement, agent reputation
  markets (identity/credential *types* may exist; the *economy* does not)
- ❌ "Proof of Sentience" / novelty scoring as anything consensus-affecting
- ❌ zk-STARK task proofs / ZK proof-of-personhood
- ❌ Multi-shard / cross-shard atomicity (single shard only; stay forward-compatible)
- ❌ Cross-chain bridges (risk #9 — deferred indefinitely)
- ❌ Biometric DIDs / human personhood registration
- ❌ Hive-Mind governance lifecycle beyond parameter voting; biological veto wiring beyond a
  treasury cap stub
- ❌ Public testnet/mainnet launch, token sale, or any production use
- ❌ LB-VRF / PQ-SSLE leader election (classical fallback is fine for v1)
- ❌ Dynamic economic auto-balancing, AI governors, yield curves

## 4. Exit criteria (how we know v1 is done)

1. A 3–5 node devnet runs for ≥ 24h producing and finalizing blocks without a safety fault.
2. All §2 checkboxes are checked, each backed by tests in CI.
3. A short **research report** is published from the exported metrics (PQ overhead, throughput,
   parallel speedup) — v1's actual deliverable is *data*, per the readme's "the chain is a dataset
   generator."
4. A security self-review of the consensus + crypto path is complete (external audit is a
   *mainnet* gate, not a v1 gate).

## 5. Changing this contract
Adding anything to §2 or removing anything from §3 is a scope change: it REQUIRES an
[RFC](../rfc/) and an update to this file and the [roadmap](../09-roadmap/). "While we're here"
additions are exactly the failure mode this document exists to prevent.

---

### Open Questions
- Is even *basic staking + slashing* too much for a first devnet milestone, or the right minimum
  to study the economic questions? (Could split into v1a "chain" / v1b "economy".)
- Should HuxVM program-logic be in v1 at all, or is signature-logic-only the honest MVP (with
  HuxVM as v1.x)?
- What exact metrics constitute a publishable v1 research report (defines "done" criterion #3)?

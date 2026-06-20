# ADR-0014: Validator key management & custody

- Status: Accepted
- Date: 2026-06-21
- Deciders: Founding architect, security, operations

## Context

[ADR-0002](0002-cryptographic-parameter-set.md) split signing roles — **ML-DSA-44** for hot
per-block/per-vote signing, **SLH-DSA-128s** for long-lived validator identity/root-of-trust —
but did not say how those keys are *generated, stored, separated, rotated, or recovered* in
operation. The codebase derives ML-DSA seeds from a BIP32 path
(`m/44'/931931'/0'/0'/{i}'`, `src/crypto/bip32.rs`) from a 64-byte master seed, which gives us a
deterministic hierarchy to build custody on. Before validators run (devnet, Phase 1), the
operational key model must be fixed, because key-handling mistakes (double-sign, key theft,
unrecoverable loss) are slashing events and the #1 operational risk for stakers.

Forces:
- **Hot/cold separation** — the always-online signing key is the most exposed; the
  identity/stake-authority key must be able to stay offline.
- **Anti-double-sign** — the hot signer must be structurally prevented from signing two
  conflicting messages at the same height/round (equivocation = slashing).
- **Recoverability** — operators must be able to recover or rotate after key loss/compromise
  without losing identity or stake where the design allows.
- **Agility** — keys must be rotatable under a suite migration (ADR-0002) without re-bootstrapping
  identity.
- **Determinism vs. exposure** — BIP32 derivation is convenient but means the master seed is a
  single catastrophic secret; it must never touch a hot machine.

## Options

- **A — Single ML-DSA-44 key for everything.** Simplest. *Cost:* identity == hot key; one
  compromise loses identity and stake; no offline root.
- **B — Three-tier hierarchy:** offline **master seed** (BIP32 root) → **SLH-DSA identity/stake
  key** (cold, hardware/airgap) → **ML-DSA-44 session signing key(s)** (hot, rotatable), with an
  external **anti-double-sign guard** (slashing-protection DB / remote signer). *Cost:* more
  operational complexity and tooling.
- **C — Threshold/MPC hot signing.** Strongest against single-host compromise. *Cost:* PQ
  threshold signatures for ML-DSA are immature; premature for devnet.

## Decision

**Option B — a three-tier hot/cold hierarchy with an anti-double-sign guard.** (Threshold/MPC,
Option C, is deferred as future hardening, tracked in [11-research](../11-research/).)

| Tier | Key | Custody | Role |
|---|---|---|---|
| Root | 64-byte master seed (BIP32) | **Offline / airgapped**, backed up (e.g. Shamir split) | Derives all keys; never on a validator host |
| Identity | **SLH-DSA-128s** | **Cold** (hardware token / airgap) | Long-lived validator identity, stake authority, authorizes session-key rotation |
| Session | **ML-DSA-44**, derived at `m/44'/931931'/0'/0'/{i}'` (index = key epoch) | **Hot** (validator host / remote signer) | Per-block/vote signing over the block-phase contexts |

Rules:
1. **The hot session key never authorizes stake movement or identity change** — those require the
   cold SLH-DSA identity key.
2. **Rotation:** bump the BIP32 index `{i}` to mint a new session key; the cold identity key signs
   a `huxplex-{network}:validator:registration:v1` record binding the new session key to the
   validator. Mandatory rotation each key epoch and immediately on suspected compromise.
3. **Anti-double-sign guard (mandatory):** the signer maintains a persistent, monotonic
   high-water mark of `(height, round, phase)` and MUST refuse to sign anything not strictly
   advancing it. Implemented as a slashing-protection DB in front of (ideally) a separate
   remote-signer process, so a compromised consensus binary still cannot equivocate.
4. **The master seed MUST NOT be present on any online validator host.** Session keys are
   exported to the host; the root/identity tiers stay offline.
5. **Agility:** the SLH-DSA identity and ML-DSA-44 session roles are suite-versioned (ADR-0002);
   a migration rotates keys through the same cold-authorized registration flow.

## Consequences

- ➕ A hot-key compromise loses (at most) recent signing ability, not identity or stake; the cold
  key can rotate the session key and continue.
- ➕ Anti-double-sign is enforced by an independent guard, not by trusting the consensus code path.
- ➕ Reuses the existing BIP32 derivation and the `validator:registration:v1` context already in
  the codebase.
- ➖ More moving parts: airgap procedures, remote signer, slashing-protection DB — to be covered
  in [13-operational/validator-guide](../13-operational/validator-guide.md).
- ➖ BIP32 master seed is a single high-value secret; backup/Shamir procedures are mandatory and
  must be operator-documented.
- ➖ No threshold protection yet for the hot key (accepted for devnet; revisit for mainnet).

## Links
- [ADR-0002 (signing roles)](0002-cryptographic-parameter-set.md),
  [key-management (PQ)](../03-post-quantum/key-management.md),
  [validator-guide](../13-operational/validator-guide.md),
  [disaster-recovery](../13-operational/disaster-recovery.md)
- Code: `src/crypto/bip32.rs`; contexts `validator:registration:v1`, `block:{preprepare,prepare,commit}:v1`

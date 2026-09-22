# ADR-0014: Validator key management & custody

- Status: Accepted
- Date: 2026-06-21
- Deciders: Founding architect, security, operations

## Context

[ADR-0002](0002-cryptographic-parameter-set.md) split signing roles — **ML-DSA-44** for hot
per-block/per-vote signing, **SLH-DSA-128s** for long-lived validator identity/root-of-trust —
but did not say how those keys are *generated, stored, separated, rotated, or recovered* in
operation. The codebase derives ML-DSA seeds from a BIP32 path
(`m/44'/931931'/0'/0'/{i}'`, `crates/hux-crypto/src/bip32.rs`) from a 64-byte master seed, which gives us a
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

## Review note — 2026-09-22

The Layer-0 technology review
([`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md))
**validates the three-tier hierarchy** and adds two constraints that the tier structure can
absorb but that the ADR does not yet quantify:

1. **Rotation cadence is now a cryptographic parameter, not an operational preference.**
   eprint 2026/1366 demonstrates ML-DSA secret-key recovery from sign leakage at **190,000
   signatures**. A validator signing every block and every vote phase produces on the order of
   10⁵ signatures per day, so that bound is reached in **days**. Rule 2 above ("mandatory
   rotation each key epoch") is correct; the key epoch must now be **sized from this bound with
   margin** and stated as a protocol parameter. The hot/cold split means the cost of hitting it
   is a rotation, not an identity loss — the structural decision was right.
2. **Future quorum-certificate aggregation constrains the key hierarchy.** Every viable PQ
   aggregation candidate (Chipmunk, Lemur+, DKKW/LeanSig) is **synchronized or stateful**: it
   requires pre-committed, time-indexed key material with a declared lifetime — Lemur+ quotes 42
   years. That cannot be retrofitted onto a plain ML-DSA session key. If R-A1 is ever to be
   resolved with aggregation, the session-key derivation must be aggregation-compatible **now**,
   while there are zero validators to migrate. Proposed `adr/0021-*`.

   ⚠️ **These two pull in opposite directions** — a 42-year committed key lifetime against a
   rotation cadence measured in days. Resolving that tension is the substance of the proposed
   ADR, not an afterthought to it.

### Amendment — 2026-09-22: the derivation path gains a purpose level

✅ **Decided.** The path in the *Session* tier above becomes
**`m/44'/931931'/{purpose}'/0'/{index}'`**, where `{purpose}` matches the signature roles of
[ADR-0018](0018-signature-role-profiles.md): `0'` Transaction, `1'` QuorumCert (**reserved**),
`2'` Identity, `3'` Governance. Consequences for this ADR:

- **Rule 2 (rotation) is unchanged.** `{index}` remains the key epoch and still rotates by
  increment; only its parent level is new.
- **Rule 4 and the tier table stand.** The master seed still derives everything and still never
  touches an online host.
- **Rule: a validator may hold more than one key.** The `validator:registration:v1` record MUST
  be able to bind several purposes, not exactly one session key. This is the substantive change.
- **`purpose = 0'` is byte-identical to the previous path**, so no derived key, KAT fixture or
  test vector changes (🟢 `test_transaction_purpose_reproduces_the_original_path`).

**Why now rather than at G6.** Changing a derivation path changes every key derived from it.
G1 commits byte-exact KAT fixtures (R-CRYPTO-KAT); after that, a path change is a migration for
every validator. The purpose level is therefore added *before* the fixtures exist — the same
closing-window argument as [ADR-0018](0018-signature-role-profiles.md), on the key-derivation
axis instead of the descriptor axis.

**What this does not decide.** Not Chipmunk vs Lemur+ vs STARK-compressed; not whether to
aggregate at all; not any key lifetime. Purpose `1'` is reserved and unused. The hypothesis it
preserves — that the sign-leakage bound binds the *lattice* session key while an aggregation key
is a structurally different object with different leakage properties — remains to be verified
against the candidate constructions, and is the substance of `adr/0021-*`.

### Amendment — 2026-09-22: rotation cadence (closes R-A9)

✅ **Decided.** Rule 2's "mandatory rotation each key epoch" now has a definition:

> **A `Transaction`-purpose session key MUST be rotated after 50,000 signatures or 7 days,
> whichever comes first.**

| | Value | Why |
|---|---|---|
| Primary trigger | **50,000 signatures** | The demonstrated ML-DSA sign-leakage key recovery needs ~190,000 signatures (eprint 2026/1366). 50k leaves ≈4× margin against a published attack that will only improve |
| Secondary cap | **7 days** | Bounds exposure for low-throughput validators, where a count-only rule could leave one key live for months |
| Mechanism | increment the BIP32 index `{i}`; the cold SLH-DSA identity key signs a new `validator:registration:v1` | unchanged from rule 2 |

**The trade being made.** Rotation is not free: each one requires the **cold** identity key, so
the cadence is a safety-versus-operational-burden choice, not a purely technical one. 50k/7d puts
a routine airgap operation on roughly a weekly cadence for an active validator. Both numbers are
governance parameters and may be tuned with evidence; the 4× margin is the property to preserve,
not the literal 50,000.

**Scope.** This binds the `Transaction` purpose. `Identity` (SLH-DSA, cold) rotates on
compromise or suite migration only. `Transport` (ADR-0019) rotates on its own schedule — it signs
handshakes, not blocks, at a far lower rate — and `QuorumCert` is unused pending `adr/0021-*`,
where the tension between this cadence and multi-year committed aggregation keys must be
resolved.

## Links
- [ADR-0002 (signing roles)](0002-cryptographic-parameter-set.md),
  2026 review: [`brainstorming/01-layer0-technology-review-2026.md`](../brainstorming/01-layer0-technology-review-2026.md) §4, §5,
  [key-management (PQ)](../03-post-quantum/key-management.md),
  [validator-guide](../13-operational/validator-guide.md),
  [disaster-recovery](../13-operational/disaster-recovery.md)
- Code: `crates/hux-crypto/src/bip32.rs`; contexts `validator:registration:v1`, `block:{preprepare,prepare,commit}:v1`

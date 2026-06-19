# Validator Onboarding Checklist

A step-by-step onboarding companion to the [validator-guide](../13-operational/validator-guide.md)
(which explains the *why*). This is the *do-this-in-order* checklist. 🟡 = depends on
not-yet-built components.

## Stage 0 — Decide & prepare

- [ ] Read [validator-guide](../13-operational/validator-guide.md),
      [staking](../06-tokenomics/staking.md), [incident-response](../08-security/incident-response.md).
- [ ] Confirm you can meet uptime + security + monitoring + incident-response commitments.
- [ ] Provision hardware (16+ cores, 32–64 GB RAM, 1–2 TB NVMe, 1 Gbps low-latency) — sized for PQ
      bandwidth + parallel execution.
- [ ] Acquire HSM / air-gapped device for the cold identity key.

## Stage 1 — Keys (do this carefully)

- [ ] Generate BIP39 mnemonic → master seed **offline**; back up in ≥2 secure locations.
- [ ] Derive/generate **cold identity key (SLH-DSA-128s 🟡)**; store air-gapped / in HSM.
- [ ] Derive **hot block-signing key (ML-DSA-44 🟢)** via `m/44'/931931'/…`.
- [ ] Verify: cold key can authorize a hot-key rotation (test on testnet first).
- [ ] Confirm failover design guarantees **no simultaneous double-signing** (mutual exclusion).

## Stage 2 — Stake & register 🟡

- [ ] Acquire and self-bond the minimum HUX stake.
- [ ] (Optional) Set commission; attract delegations.
- [ ] Submit validator registration (cold key + stake + endpoint metadata).

## Stage 3 — Node setup

- [ ] Install a **verified** client release; **check the reproducible-build hash** against the
      governance proposal.
- [ ] Configure network (`testnet`/`mainnet` — this is a signing domain!), peers, ports, storage,
      crypto-suite floor.
- [ ] Set up the **sentry topology** (validator peers only with its sentries) to resist DDoS/eclipse.
- [ ] Sync via **state-sync from a signed snapshot**, then live.

## Stage 4 — Monitoring & resilience (before going active)

- [ ] Metrics + alerting live ([monitoring](../13-operational/monitoring.md)); critical alerts wired
      (missed votes, finality lag, **your own double-sign risk**, disk/bandwidth).
- [ ] Backups configured + **restore-tested** ([disaster-recovery](../13-operational/disaster-recovery.md)).
- [ ] Incident runbooks on hand; on-call defined; out-of-band operator comms joined.

## Stage 5 — Go active

- [ ] Join the validator set at the next epoch boundary.
- [ ] Confirm you are signing blocks (commit votes over `…:block:commit:v1`) and earning rewards.
- [ ] Monitor for the first full epoch before considering yourself stable.

## Ongoing duties

- [ ] Apply governed upgrades **before activation height**; verify hashes.
- [ ] Rotate hot key per epoch; protect cold key.
- [ ] Participate in governance (especially upgrades + crypto-suite migrations).
- [ ] Maintain uptime; respond to incidents; keep monitoring green.

## Golden rules

1. **Better down than double-signing** — never run the hot key on two nodes at once.
2. **Never run unverified client code** — verify the reproducible-build hash.
3. **Back up the mnemonic / cold key offline** — it has no other backstop.
4. **Set the right network** — it's a signing domain; a mistake can't cross-replay but will get you
   out of consensus.

---

*Specific commands, config files, and reference sentry topology will accompany the Phase-1 testnet
release; this checklist captures the durable procedure.*
</content>

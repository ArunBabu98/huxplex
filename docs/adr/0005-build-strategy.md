# ADR-0005: Custom Rust workspace, not Substrate

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect

## Context

Should Huxplex build on an existing framework (Substrate, Cosmos SDK) or as a custom Rust stack?
The chain is PQ-native, HRM-based, with custom consensus (Q-BFT) and execution (HuxVM) — none of
which match framework defaults. The existing code is already a standalone Rust crate.

## Options

- **A — Substrate (Polkadot SDK).** Mature framework, forkless runtime upgrades, FRAME pallets.
  *Cons*: classical crypto baked in (sr25519/ed25519), account model assumed, GRANDPA/BABE
  classical; going PQ-native + HRM means replacing the parts that *are* Substrate.
- **B — Cosmos SDK + CometBFT.** CometBFT is sig-agnostic (attractive). *Cons*: SDK assumes
  account/bank model + ed25519 defaults; HRM + S-EUTXO + PQ keys fight the grain.
- **C — Custom Rust workspace.** Maximum fit; own the differentiators (consensus/state/exec).
  *Cons*: most engineering effort; must build upgrade/runtime tooling ourselves.

## Decision

**Option C — custom Rust workspace** ([repository-structure](../10-development/repository-structure.md)),
*reusing mature libraries* (`libp2p`, `wasmtime`/`wasmi`, `rocksdb`, `libcrux`) but owning
consensus, state, and execution. We may borrow CometBFT/HotStuff *algorithms* (ADR-0004) without
adopting a framework.

Rationale: Huxplex's defining properties (PQ-native, HRM, Q-BFT, HuxVM, crypto-agility) are
exactly the parts a framework fixes for you with the *wrong* choices. Building on a framework
would mean fighting it precisely where our value lives. The existing crypto/network code is
already framework-free and on-path.

## Consequences

- ➕ Full control over PQ-native + HRM + agility; no framework lock-in to classical assumptions.
- ➕ Existing code slots in as crate 0.
- ➖ Must build what frameworks give free: runtime upgrades, tooling, some boilerplate. (Mitigated:
  governed time-locked binary releases approximate forkless upgrades; evaluate an on-chain
  upgradable runtime module later — [protocol-upgrades](../07-governance/protocol-upgrades.md).)
- ➖ Higher engineering burden — sharpens the solo-vs-team question (R-F2).

## Amendment — 2026-09-22: the workspace split happens at G0/G1, not later

✅ **Decided.** [repository-structure.md](../10-development/repository-structure.md) described the
target workspace but left the *timing* open. The split is now scheduled as part of closing **G0**,
immediately before the agility registry is written.

**Why now.** G0 item 4 (splitting the 3,607-line `src/crypto/mod.rs`) is outstanding regardless,
so the code is being moved either way — one disruption instead of two. More importantly,
[ADR-0018](0018-signature-role-profiles.md)'s `(role, version)` registry *is* `hux-crypto`'s
public surface; drawing the crate boundary while designing that surface is cheaper than moving it
afterwards, and the downward-only dependency rule can be wired into CI once.

**Scope of the split at this gate** — steps 1 and 2 of the migration plan only:

```
huxplex/
├── Cargo.toml              # [workspace]
└── crates/
    ├── hux-crypto/         # ← src/crypto  (+ the agility registry, G1)
    └── hux-network/        # ← src/network (+ the transport, G5)
```

`hux-types` and everything above it wait for G2 and later, per the existing migration plan. No
rewrite: the move is mechanical, and the 108 passing tests are the regression harness for it.

## Links
- [repository-structure](../10-development/repository-structure.md), [consensus](../02-architecture/consensus.md)
- Implementation plan: [`18-implementation-plan/00-workspace-migration.md`](../18-implementation-plan/00-workspace-migration.md)
</content>

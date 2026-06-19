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

## Links
- [repository-structure](../10-development/repository-structure.md), [consensus](../02-architecture/consensus.md)
</content>

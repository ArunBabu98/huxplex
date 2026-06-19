# Coding Standards

Standards for a codebase that must be **correct, auditable, and deterministic** for decades.
Brevity here; the *why* is in [`01-vision/principles.md`](../01-vision/principles.md).

## Language & toolchain

- **Rust**, pinned via `rust-toolchain.toml` (reproducibility). Edition 2024 (as current repo).
- **`#![forbid(unsafe_code)]`** in every crate **except** `hux-crypto`'s vetted primitive layer,
  where `unsafe` is isolated, justified with `// SAFETY:` comments, and audited (Principle #8).
- **`#![deny(warnings)]`** in CI; `clippy` clean (`-D warnings`); `rustfmt` enforced.
- MSRV declared and tested.

## Determinism rules (consensus-critical — non-negotiable)

Anything that touches state transition or consensus:

- ❌ No floating point in consensus/execution paths (HuxVM enforces; lint flags `f32/f64`).
- ❌ No `HashMap`/`HashSet` iteration in consensus output (random order) — use `BTreeMap`/sorted.
- ❌ No wall-clock time, threads, RNG, or environment in deterministic paths (inject them).
- ❌ No platform-dependent behavior (sizes, endianness) — explicit, fixed encodings.
- ✅ **Canonical serialization** (`postcard`/`bincode` with a canonical config); round-trip tested.
- ✅ Same input ⇒ same bytes ⇒ same hash ⇒ same root, on every node. Differential-tested (T27).

## Error handling

- `thiserror` for library errors (the repo already does this well — `CryptoError`, `NetworkError`).
- No `unwrap()`/`expect()`/`panic!` in node/consensus/validation paths — return `Result`. (The
  current code uses `expect` in `bip32.rs` derivation and tests; node-path code must not.)
- Panics are reserved for truly unreachable invariants, with a message; a panic in consensus is a
  liveness bug.
- Errors are typed and exhaustive; no stringly-typed control flow.

## Cryptography rules

- **No homemade crypto** — compose standardized primitives only (Principle: §crypto).
- **Constant-time** for secret-dependent operations; no secret-dependent branches/indexing.
- Secrets in **zeroizing** wrappers (`zeroize`); never logged, never `Debug`-printed.
  ⚠️ Current `PrivateKey { bytes: Vec<u8> }` derives `Debug` and isn't zeroizing — **fix before
  Production** (backlog).
- All primitives go through the **agility registry** — no hard-coded algorithm calls in higher
  crates. ⚠️ Current `publickey.rs`/`signature.rs` hard-code `[u8; 1312]`/`[u8; 2420]` — these
  move behind the suite descriptor.
- **Domain separation** for every signed object via context strings (the repo's strongest
  existing pattern — extend it; never add an unbound signature).

## Concurrency

- Prefer message-passing/`async` (tokio) over shared mutable state.
- Deterministic-execution code is **single-logical-thread per group** (TCHAO groups parallelize,
  but each group's result is deterministic and the merge is order-independent).
- Concurrency tested with `loom` (named in the tech stack) for lock-free/atomic code.

## API & module design

- Minimal public surface; `pub(crate)` by default.
- Downward-only crate dependencies (no cycles — CI-enforced; see
  [repository-structure](repository-structure.md)).
- Traits for swappable infra (`Vm`, `StateStore`, `Signer`/`Verifier`/`Kem`) — agility extends to
  implementations.
- Newtypes over primitive obsession (`Hash`, `PeerId` (🟢), `ResourceId`, `Epoch`) — the repo's
  `PeerId`/`GossipTopic` newtypes are the right instinct.

## Documentation

- Every public item has a doc comment; `#![deny(missing_docs)]` on library crates.
- Each crate README links to its `/docs` section.
- Non-obvious decisions reference an ADR (`// see ADR-000X`).
- Security-relevant invariants get a `// INVARIANT:` comment + a test that enforces them.

## Testing expectations (detail in [testing-strategy](testing-strategy.md))

- Unit tests co-located (`#[cfg(test)]`) — the repo's existing pattern, and its crypto suite is
  exemplary (cross-context replay, randomized-signing, byte-tamper, multi-validator).
- Property tests (`proptest`) for invariants; fuzz targets for parsers/VM; KATs for crypto.
- New consensus/crypto code requires negative tests (tamper, downgrade, cross-context).

## Commit & review

- Conventional Commits; signed commits encouraged (PQ-signed releases later).
- Every PR: green CI, ≥1 review (≥2 + security review for consensus/crypto), linked issue/RFC.
- No direct pushes to the default branch.
- Consensus/crypto/economic changes require an **RFC** ([`../rfc/`](../rfc/)) and often an **ADR**.

---

### Open Questions
- Adopt `cargo-vet` and/or `cargo-crev` for dependency trust from day one? (Recommended — supply chain T20.)
- Enforce a "no new `unsafe` outside hux-crypto" CI gate mechanically (e.g., `cargo-geiger`)?
</content>

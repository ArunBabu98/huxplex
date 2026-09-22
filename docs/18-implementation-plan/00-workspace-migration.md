# 00 — Workspace migration

> Single crate → Cargo workspace. Per the [ADR-0005 amendment](../adr/0005-build-strategy.md),
> this happens **before** the agility registry is written, because the registry *is*
> `hux-crypto`'s public surface and G0 item 4 already requires moving the same code.
>
> **This is a mechanical move. No behaviour changes. The passing test suite is the harness.**
>
> *Baseline at the time of the move: **112 passed, 0 failed, 84 ignored** (108 before the G0-6
> secret-hygiene fix added four). The counts after the move must match exactly.*

## Target layout (this gate only)

```
huxplex/
├── Cargo.toml                  # [workspace] — members, shared lints, shared dep versions
├── Cargo.lock                  # one lockfile for the workspace
├── rust-toolchain.toml         # unchanged (1.85.0)
├── deny.toml, clippy.toml, rustfmt.toml
└── crates/
    ├── hux-crypto/
    │   ├── Cargo.toml
    │   ├── README.md           # purpose + link to docs/02-architecture/cryptography.md
    │   └── src/
    │       ├── lib.rs
    │       ├── signaturescheme.rs  signature.rs  publickey.rs  privatekey.rs
    │       ├── kem.rs  bip32.rs  error.rs
    │       ├── slh_dsa.rs  lb_vrf.rs  pq_ssle.rs  zk_stark.rs   # stubs, gate-labelled
    │       └── (suite/ arrives in G1)
    │   └── tests/              # ← the suites currently inside src/crypto/mod.rs
    └── hux-network/
        ├── Cargo.toml
        ├── README.md
        └── src/
            ├── lib.rs
            ├── message.rs  topic.rs  peer.rs  error.rs
        └── tests/              # ← the suites currently inside src/network/mod.rs
```

**`hux-types` is deliberately not created.** It has no members until G2 introduces `Resource`,
`Transaction`, `Block` and `Vote`. An empty crate now would be scaffolding pretending to be
architecture.

## Why the test files move too

`src/crypto/mod.rs` was 3,607 lines (now `crates/hux-crypto/src/lib.rs`), of which the overwhelming majority is the conformance suite
(G0 item 4, outstanding). Moving the crate without splitting it would carry the problem forward.
Integration tests in `crates/*/tests/` also enforce something useful for free: **they can only
reach the public API**, which surfaces any over-broad `pub` immediately.

> ⚠️ **Watch for this:** some existing tests reach internals. Any that break on the move are
> telling you the API surface is wrong, not that the move is wrong. Fix by widening the API
> deliberately or keeping that specific test as a `#[cfg(test)]` unit test inside `src/` —
> **never** by making a secret field `pub` to satisfy a test.

### How the split actually landed

| File | Covers |
|---|---|
| `hux-crypto/tests/ml_dsa.rs` | FIPS 204 conformance, tamper rejection, hedged signing, secret hygiene (29) |
| `hux-crypto/tests/ml_kem.rs` | FIPS 203 conformance, directional session keys (32) |
| `hux-crypto/tests/domain_separation.rs` | The canonical context registry and its rejection matrix (4) |
| `hux-crypto/tests/hd_derivation.rs` | BIP32 paths and key purposes (8) |
| `hux-network/tests/peer_identity.rs` | `PeerId` derivation (10) |
| `hux-network/tests/topics.rs` | Topic strings and gossip contexts (7) |
| `hux-network/tests/envelopes.rs` | Signed gossip/DHT, forgery and replay rejection (22) |

**The gated stubs did not move to `tests/`, deliberately.** `slh_dsa`, `lb_vrf`, `pq_ssle` and
`zk_stark` are `#[cfg(test)]` modules precisely so that no `unimplemented!()` cryptography is
reachable from the public API. Integration tests compile against the crate as an *external*
crate, with `cfg(test)` off, so moving their suites to `tests/` would have required making the
stubs public — trading a real safety property for tidiness. Their suites are now co-located
`#[cfg(test)] mod` blocks inside the module files they exercise, which is idiomatic Rust and
keeps the stubs unreachable.

## Tasks

| ID | Task | Acceptance |
|---|---|---|
| **W1** ✅ | Create the workspace root `Cargo.toml`; move `src/crypto` → `crates/hux-crypto/src`, `src/network` → `crates/hux-network/src`; `hux-network` depends on `hux-crypto` | ✅ `cargo test` passes with the same **112 / 0 / 84** counts (73 in `hux-crypto`, 39 in `hux-network`) |
| **W2** ✅ | Extract the test suites into `crates/*/tests/`, split by concern | ✅ 112 tests, unchanged. `lib.rs` now **36** and **10** lines. All **84** `#[ignore]`s keep their `GATE:` label |
| **W3** ✅ | Hoist shared dependency versions to `[workspace.dependencies]`; hoist lints to `[workspace.lints]` including `unsafe_code = "forbid"` | `cargo clippy --all-targets` clean; no crate declares a version already in the workspace table |
| **W4** ✅ | Per-crate `README.md` linking to the owning `/docs` section (convention in [repository-structure](../10-development/repository-structure.md)) | Both exist and link correctly |
| **W5** ✅ | CI dependency-direction check: `hux-crypto` MUST NOT depend on `hux-network` | A deliberate reversed dependency fails CI |

## Ordering

W1 → W2 → W3 → W4, with W5 any time after W1. **W1 and W2 in separate commits** — a mechanical
move and a file split are different kinds of change, and reviewing them together hides mistakes
in both.

## Acceptance for the whole migration

- `cargo test` — **112 passed, 0 failed, 84 ignored**, identical to before the move. ✅
- `cargo clippy --all-targets` — zero warnings. ✅
- `forbid(unsafe_code)` survives the move to `[workspace.lints]` — verified by compiling a
  deliberate `unsafe {}` probe and confirming it is rejected. ✅
- No file renamed *and* edited in the same commit, so `git log --follow` stays useful.
- No public API item added that was not public before, except where W2 proved one was needed —
  and each such case is named in the commit message.

## What this migration must not do

- **Not** change any derived key, context string, or signature. The move is byte-neutral;
  `test_transaction_purpose_reproduces_the_original_path` and the KAT-adjacent tests are the
  proof.
- **Not** start the registry. That is [G1](02-g1-crypto-core.md), and mixing it in makes the
  mechanical move unreviewable.
- **Not** create crates with no members.

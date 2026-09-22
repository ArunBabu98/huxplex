# 01 — Verifying the cryptography by hand

> Companion to `cargo run -p hux-crypto --example crypto_walkthrough`. Each section below says
> what the walkthrough step proves, **how to check it independently**, and what a failure would
> mean.
>
> Normative contract: [`../15-specifications/02-cryptography-spec.md`](../15-specifications/02-cryptography-spec.md).

## 1. Sizes match FIPS 204 and FIPS 203

| Object | Bytes | Standard |
|---|---|---|
| ML-DSA-44 public key | **1,312** | FIPS 204, Table 2 |
| ML-DSA-44 secret key | **2,560** | FIPS 204, Table 2 |
| ML-DSA-44 signature | **2,420** | FIPS 204, Table 2 |
| ML-KEM-768 encapsulation key | **1,184** | FIPS 203 |
| ML-KEM-768 decapsulation key | **2,400** | FIPS 203 |
| ML-KEM-768 ciphertext | **1,088** | FIPS 203 |

**Check it independently:** look these up in the published FIPS documents rather than taking the
table's word for it. This matters more than it looks — the project's own founding essay stated
the ML-DSA-44 *signature* as 2,560 bytes, which is actually the **secret key** size. That error
is recorded and corrected in [ADR-0002](../adr/0002-cryptographic-parameter-set.md), and the code
is the authority.

```bash
cargo test -p hux-crypto -- --nocapture sizes
```

**A failure means:** a dependency changed parameter sets under you, or a backend swap altered
output. Either is a consensus-breaking event on a live chain.

## 2. Secret hygiene

Three properties, all independently checkable:

```rust
// Debug is redacted
format!("{:?}", keypair.private_key())
// → PrivateKey { scheme: Dilithium2, bytes: "<redacted>", len: 2560 }
```

**Check it:** grep the crate for anything that could print a secret.

```bash
rg 'expose_secret' crates/            # every place a secret can escape — should be few
rg 'derive\(.*Debug' crates/hux-crypto/src/privatekey.rs   # should find nothing
```

The accessor is deliberately named `expose_secret()` so that *every* call site is greppable in
review. If that grep ever returns a result inside a logging, serialization or formatting path,
that is a bug.

**Why it matters:** the crypto here is correct; the plumbing around it is where keys leak. This
type derived `Debug` until 2026-09-22, which meant one `tracing::debug!` on a `Keypair` would
have written 2,560 bytes of signing key into logs that get shipped off-host.

## 3. HD derivation and key purposes

Path: `m/44'/931931'/{purpose}'/0'/{index}'`, hardened at every level.

| Purpose | Index | Role |
|---|---|---|
| `Transaction` | `0'` | hot per-block/per-vote and user transaction signing |
| `QuorumCert` | `1'` | **reserved** for a future aggregating scheme |
| `Identity` | `2'` | long-lived validator identity (SLH-DSA) |
| `Governance` | `3'` | credential issuance, constitutional records |
| `Transport` | `4'` | TLS certificate key; `PeerId` derives from this |

**Check it:** two properties matter and both are tested.

```bash
cargo test -p hux-crypto key_purposes_are_domain_separated
cargo test -p hux-crypto transaction_purpose_reproduces_the_original_path
```

The second is the one to care about: adding the purpose level must **not** have changed any key
derived before it existed. Purpose `0'` reproduces the original path byte-for-byte.

**Why separate purposes:** a TLS stack needs the raw private key, so a key handed to rustls
cannot sit behind the remote-signer boundary that guards against double-signing
([ADR-0014](../adr/0014-validator-key-management.md) rule 3). Separating `Transport` from
`Transaction` means a compromised TLS stack does not reach the consensus key.

## 4. Hedged (randomized) signing

Signing the same message twice **must** produce different signatures, and both **must** verify.

**Check it:**

```bash
cargo test -p hux-crypto randomized
```

**Why it matters, and why you should not "fix" it:** deterministic lattice signing plus fault
injection is a demonstrated key-recovery path (IACR eprint 2025/2009 — the vulnerable
implementation pattern was found in PQM4, liboqs, PQClean and wolfSSL). The cost is that
signature bytes are not reproducible, so Known-Answer-Test fixtures must pin the 32 bytes of
randomness explicitly. Production signing must **never** accept caller-supplied randomness; that
is a separate, test-only entry point.

## 5. Tamper detection

Three trials, all of which must reject:

| Mutation | Expected |
|---|---|
| One flipped bit in the message | ❌ rejected |
| One flipped bit in the signature | ❌ rejected |
| A different public key | ❌ rejected |

**Check it yourself** — edit the walkthrough, flip a bit somewhere else, and confirm it still
rejects. An assertion you have personally tried to break is worth more than one you read.

## 6. Domain separation — the property to scrutinise hardest

Every protocol signature is bound to a context string of the form
`huxplex-{network}:{purpose}:v{n}`. A signature valid under one context **must not** verify under
any other.

The walkthrough sweeps all 5×5 pairs. The test suite sweeps the full canonical matrix:

```bash
cargo test -p hux-crypto context
cargo test -p hux-crypto all_canonical_context_strings_are_mutually_domain_separated
```

What this kills, concretely:

- a **mainnet** transaction signature replayed on **testnet**;
- a block `prepare` vote replayed as a `commit` vote — which would break consensus safety;
- a gossip signature for shard 0 replayed on shard 1;
- a DHT record replayed across networks.

**Check it yourself:** add a context string to the list in the walkthrough and confirm the sweep
still holds. Then try to construct a pair that *does* cross-verify. If you find one, that is a
serious finding — please report it.

**Why it is load-bearing:** this is the cheapest high-leverage defence in the system
(principle 7), and it is also the property most likely to be silently broken by a refactor. That
is why it is tested by exhaustive pair sweep rather than spot checks.

## 7. ML-KEM-768 and directional session keys

Two properties:

1. `encapsulate` and `decapsulate` agree on the 32-byte shared secret.
2. `derive_session_key(ss, A, B, …)` ≠ `derive_session_key(ss, B, A, …)`.

The second is **directionality**, and the ordering rule is normative: `peer_a` is the initiator
(the side that sent `ClientHello`), `peer_b` the responder
([crypto spec §4.2](../15-specifications/02-cryptography-spec.md)). The rule is a property of the
connection role, not of the key bytes, so it cannot flip when a peer re-keys.

**Why it matters:** without directionality, an A→B session key equals the B→A key and a
reflection attack can replay a peer's own traffic back at it.

## 8. Architecture portability

```bash
cargo test --all-features           # on x86_64
cargo test --all-features           # on aarch64
```

The walkthrough prints derived key material. **Those values must be identical on both
architectures** — ML-KEM and ML-DSA keygen are deterministic in their seeds, and libcrux's
backends (AVX2, NEON, portable) are output-identical by construction.

**Check it:** run the walkthrough on two machines and diff the output.

```bash
cargo run -q -p hux-crypto --example crypto_walkthrough > arch-a.txt
# …on the other machine…
diff arch-a.txt arch-b.txt        # only the "target arch:" line should differ
```

**A difference anywhere else is a fork bug** and should be reported immediately.

**Do not** introduce a call to an architecture-specific backend path (`mlkem768::avx2::*`,
`::neon::*`). Always the top-level dispatching entry point. The codebase has been broken this way
once already.

## What is not verifiable yet

- **SLH-DSA-128s** — 24 conformance tests exist and are `#[ignore]`d with `GATE: G1`.
  `cargo test -- --ignored` will show them failing with `unimplemented!()`; that is expected.
- **The agility registry** — `SignatureSchemeId` still has one variant. Rotation without state
  migration (test G1-T1) is the whole crypto-agility thesis and cannot be demonstrated yet.
- **FIPS Known-Answer-Test vectors** — not yet committed (G1 task C10).
- **Multi-vendor differential tests** — `libcrux` ↔ `aws-lc-rs`, `fips205` ↔ `slh-dsa` (G1 tasks
  C8 and C11).
- **Side-channel and constant-time testing** beyond the constant-time equality in `PrivateKey`.

Each is a named task in [`../18-implementation-plan/02-g1-crypto-core.md`](../18-implementation-plan/02-g1-crypto-core.md).

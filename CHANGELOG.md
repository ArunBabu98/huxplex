# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Pre-1.0 note: while the version is `0.x`, the API and protocol are unstable and may change in
> any release. Breaking changes will still be called out under **Changed**/**Removed**.

## [Unreleased]

### Added
- Repository engineering scaffolding: `LICENSE` (Apache-2.0), `NOTICE`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, this changelog, lint/toolchain config (`rustfmt.toml`, `clippy.toml`,
  `deny.toml`, `rust-toolchain.toml`), and CI (`.github/workflows/`).
- `docs/14-use-cases/` — use cases, applications & impacts catalogue.
- `docs/15-specifications/` — normative specification layer: data model & encoding, cryptography
  spec with context-string registry and test vectors, HRM state-transition spec, consensus spec,
  network wire protocol, and the frozen v1 scope contract.
- ADR-0010 (hash function), ADR-0011 (canonical serialization), ADR-0012 (network transport),
  ADR-0013 (`did:huxplex` method), ADR-0014 (validator key management & custody).

### Notes
- No functional/code changes to the crypto or network primitives in this entry — documentation,
  decisions, and tooling only.

## [0.1.0] - 2026

### Added
- Post-quantum cryptographic primitives: ML-DSA-44 sign/verify, ML-KEM-768 KEM with HKDF session
  key derivation, BIP32 → ML-DSA seed derivation (`m/44'/931931'/0'/0'/{i}'`), and
  domain-separated context strings with cross-context replay tests.
- Networking primitive types: `PeerId` (SHAKE-256 of the ML-DSA-44 public key), signed
  `GossipMessage`, and signed Kademlia `DhtEntry`.

[Unreleased]: https://github.com/ArunBabu98/huxplex/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ArunBabu98/huxplex/releases/tag/v0.1.0

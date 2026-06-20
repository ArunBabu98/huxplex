# Security Policy

Huxplex is a **post-quantum cryptography and distributed-systems research project**. Security is
the entire point of the project, so we take vulnerability reports seriously — including reports
about the cryptographic design, not just implementation bugs.

> ⚠️ **Status.** Huxplex is pre-production research software (~1,200 LOC of crypto and networking
> primitives; no ledger, consensus, or network transport yet — see
> [`docs/00-executive-summary.md`](docs/00-executive-summary.md)). **Do not use it to secure
> anything of value.** It has not been audited.

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` (pre-release) | Best-effort only; no security guarantees |

There is no released, supported version yet. Until the first audited release, treat all code as
experimental.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via one of:

1. **GitHub private vulnerability reporting** — the "Report a vulnerability" button under the
   repository's **Security** tab (preferred). This creates a private advisory.
2. **Email** — `tenshilabs@gmail.com` with subject line `HUXPLEX-SECURITY`.

Please include:

- A description of the issue and its security impact.
- The component (crypto primitive, key derivation, domain separation, networking, etc.).
- Steps to reproduce or a proof-of-concept, if available.
- The commit hash / version affected.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement of report | within **5 business days** |
| Initial assessment & severity triage | within **10 business days** |
| Fix or mitigation plan communicated | depends on severity; high/critical prioritized |
| Public disclosure | coordinated with the reporter, after a fix or mitigation exists |

We follow **coordinated disclosure**. We will credit reporters who wish to be named.

## Scope — what we especially want to hear about

Because this is a cryptography project, the following are in-scope and high priority:

- **Cryptographic misuse** — incorrect use of ML-DSA-44, ML-KEM-768, HKDF, SHAKE-256, or BIP32.
- **Domain-separation / context-binding flaws** — any way to make a signature valid in a context
  it was not intended for (cross-network, cross-shard, cross-phase replay). The context-string
  scheme is a core security mechanism; see
  [`docs/15-specifications/02-cryptography-spec.md`](docs/15-specifications/02-cryptography-spec.md).
- **Key derivation weaknesses** — issues in the BIP32 → ML-DSA seed path
  (`m/44'/931931'/0'/0'/{i}'`).
- **Session-key derivation** — flaws in the ML-KEM-768 + HKDF directional derivation.
- **Memory safety** — although the crypto core depends on `libcrux`, report any unsafe usage or
  secret-material handling issues (e.g. secrets not zeroized).
- **Determinism / serialization** — any non-determinism that could break consensus hashing
  (relevant once the ledger exists).

## Out of scope (for now)

- The unbuilt protocol layers (consensus, VM, ledger, transport) — they do not exist yet, so
  there is nothing to attack. Design-level concerns belong in an
  [RFC](docs/rfc/) or an issue, not a security report.
- Theoretical breaks of the underlying NIST PQC standards themselves (ML-DSA/ML-KEM) — these are
  tracked by the crypto-agility design ([ADR-0002](docs/adr/0002-cryptographic-parameter-set.md));
  report novel cryptanalysis to the relevant standards bodies as well.

## Safe harbor

We will not pursue legal action against researchers who act in good faith, avoid privacy
violations and service disruption, and give us reasonable time to remediate before public
disclosure.

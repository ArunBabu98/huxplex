# Contributing to Huxplex

Huxplex is building civilization-scale, decade-survival infrastructure. Contributions are welcome
and held to a correspondingly high bar — especially on consensus, cryptography, and economics.

## Before you start

1. Read the [blueprint README](../README.md), [principles](../01-vision/principles.md), and
   [coding-standards](../10-development/coding-standards.md).
2. Check the [open-problems register](../11-research/open-problems.md) and
   [backlog](../backlog/) for where help is needed.
3. For anything substantial, **open or read an [RFC](../rfc/)** first — don't write consensus/
   crypto/economic code without an agreed design.

## Contribution types & paths

| Type | Path |
|---|---|
| Bug fix / docs / tests / refactor | normal PR (link an issue) |
| New feature (small) | issue → PR |
| Consensus / crypto / economic / governance change | **RFC → ADR → PR** |
| Research (simulation, cryptanalysis, mechanism design) | research issue → write-up → maybe grant |
| Security vulnerability | **do NOT open a public issue** — see [security disclosure](#security) |

## Pull request requirements

- Green CI: fmt, clippy `-D warnings`, build, tests, property tests, KATs, determinism check,
  dependency audit ([ci-cd](../10-development/ci-cd.md)).
- `#![forbid(unsafe_code)]` respected (only `hux-crypto` may use vetted, commented `unsafe`).
- Determinism rules honored (no FP/map-iteration/time/RNG/threads on consensus paths).
- New signed objects are **domain-separated** (context string) and **algo-suite-versioned**.
- Tests for new behavior, incl. negative tests (tamper/downgrade/cross-context) for crypto.
- Docs updated; non-obvious decisions reference an ADR (`// see ADR-000X`).
- Reviews: ≥1 for normal changes; **≥2 + a security reviewer** for consensus/crypto/economic code.
- Conventional Commits; no direct pushes to the default branch.

## Code review values

- Correctness and determinism over cleverness.
- Minimize trusted base and attack surface.
- Document tradeoffs, not just conclusions.
- Honest framing — no overclaiming in code comments, docs, or names.

## Good first contributions

- Refactor hard-coded crypto sizes (`[u8;1312]`/`[u8;2420]`) behind the suite descriptor (agility).
- Add zeroizing wrappers for secret key material (`PrivateKey`).
- Extend the domain-separation context inventory + tests for new object types.
- Property tests for HRM invariants (conservation, nullifier uniqueness).
- Documentation improvements and diagrams.

## Security {#security}

- **Never** report vulnerabilities via public issues/PRs.
- Use the responsible-disclosure channel (security contact / encrypted email — to be published).
- Eligible for bug bounties ([audits](../08-security/audits.md)), incl. a **PQ-cryptanalysis track**.
- Safe-harbor for good-faith research.

## Communication & conduct

- Be rigorous, be kind, assume good faith. A Code of Conduct applies (to be published).
- Technical disagreements resolve via RFC discussion + data, not seniority.

## Licensing

- Contributions are under **Apache-2.0** (matching the project). By contributing you agree your
  work is licensed accordingly. Keeping the license permissive preserves the right to fork — a
  core neutrality guarantee ([constitutional-layer](../07-governance/constitutional-layer.md)).

---

*Maintainership, escalation, and decision rights mature as the project decentralizes
([phase4](../09-roadmap/phase4-global-scale.md)). Early on, the founding team stewards; the goal is
founder-independence.*
</content>

# 01 — Layer 0 technology review, September 2026

> **Non-normative.** Nothing in this file is a decision. It is a literature and ecosystem
> review of every Layer-0 choice recorded in [`02-architecture/cryptography.md`](../02-architecture/cryptography.md),
> [`02-architecture/networking.md`](../02-architecture/networking.md),
> [ADR-0002](../adr/0002-cryptographic-parameter-set.md), [ADR-0010](../adr/0010-hash-function-domains.md),
> [ADR-0012](../adr/0012-network-transport.md) and [ADR-0014](../adr/0014-validator-key-management.md),
> measured against the state of the art as of **2026-09-22**. Where it recommends a change,
> that change is an **action arising** (§7), not a decision — the blueprint and the ADRs win
> until an ADR supersedes them.

| | |
|---|---|
| **Scope** | L0 only — PQ crypto suite, transport, handshake, gossip, DHT, peer identity, hashing |
| **Reviewer** | Architecture review, Sept 2026 |
| **Method** | Ecosystem survey + 2026 IACR/arXiv literature + upstream `libp2p`/`rustls` implementation status |
| **Companion** | [`17-landscape-2026.md`](../17-landscape-2026.md) §6 (PQC) — this file is the L0-depth version |

**Legend:** ✅ validated, keep · 🔄 behind the state of the art, change · ⏳ watch, do not adopt yet · ⚠️ under-weighted risk

---

## 0. Headline

**The L0 architecture is sound. No rip-and-replace is warranted.** Most of it has been
*vindicated* by 2026 developments rather than overtaken — in three cases (hybrid KEX, family
diversity, non-ZK-friendly hashing) the project made a call the rest of the field has since
converged on.

Three choices are now materially behind the state of the art, and two documented facts are
stale:

| # | Finding | Class | Action |
|---|---|---|---|
| 1 | One signature scheme serves both transactions and quorum certificates — the 2026 literature says these are different design problems | 🔄 | [A1](#a1) |
| 2 | ML-DSA-44 (Cat 1) is now the minority hot-path choice, and is mismatched against a Cat-3 KEX | 🔄 | [A2](#a2) |
| 3 | GossipSub alone for block propagation; the field moved to erasure-coded broadcast in 2025–26 | 🔄 | [A3](#a3) |
| 4 | LB-VRF is superseded by iVRF (hash-based, faster than classical ECVRF) | 🔄 | [A4](#a4) |
| 5 | The libp2p upstream PQ path covers **confidentiality only** — it will never supply PQ authentication | 🔄 | [A5](#a5) |
| 6 | QUIC's 3× anti-amplification limit is not acknowledged anywhere in the networking design | ⚠️ | [A6](#a6) |
| 7 | 2026's realised attacks on ML-DSA/ML-KEM are **implementation** attacks, and validator signing volume walks straight into one of them | ⚠️ | [A7](#a7) |
| 8 | R-A1 (PQ aggregation) is no longer an open void — it has named candidates, all of them stateful | 🔄 | [A8](#a8) |

---

## 1. What is validated ✅

### 1.1 Hybrid X25519 + ML-KEM-768 — went from "recommended" to de-facto standard

[`networking.md`](../02-architecture/networking.md) and [ADR-0012](../adr/0012-network-transport.md)
called this correctly and early. Since then:

- It ships in Chrome and Cloudflare, and is the rustls PQ path (`prefer-post-quantum`; ML-KEM
  moved from the `rustls-post-quantum` crate into `rustls` itself at 0.23.22).
- **libp2p standardized the same construction**: `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`
  ([libp2p/specs#727](https://github.com/libp2p/specs/pull/727), Stage-1 working draft).
- Cross-implementation interop (TypeScript ↔ Python ↔ Rust ↔ Nim, all six pairs) completed
  **2026-09-05**.
- IETF `draft-ietf-tls-ecdhe-mlkem` is at -05.

The existing `kem768_derive_session_key` directional derivation in `crates/hux-crypto/src/kem.rs`
anticipates the design that the ecosystem then settled on. Keep it.

### 1.2 Family diversity (lattice + hash-based) — the year's best-vindicated call

Two 2026 events make [ADR-0002](../adr/0002-cryptographic-parameter-set.md)'s Option B look
prescient:

- **The Luo scare (May 2026).** Ming-Xing Luo posted a four-part preprint claiming an extension
  of the CDPR quantum attack breaks ML-KEM (FIPS 203) at *all* standardized parameter sets with
  ~1,400 logical qubits and ~10⁸ logical gates. It was refuted within eight days — Daniel Apon
  and Thomas Espitau independently identified fatal flaws (the attack targets a determinant
  ideal whose value is identical regardless of which secret key produced it; Algorithm 2 treats
  √2 as a unit; the paper's own precision formula demands ~2.9M qubits, not 1,400). **ML-KEM is
  not broken.** But for eight days nobody could say that with certainty, and the refutation's
  own conclusion is *"crypto-agility remains essential."*
- **The MLWE/LWE hardness gap (Feb 2026).** A result on the concrete hardness gap between MLWE
  and LWE saves a few bits against ML-KEM by exploiting module structure. The improvement is
  minor — but it **contradicts the prior claim that no cryptanalysis exploits module structure
  better than generic lattice reduction.** The direction of travel is what matters.

Neither event breaks anything. Both are exactly the scenario diversity + agility exist for.

### 1.3 BLAKE3 / SHAKE-256 over a ZK-friendly hash — strongly vindicated

[ADR-0010](../adr/0010-hash-function-domains.md) chose SHAKE-256 for identity domains and
BLAKE3 for bulk state, and never adopted an arithmetization-friendly hash. In 2026:

- The **Ethereum Foundation abandoned Poseidon** for base-layer hashing after more than a year
  of evaluation, in favour of SHA and BLAKE3.
- Its own cryptanalysis programme found issues in **Poseidon2 serious enough to consider adding
  rounds or reverting to Poseidon1**.
- The stated reason is doubly useful to Huxplex: proof systems improved enough that the exotic
  hash no longer buys a meaningful edge, and **SHA-256/BLAKE3 are more straightforward to
  evaluate in post-quantum security models** because their foundations are better understood.
- StarkNet is moving state commitments to BLAKE2 and introducing Falcon-512 consensus
  signatures.

Huxplex never took the ZK-friendly-hash bait. That is now the mainstream position, not a
conservative one.

### 1.4 libp2p over a custom stack (ADR-0012 Option B) — still correct

litep2p, the most credible alternative, **remains non-default even inside the Polkadot SDK**
(selectable via `--network-backend litep2p`, still described as experimental) and is explicitly
*not* a drop-in replacement from a developer's perspective. There is no reason to revisit
Option A/B/C at the library level. (The security-transport question is separate — see
[§3.2](#32-the-libp2p-upstream-pq-path-will-not-give-huxplex-what-it-needs).)

### 1.5 Domain-separated context strings — ahead of peers, and independently converged on

The 2026 blockchain-signature literature arrives at the same discipline from the other
direction, recommending that L1s *"fix single encoding formats, publish negative test vectors,
and measure adversarial verification costs before deployment."* The context registry in
[`15-specifications/02-cryptography-spec.md`](../15-specifications/02-cryptography-spec.md) and
the exhaustive cross-context replay tests already do the first two. Keep, and keep testing
exhaustively (G1-T2).

---

## 2. Where L0 is behind 🔄

### 2.1 One signature scheme for transactions *and* votes is the wrong abstraction

The single most relevant paper of the review is ***Domain-Specific Post-Quantum Signatures for
Blockchains*** (arXiv:2609.24689, Sept 2026). Its thesis:

> *"Most academic post-quantum signature work targets the wrong abstraction for public
> blockchains."*
>
> *"NIST single-signer signatures are necessary components … although none of the current
> schemes is a drop-in replacement for the signature layer of modern public blockchains."*

It argues L1s must define **per-role signature profiles**, because transaction authorization and
quorum certification have different adversaries, different cost models, and different required
operations:

| Role | Needs | Huxplex object |
|---|---|---|
| **Transaction authorization** (T-class) | bind chain ID, nonce, fee and intent; priced rejection of invalid input | `Transaction`, `Intent` |
| **Quorum certificate** (Q-class) | public aggregation, merge semantics, slashing evidence, light-client verification | `Vote`, block certificate |

Its throughput classes, with the signature-size budget each implies:

| Class | Budget | Fits |
|---|---|---|
| TMTU (packet-limited) | ≤ 512 B | MAYO-1 (454), HAWK-512 (555, marginal) |
| THT (high-throughput) | ≤ 1 KB + fast rejection | Falcon-512 (666), HAWK-512 (555) |
| TGEN (general) | ≤ 3 KB | **ML-DSA-44 (2,420)**, ML-DSA-65 (3,309) |
| TROOT (governance) | large OK | **SLH-DSA-128s (7,856)** |

Huxplex's split is already *half* right — hot ML-DSA vs. long-lived SLH-DSA is exactly the
TGEN/TROOT distinction. What is missing is that **`Transaction` and `Vote` are both pinned to
the same hot-path scheme**, and the suite descriptor sketched in
[`cryptography.md`](../02-architecture/cryptography.md) versions the suite but carries no
**role** dimension.

> The fix is small *if done before G1*: `AlgoSuite { role, version }` rather than
> `AlgoSuite { version }`. Retrofitting a role dimension after every object type has an
> embedded algorithm ID is a state-model migration.

### 2.2 ML-DSA-44 is now the minority hot-path choice

[ADR-0002](../adr/0002-cryptographic-parameter-set.md) deferred 44-vs-65 to Phase-0 benchmarks
as **R-A2**. The 2026 evidence has moved decisively toward Category 3:

| Who | Choice | Stated reason |
|---|---|---|
| **Sui** | **ML-DSA-65** (Cat 3) for native account authentication, explicitly over the cheaper 44 | (i) AI-assisted attacks on lattice schemes — including HAWK — found vulnerabilities that *"survived years of human review"*; (ii) alignment with the Chrome/Cloudflare Cat-3 posture and financial-sector expectation; (iii) verification at **parity with Ed25519**, so validator cost is not the constraint |
| **NSA CNSA 2.0** | ML-DSA-**87** + ML-KEM-**1024**, exclusively, for national-security systems | Category 5 only; software/firmware signing exclusive by 2030 |
| **BSC** | ML-DSA-**44** | Shipped it; measured **40–50% TPS reduction**, tx 110 B → ~2.5 KB |
| General guidance | ML-DSA-65 for general use; 44 *"when signature/key size is critical"* | — |

Two things follow.

**First, an internal inconsistency worth naming.** The genesis suite pairs a **Cat-1 signature**
(ML-DSA-44) with a **Cat-3 KEX** (ML-KEM-768). Whatever the right answer is, the current pair is
not deliberate — the weakest link sets the margin, and nothing in ADR-0002 argues for Cat 1 on
the signature side beyond size.

**Second, the BSC number is the real counter-argument** and should be respected: 40–50% TPS loss
at 2,420 B. ML-DSA-65 is +37% on signature (2,420 → 3,309 B) and +49% on public key
(1,312 → 1,952 B) on top of that. This is a genuine trade, not a free upgrade — which is
precisely why it should be decided **per role** (§2.1) rather than globally. Consensus votes are
O(validators) per block and bounded; user transactions are unbounded.

Suggested shape, pending benchmarks: **Cat 3 for consensus/identity-bearing roles, Cat 1
available as a transaction profile if measurement demands it.**

### 2.3 GossipSub alone for block propagation is no longer state of the art

This is the finding with the highest retrofit cost, and the one most specific to Huxplex —
**PQ signature sizes put Huxplex squarely in the regime where gossip degrades.**

The field moved to erasure-coded broadcast in 2025–26:

| System | Approach | Status |
|---|---|---|
| **ethp2p** | Reed–Solomon erasure-coded broadcast, object-specific rather than generic store-and-forward | **Scheduled to succeed GossipSub in late 2026**; Go module published 2026-08-19; simulator benchmarks against a gossipsub baseline on real Ethereum topologies |
| **RaptorCast** (Monad) | Rateless Raptor codes + hierarchical leader → first-level-validator → network dissemination | Production, MonadBFT |
| **Optimum P2P / Peer-Turbo** | RLNC-based broadcast (arXiv:2605.15715) | Research + implementation |
| **Turbine** (Solana) | Erasure-coded fanout tree | Production, years |
| Ethereum **EIP-8411** | Sub-1s payload propagation experiments | Testing |

The diagnosis is the same everywhere: gossip reduces *leader* bandwidth but pays for it in
**hops**, and hop count is what breaks a latency budget for large objects.

[`networking.md`](../02-architecture/networking.md) currently assigns GossipSub to blocks, the
mempool **and** intents. Those are three different traffic shapes:

| Traffic | Shape | Right primitive |
|---|---|---|
| Block / DAG batch | large, single-source, latency-critical, known epoch validator set | **erasure-coded broadcast** |
| Mempool, intents | small, many-source, churn-tolerant, needs abuse resistance | **GossipSub** (its peer scoring and attack-resilience are the point) |
| DHT records | small, long-lived | Kademlia (unchanged) |

GossipSub is not *wrong* — it is wrong for one of the three. Note also that GossipSub's own
attack-resilience research (Vyzovitis et al.) remains the reason to keep it for the mempool.

### 2.4 LB-VRF is superseded

[ADR-0002](../adr/0002-cryptographic-parameter-set.md) lists **LB-VRF** for leader-election
randomness and [`cryptography.md`](../02-architecture/cryptography.md) flags it as immature
(**R-A3**). The follow-on work to Esgin's LB-VRF supersedes it:

| | LB-VRF | **iVRF / authenticated iVRF** |
|---|---|---|
| Family | lattice | **hash-based** |
| Construction | lattice VRF | indexed VRF with modified uniqueness/pseudorandomness, enabling a hash-function instantiation **with no ZK proof of correct PRF evaluation** |
| Eval / verify | — | **0.02 ms** (C) — *faster than the classical ECVRF Algorand uses* |
| Forward security | — | authenticated iVRF adds it, **32 B overhead** on top of the best PQ forward-secure signature |
| Maturity | research | published, benchmarked |

It is better on every axis that matters here, *and* it moves consensus randomness off the
lattice family — improving the diversity property of §1.2. The documented reason to treat
LB-VRF as Production-phase-only largely evaporates.

Caveat to check before acting: iVRF's modified uniqueness is stated for an *Algorand-like*
sortition setting. Huxplex's Q-BFT has a bounded, known validator set per epoch, which is a
friendlier setting — but the mapping needs to be verified, not assumed.

---

## 3. Two stale facts in the current docs ⚠️

### 3.1 QUIC anti-amplification is not acknowledged

Neither [`networking.md`](../02-architecture/networking.md) nor
[ADR-0012](../adr/0012-network-transport.md) mentions it. It is a hard protocol constraint:

> Before a client's address is validated, a QUIC server **may send at most 3× the bytes it has
> received**.

Measured in the 2026 literature: a PQC ClientHello carrying an X25519MLKEM768 share is ~1.3 KB,
permitting ~3.9 KB in response — against **~17.5 KB** for a real PQ certificate chain
(ML-DSA-65 leaf issuer signature alone is 3,309 B vs 64 B for Ed25519; depth-2 chain plus two CT
SCTs → ~32× the Ed25519 total).

**Huxplex is much better placed than TLS here** — self-certifying `PeerId`s mean there is no
X.509 chain at all, which is a real architectural advantage worth stating explicitly. Counted by
flight (the limit governs the responder's **first** flight only; the initiator's second flight
validates the address):

| Flight | Contents | Bytes | Pre-validation? |
|---|---|---|---|
| ClientHello → | X25519 32 + ML-KEM ek 1,184 + `PeerId` 32 + framing | ≈ 1,300 | — |
| ← ServerHello | X25519 32 + ML-KEM ct 1,088 + `PeerId` 32 + ML-DSA pk 1,312 + framing | **≈ 2,500** | ✅ the binding one |
| Finished (I) → | ML-DSA-44 sig 2,420 | ≈ 2,450 | validates the address |
| ← Finished (R) | ML-DSA-44 sig 2,420 | ≈ 2,450 | no |

**≈ 2,500 B against ~3,900 B — it fits, with ~1.4 KB of headroom**, and still fits at ML-DSA-65
(≈ 3,100 B). The transcript signatures travel after validation.

> ⚠️ **Correction (2026-09-22).** The first revision of this section summed every responder byte,
> including `Finished (R)`, and reported a ~1 KB deficit. That was wrong — `Finished (R)` is the
> fourth flight. The finding survives as a *watch item*, not a defect: it is a budget with
> headroom that a later change can silently spend.

What remains genuinely undecided is upstream of the arithmetic: **does the ML-DSA handshake
replace QUIC's TLS crypto layer, or run as an application-level handshake over a standard
QUIC + rustls (`X25519MLKEM768`) connection?** The budget binds only in the first case. In the
second the address is validated before the first ML-DSA byte, the hybrid KEX comes from upstream
for free — but **channel binding becomes mandatory** (a TLS exporter mixed into the ML-DSA
transcript, or a relay attack is possible), and unauthenticated connections must be rate-limited
because the QUIC session is established before any peer proves identity.

Two things that would break the budget if the first option is chosen, and should be pinned by a
test either way: moving an identity proof earlier, or putting an SLH-DSA-128s signature
(7,856 B) anywhere in the first flight.

### 3.2 The libp2p upstream PQ path will not give Huxplex what it needs

[`networking.md`](../02-architecture/networking.md) asks, as an open question:

> *"Does libp2p's security-transport API cleanly accept a hybrid X25519+ML-KEM + ML-DSA
> upgrade, or do we need a fork?"*

**This now has an answer, and it is more precise than "yes" or "no".** Both upstream artifacts
say the same thing:

| Artifact | Status | What it does | What it does *not* do |
|---|---|---|---|
| [libp2p/specs#727](https://github.com/libp2p/specs/pull/727) | Stage-1 working draft, **open** | `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` under protocol ID `/noise-mlkem768-hfs/0.1.0`, negotiated ahead of `/noise` with fallback | States plainly: **"authentication stays classical: in libp2p the identity key signs the static key."** Identity remains Ed25519 |
| [rust-libp2p#6481](https://github.com/libp2p/rust-libp2p/pull/6481) | **Draft, open**, blocked | Off-by-default `mlkem-hfs` feature; four independent implementations interoperate with no protocol change | Blocked on ML-KEM support in `snow` (mcginty/snow#210); maintainer asked to wait for spec development. **No mention of QUIC/TLS, PQ identity keys, or static-key auth upgrades** |

So the split is clean:

- **Confidentiality** — will land upstream. Huxplex should consume it rather than reimplement.
- **Authentication and identity** — will *not*. `PeerId = SHAKE-256(ml_dsa44_pk)[..32]`
  (ADR-0010, ADR-0012 rule 5) is the entire self-certifying-identity premise, and upstream is
  not going there.

**Conclusion: Huxplex carries custom transport authentication either way.** ADR-0012's
consequence *"integrating a custom security upgrade into libp2p is non-trivial"* is confirmed.

> ✅ **Resolved 2026-09-22 — and not in the direction this section expected.**
> The premise above ("QUIC gets `X25519MLKEM768` free but gets ML-DSA authentication from
> nowhere") was true when written and false two weeks later. **rustls 0.23.44, released
> 2026-09-07, enables ML-DSA certificates by default**, and `draft-ietf-tls-mldsa-06` assigns
> `mldsa44` = `SignatureScheme` **0x0904**. ML-DSA therefore enters the TLS handshake *natively*:
> no custom `SecurityUpgrade`, no certificate extension, no application-level binding, and no
> classical key anywhere in the authentication path. ML-DSA certificates are unusable in the
> public Web PKI but supported for **private hierarchies**, which is exactly what a
> self-certifying `PeerId` network is. See [ADR-0019](../adr/0019-transport-authentication.md)
> for the full option analysis, including why AuthKEM/KEMTLS was rejected.
>
> The one surviving risk is integration, not architecture: whether `libp2p-quic` accepts a custom
> rustls configuration. That is a G5 entry spike.
>
> *Method note for future reviews: this is the second finding in this document overturned within
> weeks of being written (the other being the amplification arithmetic in §3.1). A fast-moving
> dependency deserves a re-check immediately before the gate that consumes it, not only at
> review time.*

---

## 4. The threat that is actually materializing: implementation attacks ⚠️

The 2026 literature is unambiguous that the near-term danger to ML-DSA/ML-KEM is **not**
mathematical:

| Attack | Result | Relevance |
|---|---|---|
| **Fault attack on the seed pointer** (eprint 2025/2009) | Full ML-KEM key **and** message recovery; ML-DSA **signature forgery**. The vulnerable implementation pattern is *verified present in PQM4, liboqs, PQClean and wolfSSL* | Library choice is not a safety guarantee. Reinforces the multi-vendor rule |
| **Key recovery from sign leakage** (eprint 2026/1366) | First ML-DSA secret-key recovery from signature-sign leakage, at **190,000 signatures** | **A Huxplex validator signing every block and vote reaches 190k signatures in days, not years** |
| **Horizontal fusion attacks** (eprint 2026/1904) | Side-channel key recovery against ML-DSA implementations | Constant-time is necessary, not sufficient |
| **Noisy randomness leakage** (eprint 2026/1712) | Statistical inference attacks on ML-DSA | Rejection sampling remains the exposed surface, as `cryptography.md` §*Engineering rules* rule 2 already warns |

The 190k figure is the one that changes a design parameter. At a 1-second block time and one
vote per phase, a validator produces on the order of 10⁵ signatures per day. **Key-epoch
rotation cadence stops being an operational nicety and becomes a cryptographic requirement with
a number attached.**

[ADR-0014](../adr/0014-validator-key-management.md) already has the right structure — BIP32
index `{i}` as the key epoch, cold SLH-DSA authorizing rotation — so this is a *parameter* to
set, not a redesign. It is, again, an argument the project already won: the hot/cold split
means a leaked session key costs a rotation, not an identity.

Related and unresolved: `libcrux-ml-dsa` and `libcrux-ml-kem` are at **0.0.10** in
[`Cargo.toml`](../../Cargo.toml). Still `0.0.x`. Rule 4 of
[`cryptography.md`](../02-architecture/cryptography.md) ("multi-vendor: keep the ability to swap
the implementation") is promoted by this evidence from prudence to requirement.

---

## 5. R-A1 (PQ aggregation) is no longer an open void

[`open-problems.md`](../11-research/open-problems.md) R-A1 and
[`cryptography.md`](../02-architecture/cryptography.md) both record "no efficient PQ signature
aggregation standard" as an unresolved risk. As of 2026 there are **named, benchmarked
candidates** — the question has changed from *"does anything exist?"* to *"which trade do we
take, and what does it cost the key lifecycle?"*

| Scheme | Certificate size | Assumptions | Notes |
|---|---|---|---|
| BLS (classical baseline) | **96 B**, any committee size | pairings | What PQ has to replace. Not PQ-safe |
| **Chipmunk** | ~**20 KB** @ 1,024 validators | lattice, synchronized | Referenced as the leading synchronized-aggregation candidate |
| **Lemur+** ([eprint 2026/2054](https://eprint.iacr.org/2026/2054)) | ~**56 KB** @ 10⁶ signers, 42-year key lifetime (8.8× better than Lemur's 491 KB) | MLWE + MSIS | **Multi-hop aggregation**; 7.75 s aggregate / **0.29 s verify** at 2¹³ signers |
| **STARK-compressed multi-sig** | **O(1)** on-chain | hash-based | Circle STARK / Stwo + Poseidon2 OODS sponge; proving cost moves off-chain. *Note the Poseidon2 caveat in §1.3* |
| DKKW / LeanSig | — | hash-based | Hash-based multi-signature alternative |

**The load-bearing consequence, and the reason this belongs in an L0 review rather than a
consensus one:**

> Every viable PQ aggregation scheme is **stateful or synchronized** — it requires
> pre-committed, time-indexed key material with a declared lifetime (Lemur+ quotes 42 years;
> Chipmunk is explicitly synchronized).

That cannot be bolted onto a plain ML-DSA keypair after the fact. If quorum-certificate
aggregation is ever wanted — and R-A1 is marked 🔴 precisely because scale depends on it — then
the **validator key lifecycle must be designed to be aggregation-compatible now**, at
[ADR-0014](../adr/0014-validator-key-management.md), while there are zero validators to migrate.

This also intersects §4: synchronized schemes fix a key lifetime *in advance*, while the
sign-leakage result argues for *frequent* rotation. Those pull in opposite directions and the
tension must be resolved deliberately, not discovered later.

---

## 6. Watch, do not adopt ⏳

| Scheme | Numbers | Why not yet |
|---|---|---|
| **FN-DSA / Falcon** (FIPS 206) | 897 B pk / **666 B** sig | Draft FIPS expected **late 2026**, final ~2027. **Floating-point signing is a determinism hazard for a consensus system**; arXiv:2609.24689 explicitly flags Falcon/HAWK as requiring specific floating-point or compiler settings for signing reproducibility. Revisit when FIPS 206 is final *and* a deterministic-signing profile exists |
| **HAWK-512** | 1,024 B pk / **555 B** sig, integer-only arithmetic | Advanced to **NIST Round 3** (May 2026) — Round 3 runs ~2 years, tweaks due 2026-08-14. Attractive for a future THT transaction profile. But Sui cites **AI-assisted attacks on HAWK** as a reason for extra margin elsewhere |
| **MAYO-1** | 1,420 B pk / **454 B** sig | Round 3. Smallest signature of the finalists; multivariate family adds a third family to the diversity argument. Immature |
| **SQIsign-I** | **65 B** pk / **148 B** sig, moderate verification | Round 3. Genuinely interesting for **light clients and low-frequency governance roles** (R-B9 — light-client viability under PQ sizes). Slow verification rules it out of the hot path |
| **Pure ML-KEM** (drop the classical half) | — | **Do not.** The Luo episode is the argument for keeping X25519 regardless of how it resolved. `networking.md` already frames this correctly as a later, agility-gated step |
| **litep2p** | — | Non-default even in Polkadot; not developer-drop-in |

NIST Round-3 finalists, for the record: **FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA,
SQIsign, UOV** (nine advanced May 2026). FN-DSA is separately on the FIPS 206 track.

---

## 7. Actions arising

Cross-referenced to the gates in [`16-action-plan.md`](../16-action-plan.md). Status ⬜ = open.

| # | Action | Target | Gate | Status |
|---|---|---|---|---|
| <a id="a1"></a>**A1** | **ADR: role-separated signature profiles.** Add a `role` dimension to the suite descriptor (T-class tx / Q-class vote / identity / governance) before the registry is built | `adr/0018-*` | **G1** | ⬜ |
| <a id="a2"></a>**A2** | Re-run **R-A2** as a per-role benchmark, not a global one; expect Cat 3 for consensus. Record the Cat-1-sig / Cat-3-KEX mismatch as a finding either way | [R-A2](../11-research/open-problems.md) | G1 | ⬜ |
| <a id="a3"></a>**A3** | **ADR: block propagation.** Erasure-coded broadcast for blocks and DAG batches; GossipSub retained for mempool, intents and control | `adr/0020-*` | **G5**, G6 | ⬜ |
| <a id="a4"></a>**A4** | Replace LB-VRF with **iVRF / authenticated iVRF** in ADR-0002's suite table and the consensus spec, after verifying the uniqueness properties map to a bounded validator set | [ADR-0002](../adr/0002-cryptographic-parameter-set.md), [R-A3](../11-research/open-problems.md) | G6 | ⬜ |
| <a id="a5"></a>**A5** | Record in [`networking.md`](../02-architecture/networking.md) that upstream libp2p PQ work covers **confidentiality only**; plan the ML-DSA authentication transport as a named work item and an upstream contribution, not a risk | [networking.md](../02-architecture/networking.md), ADR-0012 | G5 | ✅ done |
| <a id="a6"></a>**A6** | Choose a **QUIC anti-amplification mitigation** and record the handshake byte budget in the wire-protocol spec | [`15-specifications/05-*`](../15-specifications/05-network-wire-protocol.md) §2.6 | G5 | ✅ **client-Initial padding**, per [ADR-0019](../adr/0019-transport-authentication.md) |
| <a id="a7"></a>**A7** | Set a **key-epoch rotation cadence** as a named protocol parameter, derived from the 190k-signature leakage bound with margin; add side-channel tests beyond FIPS KATs | [ADR-0014](../adr/0014-validator-key-management.md), G1 | G1, G5 | ⬜ |
| <a id="a8"></a>**A8** | **ADR: aggregation-compatible validator key lifecycle.** Decide now whether the key hierarchy must support synchronized/stateful aggregation later; resolve the tension with A7 | `adr/0021-*` | G1 → G6 | ⬜ |
| **A9** | Update **R-A1** from "does anything exist?" to a candidate comparison (Chipmunk / Lemur+ / STARK-compressed) with the statefulness consequence stated | [R-A1](../11-research/open-problems.md) | G6 | ✅ done |
| **A10** | Fold the L0 findings into [`17-landscape-2026.md`](../17-landscape-2026.md) §6 so the competitive read stays current | [17-landscape-2026.md](../17-landscape-2026.md) | — | ✅ done |

**Sequencing note.** A1, A2 and A8 all land on **G1**, and G1 is the gate the executive summary
calls *"the top architectural priority."* A1 in particular is cheap now and a state migration
later — it is the one item on this list with a closing window.

---

## 8. What this review did *not* find

Stated explicitly, because a review that only reports problems is not calibrated:

- **No reason to change the transport library, the hash functions, the AEAD, the peer-identity
  construction, the KEM, or the hybrid-KEX design.**
- **No credible break** of ML-KEM or ML-DSA. The one dramatic claim of 2026 was refuted in eight
  days.
- **No evidence that agility-first was the wrong priority.** Every source that discusses the
  question — including the refutation of the ML-KEM "break" — closes on the same recommendation.
- **No evidence the project is behind on PQ *adoption*.** BSC shipped ML-DSA-44, Sui is
  integrating ML-DSA-65, StarkNet is adding Falcon-512. Huxplex's L0 primitives are
  contemporary with, not behind, production chains — which, given §*Behind* in
  [`17-landscape-2026.md`](../17-landscape-2026.md), is worth saying out loud: **L0 is the part
  of Huxplex that is not behind.**

---

## Sources

**Post-quantum signatures and standardization**
- [*Domain-Specific Post-Quantum Signatures for Blockchains*, arXiv:2609.24689](https://arxiv.org/html/2609.24689) — the review's most directly applicable paper
- [NIST IR 8610 — Status Report on the Second Round of the Additional Digital Signature Schemes](https://csrc.nist.gov/pubs/ir/8610/final)
- [Nine schemes advance to Round 3 — Project Eleven](https://www.projecteleven.com/blog/nine-schemes-advance-to-round-3-of-nists-additional-digital-signatures-process)
- [NIST Advances Nine PQ Signature Algorithms to Third Round — The Quantum Insider](https://thequantuminsider.com/2026/05/21/nist-advances-nine-post-quantum-signature-algorithms-to-third-round/)
- [How we chose Sui's post-quantum signature schemes — Sui](https://www.sui.io/blog/suis-post-quantum-signature-schemes)
- [BSC adopts post-quantum cryptography with ML-DSA-44 — blockchain.news](https://blockchain.news/news/bsc-post-quantum-cryptography-migration)

**Aggregation**
- [*Lemur+: Compact Post-Quantum Synchronized Multi-Signatures and Multi-Hop Aggregation*, eprint 2026/2054](https://eprint.iacr.org/2026/2054)

**Lattice cryptanalysis**
- [Analysis of the Luo ML-KEM quantum attack claim (and its refutation)](https://postquantum.com/security-pqc/luo-ml-kem-quantum-attack-analysis/)
- [Bernstein, *Understanding lattice risks*, 2026-06-30](https://blog.cr.yp.to/20260630-risk.html)
- [*When Randomness Isn't Random: Practical Fault Attack on Post-Quantum Lattice Standards*, eprint 2025/2009](https://eprint.iacr.org/2025/2009)
- [*Halfspace Learning for Lattice Signature Key Recovery from Signs*, eprint 2026/1366](https://eprint.iacr.org/2026/1366)
- [*When Module Lattice Leaks: Horizontal Fusion Attacks on ML-DSA*, eprint 2026/1904](https://eprint.iacr.org/2026/1904)
- [*Statistical Inference from Noisy Randomness Leakage for ML-DSA Attacks*, eprint 2026/1712](https://eprint.iacr.org/2026/1712)

**Transport and handshake**
- [libp2p/specs#727 — PQ Noise working draft](https://github.com/libp2p/specs/pull/727)
- [rust-libp2p#6481 — `mlkem-hfs` hybrid handshake (draft)](https://github.com/libp2p/rust-libp2p/pull/6481)
- [pq-noise-artifacts — cross-implementation interop vectors](https://github.com/paschal533/pq-noise-artifacts)
- [rustls post-quantum key exchange](https://docs.rs/rustls-post-quantum/latest/rustls_post_quantum/)
- [draft-ietf-tls-ecdhe-mlkem-05](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [*Post-quantum authentication in QUIC under amplification and congestion constraints* — research artifact](https://zenodo.org/records/22862522)
- [*Network Impact of Post-Quantum Certificate Chain Sizes on TTFB*, arXiv:2604.24869](https://arxiv.org/html/2604.24869)
- [Why post-quantum signatures are breaking TLS handshake limits — Red Sift](https://redsift.com/blog/post-quantum-signature-sizes)

**Propagation**
- [ethp2p](https://pkg.go.dev/github.com/ethp2p/ethp2p) · [EC broadcast strategy spec](https://github.com/ethp2p/ethp2p/blob/main/specs/003-ec-broadcast-rs.md)
- [RaptorCast — Monad's block propagation protocol](https://medium.com/@monadwhisper/raptorcast-0fc15424d497)
- [*Optimum Peer-Turbo: A Scalable and Efficient Solution for P2P Broadcasting*, arXiv:2605.15715](https://arxiv.org/html/2605.15715)
- [*OptimumP2P: Fast and Reliable Gossiping in P2P Networks*, arXiv:2508.04833](https://arxiv.org/pdf/2508.04833)
- [*GossipSub: Attack-Resilient Message Propagation in Filecoin and ETH2.0*](https://research.protocol.ai/publications/gossipsub-attack-resilient-message-propagation-in-the-filecoin-and-eth2.0-networks/)

**Hashing**
- [Ethereum roadmap drops Poseidon for SHA/BLAKE](https://postquantum.com/security-pqc/ethereum-roadmap-drops-poseidon/)

**Randomness**
- [*A New Look at Blockchain Leader Election: Simple, Efficient, Sustainable and Post-Quantum* (LB-VRF → iVRF), eprint 2022/993](https://eprint.iacr.org/2022/993)
- [*Post-Quantum VRF and its Applications in Future-Proof Blockchain Systems*, arXiv:2109.02012](https://arxiv.org/pdf/2109.02012)

---

### Open Questions

- Does iVRF's modified uniqueness property hold usefully for a **bounded, known** Q-BFT validator
  set, or is its advantage specific to Algorand-style sortition from an open set? (Blocks A4.)
- Can an erasure-coded block broadcast and a DAG mempool ([ADR-0004](../adr/0004-consensus-selection.md))
  share one dissemination path, or does the DAG's causal-batch traffic want its own? (Blocks A3.)
- Is the tension in §5 real — does any synchronized aggregation scheme permit a rotation cadence
  short enough to respect the 190k-signature leakage bound, or must Huxplex choose between
  compact certificates and frequent rotation? (Blocks A7 + A8.)
- If the ML-DSA authentication transport must be custom regardless (§3.2), is QUIC still the
  right primary — or does building on libp2p's **Noise** path, where the PQ work is actually
  happening, cost less integration effort? (Re-opens an ADR-0012 sub-decision.)

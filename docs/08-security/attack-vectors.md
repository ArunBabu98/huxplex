# Attack Vectors

Concrete attack techniques, how they'd play out on Huxplex, and the specific defense. Organized
by the directive's adversary list. Cross-references the register in [threat-model](threat-model.md).

## 1. Nation-state actors
- **Validator infiltration**: fund/run validators to approach 1/3. *Defense*: open but bounded
  set, stake cost, delegation diversity, correlation slashing, governance monitoring (T4).
- **Legal coercion of team/infra**: subpoena keys, seize servers. *Defense*: minimal trusted
  base, jurisdictional diversity, no single coercible chokepoint, reproducible community-buildable
  clients (T23).
- **Traffic analysis / deanonymization**: map peers and intents. *Defense*: PQ-TLS, mixnet for
  intents (future), DID rotation (T6, privacy).
- **BGP / routing attacks → eclipse**: partition validators. *Defense*: anti-eclipse peer
  buckets, validator mesh, multiple network paths (T6).

## 2. Quantum attackers
See [quantum-threats](quantum-threats.md). Headline: HNDL (T2) and a future scheme break (T1),
both addressed by PQ-native + hybrid + agility + family diversity.

## 3. Hostile AI agents
- **Spam swarm**: millions of micro-txs/intents. *Defense*: per-Visa bonds, fees, rate limits,
  verify-pricing, GossipSub scoring (T8, T10).
- **Metric grinding**: farm novelty/reputation. *Defense*: metrics off-consensus, bounded +
  decaying, HLC anti-grinding, diminishing returns (T11).
- **Collusion rings**: wash reputation/markets. *Defense*: independence checks, graph clustering
  detection, value-weighting, economic friction (T13).
- **Market manipulation (intent front-running)**: solver steals opportunity. *Defense*:
  commit-reveal, escrow pre-lock, intent expiry (marketplace).
- **Constraint evasion**: agent exceeds Work Visa limits. *Defense*: in-VM enforcement of caps,
  fast revocation, bond slash (agent-wallets).

## 4. Economic attacks
- **MEV / reordering**: extract value from tx ordering. *Defense*: intent-centric design reduces
  extractable value, deterministic selection, sealed bids; DAG mempool fair-ordering research.
- **Fee manipulation**: spam to spike fees / grief. *Defense*: per-dimension base fees, bounded
  adjustment, priority tips (fee-model).
- **Governance bribery / dark DAOs**: pay for votes. *Defense*: soulbound non-transferable
  votes, ZK unlinkable voting (no provable receipt) (T14, voting).
- **Staking/slashing edge cases**: trigger false slashes or avoid real ones. *Defense*: provable
  faults only, challenge window, audited slashing logic (T21, staking).

## 5. Validator collusion
- **Equivocation / double-sign**: sign two blocks at a height. *Defense*: cryptographically
  provable via domain-separated phase contexts (🟢); major slash + eject (T4, staking).
- **Censorship cartel**: exclude target txs. *Defense*: leader rotation, inclusion lists/
  force-inclusion mechanisms (research), open set, governance pressure.
- **Liveness attack (1/3 go offline)**: halt finality. *Defense*: BFT liveness needs 2/3;
  monitoring, validator diversity, restart-from-checkpoint runbook (T5, incident-response).

## 6. Sybil attacks
- **Identity Sybils**: many fake identities to game governance/markets. *Defense*: personhood
  gate for SVRGN, bonded distinct controllers, per-controller caps (T12).
- **Validator Sybils**: many cheap validators. *Defense*: min self-bond + bounded set (staking).
- **Whitewashing**: abandon bad-rep identity, restart. *Defense*: new DIDs start at zero with
  high bonds; reputation sticky-down (reputation).

## 7. Network attacks
- **Eclipse** (T6), **DDoS on leader** (T7), **PQ-verify flood** (T8), **DHT poisoning**
  (signed entries 🟢 + S/Kademlia), **amplification** (big PQ messages → bond-gated gossip).
  Details in [`02-architecture/networking.md`](../02-architecture/networking.md).

## 8. Bridge attacks
- **The #1 historical loss vector in crypto.** A custodial bridge holding wrapped assets is a
  honeypot. *Defense (decisive)*: **defer bridges entirely**; when cross-chain is needed, use
  **light-client verification + PQ proofs**, never custodial multisig bridges. No treasury or
  user funds behind a bridge (T19). This single choice removes a whole class of catastrophic
  exploits.

## 8b. Connector attacks — an *oracle* boundary, not a custody boundary

Connectors ([ADR-0015](../adr/0015-connector-architecture.md)) are **not** bridges, and
classifying them correctly determines the whole defense posture:

| | Bridge (§8) | Connector |
|---|---|---|
| Holds funds/credentials | Yes | **No** — HCP invariant A7 forbids it |
| Can create authority | Yes, its signature mints | **No** — the visa resolves at L3 *before* invocation |
| Worst case | Unbounded theft up to TVL | Lies about an external fact, inside a bounded envelope |
| Recourse | None | Merchant records, chargebacks, external audit trails |

Note also that the trust boundary exists with or without Huxplex: if an agent transacts on a
user's behalf, someone is trusting the merchant. A connector under a visa **bounds and attests**
an exposure that already existed — against the realistic alternative (an agent holding the
user's card with unbounded API access) it is a net security improvement.

| Attack | Defense |
|---|---|
| **Malicious connector lies about occurrence** | Evidence classes: `Relayed` proves receipt only; settlement requires the class the user demanded ([ADR-0016](../adr/0016-evidence-and-attestation.md)). Bonding + slashing for *provably* false attestations. **Bounded, not eliminated** |
| **Connector attempts to exceed authority** | Structurally impossible: it holds an attenuated envelope, never the visa (invariants A1–A4) |
| **Agent + connector collude** | Loss bounded above by the visa the human signed — test G11-T6. The protocol's strongest property |
| **Connector goes silent mid-intent** | Signed heartbeats; `Active → Stale → Breached` → remediation. Silence is a detectable event, never an indefinite wait |
| **Withheld or reordered events** | Gapless per-session `seq`; later events cannot apply over a gap |
| **Replay / duplicate effect** | Effect Keys `H(session ‖ envelope ‖ nonce)`; connectors MUST be idempotent |
| **Indeterminate outcome treated as failure** | `Unknown ≠ Failed` (invariant A6); reconcile before compensating, or risk double purchase |
| **Aggregate drain via many bounded intents** | Per-connector, per-epoch `aggregate_exposure_cap` + circuit breaker |
| **Credential theft via the substrate** | No credentials ever enter the protocol (A7). Payment uses bounded mandate references |
| **Commerce/payment authority confusion** | Disjoint action classes; neither connector holds the other's envelope (A8) |
| **Silent API rot** | Continuous conformance testing as a registry requirement; failure → `Probation`/`Suspended`, sessions quarantine rather than hang |
| **Profile-3 (custodial) connectors** | **Custody-shaped — treat as a bridge.** Inherits the §8 deferral in full: governance super-majority, Phase 4 at the earliest |

The genuine long-run costs here are **liability, scope and maintenance**, not theft — see
[connector protocol](../15-specifications/07-connector-protocol.md) §12–§13.

## 9. Supply-chain attacks
- **Malicious dependency / build-server compromise**: inject backdoor into the client.
  *Defense*: **reproducible builds** (anyone can verify binary = source), signed releases, SBOM,
  dependency pinning + auditing, minimal dependency surface, vendored crypto, `cargo-vet`/
  `cargo-audit` in CI (T20). This is gate-blocking for every release.
- **Compromised PQ library**: *Defense*: multi-vendor crypto, KAT vectors, isolation.

## 10. Social engineering
- **Phishing operators / governance voters**: trick into signing malicious actions. *Defense*:
  hardware-key/phishing-resistant auth, multi-party approval for sensitive ops, clear signing
  (show what you sign), runbooks, training (T24).
- **Fake-urgency governance proposals**: rush a malicious change. *Defense*: time-locks, double-
  confirmation for big changes, human veto (governance).

## 11. Insider threats
- **Founder/core-dev backdoor or upgrade-key abuse**: *Defense*: no privileged backdoor,
  on-chain governed + time-locked upgrades, reproducible builds, transparency, minimal trusted
  base, eventual full decentralization (T23). The roadmap's decentralization milestones exist
  partly to *remove the insider as a single point of trust*.

## Cross-cutting defense themes

1. **Make the expensive thing (PQ verify) priced and rate-limited** — most DoS vectors route
   through underpriced verification.
2. **Keep dangerous metrics off the critical path** — gaming reputation/novelty must never
   threaten safety.
3. **Defer/avoid the historically-deadly features** — bridges, classical crypto.
4. **Reproducibility + minimal trusted base** — defeats supply-chain and insider classes.
5. **Soulbound, personhood-gated power** — defeats vote-buying and Sybil-governance.

---

### Open Questions
- Censorship resistance: do we need force-inclusion / inclusion lists at L1, and how under PQ costs?
- Fair ordering (MEV resistance) in a DAG mempool — which scheme?
- Cheapest robust defense against PQ-verification flooding for unauthenticated peers?
</content>

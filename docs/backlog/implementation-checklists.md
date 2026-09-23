# Implementation Checklists

Per-component "definition of done" checklists. Use these as acceptance criteria on the
corresponding [backlog](README.md) epics. ✅ = done in current code; ⬜ = to build.

## Crypto core (`hux-crypto`)

- ✅ ML-DSA-44 sign/verify with context binding
- ✅ ML-KEM-768 keygen/encaps/decaps + HKDF directional session key
- ✅ BIP32 → ML-DSA hardened seed derivation (coin type 931931)
- ✅ Domain-separated context strings + cross-context replay tests
- ✅ PeerId = SHAKE-256(pk)[..32]
- ⬜ `AlgoSuite` versioned registry; `Signer/Verifier/Kem` traits
- ⬜ Sizes parameterized by suite (remove hard-coded `1312`/`2420`)
- ⬜ `algo_suite` field on all signed objects + downgrade-resistance
- ⬜ Zeroizing secret types; no `Debug` on secrets
- ⬜ SLH-DSA-128s via `fips205` (validator identity); LB-VRF/iVRF and PQ-SSLE deferred to G6
- ⬜ FIPS KAT vectors in CI (signature fixtures pin the randomness); constant-time/side-channel tests
- ⬜ Multi-vendor differential tests: `libcrux` ↔ `aws-lc-rs` (ML-DSA), `fips205` ↔ `slh-dsa` (SLH-DSA)
- ⬜ Production/test signing API split — production MUST NOT accept caller-supplied randomness
- ⬜ `SigRole` + `KeyPurpose` (🟢 purposes done); role-confusion rejection (G1-T6)
- ⬜ Dummy-V2 migration test (agility proven)

## State (`hux-state`, `hux-types`)

- ⬜ Resource / Transaction / Block / nullifier types (canonical serialization)
- ⬜ Kind-balance invariant enforced; logic-script hook
- ⬜ Nullifier set (Merkleized) + in-memory filter; double-spend prevention
- ⬜ RocksDB-backed `StateStore` trait; Jellyfish Merkle Tree
- ⬜ Witness/signature separation + post-finality pruning
- ⬜ State-sync snapshots (signed); shard-ready layout (nonce → shard fn)
- ⬜ proptest: conservation, nullifier uniqueness, serialization round-trip

## Execution (`hux-vm`, `hux-scheduler`)

- ⬜ `Vm` trait; `wasmi` engine; restricted-opcode module validator
- ⬜ Gas metering; crypto host functions (ML-DSA verify=250, etc.)
- ⬜ Determinism: differential test across nodes/engines (T27)
- ⬜ Block-STM parallel scheduler + HAOT hint; deterministic merge
- ⬜ `wasmtime` restricted profile (Production)

## Consensus (`hux-consensus`)

- ⬜ PrePrepare/Prepare/Commit with ML-DSA votes (contexts ✅)
- ⬜ Deterministic finality (2f+1); equivocation evidence + slashing
- ⬜ DAG mempool (Narwhal-style); LB-VRF + PQ-SSLE leader election (Production)
- ⬜ Epoch rotation; bounded validator set; HLC + vector-clock metadata
- ⬜ TLA+ safety spec; formal verification (Production gate)

## Networking (`hux-network`)

- ✅ GossipMessage / DhtEntry signed types + topics + contexts (network-parameterized)
- ⬜ libp2p/QUIC transport; TLS 1.3 with **native ML-DSA-44 certificates**, mutual auth,
  ALPN `huxplex/{network}/1`, padded client Initial (ADR-0019)
- ⬜ Running swarm, peer state machine, Kademlia discovery, peer scoring
- ⬜ Eclipse/DDoS resistance; sentry topology; rate-limited unauthenticated gossip

## Economy (`hux-economy`)

- ⬜ HUX balances/transfers/fees; block rewards
- ⬜ Staking bond/unbond/delegation; slashing (double-sign first)
- ⬜ EIP-1559-style base fee + governance burn fraction; sponsored fees
- ⬜ SNTNC soulbound mint/decay (off-consensus); on-chain treasury (milestone-gated)

## Identity (`hux-identity`)

- ⬜ `did:huxplex` (✅ primitive) DID docs as resources; key rotation; identity classes
- ⬜ ZK proof-of-personhood (multi-provider); personhood-gated SVRGN
- ⬜ Work Visa VCs + in-VM constraint enforcement + fast revocation
- ⬜ Provenance records (human + machine origin; context ✅)

## Governance (`hux-governance`)

- ⬜ Four-phase Hive-Mind lifecycle; SVRGN veto (>33%); SNTNC log-weight
- ⬜ Constitutional layer (invariants + super-process + time-locks)
- ⬜ Governed, hash-pinned, time-locked upgrades; emergency path (constitution-bounded)

## ZK (`hux-zk`)

- ⬜ zk-STARK integration (versioned proof system); proof-of-personhood circuit
- ⬜ Verifiable task-completion; (future) shielded resources, compressed certs

## Cross-cutting / release

- ✅ `Cargo.lock` committed; `thiserror` errors; newtype IDs
- ⬜ CI: fmt/clippy/test/proptest/loom/KATs/determinism/audit/no-dep-cycle
- ⬜ Fuzzing (parsers, VM loader, messages); mutation testing on critical crates
- ⬜ Reproducible signed releases + SBOM; weak-subjectivity checkpoints
- ⬜ Monitoring + independent invariant monitors; DR backups restore-tested

---

*Update the ✅/⬜ marks as components land. A component is "done" only when its tests + (where
required) audit/formal-verification boxes are also checked.*
</content>

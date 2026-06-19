# Post-Quantum Cryptography

> Satisfies the directive's **Cryptography Research** requirement: ML-DSA, ML-KEM, SLH-DSA,
> hybrid cryptography, crypto-agility, HD PQ wallets, quantum-resistant signatures, key
> rotation. Parameter decisions: [ADR-0002](../adr/0002-cryptographic-parameter-set.md).

## The standards baseline

NIST finalized the first PQ standards in 2024. Huxplex builds on them:

| FIPS | Name | Type | Underlying hardness |
|---|---|---|---|
| **203** | ML-KEM (Kyber) | Key encapsulation | Module-LWE (lattice) |
| **204** | ML-DSA (Dilithium) | Signatures | Module-LWE / Fiat-Shamir-with-Aborts |
| **205** | SLH-DSA (SPHINCS+) | Signatures | Hash functions only |

Plus non-FIPS building blocks Huxplex needs: a lattice VRF (**LB-VRF**), single-secret leader
election (**PQ-SSLE**), and **zk-STARKs** (hash-based, no trusted setup).

## Selected parameter sets and exact sizes

| Primitive | Param set | Public | Secret | Output | NIST cat | Status |
|---|---|---|---|---|---|---|
| Signature (hot) | **ML-DSA-44** | 1,312 B | **2,560 B** | sig **2,420 B** | 1 (~AES-128) | 🟢 implemented |
| KEM (transport) | **ML-KEM-768** | ek 1,184 B | dk 2,400 B | ct 1,088 B, ss 32 B | 3 (~AES-192) | 🟢 implemented |
| Identity (validators) | **SLH-DSA-128s** | 32 B | 64 B | sig ~7,856 B | 1 | 🟡 planned |
| Hash / XOF | SHAKE-256 / BLAKE3 | — | — | 256-bit | — | 🟢 (SHAKE) |

> ❗ **Correction to the vision essays**: they state an ML-DSA-44 *signature* of 2,560 bytes.
> That figure is the **secret key** size. The signature is **2,420 bytes** (confirmed by the
> implementation's tests). Documentation and gas/weight models must use 2,420 B.

Note ML-DSA-44 is NIST Category 1 while ML-KEM-768 is Category 3 — a slight asymmetry. We may
raise the signature to **ML-DSA-65** (Cat 3) for balance in a later suite version; the agility
registry makes this a parameter change, not a redesign. (Open item in ADR-0002.)

## Why these algorithms

- **ML-DSA-44**: best practical signing/verification speed and size among FIPS signatures; the
  whole hot path (txs, votes) uses it. Lattice security resists Shor. Randomized signing (FIPS
  204) means two signatures over the same message differ but both verify — already tested.
- **ML-KEM-768**: PQ confidentiality for transport against HNDL; ciphertext (1,088 B) fits a
  QUIC datagram. Used in a **hybrid** with X25519.
- **SLH-DSA-128s**: hash-based, *structure-free* — its security rests only on hash functions,
  so it survives even a total break of lattice assumptions. Large/slow, so reserved for
  **rarely-signed long-lived validator identity keys** (root of trust), not per-block signing.
- **zk-STARK**: transparent (no trusted setup) and hash-based → PQ-safe, unlike pairing-based
  SNARKs. Used for task-completion and (future) state/execution proofs.

## Hybrid cryptography

Where cheap, combine classical + PQ so an attacker must break **both**:

- **Transport KEX**: `shared = HKDF( X25519_ss ‖ ML-KEM_ss )`. Protects against (a) a future
  CRQC breaking X25519 and (b) a future cryptanalytic break of ML-KEM. Recommended for the
  transition window; drop the classical half later via agility. (See
  [`02-architecture/networking.md`](../02-architecture/networking.md).)
- **Signatures**: hybrid signing (ML-DSA + Ed25519) is *possible* but **doubles an already-large
  signature** and complicates aggregation. Recommendation: **do not** hybridize signatures by
  default; rely on family diversity (SLH-DSA fallback) + agility instead. Revisit only if ML-DSA
  cryptanalysis emerges.

## Hierarchical deterministic PQ wallets

The code already derives ML-DSA seeds via BIP32:

```
m/44'/931931'/0'/0'/{index}'    // 931931 = Huxplex coin type; hardened-only
BIP32 child private key (32 B) → ML-DSA-44 keygen seed
```

Design notes & caveats:

- **Hardened-only derivation is required.** Non-hardened BIP32 derivation leaks relationships
  via the chain code; ML-DSA has no point-addition homomorphism anyway, so only hardened makes
  sense. The code enforces this (all path components hardened). ✅
- ⚠️ **This is a *seed-derivation* scheme, not standardized PQ HD.** We reuse BIP32 to derive
  *entropy*, then run ML-DSA keygen on it. There is no PQ equivalent of xpub-based public
  derivation (you cannot derive child ML-DSA public keys without the secret). Document this
  limitation: **watch-only/xpub workflows do not exist** for ML-DSA wallets.
- Master seed handling, mnemonics (BIP39), and recovery are in
  [key-management.md](key-management.md).

## Security margins & Grover

Grover halves search security, so:
- Symmetric keys / AEAD: **256-bit** (ChaCha20-Poly1305 256-bit).
- Hashes: **256-bit output** (SHAKE-256, BLAKE3) → ~128-bit quantum collision/preimage margin,
  acceptable.

## The agility imperative (restated)

PQ schemes are *young*. The single most important PQ decision is **not which algorithm** but
**that no algorithm is permanent**. See [crypto-agility.md](crypto-agility.md). Everything above
is "suite v1," addressable and replaceable.

## MVP / Production / Future

- **MVP**: ML-DSA-44 (🟢), ML-KEM-768 (🟢) hybrid handshake, SHAKE/BLAKE3, BIP32 HD (🟢).
- **Production**: add SLH-DSA-128s validator identity keys, LB-VRF + PQ-SSLE for consensus,
  FIPS KAT CI, side-channel audits, suite-version field on all signed objects.
- **Future**: zk-STARK task/state proofs, suite v2 (possibly ML-DSA-65, new schemes), PQ
  signature aggregation research, formal verification of the agility state machine.

---

### Open Questions
- ML-DSA-44 (Cat 1) vs ML-DSA-65 (Cat 3) for the hot path — security/perf/bandwidth tradeoff.
- Which audited Rust LB-VRF / PQ-SSLE implementations exist, if any?
- Should we adopt a stateful hash signature (XMSS/LMS) anywhere, or avoid statefulness entirely? (Leaning avoid; SLH-DSA is stateless.)
</content>

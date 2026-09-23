use bip32::{DerivationPath, XPrv};

/// The BIP44 `account'` level of the Huxplex derivation path, repurposed as a **key purpose**.
///
/// Derivation path: `m/44'/931931'/{purpose}'/0'/{index}'`
///
/// The discriminants are deliberately identical to the signature roles of ADR-0018, so a key's
/// purpose and the role it may sign under cannot drift apart. Per ADR-0018 rule V2, purposes are
/// **added, never removed or renumbered** — an existing discriminant is part of the derivation
/// path of every key already issued under it.
///
/// `Transaction` is `0`, which reproduces the original single-purpose path byte-for-byte; every
/// key and test vector derived before purposes existed is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyPurpose {
    /// Hot per-block / per-vote signing and user transactions (ML-DSA-44).
    Transaction = 0,
    /// Quorum-certificate signing. Reserved so a future synchronized/aggregating scheme
    /// (ADR-0021) can own a key tree of its own without colliding with session keys.
    QuorumCert = 1,
    /// Long-lived validator identity / root of trust (SLH-DSA-128s).
    Identity = 2,
    /// Governance: credential issuance, constitutional records, registry updates.
    Governance = 3,
    /// Transport / TLS certificate key (ADR-0019). `PeerId = SHAKE-256(pk)[..32]` is derived
    /// from this key. Held separately from `Transaction` because the TLS stack requires the
    /// raw private key, which would defeat the remote-signer isolation ADR-0014 rule 3
    /// mandates for the consensus signer.
    Transport = 4,
}

impl KeyPurpose {
    pub fn index(self) -> u32 {
        self as u32
    }
}

/// Derives a 32-byte ML-DSA keygen seed at `m/44'/931931'/{purpose}'/0'/{index}'`.
///
/// `index` is the key epoch (ADR-0014). Hardened at every level, so a leaked child key never
/// exposes a sibling or the parent.
pub fn derive_mldsa_seed_for_purpose(bytes: [u8; 64], purpose: KeyPurpose, index: u32) -> [u8; 32] {
    let path_str = format!("m/44'/931931'/{}'/0'/{index}'", purpose.index());
    let path: DerivationPath = path_str.parse().expect("Invalid path string");
    let child_xprv = XPrv::derive_from_path(bytes, &path).expect("BIP32 derivation failed");

    // 4. Extract the 32-byte private key to use as the ML-DSA entropy
    let mut mldsa_seed = [0u8; 32];
    mldsa_seed.copy_from_slice(&child_xprv.private_key().to_bytes());

    mldsa_seed
}

/// Derives a transaction-purpose ML-DSA seed — `m/44'/931931'/0'/0'/{index}'`.
///
/// Equivalent to [`derive_mldsa_seed_for_purpose`] with [`KeyPurpose::Transaction`], and
/// identical to the pre-ADR-0018 derivation.
pub fn derive_mldsa_seed(bytes: [u8; 64], index: u32) -> [u8; 32] {
    derive_mldsa_seed_for_purpose(bytes, KeyPurpose::Transaction, index)
}

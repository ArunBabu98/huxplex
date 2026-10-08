//! X25519 (RFC 7748) — the classical half of the hybrid KEM.
//!
//! **This module is the only place in the workspace permitted to name `libcrux_curve25519`**
//! (G1 task C4, enforced by `scripts/check-primitive-encapsulation.sh`). It is HACL*'s formally
//! verified Curve25519 — the same verified-vendor policy that chose libcrux for ML-DSA and ML-KEM.
//!
//! X25519 is never used on its own in Huxplex. It exists to be one half of
//! [`super::hybrid`], so that a transport session survives a cryptanalytic break of ML-KEM;
//! ML-KEM is the half that survives a quantum adversary.

use crate::error::{CryptoError, CryptoResult};

/// Secret scalar, public point and shared secret are all 32 bytes (RFC 7748 §5).
pub const KEY_LEN: usize = 32;

/// The public point for a secret scalar. Clamping is applied inside the scalar multiplication,
/// so any 32 bytes are a valid secret.
pub fn public_key(secret: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut public = [0u8; KEY_LEN];
    libcrux_curve25519::secret_to_public(&mut public, secret);
    public
}

/// Diffie–Hellman. Fails on an all-zero output — a low-order peer point, which RFC 7748 §6.1
/// permits rejecting and which TLS's `X25519MLKEM768` requires rejecting. An all-zero secret
/// contributes nothing, so accepting it would quietly reduce the hybrid to ML-KEM alone while
/// still calling itself hybrid.
pub fn shared_secret(secret: &[u8; KEY_LEN], peer: &[u8; KEY_LEN]) -> CryptoResult<[u8; KEY_LEN]> {
    let mut shared = [0u8; KEY_LEN];
    libcrux_curve25519::ecdh(&mut shared, peer, secret).map_err(|_| {
        CryptoError::KeyAgreementFailed("X25519 produced an all-zero shared secret".into())
    })?;
    Ok(shared)
}

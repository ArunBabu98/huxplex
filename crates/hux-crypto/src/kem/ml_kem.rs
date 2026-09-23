use hkdf::Hkdf;
use libcrux_ml_kem::{
    MlKemCiphertext,
    mlkem768::{self, MlKem768PrivateKey, MlKem768PublicKey},
};
use sha2::Sha256;

pub const EK_SIZE: usize = 1184;
pub const DK_SIZE: usize = 2400;
pub const CT_SIZE: usize = 1088;

// Backend selection note (see docs/16-action-plan.md, gate G0):
//
// These call `mlkem768`'s top-level entry points, which dispatch through libcrux's
// `multiplexing` layer: it detects CPU capabilities at runtime and selects AVX2, NEON, or the
// portable implementation, falling back to portable when a SIMD backend was not compiled in.
//
// They MUST NOT be replaced with a hardcoded backend path such as `mlkem768::avx2::*`. That
// path exists only under the `simd256` feature on x86-64 and does not compile on aarch64 —
// which excludes Apple Silicon, ARM CI runners, and ARM validators. Architecture portability
// is a decentralization property here, not a convenience.
//
// ML-KEM is deterministic in its seed, so every backend produces identical output; switching
// backends cannot change a test vector or fork the network.

pub fn kem768_keygen(randomness: [u8; 64]) -> ([u8; EK_SIZE], [u8; DK_SIZE]) {
    let keypair = mlkem768::generate_key_pair(randomness);
    let (dk, ek) = keypair.into_parts();
    (*ek.as_slice(), *dk.as_slice())
}

pub fn kem768_encapsulate(ek: [u8; EK_SIZE], randomness: [u8; 32]) -> ([u8; CT_SIZE], [u8; 32]) {
    let public_key = MlKem768PublicKey::from(ek);
    let (ct, ss_encap) = mlkem768::encapsulate(&public_key, randomness);
    (*ct.as_slice(), ss_encap)
}

pub fn kem768_decapsulate(dk: [u8; DK_SIZE], ct: [u8; CT_SIZE]) -> [u8; 32] {
    let private_key = MlKem768PrivateKey::from(dk);
    let ciphertext = MlKemCiphertext::from(ct);
    mlkem768::decapsulate(&private_key, &ciphertext)
}

pub fn kem768_derive_session_key(
    ss: [u8; 32],
    peer_a: [u8; 32],
    peer_b: [u8; 32],
    salt: Option<&[u8]>,
    protocol_label: Option<&[u8]>,
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, &ss);

    let mut info = Vec::with_capacity(128);

    info.extend_from_slice(b"ML-KEM-768-v1-DERIVE");

    info.extend_from_slice(&peer_a);
    info.extend_from_slice(&peer_b);

    if let Some(label) = protocol_label {
        info.extend_from_slice(label);
    }

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid length for HKDF-SHA256");

    okm
}

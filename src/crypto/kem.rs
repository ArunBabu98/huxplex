use hkdf::Hkdf;
use libcrux_ml_kem::{
    MlKemCiphertext,
    mlkem768::{self, MlKem768PrivateKey, MlKem768PublicKey},
};
use sha2::Sha256;

pub const EK_SIZE: usize = 1184;
pub const DK_SIZE: usize = 2400;
pub const CT_SIZE: usize = 1088;

pub fn kem768_keygen(randomness: [u8; 64]) -> ([u8; EK_SIZE], [u8; DK_SIZE]) {
    let keypair = mlkem768::avx2::generate_key_pair(randomness);
    let (dk, ek) = keypair.into_parts();
    (ek.as_slice().clone(), dk.as_slice().clone())
}

pub fn kem768_encapsulate(ek: [u8; EK_SIZE], randomness: [u8; 32]) -> ([u8; CT_SIZE], [u8; 32]) {
    let public_key = MlKem768PublicKey::from(ek);
    let (ct, ss_encap) = mlkem768::avx2::encapsulate(&public_key, randomness);
    (ct.as_slice().clone(), ss_encap)
}

pub fn kem768_decapsulate(dk: [u8; DK_SIZE], ct: [u8; CT_SIZE]) -> [u8; 32] {
    let private_key = MlKem768PrivateKey::from(dk);
    let ciphertext = MlKemCiphertext::from(ct);
    let ss_decap = mlkem768::avx2::decapsulate(&private_key, &ciphertext);
    ss_decap
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

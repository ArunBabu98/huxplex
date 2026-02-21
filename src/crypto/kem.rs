use libcrux_ml_kem::{
    MlKemCiphertext,
    mlkem768::{self, MlKem768PrivateKey, MlKem768PublicKey},
};

pub const EK_SIZE: usize = 1184;
pub const DK_SIZE: usize = 2400;

pub fn kem768_keygen(randomness: [u8; 64]) -> ([u8; EK_SIZE], [u8; DK_SIZE]) {
    let keypair = mlkem768::generate_key_pair(randomness);
    let (dk, ek) = keypair.into_parts();
    (ek.as_slice().clone(), dk.as_slice().clone())
}

pub fn kem768_encapsulate(ek: [u8; EK_SIZE], randomness: [u8; 32]) -> ([u8; 1088], [u8; 32]) {
    let public_key = MlKem768PublicKey::from(ek);
    let (ct, ss_encap) = mlkem768::encapsulate(&public_key, randomness);
    (ct.as_slice().clone(), ss_encap)
}

pub fn kem768_decapsulate(dk: [u8; DK_SIZE], ct: [u8; 1088]) -> [u8; 32] {
    let private_key = MlKem768PrivateKey::from(dk);
    let ciphertext = MlKemCiphertext::from(ct);
    let ss_decap = mlkem768::decapsulate(&private_key, &ciphertext);
    ss_decap
}

use libcrux_ml_kem::mlkem768;

pub const EK_SIZE: usize = 1184;
pub const DK_SIZE: usize = 2400;

pub fn kem768_keygen(randomness: [u8; 64]) -> ([u8; EK_SIZE], [u8; DK_SIZE]) {
    let keypair = mlkem768::generate_key_pair(randomness);
    let (dk, ek) = keypair.into_parts();
    (ek.as_slice().clone(), dk.as_slice().clone())
}

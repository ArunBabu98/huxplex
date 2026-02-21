use std::io::Read;

use sha2::digest::{ExtendableOutput, Update};
use sha3::Shake256;

use crate::crypto::publickey::PublicKey;

#[derive(Debug, PartialEq)]
pub struct PeerId {
    pub id: [u8; 32],
}

impl PeerId {
    pub fn from_ml_dsa_pk(pk: PublicKey) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(pk.bytes.as_slice());

        // Squeeze out 32 bytes
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; 32];
        reader.read(&mut output);
        PeerId { id: output }
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.id)
    }
}

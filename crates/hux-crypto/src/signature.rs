use rand::Rng;

use crate::{
    error::CryptoResult, privatekey::PrivateKey, publickey::PublicKey, sig::ml_dsa,
    signaturescheme::SignatureSchemeId,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub scheme: SignatureSchemeId,
    pub bytes: Vec<u8>,
}

pub struct Keypair {
    publickey: PublicKey,
    privatekey: PrivateKey,
}

impl Keypair {
    pub fn generate(scheme: SignatureSchemeId, seed: [u8; 32]) -> CryptoResult<Self> {
        match scheme {
            SignatureSchemeId::Dilithium2 => {
                let (pk, sk) = ml_dsa::generate(seed);
                Ok(Keypair {
                    publickey: PublicKey {
                        scheme: scheme.clone(),
                        bytes: pk,
                    },
                    privatekey: PrivateKey::new(scheme, sk),
                })
            }
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.publickey
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.privatekey
    }

    pub fn sign(&self, message: &[u8], context: Option<&[u8]>) -> CryptoResult<Signature> {
        // Per-signature randomness from the system CSPRNG. Deterministic lattice signing plus
        // fault injection is a demonstrated key-recovery path (eprint 2025/2009), so hedging is
        // mandatory, not optional. G1 task C9 will make the deterministic path reachable only
        // from a separate test-only entry point, so no caller can supply this value.
        let mut randomness = [0u8; ml_dsa::SIGNING_RANDOMNESS_LEN];
        rand::rng().fill_bytes(&mut randomness);

        let ctx_bytes = context.unwrap_or(&[]);

        match self.public_key().scheme {
            SignatureSchemeId::Dilithium2 => {
                let bytes = ml_dsa::sign(
                    self.private_key().expose_secret(),
                    message,
                    ctx_bytes,
                    randomness,
                )?;
                Ok(Signature {
                    scheme: self.public_key().scheme.clone(),
                    bytes,
                })
            }
        }
    }
}

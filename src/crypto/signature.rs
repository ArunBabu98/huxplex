use libcrux_ml_dsa::ml_dsa_44;
use rand::Rng;

use crate::crypto::{
    error::{CryptoError, CryptoResult},
    privatekey::PrivateKey,
    publickey::PublicKey,
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
                let keypair = ml_dsa_44::generate_key_pair(seed);
                Ok(Keypair {
                    publickey: PublicKey {
                        scheme: scheme.clone(),
                        bytes: keypair.verification_key.as_ref().to_vec(),
                    },
                    privatekey: PrivateKey {
                        scheme,
                        bytes: keypair.signing_key.as_ref().to_vec(),
                    },
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
        let sk_bytes: [u8; 2560] = self
            .private_key()
            .bytes
            .as_slice()
            .try_into()
            .map_err(|e| CryptoError::InvalidSecretKeySize(format!("{:?}", e)))?;

        let signing_key = ml_dsa_44::MLDSA44SigningKey::new(sk_bytes);

        let mut randomness = [0u8; 32];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut randomness);
        let ctx_bytes = context.unwrap_or(&[]);

        let sig_obj = ml_dsa_44::sign(&signing_key, message, ctx_bytes, randomness)
            .map_err(|e| CryptoError::SigningFailed(format!("{:?}", e)))?;

        Ok(Signature {
            scheme: self.public_key().scheme.clone(),
            bytes: sig_obj.as_ref().to_vec(),
        })
    }
}

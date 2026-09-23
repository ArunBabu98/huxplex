use rand::Rng;

use crate::{
    error::CryptoResult, privatekey::PrivateKey, publickey::PublicKey, sig::ml_dsa,
    signaturescheme::SignatureSchemeId, traits,
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
    /// Generates a keypair for `scheme` from a 32-byte seed.
    ///
    /// Dispatches through the registry's trait rather than matching on the scheme, so adding a
    /// scheme is a registry row plus an implementation — never an edit here (G1 tasks C4, C6).
    pub fn generate(scheme: SignatureSchemeId, seed: [u8; 32]) -> CryptoResult<Self> {
        let implementation = traits::implementation(scheme)?;
        let (pk, sk) = implementation.generate(&seed)?;

        Ok(Keypair {
            publickey: PublicKey { scheme, bytes: pk },
            privatekey: PrivateKey::new(scheme, sk),
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.publickey
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.privatekey
    }

    pub fn sign(&self, message: &[u8], context: Option<&[u8]>) -> CryptoResult<Signature> {
        let scheme = self.public_key().scheme;
        let implementation = traits::implementation(scheme)?;

        // Per-signature randomness from the system CSPRNG. Deterministic lattice signing plus
        // fault injection is a demonstrated key-recovery path (eprint 2025/2009), so hedging is
        // mandatory, not optional. G1 task C9 moves the deterministic path behind a separate
        // test-only entry point so no caller can supply this value.
        let mut randomness = [0u8; ml_dsa::SIGNING_RANDOMNESS_LEN];
        rand::rng().fill_bytes(&mut randomness);

        let bytes = implementation.sign(
            self.private_key().expose_secret(),
            message,
            context.unwrap_or(&[]),
            &randomness,
        )?;

        Ok(Signature { scheme, bytes })
    }
}

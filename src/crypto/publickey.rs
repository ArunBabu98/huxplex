use crate::crypto::signaturescheme::SignatureSchemeId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub scheme: SignatureSchemeId,
    pub bytes: Vec<u8>
}

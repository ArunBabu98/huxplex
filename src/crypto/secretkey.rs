use crate::crypto::signaturescheme::SignatureSchemeId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey {
    pub scheme: SignatureSchemeId,
    pub bytes: Vec<u8>,
}

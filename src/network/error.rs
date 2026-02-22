use thiserror::Error;

pub type NetworkResult<T> = Result<T, NetworkError>;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Invalid peer ID size: expected 32 bytes, got {0}")]
    InvalidPeerIdSize(usize),

    #[error("Gossip signature verification failed")]
    GossipSignatureInvalid,

    #[error("Gossip message scheme mismatch")]
    SchemeMismatch,

    #[error("DHT entry signature invalid for peer {0}")]
    DhtAuthFailed(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] crate::crypto::error::CryptoError),
}

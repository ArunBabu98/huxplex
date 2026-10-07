//! TLS 1.3 for the QUIC handshake — tasks **N2–N5**, **N7**;
//! [ADR-0019](../../../../docs/adr/0019-transport-authentication.md),
//! [wire spec §2](../../../../docs/15-specifications/05-network-wire-protocol.md).
//!
//! Huxplex constructs both rustls configs itself (N0 outcome 3), so every ADR-0019 requirement
//! is a line in this file rather than a hope about someone else's defaults:
//!
//! | Requirement | Where |
//! |---|---|
//! | TLS 1.3 only | [`provider`], `with_protocol_versions(&[&TLS13])` |
//! | `X25519MLKEM768` only — a classical-only peer is refused (G5-T1) | [`provider`] |
//! | native ML-DSA-44 certificates, `SignatureScheme` 0x0904 | `MlDsaKey`, [`PeerVerifier`] |
//! | no CA, no names, no expiry; `PeerId` = SHAKE-256(spki) is the identity (N2) | [`PeerVerifier`] |
//! | mutual authentication — no client certificate, no connection (N3) | `client_auth_mandatory` |
//! | ALPN `huxplex/{network}/1` — cross-network dials fail in the handshake (N4) | [`alpn`] |
//! | 1-RTT resumption on, 0-RTT early data off (N7) | [`client_config`], [`server_config`] |
//!
//! # Which ML-DSA, and which context
//!
//! TLS signatures — the certificate's self-signature and `CertificateVerify` — are made and
//! checked by **libcrux** through the `hux-crypto` registry, with the **empty** FIPS 204 context,
//! as `draft-ietf-tls-mldsa` specifies. The transport key therefore never leaves `hux-crypto`'s
//! zeroizing types. aws-lc-rs supplies only what rustls cannot do without it: the hybrid key
//! exchange, the AEAD and the key schedule. The two ML-DSA implementations are held to identical
//! verdicts by `hux-crypto`'s C11 differential.
//!
//! The empty context is what separates a TLS signature from every Huxplex protocol signature:
//! each `huxplex-{network}:…:v1` context is encoded into its FIPS 204 preimage, the TLS one is
//! not, so neither can verify as the other (**G5-T7**, `tests/transport.rs`).

use std::{fmt, sync::Arc};

use hux_crypto::{
    context::Network,
    publickey::PublicKey,
    signature::{Keypair, Signature},
};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureAlgorithm,
    SignatureScheme,
    client::{
        ClientSessionMemoryCache, ClientSessionStore, ResolvesClientCert, Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        ClientHello, ResolvesServerCert,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::{CertifiedKey, Signer, SigningKey},
    version::TLS13,
};

use super::cert::{self, CertError};
use crate::peer::PeerId;

/// The one signature scheme offered and accepted. A suite rotation is a new code point here and
/// a new registry row (ADR-0018), never a negotiation fallback.
pub const SCHEME: SignatureScheme = SignatureScheme::ML_DSA_44;

/// ALPN for `network`: `huxplex/{network}/1`. QUIC requires ALPN agreement, so a mainnet node and
/// a testnet node cannot complete a handshake — before any Huxplex code runs (wire spec §2.4).
pub fn alpn(network: Network) -> Vec<u8> {
    format!("huxplex/{network}/1").into_bytes()
}

/// The rustls `ServerName` a dial to `peer` uses.
///
/// Nothing checks names — identity is the key — but rustls keys its resumption cache by server
/// name, so the name must be **per peer**: a ticket issued by one peer must never be offered to
/// another. The hex `PeerId` split into two 32-character DNS labels does that.
pub fn server_name(peer: &PeerId) -> ServerName<'static> {
    let hex = peer.to_hex();
    ServerName::try_from(format!("{}.{}.peer.huxplex", &hex[..32], &hex[32..]))
        .expect("two 32-hex-digit labels form a valid DNS name")
}

/// aws-lc-rs, restricted to TLS 1.3 suites and **`X25519MLKEM768` alone**.
///
/// Offering plain X25519 as well would let an active attacker who strips the hybrid share force
/// a classical session — the downgrade G5-T1 forbids. With a single group there is nothing to
/// fall back to.
pub fn provider() -> Arc<CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites = vec![
        aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    Arc::new(provider)
}

/// The node's transport identity: the `Transport`-purpose keypair, its certificate and `PeerId`.
pub struct TransportIdentity {
    certificate: CertificateDer<'static>,
    peer_id: PeerId,
    /// One resolver for the identity's lifetime. rustls resumes a session only under the same
    /// credentials `Arc` it was issued under, so this must not be rebuilt per connection.
    resolver: Arc<CertResolver>,
}

impl fmt::Debug for TransportIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportIdentity")
            .field("peer_id", &self.peer_id.to_hex())
            .finish_non_exhaustive()
    }
}

impl TransportIdentity {
    pub fn new(keypair: Keypair) -> Result<Self, CertError> {
        let certificate = CertificateDer::from(cert::generate(&keypair)?);
        let peer_id = PeerId::from_ml_dsa_pk(keypair.public_key().clone());
        let resolver = Arc::new(CertResolver(Arc::new(CertifiedKey::new(
            vec![certificate.clone()],
            Arc::new(MlDsaKey(Arc::new(keypair))),
        ))));
        Ok(TransportIdentity {
            certificate,
            peer_id,
            resolver,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }
}

/// Signs TLS handshake content: ML-DSA-44, **empty** context. What rustls calls for
/// `CertificateVerify`, exposed so G5-T7 can test the separation it relies on.
pub fn sign_handshake(keypair: &Keypair, message: &[u8]) -> Result<Vec<u8>, Error> {
    keypair
        .sign(message, None)
        .map(|s| s.bytes)
        .map_err(|e| Error::General(format!("ML-DSA signing failed: {e}")))
}

/// Verifies TLS handshake content: ML-DSA-44, **empty** context. The other half of
/// [`sign_handshake`].
pub fn verify_handshake(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    public_key
        .verify(
            message,
            &Signature {
                scheme: public_key.scheme,
                bytes: signature.to_vec(),
            },
            None,
        )
        .unwrap_or(false)
}

/// The rustls signing key: the transport keypair, signing through `hux-crypto`.
struct MlDsaKey(Arc<Keypair>);

impl fmt::Debug for MlDsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsaKey(<transport key>)")
    }
}

impl SigningKey for MlDsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SCHEME)
            .then(|| Box::new(MlDsaSigner(self.0.clone())) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        // ML-DSA has no TLS 1.2 `SignatureAlgorithm`; this value is consulted only for 1.2 suite
        // selection, which is disabled.
        SignatureAlgorithm::Unknown(0)
    }
}

struct MlDsaSigner(Arc<Keypair>);

impl fmt::Debug for MlDsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsaSigner(<transport key>)")
    }
}

impl Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        sign_handshake(&self.0, message)
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

#[derive(Debug)]
struct CertResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl ResolvesClientCert for CertResolver {
    fn resolve(&self, _: &[&[u8]], sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        sigschemes.contains(&SCHEME).then(|| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The certificate verifier — **the sole authority for peer identity** (ADR-0021 rule I5).
///
/// Outbound it knows the `PeerId` it is dialling and rejects any other; inbound it learns the
/// `PeerId` from the verified key. Either way: verify the self-signature, derive
/// `SHAKE-256(spki)[..32]`, and never consult a name, a chain or a clock.
#[derive(Debug)]
pub struct PeerVerifier {
    expected: Option<PeerId>,
}

impl PeerVerifier {
    /// For a dial: only `peer` will be accepted.
    pub fn outbound(peer: PeerId) -> Self {
        PeerVerifier {
            expected: Some(peer),
        }
    }

    /// For a listener: any peer that proves possession of its key.
    pub fn inbound() -> Self {
        PeerVerifier { expected: None }
    }

    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), Error> {
        if !intermediates.is_empty() {
            // A self-certifying identity has no chain; a peer sending one is not a Huxplex peer.
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        }
        let verified = cert::verify(end_entity).map_err(cert_error)?;
        match self.expected {
            Some(expected) if expected != verified.peer_id => Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
            _ => Ok(()),
        }
    }

    fn handshake_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != SCHEME {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        let verified = cert::verify(cert).map_err(cert_error)?;
        if verify_handshake(&verified.public_key, message, dss.signature()) {
            Ok(HandshakeSignatureValid::assertion())
        } else {
            Err(Error::InvalidCertificate(CertificateError::BadSignature))
        }
    }
}

fn cert_error(e: CertError) -> Error {
    match e {
        CertError::BadSelfSignature => Error::InvalidCertificate(CertificateError::BadSignature),
        _ => Error::InvalidCertificate(CertificateError::BadEncoding),
    }
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.check(end_entity, intermediates)
            .map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}

impl ClientCertVerifier for PeerVerifier {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.check(end_entity, intermediates)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}

/// The listener's TLS config.
pub fn server_config(identity: &TransportIdentity, network: Network) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .expect("aws-lc-rs supports TLS 1.3")
        .with_client_cert_verifier(Arc::new(PeerVerifier::inbound()))
        .with_cert_resolver(identity.resolver.clone());
    config.alpn_protocols = vec![alpn(network)];
    // 0-RTT early data is forbidden (wire spec §2.5): it reintroduces replay on the one path
    // with no application-layer nonce. Zero means tickets carry no early-data allowance.
    config.max_early_data_size = 0;
    config
}

/// A shared resumption cache, so every dial from one node can resume with any peer it has
/// handshaken with before. Keyed per peer by [`server_name`].
pub fn session_cache() -> Arc<dyn ClientSessionStore> {
    Arc::new(ClientSessionMemoryCache::new(256))
}

/// The dialler's TLS config: only the peer `verifier` expects will be accepted.
///
/// **Resumption** happens only between configs built from the same `verifier` `Arc` (and the
/// identity's one credentials resolver) — rustls refuses to resume a session under a different
/// verifier, so that a ticket earned under weak checks can never be redeemed under strong ones.
/// Reuse one verifier per peer; [`super::quic::ClientConfigs`] does.
pub fn client_config(
    identity: &TransportIdentity,
    network: Network,
    verifier: Arc<PeerVerifier>,
    sessions: Arc<dyn ClientSessionStore>,
) -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .expect("aws-lc-rs supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(identity.resolver.clone());
    config.alpn_protocols = vec![alpn(network)];
    config.resumption = Resumption::store(sessions);
    config.enable_early_data = false;
    config
}

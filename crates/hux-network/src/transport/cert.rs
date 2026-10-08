//! The transport certificate — task **N1**,
//! [ADR-0019](../../../../docs/adr/0019-transport-authentication.md) §1,
//! [wire spec §2.2](../../../../docs/15-specifications/05-network-wire-protocol.md).
//!
//! ```text
//! self-signed X.509 v3 certificate
//!   SubjectPublicKeyInfo : id-ML-DSA-44, the 1,312-byte public key
//!   signatureAlgorithm   : id-ML-DSA-44  (2.16.840.1.101.3.4.3.17), no parameters
//!   self-signature       : ML-DSA-44, empty context (pure mode, as for X.509)
//! ```
//!
//! There is no CA, no chain, no name checking and no expiry: **identity is the key**. Subject and
//! issuer are empty and the serial number is `1`; nothing reads them — the verifier derives the
//! `PeerId` from the key, never from a name. Every field is as small as X.509 allows on purpose:
//! the certificate rides in the responder's first flight, whose margin under QUIC's 3×
//! amplification limit is measured in tens of bytes (G5-T6). A `PeerId` in the subject alone
//! would cost ~170 of them.
//!
//! Built from typed `x509-cert` structures and parsed back with its strict DER decoder; no DER is
//! written by hand.

use std::time::Duration;

use hux_crypto::{
    publickey::PublicKey,
    signature::{Keypair, Signature},
    signaturescheme::SignatureSchemeId,
    suite::{AlgoSuite, SigRole, SuiteVersion},
};
use x509_cert::{
    Certificate, TbsCertificate, Version,
    der::{
        Decode, Encode,
        asn1::{BitString, GeneralizedTime, ObjectIdentifier, UtcTime},
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
};

use crate::peer::PeerId;

/// `id-ml-dsa-44` (NIST CSOR, FIPS 204).
pub const ID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// Why a certificate was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    #[error("not a DER certificate: {0}")]
    Malformed(String),
    #[error("certificate algorithm is not ML-DSA-44")]
    WrongAlgorithm,
    #[error("public key is {0} bytes, not an ML-DSA-44 key")]
    WrongKeyLength(usize),
    #[error("certificate self-signature does not verify")]
    BadSelfSignature,
    #[error("the transport key must resolve from the Transport role: {0}")]
    WrongScheme(String),
}

/// A certificate whose self-signature has been verified, and the identity it proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCertificate {
    pub peer_id: PeerId,
    pub public_key: PublicKey,
}

fn ml_dsa_44() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_ML_DSA_44,
        parameters: None,
    }
}

/// The scheme the `Transport` role resolves to — ML-DSA-44 in suite v1 (crypto spec §1.1). The
/// certificate's algorithm identifier is fixed to it; a rotation is a new code point and a new
/// suite row, never a silent change here.
fn transport_scheme() -> SignatureSchemeId {
    AlgoSuite::new(SigRole::Transport, SuiteVersion::V1)
        .signature_scheme()
        .expect("suite v1 has a Transport row")
}

/// Generates the self-signed certificate for `keypair` — the node's `Transport`-purpose key,
/// `m/44'/931931'/4'/0'/{index}'`.
pub fn generate(keypair: &Keypair) -> Result<Vec<u8>, CertError> {
    let scheme = transport_scheme();
    if keypair.public_key().scheme != scheme {
        return Err(CertError::WrongScheme(format!(
            "{:?} is not {scheme:?}",
            keypair.public_key().scheme
        )));
    }
    let name = Name::default();
    let der = |e: x509_cert::der::Error| CertError::Malformed(e.to_string());

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[1]).map_err(der)?,
        signature: ml_dsa_44(),
        issuer: name.clone(),
        // Identity is the key: no expiry is checked, so the widest validity RFC 5280 can express
        // — the Unix epoch to 9999-12-31T23:59:59Z, the "no well-defined expiration" value.
        validity: Validity {
            not_before: Time::UtcTime(UtcTime::from_unix_duration(Duration::ZERO).map_err(der)?),
            not_after: Time::GeneralTime(
                GeneralizedTime::from_unix_duration(Duration::from_secs(253_402_300_799))
                    .map_err(der)?,
            ),
        },
        subject: name,
        subject_public_key_info: SubjectPublicKeyInfoOwned {
            algorithm: ml_dsa_44(),
            subject_public_key: BitString::from_bytes(&keypair.public_key().bytes).map_err(der)?,
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };

    let tbs_der = tbs.to_der().map_err(der)?;
    let signature = keypair
        .sign(&tbs_der, None)
        .map_err(|e| CertError::Malformed(e.to_string()))?;

    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ml_dsa_44(),
        signature: BitString::from_bytes(&signature.bytes).map_err(der)?,
    }
    .to_der()
    .map_err(der)
}

/// Parses `der`, checks it is an ML-DSA-44 certificate, verifies its self-signature, and derives
/// the `PeerId` from its key — steps 1 and 2 of the verification in wire spec §2.3. Step 3, the
/// comparison against the intended peer, is the caller's (the TLS verifier's) job.
pub fn verify(der: &[u8]) -> Result<VerifiedCertificate, CertError> {
    let cert = Certificate::from_der(der).map_err(|e| CertError::Malformed(e.to_string()))?;
    let tbs = &cert.tbs_certificate;

    let ml_dsa = ml_dsa_44();
    if cert.signature_algorithm != ml_dsa
        || tbs.signature != ml_dsa
        || tbs.subject_public_key_info.algorithm != ml_dsa
    {
        return Err(CertError::WrongAlgorithm);
    }

    let scheme = transport_scheme();
    let key = tbs
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(CertError::WrongAlgorithm)?;
    let public_key = PublicKey {
        scheme,
        bytes: key.to_vec(),
    };
    let signature = Signature {
        scheme,
        bytes: cert
            .signature
            .as_bytes()
            .ok_or(CertError::BadSelfSignature)?
            .to_vec(),
    };

    let tbs_der = tbs
        .to_der()
        .map_err(|e| CertError::Malformed(e.to_string()))?;
    match public_key.verify(&tbs_der, &signature, None) {
        Ok(true) => {}
        Ok(false) => return Err(CertError::BadSelfSignature),
        Err(hux_crypto::error::CryptoError::InvalidPublicKeySize(_)) => {
            return Err(CertError::WrongKeyLength(key.len()));
        }
        Err(_) => return Err(CertError::BadSelfSignature),
    }

    Ok(VerifiedCertificate {
        peer_id: PeerId::from_ml_dsa_pk(public_key.clone()),
        public_key,
    })
}

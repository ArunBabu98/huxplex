//! The transport — gate **G5**: QUIC, TLS 1.3 with native ML-DSA-44 certificates, and the libp2p
//! `Transport` that carries it ([ADR-0019](../../../../docs/adr/0019-transport-authentication.md),
//! [ADR-0021](../../../../docs/adr/0021-peer-identity-across-libp2p.md)).
//!
//! | Module | Task |
//! |---|---|
//! | [`cert`] | N1 — the self-signed ML-DSA-44 certificate |
//! | [`tls`] | N2–N5, N7 — verifiers, mutual auth, ALPN, `X25519MLKEM768`, no 0-RTT |
//! | [`quic`] | N0b, N6 — quinn configuration and Initial padding |
//! | [`p2p`] | N0b — the libp2p `Transport` over quinn |
//! | [`muxer`] | QUIC streams as libp2p substreams |
//! | [`socket`] | datagram filters for fault injection (G5-T4) and measurement (G5-T6) |

pub mod cert;
pub mod muxer;
pub mod p2p;
pub mod quic;
pub mod socket;
pub mod tls;

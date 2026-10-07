//! QUIC endpoint configuration — task **N0b** (quinn driven directly, not `libp2p-quic`) and
//! **N6** (Initial padding).

use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    time::Duration,
};

use hux_crypto::context::Network;
use quinn::{
    Runtime as _,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rand::Rng;
use rustls::client::ClientSessionStore;

use super::{
    socket::{DatagramFilter, FilteredSocket},
    tls::{self, TransportIdentity},
};
use crate::peer::PeerId;

/// The datagram size every Initial is padded to — **N6**, guarding **G5-T6**.
///
/// RFC 9000 §8.1 lets an unvalidated responder send at most 3× the bytes it has received. The
/// responder's first flight carries an ML-DSA-44 certificate (3,839 B) and `CertificateVerify`
/// (2,420 B); measured on the wire with [`CONNECTION_ID_LEN`]-byte connection IDs it is
/// ≈ 8,080 B, *including* the `NEW_CONNECTION_ID` packet quinn sends as soon as it has 1-RTT
/// keys. The client's `X25519MLKEM768` ClientHello spans two Initial datagrams, and quinn pads
/// Initials to `min(min_mtu, current_mtu)`, so both are set here.
///
/// **Why 1,372.** It is the largest UDP payload that still fits a 1,420-byte tunnel MTU over IPv6
/// (40 + 8 + 1,372 — WireGuard's default), and so keeps the path-safety reason the conventional
/// 1,350 exists. Two of them buy a budget of 8,232 B: ≈ 150 B of margin, against ≈ 20 B at 1,350,
/// where run-to-run variation alone could breach the limit.
///
/// That margin is the whole headroom of the design: anything added to the responder's first
/// flight spends it, and `tests/transport.rs` measures it on the wire. Note also that quinn
/// will send a full datagram while *any* budget remains (quinn #1082), so the flight must fit
/// with room to spare, not merely round to it.
pub const INITIAL_DATAGRAM_SIZE: u16 = 1372;

/// The QUIC transport parameters every Huxplex endpoint uses.
pub fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        .initial_mtu(INITIAL_DATAGRAM_SIZE)
        .min_mtu(INITIAL_DATAGRAM_SIZE)
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("30 s is a valid idle timeout"),
        ));
    Arc::new(config)
}

/// The listener's QUIC config: [`tls::server_config`] plus [`transport_config`].
pub fn server_config(identity: &TransportIdentity, network: Network) -> quinn::ServerConfig {
    let crypto = QuicServerConfig::try_from(Arc::new(tls::server_config(identity, network)))
        .expect("the TLS 1.3 config includes the AES-128-GCM suite QUIC requires");
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport_config());
    config
}

/// The dialler's QUIC config around a TLS client config.
pub fn client_config(tls: rustls::ClientConfig) -> quinn::ClientConfig {
    let crypto = QuicClientConfig::try_from(Arc::new(tls))
        .expect("the TLS 1.3 config includes the AES-128-GCM suite QUIC requires");
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport_config());
    config
}

/// Dial configs, one per peer and reused for every dial to it.
///
/// A config is built around a verifier that accepts exactly one `PeerId`, and rustls resumes a
/// session only under the verifier it was issued under. Caching the config per peer is therefore
/// what makes 1-RTT resumption (N7) actually happen; a fresh config per dial would silently force
/// a full handshake — certificate, `CertificateVerify` and all — every time.
pub struct ClientConfigs {
    identity: Arc<TransportIdentity>,
    network: Network,
    sessions: Arc<dyn ClientSessionStore>,
    by_peer: Mutex<HashMap<PeerId, quinn::ClientConfig>>,
}

impl ClientConfigs {
    pub fn new(identity: Arc<TransportIdentity>, network: Network) -> Self {
        ClientConfigs {
            identity,
            network,
            sessions: tls::session_cache(),
            by_peer: Mutex::new(HashMap::new()),
        }
    }

    pub fn for_peer(&self, peer: PeerId) -> quinn::ClientConfig {
        self.by_peer
            .lock()
            .expect("the config cache lock is never held across a panic")
            .entry(peer)
            .or_insert_with(|| {
                client_config(tls::client_config(
                    &self.identity,
                    self.network,
                    Arc::new(tls::PeerVerifier::outbound(peer)),
                    self.sessions.clone(),
                ))
            })
            .clone()
    }
}

/// The peer a connection authenticated as.
///
/// Re-derived from the certificate the TLS verifier accepted — never from anything the peer
/// claimed (ADR-0021 rule I5). `None` only if the connection carries no verified certificate,
/// which mutual authentication makes impossible for an established connection.
pub fn authenticated_peer(connection: &quinn::Connection) -> Option<PeerId> {
    let certs = connection
        .peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let leaf = certs.first()?;
    super::cert::verify(leaf).ok().map(|v| v.peer_id)
}

/// Binds a quinn endpoint on `addr` — listening if `server` is given — optionally routing every
/// outgoing datagram through `filter`.
pub fn bind_endpoint(
    addr: SocketAddr,
    server: Option<quinn::ServerConfig>,
    filter: Option<Arc<dyn DatagramFilter>>,
) -> std::io::Result<quinn::Endpoint> {
    let runtime = Arc::new(quinn::TokioRuntime);
    let socket = runtime.wrap_udp_socket(UdpSocket::bind(addr)?)?;
    let socket: Arc<dyn quinn::AsyncUdpSocket> = match filter {
        Some(filter) => Arc::new(FilteredSocket::new(socket, filter)?),
        None => socket,
    };
    quinn::Endpoint::new_with_abstract_socket(endpoint_config(), server, socket, runtime)
}

/// Locally issued connection-ID length, in bytes.
///
/// Every long-header packet of the responder's first flight carries two connection IDs, and once
/// it has 1-RTT keys quinn sends `NEW_CONNECTION_ID` frames in the same pre-validation window —
/// all of it counted against the 3× budget (G5-T6). Four bytes instead of quinn's default eight
/// buys back part of that budget, and is ample for demultiplexing a peer-to-peer endpoint's
/// handful of connections. Zero — which would suppress the frames entirely — is **not** an
/// option: a node often holds two connections to one remote socket (simultaneous dials in each
/// direction), and zero-length IDs can only demultiplex by address.
pub const CONNECTION_ID_LEN: usize = 4;

fn endpoint_config() -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    config.cid_generator(|| Box::new(ShortConnectionIds));
    config
}

/// Random connection IDs of [`CONNECTION_ID_LEN`] bytes.
struct ShortConnectionIds;

impl quinn::ConnectionIdGenerator for ShortConnectionIds {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut id = [0u8; CONNECTION_ID_LEN];
        rand::rng().fill_bytes(&mut id);
        quinn::ConnectionId::new(&id)
    }

    fn cid_len(&self) -> usize {
        CONNECTION_ID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

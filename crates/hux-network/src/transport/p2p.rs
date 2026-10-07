//! The libp2p `Transport` — task **N0b**: quinn driven directly behind libp2p's trait, so Huxplex
//! builds the TLS configs and decides the `(PeerId, StreamMuxerBox)` the swarm sees.
//!
//! - **Listening** binds one quinn endpoint that also dials, so a peer's inbound remote address
//!   *is* its listening address — which is how Kademlia learns dialable addresses without
//!   libp2p's `identify` (whose key check cannot accept an ML-DSA identity).
//! - **Dialling** requires the address to name its peer (`…/quic-v1/p2p/<id>`). The TLS verifier
//!   is built to accept only that peer (wire spec §2.3 step 3); there is no "dial and see who
//!   answers". The swarm appends `/p2p/` to every dial whose peer it knows.
//! - **Both directions** derive the swarm's `PeerId` from the certificate the TLS verifier
//!   accepted (ADR-0021 I5), as the identity-multihash encoding of the Huxplex `PeerId` (I1).

use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use futures::{FutureExt, future::BoxFuture};
use hux_crypto::context::Network;
use libp2p::{
    Multiaddr,
    core::{
        Endpoint,
        multiaddr::Protocol,
        muxing::StreamMuxerBox,
        transport::{DialOpts, ListenerId, TransportError, TransportEvent},
    },
};
use tokio::sync::mpsc;

use super::{
    muxer::Muxer,
    quic,
    socket::DatagramFilter,
    tls::{self, TransportIdentity},
};
use crate::peer::PeerId;

/// What the transport hands the swarm: the authenticated peer and its connection.
pub type Output = (libp2p::PeerId, StreamMuxerBox);

/// Why a listen, dial or upgrade failed.
#[derive(Debug, thiserror::Error)]
pub enum TransportFailure {
    #[error("only /ip4|ip6/…/udp/…/quic-v1 addresses are supported")]
    UnsupportedAddress,
    #[error("a dial address must name its peer: …/quic-v1/p2p/<peer-id>")]
    MissingPeer,
    #[error("not a Huxplex peer id (not an identity-coded 32-byte multihash)")]
    ForeignPeerId,
    #[error("this transport already has a listener")]
    AlreadyListening,
    #[error("dialling as a listener (hole punching) is not supported")]
    UnsupportedRole,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error("connection carries no verified certificate")]
    Unauthenticated,
    #[error("peer authenticated as {actual}, dialled {expected}")]
    WrongPeer { expected: String, actual: String },
}

/// Huxplex's QUIC transport for a libp2p swarm.
pub struct HuxTransport {
    identity: Arc<TransportIdentity>,
    network: Network,
    dial_configs: quic::ClientConfigs,
    filter: Option<Arc<dyn DatagramFilter>>,
    endpoint: Option<quinn::Endpoint>,
    listener: Option<(ListenerId, Multiaddr)>,
    incoming: Option<mpsc::UnboundedReceiver<quinn::Incoming>>,
    events: VecDeque<
        TransportEvent<BoxFuture<'static, Result<Output, TransportFailure>>, TransportFailure>,
    >,
    waker: Option<Waker>,
}

impl HuxTransport {
    pub fn new(identity: Arc<TransportIdentity>, network: Network) -> Self {
        HuxTransport {
            dial_configs: quic::ClientConfigs::new(identity.clone(), network),
            identity,
            network,
            filter: None,
            endpoint: None,
            listener: None,
            incoming: None,
            events: VecDeque::new(),
            waker: None,
        }
    }

    /// Routes every outgoing datagram through `filter` — fault injection for tests.
    pub fn with_datagram_filter(mut self, filter: Arc<dyn DatagramFilter>) -> Self {
        self.filter = Some(filter);
        self
    }

    fn bind(&mut self, addr: SocketAddr) -> Result<quinn::Endpoint, TransportFailure> {
        let endpoint = quic::bind_endpoint(
            addr,
            Some(quic::server_config(&self.identity, self.network)),
            self.filter.clone(),
        )?;

        let (tx, rx) = mpsc::unbounded_channel();
        let accepting = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                if tx.send(incoming).is_err() {
                    break;
                }
            }
        });
        self.incoming = Some(rx);
        self.endpoint = Some(endpoint.clone());
        Ok(endpoint)
    }

    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// `/ip4|ip6/<ip>/udp/<port>/quic-v1[/p2p/<id>]` → the socket address and the named peer, if any.
pub fn parse_address(addr: &Multiaddr) -> Result<(SocketAddr, Option<PeerId>), TransportFailure> {
    let mut parts = addr.iter();
    let ip: IpAddr = match parts.next() {
        Some(Protocol::Ip4(ip)) => ip.into(),
        Some(Protocol::Ip6(ip)) => ip.into(),
        _ => return Err(TransportFailure::UnsupportedAddress),
    };
    let port = match parts.next() {
        Some(Protocol::Udp(port)) => port,
        _ => return Err(TransportFailure::UnsupportedAddress),
    };
    if parts.next() != Some(Protocol::QuicV1) {
        return Err(TransportFailure::UnsupportedAddress);
    }
    let peer = match parts.next() {
        None => None,
        Some(Protocol::P2p(peer)) => {
            Some(PeerId::from_libp2p(&peer).ok_or(TransportFailure::ForeignPeerId)?)
        }
        Some(_) => return Err(TransportFailure::UnsupportedAddress),
    };
    if parts.next().is_some() {
        return Err(TransportFailure::UnsupportedAddress);
    }
    Ok((SocketAddr::new(ip, port), peer))
}

/// The multiaddr for a socket address: `/ip4|ip6/<ip>/udp/<port>/quic-v1`.
pub fn socket_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    Multiaddr::empty()
        .with(addr.ip().into())
        .with(Protocol::Udp(addr.port()))
        .with(Protocol::QuicV1)
}

fn authenticated(connection: quinn::Connection) -> Result<Output, TransportFailure> {
    let peer = quic::authenticated_peer(&connection).ok_or(TransportFailure::Unauthenticated)?;
    Ok((
        peer.to_libp2p(),
        StreamMuxerBox::new(Muxer::new(connection)),
    ))
}

impl libp2p::core::Transport for HuxTransport {
    type Output = Output;
    type Error = TransportFailure;
    type ListenerUpgrade = BoxFuture<'static, Result<Output, TransportFailure>>;
    type Dial = BoxFuture<'static, Result<Output, TransportFailure>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        let (socket, peer) = parse_address(&addr)
            .map_err(|_| TransportError::MultiaddrNotSupported(addr.clone()))?;
        if peer.is_some() {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        if self.listener.is_some() || self.endpoint.is_some() {
            return Err(TransportError::Other(TransportFailure::AlreadyListening));
        }
        let endpoint = self.bind(socket).map_err(TransportError::Other)?;
        let listen_addr = socket_to_multiaddr(
            endpoint
                .local_addr()
                .map_err(|e| TransportError::Other(e.into()))?,
        );
        self.listener = Some((id, listen_addr.clone()));
        self.events.push_back(TransportEvent::NewAddress {
            listener_id: id,
            listen_addr,
        });
        self.wake();
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        match &self.listener {
            Some((listener, _)) if *listener == id => {
                self.listener = None;
                if let Some(endpoint) = self.endpoint.take() {
                    endpoint.close(0u32.into(), b"listener removed");
                }
                self.incoming = None;
                self.events.push_back(TransportEvent::ListenerClosed {
                    listener_id: id,
                    reason: Ok(()),
                });
                self.wake();
                true
            }
            _ => false,
        }
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if opts.role != Endpoint::Dialer {
            return Err(TransportError::Other(TransportFailure::UnsupportedRole));
        }
        let (socket, peer) = match parse_address(&addr) {
            Ok(parsed) => parsed,
            Err(TransportFailure::UnsupportedAddress) => {
                return Err(TransportError::MultiaddrNotSupported(addr));
            }
            Err(e) => return Err(TransportError::Other(e)),
        };
        let expected = peer.ok_or(TransportError::Other(TransportFailure::MissingPeer))?;

        let endpoint = match &self.endpoint {
            Some(endpoint) => endpoint.clone(),
            None => {
                let unspecified: SocketAddr = match socket {
                    SocketAddr::V4(_) => ([0, 0, 0, 0], 0).into(),
                    SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
                };
                self.bind(unspecified).map_err(TransportError::Other)?
            }
        };
        let config = self.dial_configs.for_peer(expected);
        let name = tls::server_name(&expected);
        let connecting = endpoint
            .connect_with(config, socket, &name.to_str())
            .map_err(|e| TransportError::Other(e.into()))?;

        Ok(async move {
            let connection = connecting.await?;
            let (peer, muxer) = authenticated(connection)?;
            // The verifier already refused any other peer; this is the swarm-facing restatement.
            if peer != expected.to_libp2p() {
                return Err(TransportFailure::WrongPeer {
                    expected: expected.to_hex(),
                    actual: PeerId::from_libp2p(&peer)
                        .map(|p| p.to_hex())
                        .unwrap_or_default(),
                });
            }
            Ok((peer, muxer))
        }
        .boxed())
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }
        let listener = self.listener.clone();
        if let (Some(rx), Some((listener_id, local_addr))) = (self.incoming.as_mut(), listener) {
            if let Poll::Ready(Some(incoming)) = rx.poll_recv(cx) {
                let send_back_addr = socket_to_multiaddr(incoming.remote_address());
                let upgrade = async move {
                    let connection = incoming.accept()?.await?;
                    authenticated(connection)
                }
                .boxed();
                return Poll::Ready(TransportEvent::Incoming {
                    listener_id,
                    upgrade,
                    local_addr,
                    send_back_addr,
                });
            }
        }
        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

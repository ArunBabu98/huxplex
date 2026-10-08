//! Gate **G5** at the transport level — QUIC + TLS 1.3 + native ML-DSA-44 certificates, driven
//! through raw quinn endpoints so each property is tested at the layer that provides it.
//!
//! | Test | Property |
//! |---|---|
//! | ADR-0021 I3/I4 | `PeerId` ↔ libp2p `PeerId` is total and lossless; foreign ids are refused |
//! | N1 | the certificate is ML-DSA-44, self-signed, and names its key's `PeerId` |
//! | **G5-T1** | no downgrade: classical-only KEX, MITM certificate, missing client certificate, wrong network — all refused in the handshake |
//! | **G5-T2** | a peer cannot present a `PeerId` whose key it does not hold |
//! | **G5-T6** | the responder's first flight fits QUIC's 3× budget, measured on the wire |
//! | N7 | 1-RTT resumption works; 0-RTT early data is refused |
//! | **G5-T7** | a TLS signature and a protocol signature can never verify as each other |

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use hux_crypto::{
    bip32::{KeyPurpose, derive_mldsa_seed_for_purpose},
    context::{self, Network, Purpose},
    publickey::PublicKey,
    signature::{Keypair, Signature},
    signaturescheme::SignatureSchemeId,
};
use hux_network::{
    peer::PeerId,
    topic::GossipTopic,
    transport::{
        cert::{self, CertError},
        muxer::Muxer,
        quic,
        socket::DatagramFilter,
        tls::{self, PeerVerifier, TransportIdentity},
    },
};
use libp2p::multihash::Multihash;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    SignatureScheme,
    client::ResolvesClientCert,
    pki_types::CertificateDer,
    server::ResolvesServerCert,
    sign::{CertifiedKey, Signer, SigningKey},
};

fn transport_key(i: u8) -> Keypair {
    let seed = derive_mldsa_seed_for_purpose([i; 64], KeyPurpose::Transport, 0);
    Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap()
}

fn identity(i: u8) -> TransportIdentity {
    TransportIdentity::new(transport_key(i)).unwrap()
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A listener for `server` on `network`, accepting connections in the background and reporting
/// the authenticated peer of each.
fn listen(
    server: &TransportIdentity,
    network: Network,
    filter: Option<Arc<dyn DatagramFilter>>,
) -> (
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<Option<PeerId>>,
) {
    let endpoint = quic::bind_endpoint(
        localhost(),
        Some(quic::server_config(server, network)),
        filter,
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let peer = match incoming.accept() {
                    Ok(connecting) => match connecting.await {
                        Ok(conn) => {
                            let peer = quic::authenticated_peer(&conn);
                            // Hold the connection open briefly so the client can finish.
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            peer
                        }
                        Err(_) => None,
                    },
                    Err(_) => None,
                };
                let _ = tx.send(peer);
            });
        }
    });
    (addr, rx)
}

fn dial_config(
    client: &TransportIdentity,
    network: Network,
    expected: PeerId,
) -> quinn::ClientConfig {
    quic::client_config(tls::client_config(
        client,
        network,
        Arc::new(PeerVerifier::outbound(expected)),
        tls::session_cache(),
    ))
}

async fn connect(
    client: &TransportIdentity,
    network: Network,
    expected: PeerId,
    addr: SocketAddr,
) -> Result<quinn::Connection, quinn::ConnectionError> {
    let endpoint = quinn::Endpoint::client(localhost()).unwrap();
    let config = dial_config(client, network, expected);
    endpoint
        .connect_with(config, addr, &tls::server_name(&expected).to_str())
        .unwrap()
        .await
}

// ─── ADR-0021 — one identity, two encodings ──────────────────────────────────────────────────

#[test]
fn i3_conversion_is_total_and_lossless_in_both_directions() {
    for i in 0..16u8 {
        let peer = PeerId::from_ml_dsa_pk(transport_key(i).public_key().clone());
        let p2p = peer.to_libp2p();
        assert_eq!(PeerId::from_libp2p(&p2p), Some(peer));
        // …and through libp2p's own byte form, which is what crosses the wire.
        let bytes = p2p.to_bytes();
        assert_eq!(
            &bytes[..2],
            &[0x00, 0x20],
            "identity code, 32-byte digest (I2)"
        );
        assert_eq!(&bytes[2..], &peer.id);
        assert_eq!(libp2p::PeerId::from_bytes(&bytes).unwrap(), p2p);
    }
}

#[test]
fn i1_a_foreign_libp2p_peer_id_is_refused() {
    // A sha2-256-coded PeerId is valid to libp2p but is not a re-encoding of a Huxplex identity.
    let foreign =
        libp2p::PeerId::from_multihash(Multihash::wrap(0x12, &[7u8; 32]).unwrap()).unwrap();
    assert_eq!(PeerId::from_libp2p(&foreign), None);
}

// ─── N1 — the certificate ────────────────────────────────────────────────────────────────────

#[test]
fn n1_certificate_is_self_signed_ml_dsa_44_and_names_its_key() {
    let kp = transport_key(1);
    let der = cert::generate(&kp).unwrap();
    let verified = cert::verify(&der).unwrap();
    assert_eq!(verified.public_key, *kp.public_key());
    assert_eq!(
        verified.peer_id,
        PeerId::from_ml_dsa_pk(kp.public_key().clone())
    );
    println!("transport certificate: {} bytes", der.len());
}

#[test]
fn n1_a_tampered_or_foreign_certificate_is_refused() {
    let der = cert::generate(&transport_key(2)).unwrap();

    let mut sig_flip = der.clone();
    let last = sig_flip.len() - 1;
    sig_flip[last] ^= 0x01;
    assert_eq!(cert::verify(&sig_flip), Err(CertError::BadSelfSignature));

    assert!(matches!(
        cert::verify(&der[..der.len() - 10]),
        Err(CertError::Malformed(_))
    ));

    // Swap in another key: a valid key, but the self-signature was not made by it.
    let other = transport_key(3).public_key().bytes.clone();
    let mine = transport_key(2).public_key().bytes.clone();
    let at = der
        .windows(mine.len())
        .position(|w| w == mine.as_slice())
        .unwrap();
    let mut swapped = der.clone();
    swapped[at..at + mine.len()].copy_from_slice(&other);
    assert_eq!(cert::verify(&swapped), Err(CertError::BadSelfSignature));

    // Only the Transport role's scheme may hold a transport certificate.
    let slh = Keypair::generate_from_seed(SignatureSchemeId::SlhDsa128s, &[1u8; 48]).unwrap();
    assert!(matches!(
        cert::generate(&slh),
        Err(CertError::WrongScheme(_))
    ));
}

// ─── G5-T1 — authenticated handshake, no downgrade ───────────────────────────────────────────

#[tokio::test]
async fn g5_t1_a_correct_handshake_authenticates_both_sides() {
    let (server, client) = (identity(10), identity(11));
    let (addr, mut accepted) = listen(&server, Network::Testnet, None);
    let conn = connect(&client, Network::Testnet, server.peer_id(), addr)
        .await
        .unwrap();
    assert_eq!(quic::authenticated_peer(&conn), Some(server.peer_id()));
    assert_eq!(accepted.recv().await.unwrap(), Some(client.peer_id()));
}

#[tokio::test]
async fn g5_t1_a_classical_only_client_is_refused() {
    let server = identity(12);
    let (addr, mut accepted) = listen(&server, Network::Testnet, None);

    // Everything Huxplex would offer, except the key exchange: X25519 alone.
    let mut provider = (*tls::provider()).clone();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PeerVerifier::outbound(server.peer_id())))
        .with_no_client_auth();
    config.alpn_protocols = vec![tls::alpn(Network::Testnet)];
    let config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(Arc::new(config)).unwrap(),
    ));

    let endpoint = quinn::Endpoint::client(localhost()).unwrap();
    let result = endpoint
        .connect_with(config, addr, &tls::server_name(&server.peer_id()).to_str())
        .unwrap()
        .await;
    assert!(result.is_err(), "a classical-only key exchange completed");
    assert_eq!(accepted.recv().await.unwrap(), None);
}

#[tokio::test]
async fn g5_t1_a_mitm_certificate_fails_the_peer_id_check() {
    // The client means to reach `honest`; `mitm` answers with its own, perfectly valid
    // certificate. Its PeerId is not the one dialled, so the client aborts.
    let (honest, mitm, client) = (identity(13), identity(14), identity(15));
    let (addr, _accepted) = listen(&mitm, Network::Testnet, None);
    let result = connect(&client, Network::Testnet, honest.peer_id(), addr).await;
    assert!(
        result.is_err(),
        "connected to a peer other than the one dialled"
    );
}

#[tokio::test]
async fn g5_t1_no_client_certificate_means_no_connection() {
    let server = identity(16);
    let (addr, mut accepted) = listen(&server, Network::Testnet, None);

    let mut config = rustls::ClientConfig::builder_with_provider(tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PeerVerifier::outbound(server.peer_id())))
        .with_no_client_auth();
    config.alpn_protocols = vec![tls::alpn(Network::Testnet)];
    let config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(Arc::new(config)).unwrap(),
    ));

    let endpoint = quinn::Endpoint::client(localhost()).unwrap();
    let outcome = async {
        let conn = endpoint
            .connect_with(config, addr, &tls::server_name(&server.peer_id()).to_str())
            .unwrap()
            .await?;
        // In TLS 1.3 the client may believe it is done before the server has judged its (absent)
        // certificate; any application stream must still fail.
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(b"hello")
            .await
            .map_err(|_| quinn::ConnectionError::LocallyClosed)?;
        send.finish()
            .map_err(|_| quinn::ConnectionError::LocallyClosed)?;
        recv.read_to_end(16)
            .await
            .map_err(|_| quinn::ConnectionError::LocallyClosed)?;
        Ok::<_, quinn::ConnectionError>(())
    }
    .await;
    assert!(
        outcome.is_err(),
        "an unauthenticated client reached an application stream"
    );
    assert_eq!(
        accepted.recv().await.unwrap(),
        None,
        "the server accepted it"
    );
}

#[tokio::test]
async fn g5_t1_a_cross_network_dial_is_refused_by_alpn() {
    let (server, client) = (identity(17), identity(18));
    let (addr, mut accepted) = listen(&server, Network::Mainnet, None);
    let result = connect(&client, Network::Testnet, server.peer_id(), addr).await;
    assert!(
        result.is_err(),
        "a testnet node completed a handshake with a mainnet node"
    );
    assert_eq!(accepted.recv().await.unwrap(), None);
}

// ─── G5-T2 — the PeerId is bound to the key ──────────────────────────────────────────────────

/// Presents `certificate` but signs with `key` — what a peer that copied someone's certificate
/// without their private key would have to do.
#[derive(Debug)]
struct Impostor {
    certified: Arc<CertifiedKey>,
}

#[derive(Debug)]
struct ImpostorKey(Arc<Keypair>);

impl SigningKey for ImpostorKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&tls::SCHEME)
            .then(|| Box::new(ImpostorSigner(self.0.clone())) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::Unknown(0)
    }
}

#[derive(Debug)]
struct ImpostorSigner(Arc<Keypair>);

impl Signer for ImpostorSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        tls::sign_handshake(&self.0, message)
    }
    fn scheme(&self) -> SignatureScheme {
        tls::SCHEME
    }
}

impl ResolvesServerCert for Impostor {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }
}

impl ResolvesClientCert for Impostor {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }
    fn has_certs(&self) -> bool {
        true
    }
}

fn impostor(victim: &Keypair, own_key: Keypair) -> Arc<Impostor> {
    let certificate = CertificateDer::from(cert::generate(victim).unwrap());
    Arc::new(Impostor {
        certified: Arc::new(CertifiedKey::new(
            vec![certificate],
            Arc::new(ImpostorKey(Arc::new(own_key))),
        )),
    })
}

#[tokio::test]
async fn g5_t2_a_server_cannot_present_a_peer_id_it_does_not_hold_the_key_for() {
    let victim = transport_key(20);
    let victim_id = PeerId::from_ml_dsa_pk(victim.public_key().clone());

    let mut config = rustls::ServerConfig::builder_with_provider(tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(PeerVerifier::inbound()))
        .with_cert_resolver(impostor(&victim, transport_key(21)));
    config.alpn_protocols = vec![tls::alpn(Network::Testnet)];
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(Arc::new(config)).unwrap(),
    ));
    server.transport_config(quic::transport_config());
    let endpoint = quic::bind_endpoint(localhost(), Some(server), None).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(c) = incoming.accept() {
                    let _ = c.await;
                }
            });
        }
    });

    // The certificate is genuinely the victim's and passes its self-signature check; the
    // CertificateVerify, made with the impostor's key, does not verify under it.
    let result = connect(&identity(22), Network::Testnet, victim_id, addr).await;
    assert!(
        result.is_err(),
        "an impostor authenticated as a PeerId it holds no key for"
    );
}

#[tokio::test]
async fn g5_t2_a_client_cannot_present_a_peer_id_it_does_not_hold_the_key_for() {
    let server = identity(23);
    let (addr, mut accepted) = listen(&server, Network::Testnet, None);

    let victim = transport_key(24);
    let mut config = rustls::ClientConfig::builder_with_provider(tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PeerVerifier::outbound(server.peer_id())))
        .with_client_cert_resolver(impostor(&victim, transport_key(25)));
    config.alpn_protocols = vec![tls::alpn(Network::Testnet)];
    let config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(Arc::new(config)).unwrap(),
    ));
    let endpoint = quinn::Endpoint::client(localhost()).unwrap();
    let _ = async {
        let conn = endpoint
            .connect_with(config, addr, &tls::server_name(&server.peer_id()).to_str())
            .unwrap()
            .await?;
        conn.open_bi().await.map(|_| ())
    }
    .await;
    assert_eq!(
        accepted.recv().await.unwrap(),
        None,
        "the server accepted a client impersonating {}",
        PeerId::from_ml_dsa_pk(victim.public_key().clone()).to_hex()
    );
}

// ─── G5-T6 — the amplification limit, measured on the wire ───────────────────────────────────

/// Watches one handshake. Client datagrams flow freely until the server first answers; then the
/// client is cut off (its datagrams dropped) for a window, so the server is left unvalidated with
/// exactly the bytes it has received. Whatever it sends in that window is its first flight, and
/// RFC 9000 §8.1 caps it at 3× what it received.
#[derive(Debug, Default)]
struct FirstFlight {
    server: Mutex<Option<SocketAddr>>,
    state: Mutex<Counters>,
    released: AtomicBool,
}

#[derive(Debug, Default)]
struct Counters {
    /// Client bytes delivered before the server's first datagram.
    client_delivered: usize,
    /// Server bytes sent while the client is cut off.
    server_first_flight: usize,
    server_started: bool,
    /// Client bytes attempted while cut off — its second flight, if it had the whole first.
    client_withheld: usize,
}

impl DatagramFilter for FirstFlight {
    fn deliver(&self, from: SocketAddr, _to: SocketAddr, datagram: &[u8]) -> bool {
        let from_server = *self.server.lock().unwrap() == Some(from);
        let mut c = self.state.lock().unwrap();
        if self.released.load(Ordering::SeqCst) {
            return true;
        }
        if from_server {
            c.server_started = true;
            c.server_first_flight += datagram.len();
            true
        } else if !c.server_started {
            c.client_delivered += datagram.len();
            true
        } else {
            c.client_withheld += datagram.len();
            false
        }
    }
}

#[tokio::test]
async fn g5_t6_the_first_flight_fits_the_3x_budget_on_the_wire() {
    let (server, client) = (identity(30), identity(31));
    let wire = Arc::new(FirstFlight::default());
    let (addr, _accepted) = listen(&server, Network::Testnet, Some(wire.clone()));
    *wire.server.lock().unwrap() = Some(addr);

    let endpoint = quic::bind_endpoint(localhost(), None, Some(wire.clone())).unwrap();
    let config = dial_config(&client, Network::Testnet, server.peer_id());
    let connecting = endpoint
        .connect_with(config, addr, &tls::server_name(&server.peer_id()).to_str())
        .unwrap();

    // Let the first flight play out against a silent client, then release.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (received, sent, withheld) = {
        let c = wire.state.lock().unwrap();
        (c.client_delivered, c.server_first_flight, c.client_withheld)
    };
    wire.released.store(true, Ordering::SeqCst);
    let connection = connecting
        .await
        .expect("the handshake completes once released");
    assert_eq!(
        quic::authenticated_peer(&connection),
        Some(server.peer_id())
    );

    println!(
        "G5-T6: client Initial flight {received} B → budget {} B; responder first flight {sent} B \
         (margin {} B); client second flight attempted {withheld} B",
        3 * received,
        (3 * received) as i64 - sent as i64
    );
    assert!(
        received >= 2 * quic::INITIAL_DATAGRAM_SIZE as usize,
        "the ClientHello must span two padded Initial datagrams (N6)"
    );
    assert!(
        sent <= 3 * received,
        "the responder exceeded 3× before address validation"
    );
    // The client could only start its second flight — which carries its 4 KB certificate — after
    // receiving the server's Finished, i.e. the whole first flight. If padding were too small the
    // server would stall at 3× and the client would have nothing to send but ACKs.
    assert!(
        withheld > 4000,
        "the whole first flight did not fit the budget: the client never began its second flight"
    );
}

// ─── N7 — resumption on, 0-RTT off ───────────────────────────────────────────────────────────

/// Counts bytes the server sends.
#[derive(Debug, Default)]
struct ServerBytes {
    server: Mutex<Option<SocketAddr>>,
    sent: Mutex<usize>,
}

impl DatagramFilter for ServerBytes {
    fn deliver(&self, from: SocketAddr, _: SocketAddr, datagram: &[u8]) -> bool {
        if *self.server.lock().unwrap() == Some(from) {
            *self.sent.lock().unwrap() += datagram.len();
        }
        true
    }
}

/// Opens one connection, waits for its session ticket, closes it, and returns the bytes the
/// server sent.
async fn session(
    endpoint: &quinn::Endpoint,
    config: rustls::ClientConfig,
    addr: SocketAddr,
    server: &TransportIdentity,
    wire: &ServerBytes,
) -> (usize, bool) {
    let name = tls::server_name(&server.peer_id());
    let connecting = endpoint
        .connect_with(quic::client_config(config), addr, &name.to_str())
        .unwrap();
    let (conn, zero_rtt) = match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            // A 0-RTT connection has no verified peer until its handshake completes.
            accepted.await;
            (conn, true)
        }
        Err(connecting) => (connecting.await.unwrap(), false),
    };
    assert_eq!(quic::authenticated_peer(&conn), Some(server.peer_id()));
    tokio::time::sleep(Duration::from_millis(150)).await;
    conn.close(0u32.into(), b"");
    tokio::time::sleep(Duration::from_millis(50)).await;
    (std::mem::take(&mut *wire.sent.lock().unwrap()), zero_rtt)
}

#[tokio::test]
async fn n7_resumption_omits_the_certificate_and_early_data_is_refused() {
    let (server, client) = (identity(32), identity(33));
    let wire = Arc::new(ServerBytes::default());
    let (addr, _accepted) = listen(&server, Network::Testnet, Some(wire.clone()));
    *wire.server.lock().unwrap() = Some(addr);

    // One verifier and one session cache across all three connections: the conditions under
    // which rustls will resume at all.
    let verifier = Arc::new(PeerVerifier::outbound(server.peer_id()));
    let sessions = tls::session_cache();
    let config = || {
        tls::client_config(
            &client,
            Network::Testnet,
            verifier.clone(),
            sessions.clone(),
        )
    };
    let endpoint = quinn::Endpoint::client(localhost()).unwrap();

    let (full, _) = session(&endpoint, config(), addr, &server, &wire).await;
    let (resumed, _) = session(&endpoint, config(), addr, &server, &wire).await;

    // Ask for 0-RTT on a resumable session: the server's tickets carry no early-data allowance.
    let mut eager = config();
    eager.enable_early_data = true;
    let (_, zero_rtt) = session(&endpoint, eager, addr, &server, &wire).await;

    println!("N7: full handshake {full} B from the server, resumed {resumed} B");
    assert!(
        resumed + 5000 < full,
        "a resumed handshake must omit the ≈3.9 KB certificate and 2.4 KB CertificateVerify"
    );
    assert!(!zero_rtt, "0-RTT early data was accepted");
}

#[tokio::test]
async fn n7_the_early_data_check_is_not_vacuous() {
    // The same client against a server that *does* allow early data gets it — so the refusal
    // above is the server's configuration, not a client that could never have sent any.
    let (server, client) = (identity(34), identity(35));
    let mut tls_server = tls::server_config(&server, Network::Testnet);
    tls_server.max_early_data_size = u32::MAX;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(Arc::new(tls_server)).unwrap(),
    ));
    config.transport_config(quic::transport_config());
    let wire = Arc::new(ServerBytes::default());
    let endpoint = quic::bind_endpoint(localhost(), Some(config), None).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(c) = incoming.accept() {
                    if let Ok(conn) = c.await {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        drop(conn);
                    }
                }
            });
        }
    });

    let verifier = Arc::new(PeerVerifier::outbound(server.peer_id()));
    let sessions = tls::session_cache();
    let config = || {
        let mut c = tls::client_config(
            &client,
            Network::Testnet,
            verifier.clone(),
            sessions.clone(),
        );
        c.enable_early_data = true;
        c
    };
    let client_endpoint = quinn::Endpoint::client(localhost()).unwrap();
    let _ = session(&client_endpoint, config(), addr, &server, &wire).await;
    let (_, zero_rtt) = session(&client_endpoint, config(), addr, &server, &wire).await;
    assert!(
        zero_rtt,
        "a server permitting early data should have offered it"
    );
}

// ─── G5-T7 — transport and protocol signatures cannot be confused ────────────────────────────

#[test]
fn g5_t7_the_tls_context_is_pinned_empty() {
    // draft-ietf-tls-mldsa: TLS signs with ML-DSA's empty context. Pin it, rather than assume it.
    let kp = transport_key(40);
    let sig = tls::sign_handshake(&kp, b"transcript").unwrap();
    let as_signature = Signature {
        scheme: kp.public_key().scheme,
        bytes: sig.clone(),
    };
    assert!(
        kp.public_key()
            .verify(b"transcript", &as_signature, None)
            .unwrap()
    );
    assert!(
        kp.public_key()
            .verify(b"transcript", &as_signature, Some(b""))
            .unwrap()
    );
    assert!(tls::verify_handshake(kp.public_key(), b"transcript", &sig));
}

#[test]
fn g5_t7_tls_and_protocol_signatures_never_verify_as_each_other() {
    let kp = transport_key(41);
    let pk: &PublicKey = kp.public_key();
    // TLS 1.3 signs 64 spaces ‖ context ‖ 0x00 ‖ transcript hash; any bytes will do for the
    // property, which is about the FIPS 204 context, not the message.
    let mut message = vec![0x20u8; 64];
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    message.extend_from_slice(&[0xAB; 32]);

    let tls_sig = tls::sign_handshake(&kp, &message).unwrap();
    for &network in Network::ALL {
        // Every context the registry can produce: each purpose, and each gossip topic *shape* —
        // the same 26-context set G1-T2 sweeps, so "every registry context" means the same thing
        // in both gates (it was two topics short until 2026-10-08).
        let mut contexts: Vec<Vec<u8>> = Purpose::ALL
            .iter()
            .map(|&p| context::context(network, p))
            .collect();
        for topic in [
            GossipTopic::intents(),
            GossipTopic::shard_blocks(0),
            GossipTopic::shard_blocks(1),
            GossipTopic::shard_mempool(0),
        ] {
            contexts.push(context::gossip_context(network.as_str(), topic.as_str()));
        }
        assert_eq!(
            contexts.len(),
            13,
            "9 purposes + 4 topic contexts per network"
        );

        for ctx in contexts {
            let label = String::from_utf8_lossy(&ctx).into_owned();
            // A TLS signature never verifies as a protocol signature…
            let as_protocol = Signature {
                scheme: pk.scheme,
                bytes: tls_sig.clone(),
            };
            assert!(
                !pk.verify(&message, &as_protocol, Some(&ctx)).unwrap(),
                "TLS sig accepted under {label}"
            );
            // …and a protocol signature never verifies as a TLS one.
            let protocol_sig = kp.sign(&message, Some(&ctx)).unwrap();
            assert!(
                !tls::verify_handshake(pk, &message, &protocol_sig.bytes),
                "{label} sig accepted by TLS"
            );
        }
    }
}

// ─── The muxer and the dial-config cache ─────────────────────────────────────────────────────

#[tokio::test]
async fn muxer_close_and_poll_are_safe_to_repeat_after_the_end() {
    use libp2p::core::muxing::StreamMuxer;
    let (server, client) = (identity(36), identity(37));
    let (addr, _accepted) = listen(&server, Network::Testnet, None);
    let conn = connect(&client, Network::Testnet, server.peer_id(), addr)
        .await
        .unwrap();
    let mut muxer = Muxer::new(conn);
    let mut muxer = std::pin::Pin::new(&mut muxer);

    // The swarm may poll a finished muxer again; an `async` block polled after completion panics.
    for _ in 0..2 {
        let closed = futures::future::poll_fn(|cx| muxer.as_mut().poll_close(cx)).await;
        assert!(closed.is_ok(), "a local close is a clean close: {closed:?}");
    }
    for _ in 0..2 {
        let event = futures::future::poll_fn(|cx| muxer.as_mut().poll(cx)).await;
        assert!(matches!(event, Err(quinn::ConnectionError::LocallyClosed)));
    }
    // Streams on a closed connection fail; they do not hang.
    let outbound = futures::future::poll_fn(|cx| muxer.as_mut().poll_outbound(cx)).await;
    assert!(outbound.is_err());
}

#[test]
fn the_dial_config_cache_is_bounded() {
    // Kademlia hands the dialler whatever PeerIds a hostile peer cares to invent.
    let configs = quic::ClientConfigs::new(Arc::new(identity(38)), Network::Testnet);
    for i in 0..(quic::MAX_CACHED_DIAL_CONFIGS + 100) {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        configs.for_peer(PeerId { id });
    }
    assert_eq!(configs.len(), quic::MAX_CACHED_DIAL_CONFIGS);
}

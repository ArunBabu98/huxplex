//! A Huxplex network node — the libp2p swarm over [`HuxTransport`], with GossipSub (**N10**),
//! Kademlia (**N9**) and peer scoring (**N11**), driven through the lifecycle in [`crate::peers`]
//! (**N8**).
//!
//! # What is checked where
//!
//! - **Gossip.** Every message is decoded with the canonical codec and verified — descriptor,
//!   role, context, signature — **before** it is accepted or forwarded (`validate_messages`).
//!   Rejected messages are never forwarded, so a flood of garbage is not amplified (**G5-T3**);
//!   the propagating peer is penalised. Message ids are SHAKE-256 of the envelope bytes: content
//!   addressed, so duplicates collapse and nothing is ever re-signed on forward (wire spec §5).
//! - **DHT.** A record is stored only if it decodes as a [`DhtEntry`], verifies, belongs to this
//!   node's network, **and** is keyed by its signer's own `PeerId` — so a record cannot be
//!   republished under another key, and a peer cannot squat another's (**G5-T5**). Records read
//!   back from the DHT are validated again before they are returned.
//!   A stored record is replaced only by one that [`DhtEntry::supersedes`] it — a higher `seq` —
//!   so a publisher's old record cannot be replayed over its new one; a lookup returns the
//!   highest-`seq` valid record any peer holds.
//! - **Identity.** Comes only from the transport, which yields no connection before mutual TLS
//!   authentication. GossipSub runs anonymous: its own signing would need a libp2p key, and every
//!   envelope already carries an ML-DSA signature.
//!
//! # Resource bounds
//!
//! Everything a remote peer can make the node hold is bounded:
//!
//! | What | Bound |
//! |---|---|
//! | Connections | [`NodeConfig::max_peers`] established, [`MAX_PENDING_INCOMING`] mid-handshake, two per peer (`connection_limits`) |
//! | Dials driven by discovery | only while fewer than [`NodeConfig::target_peers`] are connected |
//! | Events awaiting the application | [`NodeConfig::event_buffer`]; beyond it events are **dropped**, never queued |
//! | The peer table | disconnected peers forgotten after `PeerPolicy::forget_after` |
//! | A peer GossipSub has graylisted | banned and disconnected at once, not left connected and silenced |
//! | Dial configs, accepted connections | see `transport::quic` and `transport::p2p` |
//!
//! The command channel is unbounded: only the local application can write to it.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::StreamExt;
use hux_crypto::{context::Network, hash::shake::shake256_32, signature::Keypair};
use hux_types::codec::Codec;
use libp2p::{
    Multiaddr, StreamProtocol, Swarm,
    allow_block_list::{self, BlockedPeers},
    connection_limits::{self, ConnectionLimits},
    core::{ConnectedPoint, Transport as _, multiaddr::Protocol},
    gossipsub::{
        self, IdentTopic, MessageAcceptance, MessageAuthenticity, MessageId, PeerScoreParams,
        PeerScoreThresholds, TopicScoreParams, ValidationMode,
    },
    kad::{
        self, GetRecordOk, InboundRequest, Mode, QueryId, QueryResult, Quorum, Record, RecordKey,
        StoreInserts,
        store::{MemoryStore, RecordStore},
    },
    swarm::{NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
};
use tokio::sync::{mpsc, oneshot};

use crate::{
    message::{DhtEntry, GossipMessage, MAX_ENVELOPE_LEN},
    peer::PeerId,
    peers::{Offence, PeerPolicy, PeerState, PeerTable, Verdict},
    topic::GossipTopic,
    transport::{
        cert::CertError,
        p2p::{HuxTransport, socket_to_multiaddr},
        socket::DatagramFilter,
        tls::TransportIdentity,
    },
};

/// How a node is started.
pub struct NodeConfig {
    pub network: Network,
    /// The node's `Transport`-purpose ML-DSA-44 keypair, `m/44'/931931'/4'/0'/{index}'`.
    pub keypair: Keypair,
    pub listen: SocketAddr,
    /// Known peers to dial on start: identity and address. Identity is required — dials are
    /// authenticated against it.
    pub bootstrap: Vec<(PeerId, SocketAddr)>,
    pub topics: Vec<GossipTopic>,
    /// GossipSub heartbeat. Shorter converges faster at the cost of control traffic.
    pub heartbeat: Duration,
    pub policy: PeerPolicy,
    /// Fault injection for tests; `None` in production.
    pub datagram_filter: Option<Arc<dyn DatagramFilter>>,
    /// Discovery stops dialling new peers once this many are connected. Kademlia still learns
    /// them; it just does not connect to every one — which suits five nodes, not five thousand.
    pub target_peers: usize,
    /// Hard ceiling on established connections, inbound and outbound together.
    pub max_peers: u32,
    /// Events held for the application before new ones are dropped. A node must never grow
    /// without bound because its application stopped reading.
    pub event_buffer: usize,
}

/// Connections allowed to sit in the TLS handshake at once.
pub const MAX_PENDING_INCOMING: u32 = 64;

impl NodeConfig {
    pub fn new(network: Network, keypair: Keypair, listen: SocketAddr) -> Self {
        NodeConfig {
            network,
            keypair,
            listen,
            bootstrap: Vec::new(),
            topics: Vec::new(),
            heartbeat: Duration::from_secs(1),
            policy: PeerPolicy::default(),
            datagram_filter: None,
            target_peers: 32,
            max_peers: 128,
            event_buffer: 4096,
        }
    }
}

/// What a node reports.
#[derive(Clone, Debug)]
pub enum NodeEvent {
    /// First connection to a peer: mutually authenticated, `PeerId` proven.
    PeerIdentified(PeerId),
    PeerDisconnected(PeerId),
    /// A peer crossed the ban threshold and was disconnected.
    PeerBanned(PeerId),
    /// A valid gossip message, and the peer that delivered it (not necessarily its author).
    Gossip {
        message: GossipMessage,
        propagated_by: PeerId,
    },
    /// Something a peer sent was refused.
    Rejected {
        from: PeerId,
        offence: Offence,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("transport identity: {0}")]
    Identity(#[from] CertError),
    #[error("listen failed: {0}")]
    Listen(String),
    #[error("refused to publish: {0}")]
    Invalid(String),
    #[error("gossip publish failed: {0}")]
    Publish(String),
    #[error("DHT operation failed: {0}")]
    Dht(String),
    #[error("the node has stopped")]
    Stopped,
}

enum Command {
    Publish(GossipMessage, oneshot::Sender<Result<(), NodeError>>),
    PutRecord(DhtEntry, oneshot::Sender<Result<(), NodeError>>),
    GetRecord(PeerId, oneshot::Sender<Option<DhtEntry>>),
    Dial(PeerId, SocketAddr),
    ConnectedPeers(oneshot::Sender<Vec<PeerId>>),
    RoutingTable(oneshot::Sender<Vec<PeerId>>),
    PeerState(PeerId, oneshot::Sender<PeerState>),
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    blocked: allow_block_list::Behaviour<BlockedPeers>,
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
}

/// A running node: a [`NodeHandle`] for commands, plus the event stream.
///
/// The swarm runs until the node and every handle cloned from it are dropped.
pub struct Node {
    handle: NodeHandle,
    events: mpsc::Receiver<NodeEvent>,
}

/// Commands to a running node. Cheap to clone; usable from any task.
#[derive(Clone)]
pub struct NodeHandle {
    peer_id: PeerId,
    listen_addr: SocketAddr,
    commands: mpsc::UnboundedSender<Command>,
}

impl std::ops::Deref for Node {
    type Target = NodeHandle;

    fn deref(&self) -> &NodeHandle {
        &self.handle
    }
}

impl Node {
    pub async fn start(config: NodeConfig) -> Result<Node, NodeError> {
        let network = config.network;
        let identity = Arc::new(TransportIdentity::new(config.keypair)?);
        let peer_id = identity.peer_id();
        let local = peer_id.to_libp2p();

        let mut transport = HuxTransport::new(identity, network);
        if let Some(filter) = config.datagram_filter {
            transport = transport.with_datagram_filter(filter);
        }

        let limits = ConnectionLimits::default()
            .with_max_established(Some(config.max_peers))
            .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
            // Two, not one: simultaneous dials in both directions are normal between peers.
            .with_max_established_per_peer(Some(2));
        let behaviour = Behaviour {
            limits: connection_limits::Behaviour::new(limits),
            blocked: allow_block_list::Behaviour::default(),
            gossipsub: gossipsub_behaviour(network, &config.topics, config.heartbeat)?,
            kad: kad_behaviour(local, network),
        };
        let mut swarm = Swarm::new(
            transport.boxed(),
            behaviour,
            local,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(300)),
        );
        for topic in &config.topics {
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&IdentTopic::new(topic.as_str()))
                .map_err(|e| NodeError::Listen(e.to_string()))?;
        }

        swarm
            .listen_on(socket_to_multiaddr(config.listen))
            .map_err(|e| NodeError::Listen(e.to_string()))?;
        let listen_addr = loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    break crate::transport::p2p::parse_address(&address)
                        .map_err(|e| NodeError::Listen(e.to_string()))?
                        .0;
                }
                SwarmEvent::ListenerError { error, .. } => {
                    return Err(NodeError::Listen(error.to_string()));
                }
                _ => {}
            }
        };

        let (commands, command_rx) = mpsc::unbounded_channel();
        let (event_tx, events) = mpsc::channel(config.event_buffer.max(1));
        let mut driver = Driver {
            swarm,
            network,
            target_peers: config.target_peers,
            peers: PeerTable::new(config.policy),
            events: event_tx,
            pending_gets: HashMap::new(),
            pending_puts: HashMap::new(),
        };
        for (peer, addr) in config.bootstrap {
            driver.dial(peer, addr);
        }
        tokio::spawn(driver.run(command_rx));

        Ok(Node {
            handle: NodeHandle {
                peer_id,
                listen_addr,
                commands,
            },
            events,
        })
    }

    /// A handle for issuing commands from another task.
    pub fn handle(&self) -> NodeHandle {
        self.handle.clone()
    }

    /// The next event, or `None` once the node has stopped.
    pub async fn next_event(&mut self) -> Option<NodeEvent> {
        self.events.recv().await
    }

    /// Splits the node into its command handle and its event stream.
    pub fn split(self) -> (NodeHandle, mpsc::Receiver<NodeEvent>) {
        (self.handle, self.events)
    }
}

impl NodeHandle {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The bound socket address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// The full dialable address, naming this node: `…/quic-v1/p2p/<id>`.
    pub fn multiaddr(&self) -> Multiaddr {
        socket_to_multiaddr(self.listen_addr).with(Protocol::P2p(self.peer_id.to_libp2p()))
    }

    pub async fn publish(&self, message: GossipMessage) -> Result<(), NodeError> {
        self.request(|tx| Command::Publish(message, tx)).await?
    }

    pub async fn put_record(&self, entry: DhtEntry) -> Result<(), NodeError> {
        self.request(|tx| Command::PutRecord(entry, tx)).await?
    }

    /// The validated record published by `peer`, if the DHT holds one.
    pub async fn get_record(&self, peer: PeerId) -> Result<Option<DhtEntry>, NodeError> {
        self.request(|tx| Command::GetRecord(peer, tx)).await
    }

    pub fn dial(&self, peer: PeerId, addr: SocketAddr) -> Result<(), NodeError> {
        self.commands
            .send(Command::Dial(peer, addr))
            .map_err(|_| NodeError::Stopped)
    }

    pub async fn connected_peers(&self) -> Result<Vec<PeerId>, NodeError> {
        self.request(Command::ConnectedPeers).await
    }

    pub async fn routing_table(&self) -> Result<Vec<PeerId>, NodeError> {
        self.request(Command::RoutingTable).await
    }

    pub async fn peer_state(&self, peer: PeerId) -> Result<PeerState, NodeError> {
        self.request(|tx| Command::PeerState(peer, tx)).await
    }

    async fn request<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(command(tx))
            .map_err(|_| NodeError::Stopped)?;
        rx.await.map_err(|_| NodeError::Stopped)
    }
}

fn gossipsub_behaviour(
    network: Network,
    topics: &[GossipTopic],
    heartbeat: Duration,
) -> Result<gossipsub::Behaviour, NodeError> {
    let config = gossipsub::ConfigBuilder::default()
        .protocol_id_prefix(format!("/huxplex/{network}/meshsub"))
        .validation_mode(ValidationMode::Anonymous)
        .validate_messages()
        .message_id_fn(|message| MessageId::new(&shake256_32(&message.data)))
        .heartbeat_interval(heartbeat)
        .max_transmit_size(MAX_ENVELOPE_LEN)
        .build()
        .map_err(|e| NodeError::Listen(e.to_string()))?;
    let mut behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, config)
        .map_err(|e| NodeError::Listen(e.to_string()))?;

    // GossipSub's own scoring, beside the Huxplex penalties in `PeerTable`: an invalid message
    // costs the delivering peer heavily. Mesh-delivery-rate penalties are off — an honest node on
    // a quiet topic must not be penalised for silence.
    //
    // The two layers meet at the graylist. With these weights a second invalid delivery takes the
    // peer to −100 × 2² × 0.5 = −200, past the −80 graylist threshold, after which GossipSub
    // drops its traffic before the node ever sees it — so the `PeerTable` score stops moving.
    // `Driver::gossip_event` turns a graylisting into a ban (`Offence::GossipGraylisted`), so a silenced
    // peer is also disconnected. Honest peers never get there: they validate before forwarding,
    // and QUIC rules out corruption in transit.
    let mut params = PeerScoreParams::default();
    for topic in topics {
        let topic_params = TopicScoreParams {
            invalid_message_deliveries_weight: -100.0,
            invalid_message_deliveries_decay: 0.5,
            mesh_message_deliveries_weight: 0.0,
            mesh_failure_penalty_weight: 0.0,
            ..TopicScoreParams::default()
        };
        params
            .topics
            .insert(IdentTopic::new(topic.as_str()).hash(), topic_params);
    }
    behaviour
        .with_peer_score(params, gossip_thresholds())
        .map_err(|e| NodeError::Listen(e.to_string()))?;
    Ok(behaviour)
}

/// GossipSub's score thresholds — read again by `Driver::gossip_event` to catch a graylisting.
fn gossip_thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds::default()
}

fn kad_behaviour(local: libp2p::PeerId, network: Network) -> kad::Behaviour<MemoryStore> {
    let protocol = StreamProtocol::try_from_owned(format!("/huxplex/{network}/kad/1.0.0"))
        .expect("a well-formed protocol name");
    let mut config = kad::Config::new(protocol);
    // Every inbound record comes to the node for validation before it is stored.
    config.set_record_filtering(StoreInserts::FilterBoth);
    config.set_query_timeout(Duration::from_secs(10));
    config.set_periodic_bootstrap_interval(Some(Duration::from_secs(5)));
    let mut kad = kad::Behaviour::with_config(local, MemoryStore::new(local), config);
    kad.set_mode(Some(Mode::Server));
    kad
}

/// Validates a DHT record against the rules in the module docs. `None` if it fails any.
fn validate_record(record: &Record, network: Network) -> Option<DhtEntry> {
    let entry = DhtEntry::decode(&record.value).ok()?;
    let signer = PeerId::from_ml_dsa_pk(entry.signer_pk.clone());
    let well_keyed = record.key.as_ref() == entry.key.as_slice() && entry.key == signer.id;
    (entry.network == network && well_keyed && entry.verify().ok()?).then_some(entry)
}

/// A lookup in flight: who asked, for whose record, and the best valid record seen so far.
struct PendingGet {
    reply: oneshot::Sender<Option<DhtEntry>>,
    peer: PeerId,
    best: Option<DhtEntry>,
}

struct Driver {
    swarm: Swarm<Behaviour>,
    network: Network,
    target_peers: usize,
    peers: PeerTable,
    events: mpsc::Sender<NodeEvent>,
    pending_gets: HashMap<QueryId, PendingGet>,
    pending_puts: HashMap<QueryId, oneshot::Sender<Result<(), NodeError>>>,
}

impl Driver {
    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => self.command(command),
                    None => break,
                },
                event = self.swarm.select_next_some() => self.swarm_event(event),
                _ = ticker.tick() => self.tick(),
            }
        }
    }

    /// Hands an event to the application, or drops it if the application is not keeping up.
    fn emit(&self, event: NodeEvent) {
        let _ = self.events.try_send(event);
    }

    /// The record this node holds for `key`, if it is valid.
    fn held_record(&mut self, key: &RecordKey) -> Option<DhtEntry> {
        let network = self.network;
        let held = self.swarm.behaviour_mut().kad.store_mut().get(key)?;
        validate_record(&held, network)
    }

    fn dial(&mut self, peer: PeerId, addr: SocketAddr) {
        let remote = peer.to_libp2p();
        self.swarm
            .behaviour_mut()
            .kad
            .add_address(&remote, socket_to_multiaddr(addr));
        if self.peers.may_dial(&peer, Instant::now()) && !self.swarm.is_connected(&remote) {
            self.peers.dialing(peer);
            let opts = DialOpts::peer_id(remote)
                .addresses(vec![socket_to_multiaddr(addr)])
                .build();
            let _ = self.swarm.dial(opts);
        }
    }

    fn command(&mut self, command: Command) {
        match command {
            Command::Publish(message, reply) => {
                let _ = reply.send(self.publish(message));
            }
            Command::PutRecord(entry, reply) => {
                let record = Record::new(RecordKey::new(&entry.key), entry.encode());
                if validate_record(&record, self.network).is_none() {
                    let _ = reply.send(Err(NodeError::Invalid(
                        "a record must verify, be on this network, and be keyed by its signer"
                            .into(),
                    )));
                    return;
                }
                if let Some(held) = self.held_record(&record.key) {
                    if !entry.supersedes(&held) {
                        let _ = reply.send(Err(NodeError::Invalid(format!(
                            "seq {} does not supersede the held record's seq {}",
                            entry.seq, held.seq
                        ))));
                        return;
                    }
                }
                match self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, Quorum::One)
                {
                    Ok(id) => {
                        self.pending_puts.insert(id, reply);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(NodeError::Dht(format!("{e:?}"))));
                    }
                }
            }
            Command::GetRecord(peer, reply) => {
                let id = self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .get_record(RecordKey::new(&peer.id));
                self.pending_gets.insert(
                    id,
                    PendingGet {
                        reply,
                        peer,
                        best: None,
                    },
                );
            }
            Command::Dial(peer, addr) => self.dial(peer, addr),
            Command::ConnectedPeers(reply) => {
                let peers = self
                    .swarm
                    .connected_peers()
                    .filter_map(PeerId::from_libp2p)
                    .collect();
                let _ = reply.send(peers);
            }
            Command::RoutingTable(reply) => {
                let mut peers = Vec::new();
                for bucket in self.swarm.behaviour_mut().kad.kbuckets() {
                    for entry in bucket.iter() {
                        if let Some(peer) = PeerId::from_libp2p(entry.node.key.preimage()) {
                            peers.push(peer);
                        }
                    }
                }
                let _ = reply.send(peers);
            }
            Command::PeerState(peer, reply) => {
                let _ = reply.send(self.peers.state(&peer));
            }
        }
    }

    fn publish(&mut self, message: GossipMessage) -> Result<(), NodeError> {
        if message.network != self.network {
            return Err(NodeError::Invalid(format!(
                "message is for {}, node is on {}",
                message.network, self.network
            )));
        }
        match message.verify() {
            Ok(true) => {}
            Ok(false) => return Err(NodeError::Invalid("signature does not verify".into())),
            Err(e) => return Err(NodeError::Invalid(e.to_string())),
        }
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(IdentTopic::new(message.topic.as_str()), message.encode())
            .map(|_| ())
            .map_err(|e| NodeError::Publish(e.to_string()))
    }

    fn tick(&mut self) {
        let now = Instant::now();
        for peer in self.peers.expire_bans(now) {
            self.swarm
                .behaviour_mut()
                .blocked
                .unblock_peer(peer.to_libp2p());
        }
        self.peers.prune(now);
    }

    fn penalize(&mut self, peer: PeerId, offence: Offence) {
        self.emit(NodeEvent::Rejected {
            from: peer,
            offence,
        });
        if let Verdict::Banned { .. } = self.peers.penalize(peer, offence, Instant::now()) {
            // Blocking closes every connection to the peer and refuses new ones until the ban
            // expires (see `tick`).
            let remote = peer.to_libp2p();
            self.swarm.behaviour_mut().blocked.block_peer(remote);
            self.swarm.behaviour_mut().gossipsub.blacklist_peer(&remote);
            self.emit(NodeEvent::PeerBanned(peer));
        }
    }

    fn swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        let now = Instant::now();
        match &event {
            SwarmEvent::ConnectionEstablished { peer_id, .. }
            | SwarmEvent::ConnectionClosed { peer_id, .. } => eprintln!(
                "DBG {} conn event {:?}",
                &self.swarm.local_peer_id().to_string()[..12],
                (peer_id.to_string(), std::mem::discriminant(&event))
            ),
            _ => {}
        }
        match event {
            SwarmEvent::Dialing {
                peer_id: Some(peer),
                ..
            } => {
                if let Some(peer) = PeerId::from_libp2p(&peer) {
                    self.peers.dialing(peer);
                    self.peers.handshaking(peer);
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                let Some(peer) = PeerId::from_libp2p(&peer_id) else {
                    // Unreachable through HuxTransport (ADR-0021 I1); refuse rather than trust.
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                };
                self.peers.identified(peer);
                if let ConnectedPoint::Listener { send_back_addr, .. } = endpoint {
                    // One QUIC socket listens and dials, so the remote address is dialable.
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, send_back_addr);
                }
                if num_established.get() == 1 {
                    self.emit(NodeEvent::PeerIdentified(peer));
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                if let Some(peer) = PeerId::from_libp2p(&peer_id) {
                    self.peers.disconnected(peer, false, now);
                    self.emit(NodeEvent::PeerDisconnected(peer));
                }
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                ..
            } => {
                if let Some(peer) = PeerId::from_libp2p(&peer) {
                    if !self.swarm.is_connected(&peer.to_libp2p()) {
                        self.peers.disconnected(peer, true, now);
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(event)) => self.gossip_event(event),
            SwarmEvent::Behaviour(BehaviourEvent::Kad(event)) => self.kad_event(event),
            _ => {}
        }
    }

    fn gossip_event(&mut self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            } => {
                let Some(source) = PeerId::from_libp2p(&propagation_source) else {
                    return;
                };
                eprintln!(
                    "DBG gossip from {} state {:?} topic {}",
                    &source.to_hex()[..8],
                    self.peers.state(&source),
                    message.topic
                );
                let (acceptance, verdict) = if !self.peers.may_process(&source) {
                    (MessageAcceptance::Ignore, None)
                } else {
                    self.peers.active(source);
                    match self.check_gossip(&message.data, message.topic.as_str()) {
                        Ok(envelope) => (MessageAcceptance::Accept, Some(Ok(envelope))),
                        Err(offence) => (MessageAcceptance::Reject, Some(Err(offence))),
                    }
                };
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(&message_id, &propagation_source, acceptance);
                match verdict {
                    Some(Ok(message)) => self.emit(NodeEvent::Gossip {
                        message,
                        propagated_by: source,
                    }),
                    Some(Err(offence)) => {
                        self.penalize(source, offence);
                        // The rejection just reported has updated GossipSub's score. If it has
                        // crossed the graylist, nothing more from this peer will reach the node
                        // — ban now. (Polling for it misses the window: with two deliveries the
                        // score is past the graylist for at most one decay interval.)
                        let graylisted = self
                            .swarm
                            .behaviour()
                            .gossipsub
                            .peer_score(&propagation_source)
                            .is_some_and(|score| score <= gossip_thresholds().graylist_threshold);
                        if graylisted && !self.peers.is_banned(&source) {
                            self.penalize(source, Offence::GossipGraylisted);
                        }
                    }
                    None => {}
                }
            }
            gossipsub::Event::Subscribed { peer_id, .. } => {
                if let Some(peer) = PeerId::from_libp2p(&peer_id) {
                    self.peers.active(peer);
                }
            }
            _ => {}
        }
    }

    /// Decode, then bind to context, then verify — cheapest refusal first.
    fn check_gossip(&self, data: &[u8], topic: &str) -> Result<GossipMessage, Offence> {
        let envelope = GossipMessage::decode(data).map_err(|_| Offence::Malformed)?;
        // A valid envelope arriving on a different topic or network than it was signed for is a
        // replay attempt even before its signature is checked.
        if envelope.network != self.network || envelope.topic.as_str() != topic {
            return Err(Offence::CrossContextReplay);
        }
        match envelope.verify() {
            Ok(true) => Ok(envelope),
            Ok(false) => Err(Offence::InvalidSignature),
            Err(_) => Err(Offence::Malformed),
        }
    }

    fn kad_event(&mut self, event: kad::Event) {
        match event {
            kad::Event::InboundRequest {
                request:
                    InboundRequest::PutRecord {
                        source,
                        record: Some(record),
                        ..
                    },
            } => {
                let Some(peer) = PeerId::from_libp2p(&source) else {
                    return;
                };
                let Some(entry) = validate_record(&record, self.network) else {
                    self.penalize(peer, Offence::InvalidRecord);
                    return;
                };
                // A stale record is ignored, not penalised: an honest peer replicating what it
                // holds can be behind. What it cannot do is roll this node back.
                if self
                    .held_record(&record.key)
                    .is_none_or(|held| entry.supersedes(&held))
                {
                    let _ = self.swarm.behaviour_mut().kad.store_mut().put(record);
                }
            }
            kad::Event::RoutingUpdated {
                peer, addresses, ..
            } => {
                // Connect to peers discovered until the target is reached, so the gossip mesh can
                // form; beyond it Kademlia keeps the peer as a contact, not a connection.
                if self.swarm.connected_peers().count() >= self.target_peers {
                    return;
                }
                if let Some(hux) = PeerId::from_libp2p(&peer) {
                    if let Ok((socket, _)) = crate::transport::p2p::parse_address(addresses.first())
                    {
                        self.dial(hux, socket);
                    }
                }
            }
            kad::Event::OutboundQueryProgressed {
                id, result, step, ..
            } => match result {
                QueryResult::GetRecord(result) => {
                    if let Ok(GetRecordOk::FoundRecord(found)) = result {
                        if let Some(pending) = self.pending_gets.get_mut(&id) {
                            let peer = pending.peer;
                            match validate_record(&found.record, self.network)
                                .filter(|entry| entry.key == peer.id)
                            {
                                // Peers may hold different generations; keep the newest.
                                Some(entry) => {
                                    if pending.best.as_ref().is_none_or(|b| entry.seq > b.seq) {
                                        pending.best = Some(entry);
                                    }
                                }
                                None => {
                                    if let Some(source) =
                                        found.peer.and_then(|p| PeerId::from_libp2p(&p))
                                    {
                                        self.penalize(source, Offence::InvalidRecord);
                                    }
                                }
                            }
                        }
                    }
                    if step.last {
                        if let Some(pending) = self.pending_gets.remove(&id) {
                            let _ = pending.reply.send(pending.best);
                        }
                    }
                }
                QueryResult::PutRecord(result) => {
                    if let Some(reply) = self.pending_puts.remove(&id) {
                        let _ = reply.send(
                            result
                                .map(|_| ())
                                .map_err(|e| NodeError::Dht(format!("{e:?}"))),
                        );
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}

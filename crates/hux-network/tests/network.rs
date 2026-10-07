//! Gate **G5** at the swarm level — real nodes over the real transport, on localhost.
//!
//! | Test | Property |
//! |---|---|
//! | **exit** | 5 nodes discover each other, mutually authenticate over QUIC with ML-DSA certificates, gossip, and sustain sessions |
//! | **G5-T2** | every peer a node knows is the `PeerId` of the key it authenticated with |
//! | **G5-T3** | a flood of malformed, forged and replayed messages is not amplified; the offender is banned |
//! | **G5-T4** | under 20% packet loss and a healed partition, every honest node converges |
//! | **G5-T5** | the live DHT refuses forged, re-keyed and cross-network records |
//!
//! The attacker in G5-T3 and G5-T5 is a real libp2p peer with a valid Huxplex transport identity
//! — the strongest adversary that can reach a node at all — built here from the public transport
//! and stock GossipSub / Kademlia, with none of the node's validation.

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use futures::StreamExt;
use hux_crypto::{
    bip32::{KeyPurpose, derive_mldsa_seed_for_purpose},
    context::Network,
    signature::Keypair,
    signaturescheme::SignatureSchemeId,
};
use hux_network::{
    message::{DhtEntry, GossipMessage},
    node::{Node, NodeConfig, NodeEvent, NodeHandle},
    peer::PeerId,
    peers::Offence,
    topic::GossipTopic,
    transport::{
        p2p::{HuxTransport, socket_to_multiaddr},
        socket::DatagramFilter,
        tls::TransportIdentity,
    },
};
use hux_types::codec::Codec;
use libp2p::{
    StreamProtocol, Swarm,
    core::Transport as _,
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode},
    kad::{self, Quorum, Record, RecordKey, store::MemoryStore},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use tokio::sync::mpsc::UnboundedReceiver;

const NET: Network = Network::Testnet;

fn transport_key(i: u8) -> Keypair {
    let seed = derive_mldsa_seed_for_purpose([i; 64], KeyPurpose::Transport, 0);
    Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap()
}

fn author_key(i: u8) -> Keypair {
    let seed = derive_mldsa_seed_for_purpose([i; 64], KeyPurpose::Transaction, 0);
    Keypair::generate(SignatureSchemeId::Dilithium2, seed).unwrap()
}

fn topics() -> Vec<GossipTopic> {
    vec![GossipTopic::intents(), GossipTopic::shard_blocks(0)]
}

async fn start(
    i: u8,
    bootstrap: &[(PeerId, SocketAddr)],
    filter: Option<Arc<dyn DatagramFilter>>,
) -> (NodeHandle, UnboundedReceiver<NodeEvent>) {
    let mut config = NodeConfig::new(NET, transport_key(i), "127.0.0.1:0".parse().unwrap());
    config.topics = topics();
    config.heartbeat = Duration::from_millis(200);
    config.bootstrap = bootstrap.to_vec();
    config.datagram_filter = filter;
    Node::start(config).await.unwrap().split()
}

/// A bootstrap node and `n - 1` others pointed at it.
async fn network(
    n: u8,
    filter: Option<Arc<dyn DatagramFilter>>,
) -> Vec<(NodeHandle, UnboundedReceiver<NodeEvent>)> {
    let first = start(0, &[], filter.clone()).await;
    let boot = [(first.0.peer_id(), first.0.listen_addr())];
    let mut nodes = vec![first];
    for i in 1..n {
        nodes.push(start(i, &boot, filter.clone()).await);
    }
    nodes
}

/// Polls `check` until it holds or `within` elapses.
async fn eventually<F, Fut>(within: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn fully_connected(nodes: &[NodeHandle]) -> bool {
    for node in nodes {
        if node.connected_peers().await.unwrap().len() < nodes.len() - 1 {
            return false;
        }
    }
    true
}

/// Collects every gossip payload each node receives, in the background.
fn collect(events: Vec<UnboundedReceiver<NodeEvent>>) -> Vec<Arc<Mutex<Vec<NodeEvent>>>> {
    events
        .into_iter()
        .map(|mut rx| {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let sink = seen.clone();
            tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    sink.lock().unwrap().push(event);
                }
            });
            seen
        })
        .collect()
}

fn payloads(events: &Mutex<Vec<NodeEvent>>) -> HashSet<Vec<u8>> {
    events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            NodeEvent::Gossip { message, .. } => Some(message.payload.clone()),
            _ => None,
        })
        .collect()
}

fn gossip(author: u8, topic: GossipTopic, payload: &[u8]) -> GossipMessage {
    GossipMessage::sign(&author_key(author), topic, NET.as_str(), payload.to_vec()).unwrap()
}

// ─── G5 exit — five nodes ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g5_exit_five_nodes_discover_authenticate_gossip_and_sustain_sessions() {
    let (handles, events): (Vec<_>, Vec<_>) = network(5, None).await.into_iter().unzip();
    let seen = collect(events);

    // Discovery: only node 0 was configured; everyone else is found through Kademlia.
    assert!(
        eventually(Duration::from_secs(15), || fully_connected(&handles)).await,
        "5 nodes did not all discover and authenticate each other"
    );
    for node in &handles {
        assert_eq!(node.routing_table().await.unwrap().len(), 4);
    }

    // G5-T2, live: every authenticated peer is exactly the PeerId of a key in this network.
    let expected: HashSet<PeerId> = (0..5)
        .map(|i| PeerId::from_ml_dsa_pk(transport_key(i).public_key().clone()))
        .collect();
    for (i, node) in handles.iter().enumerate() {
        let connected: HashSet<PeerId> =
            node.connected_peers().await.unwrap().into_iter().collect();
        let mut others = expected.clone();
        others.remove(&node.peer_id());
        assert_eq!(
            connected, others,
            "node {i} is connected to a peer it should not know"
        );
    }

    // Gossip from every node reaches every other.
    for (i, node) in handles.iter().enumerate() {
        node.publish(gossip(
            i as u8,
            GossipTopic::intents(),
            format!("round 1 from {i}").as_bytes(),
        ))
        .await
        .unwrap();
    }
    let all_received = |round: usize| {
        let seen = seen.clone();
        async move {
            (0..5).all(|n| {
                let got = payloads(&seen[n]);
                (0..5)
                    .filter(|&i| i != n)
                    .all(|i| got.contains(format!("round {round} from {i}").as_bytes()))
            })
        }
    };
    assert!(
        eventually(Duration::from_secs(10), || all_received(1)).await,
        "gossip did not reach every node"
    );

    // Sessions are sustained: the same connections carry a second round, with no reconnection.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        fully_connected(&handles).await,
        "sessions dropped while idle"
    );
    for (i, node) in handles.iter().enumerate() {
        node.publish(gossip(
            i as u8,
            GossipTopic::shard_blocks(0),
            format!("round 2 from {i}").as_bytes(),
        ))
        .await
        .unwrap();
    }
    assert!(
        eventually(Duration::from_secs(10), || all_received(2)).await,
        "second round lost"
    );
    for events in &seen {
        assert!(
            !events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, NodeEvent::PeerDisconnected(_))),
            "a session was torn down"
        );
    }
}

// ─── The attacker ────────────────────────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct Attacker {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
}

/// A peer with a valid transport identity and stock GossipSub + Kademlia speaking Huxplex's
/// protocol names — and none of a node's validation.
fn attacker(seed: u8) -> (Swarm<Attacker>, PeerId) {
    let identity = Arc::new(TransportIdentity::new(transport_key(seed)).unwrap());
    let peer = identity.peer_id();
    let local = peer.to_libp2p();
    let gossip_config = gossipsub::ConfigBuilder::default()
        .protocol_id_prefix(format!("/huxplex/{NET}/meshsub"))
        .validation_mode(ValidationMode::Anonymous)
        .message_id_fn(|m| MessageId::new(&hux_crypto::hash::shake::shake256_32(&m.data)))
        .heartbeat_interval(Duration::from_millis(200))
        .build()
        .unwrap();
    let kad_config = kad::Config::new(
        StreamProtocol::try_from_owned(format!("/huxplex/{NET}/kad/1.0.0")).unwrap(),
    );
    let behaviour = Attacker {
        gossipsub: gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, gossip_config)
            .unwrap(),
        kad: kad::Behaviour::with_config(local, MemoryStore::new(local), kad_config),
    };
    let swarm = Swarm::new(
        HuxTransport::new(identity, NET).boxed(),
        behaviour,
        local,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(60)),
    );
    (swarm, peer)
}

/// Drives the attacker's swarm in the background, reporting whether it is still connected to
/// `target`.
fn run_attacker(
    mut swarm: Swarm<Attacker>,
    mut outbox: tokio::sync::mpsc::UnboundedReceiver<AttackerCommand>,
) -> Arc<Mutex<Vec<String>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                cmd = outbox.recv() => match cmd {
                    Some(AttackerCommand::Publish(topic, data)) => {
                        let _ = swarm.behaviour_mut().gossipsub.publish(IdentTopic::new(topic), data);
                    }
                    Some(AttackerCommand::Put(record)) => {
                        let _ = swarm.behaviour_mut().kad.put_record(record, Quorum::One);
                    }
                    Some(AttackerCommand::Dial(peer, addr)) => {
                        swarm.behaviour_mut().kad.add_address(&peer.to_libp2p(), socket_to_multiaddr(addr));
                        let _ = swarm.dial(
                            libp2p::swarm::dial_opts::DialOpts::peer_id(peer.to_libp2p())
                                .addresses(vec![socket_to_multiaddr(addr)])
                                .build(),
                        );
                    }
                    None => break,
                },
                event = swarm.select_next_some() => {
                    let line = match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => format!("connected {peer_id}"),
                        SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => format!("closed {peer_id}"),
                        _ => continue,
                    };
                    sink.lock().unwrap().push(line);
                }
            }
        }
    });
    log
}

enum AttackerCommand {
    Publish(String, Vec<u8>),
    Put(Record),
    Dial(PeerId, SocketAddr),
}

// ─── G5-T3 — amplification bounded, offender banned ──────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g5_t3_a_flood_is_not_amplified_and_the_offender_is_banned() {
    // victim ←→ bystander, and the attacker connected to the victim only.
    let victim = start(40, &[], None).await;
    let bystander = start(41, &[(victim.0.peer_id(), victim.0.listen_addr())], None).await;
    let handles = [victim.0.clone(), bystander.0.clone()];
    assert!(eventually(Duration::from_secs(10), || fully_connected(&handles)).await);
    let seen = collect(vec![victim.1, bystander.1]);

    let (mut swarm, attacker_id) = attacker(42);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&IdentTopic::new("huxplex/intents"))
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let attacker_log = run_attacker(swarm, rx);
    tx.send(AttackerCommand::Dial(
        handles[0].peer_id(),
        handles[0].listen_addr(),
    ))
    .unwrap();
    assert!(
        eventually(Duration::from_secs(10), || {
            let h = handles[0].clone();
            async move { h.connected_peers().await.unwrap().contains(&attacker_id) }
        })
        .await,
        "the attacker never connected"
    );
    tokio::time::sleep(Duration::from_secs(1)).await; // let it join the mesh

    // Three kinds of garbage: undecodable bytes, a forged signature, and a valid message
    // replayed onto a topic it was not signed for.
    let mut forged = gossip(43, GossipTopic::intents(), b"forged");
    forged.sig.bytes[0] ^= 0x01;
    let replayed = gossip(43, GossipTopic::shard_blocks(0), b"replayed onto intents");
    for i in 0..30u32 {
        let data = match i % 3 {
            0 => format!("not an envelope {i}").into_bytes(),
            1 => {
                let mut m = forged.clone();
                m.payload = format!("forged {i}").into_bytes();
                m.encode()
            }
            _ => {
                let mut m = replayed.clone();
                m.payload = format!("replayed {i}").into_bytes();
                m.encode()
            }
        };
        tx.send(AttackerCommand::Publish("huxplex/intents".into(), data))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The victim bans the attacker and drops its connection.
    let banned = eventually(Duration::from_secs(10), || {
        let seen = seen[0].clone();
        async move {
            seen.lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, NodeEvent::PeerBanned(p) if *p == attacker_id))
        }
    })
    .await;
    assert!(banned, "the offender was never banned");
    assert!(
        eventually(Duration::from_secs(5), || {
            let h = handles[0].clone();
            async move { !h.connected_peers().await.unwrap().contains(&attacker_id) }
        })
        .await,
        "a banned peer is still connected"
    );
    assert!(
        attacker_log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.starts_with("closed"))
    );

    // Every kind of offence was recognised as itself.
    let offences: HashSet<_> = seen[0]
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            NodeEvent::Rejected { from, offence } if *from == attacker_id => Some(*offence),
            _ => None,
        })
        .collect();
    for expected in [
        Offence::Malformed,
        Offence::InvalidSignature,
        Offence::CrossContextReplay,
    ] {
        assert!(
            offences.contains(&expected),
            "{expected:?} was not recognised"
        );
    }

    // Not amplified: nothing the attacker sent ever arrived at the bystander *through the
    // victim*. (The bystander may discover the attacker through Kademlia and be flooded directly
    // — it then refuses the traffic itself, which is the same property from its side.)
    tokio::time::sleep(Duration::from_secs(1)).await;
    let victim_id = handles[0].peer_id();
    for event in seen[1].lock().unwrap().iter() {
        match event {
            NodeEvent::Rejected { from, .. } => {
                assert_ne!(
                    *from, victim_id,
                    "the victim forwarded the attacker's traffic"
                );
            }
            NodeEvent::Gossip { message, .. } => {
                panic!(
                    "an attacker message was accepted: {:?}",
                    String::from_utf8_lossy(&message.payload)
                );
            }
            _ => {}
        }
    }

    // And the honest path still works.
    handles[0]
        .publish(gossip(44, GossipTopic::intents(), b"still alive"))
        .await
        .unwrap();
    assert!(
        eventually(Duration::from_secs(5), || {
            let seen = seen[1].clone();
            async move { payloads(&seen).contains(b"still alive".as_slice()) }
        })
        .await
    );
}

// ─── G5-T4 — loss and partition ──────────────────────────────────────────────────────────────

/// Random loss plus an optional partition between two groups of ports.
#[derive(Debug, Default)]
struct Lossy {
    loss_percent: AtomicU32,
    rng: Mutex<u64>,
    partition: Mutex<Option<(HashSet<u16>, HashSet<u16>)>>,
}

impl DatagramFilter for Lossy {
    fn deliver(&self, from: SocketAddr, to: SocketAddr, _: &[u8]) -> bool {
        if let Some((a, b)) = &*self.partition.lock().unwrap() {
            let (f, t) = (from.port(), to.port());
            if (a.contains(&f) && b.contains(&t)) || (b.contains(&f) && a.contains(&t)) {
                return false;
            }
        }
        let mut s = self.rng.lock().unwrap();
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        (*s % 100) as u32 >= self.loss_percent.load(Ordering::Relaxed)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g5_t4_propagation_under_loss_and_a_healed_partition() {
    let wire = Arc::new(Lossy {
        rng: Mutex::new(0x9E37_79B9_7F4A_7C15),
        ..Lossy::default()
    });
    let (handles, events): (Vec<_>, Vec<_>) =
        network(5, Some(wire.clone())).await.into_iter().unzip();
    let seen = collect(events);
    assert!(eventually(Duration::from_secs(15), || fully_connected(&handles)).await);

    let delivered_everywhere = |labels: Vec<(usize, String)>| {
        let seen = seen.clone();
        async move {
            (0..5).all(|n| {
                let got = payloads(&seen[n]);
                labels
                    .iter()
                    .filter(|(from, _)| *from != n)
                    .all(|(_, l)| got.contains(l.as_bytes()))
            })
        }
    };

    // Phase 1 — 20% of every datagram, in both directions, is dropped.
    wire.loss_percent.store(20, Ordering::Relaxed);
    let mut phase1 = Vec::new();
    for k in 0..10usize {
        let from = k % 5;
        let label = format!("lossy {k}");
        handles[from]
            .publish(gossip(from as u8, GossipTopic::intents(), label.as_bytes()))
            .await
            .unwrap();
        phase1.push((from, label));
    }
    assert!(
        eventually(Duration::from_secs(20), || delivered_everywhere(
            phase1.clone()
        ))
        .await,
        "messages were lost under 20% packet loss"
    );

    // Phase 2 — partition {0,1} | {2,3,4}, still lossy; publish on both sides, then heal.
    let ports = |ix: &[usize]| {
        ix.iter()
            .map(|&i| handles[i].listen_addr().port())
            .collect::<HashSet<_>>()
    };
    *wire.partition.lock().unwrap() = Some((ports(&[0, 1]), ports(&[2, 3, 4])));
    let mut phase2 = Vec::new();
    for (k, from) in [0usize, 1, 2, 3, 4, 0].into_iter().enumerate() {
        let label = format!("partitioned {k}");
        handles[from]
            .publish(gossip(
                from as u8,
                GossipTopic::shard_blocks(0),
                label.as_bytes(),
            ))
            .await
            .unwrap();
        phase2.push((from, label));
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    *wire.partition.lock().unwrap() = None;

    assert!(
        eventually(Duration::from_secs(30), || delivered_everywhere(
            phase2.clone()
        ))
        .await,
        "the network did not converge after the partition healed"
    );
}

// ─── G5-T5 — the live DHT ────────────────────────────────────────────────────────────────────

fn record_for(publisher: u8, value: &[u8], network: &str) -> DhtEntry {
    let kp = transport_key(publisher);
    let key = PeerId::from_ml_dsa_pk(kp.public_key().clone()).id.to_vec();
    DhtEntry::sign(&kp, key, value.to_vec(), network).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g5_t5_the_live_dht_refuses_forgery_rekeying_and_cross_network_replay() {
    let (handles, events): (Vec<_>, Vec<_>) = network(4, None).await.into_iter().unzip();
    let seen = collect(events);
    assert!(eventually(Duration::from_secs(15), || fully_connected(&handles)).await);
    let (a, b, d) = (&handles[0], &handles[1], &handles[3]);

    // Honest publication and lookup.
    let genuine_a = record_for(0, b"/ip4/10.0.0.1/udp/9000/quic-v1", NET.as_str());
    let genuine_b = record_for(1, b"/ip4/10.0.0.2/udp/9000/quic-v1", NET.as_str());
    a.put_record(genuine_a.clone()).await.unwrap();
    b.put_record(genuine_b.clone()).await.unwrap();
    assert_eq!(
        d.get_record(a.peer_id()).await.unwrap(),
        Some(genuine_a.clone())
    );

    // A node will not even publish a record that fails validation.
    assert!(a.put_record(record_for(0, b"x", "mainnet")).await.is_err());

    // The attacker, a full DHT participant, tries three forgeries.
    let (swarm, attacker_id) = attacker(50);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    run_attacker(swarm, rx);
    for node in &handles {
        tx.send(AttackerCommand::Dial(node.peer_id(), node.listen_addr()))
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 1. Squatting: A's key, the attacker's value, the attacker's signature.
    let squat = {
        let kp = transport_key(50);
        let mut e = DhtEntry::sign(
            &kp,
            a.peer_id().id.to_vec(),
            b"/ip4/6.6.6.6/udp/1/quic-v1".to_vec(),
            NET.as_str(),
        )
        .unwrap();
        e.key = a.peer_id().id.to_vec();
        Record::new(RecordKey::new(&a.peer_id().id), e.encode())
    };
    // 2. Re-keying: A's genuine signed record, stored under B's key.
    let rekeyed = Record::new(RecordKey::new(&b.peer_id().id), genuine_a.encode());
    // 3. Cross-network replay: the attacker's own valid record — signed for mainnet.
    let cross = {
        let e = record_for(50, b"/ip4/6.6.6.6/udp/1/quic-v1", "mainnet");
        Record::new(RecordKey::new(&e.key), e.encode())
    };
    for record in [squat, rekeyed, cross] {
        tx.send(AttackerCommand::Put(record)).unwrap();
    }

    // Every honest node that was offered a forgery refused it as an invalid record.
    assert!(
        eventually(Duration::from_secs(10), || {
            let seen = seen.clone();
            async move {
                seen.iter().any(|s| {
                    s.lock().unwrap().iter().any(|e| {
                        matches!(e, NodeEvent::Rejected { from, offence: Offence::InvalidRecord } if *from == attacker_id)
                    })
                })
            }
        })
        .await,
        "no node recognised the forged records"
    );

    // And the DHT still answers with the genuine records only — from every node.
    for node in &handles {
        assert_eq!(
            node.get_record(a.peer_id()).await.unwrap(),
            Some(genuine_a.clone()),
            "A's record was overwritten"
        );
        assert_eq!(
            node.get_record(b.peer_id()).await.unwrap(),
            Some(genuine_b.clone()),
            "B's key was hijacked"
        );
        assert_eq!(
            node.get_record(attacker_id).await.unwrap(),
            None,
            "a cross-network record was stored"
        );
    }
}

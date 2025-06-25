use std::{borrow::Cow, error::Error, iter, str::FromStr, time::Duration};

use clap::Parser;
use futures::{executor::block_on, future::FutureExt, stream::StreamExt};
use libp2p::{
    core::multiaddr::{Multiaddr, Protocol},
    dcutr, identify, identity, noise, ping, relay,
    kad::{self, store::{RecordStore, Error as StoreError}, Config, ProviderRecord, Record, RecordKey},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, StreamProtocol,
};
use tokio::{
    io::{self, AsyncBufReadExt},
    select,
};
use tracing::warn;
use tracing_subscriber::EnvFilter;

// --- Add the module declaration for routing_table.rs ---
mod routing_table;

// --- A SIMPLER, KEY-VALUE FOCUSED SledStore ---
#[derive(Debug)]
pub struct SimpleSledStore {
    db: sled::Db,
}

impl SimpleSledStore {
    pub fn new(path: &str) -> Self {
        let db = sled::open(path).expect("Failed to open sled database");
        println!("Attempting to open database at: {}", path);

        println!("--- DHT Database Contents ---");
        let mut count = 0;
        for item in db.iter() {
            if let Ok((key_bytes, value_bytes)) = item {
                println!("[Record {}]", count + 1);
                println!("  Raw Key  : {}", String::from_utf8_lossy(&key_bytes));
                println!("  Value    : {}", String::from_utf8_lossy(&value_bytes));
                count += 1;
            }
        }
        println!("--- End of Database ({} records) ---", count);

        SimpleSledStore { db }
    }
}

impl RecordStore for SimpleSledStore {
    type RecordsIter<'a> = Box<dyn Iterator<Item = Cow<'a, Record>> + 'a>;
    type ProvidedIter<'a> = Box<dyn Iterator<Item = Cow<'a, ProviderRecord>> + 'a>;

    fn get(&self, key: &RecordKey) -> Option<Cow<Record>> {
        if let Ok(Some(value_bytes)) = self.db.get(key.as_ref()) {
            let record = Record {
                key: key.clone(),
                value: value_bytes.to_vec(),
                publisher: None,
                expires: None,
            };
            return Some(Cow::Owned(record));
        }
        None
    }

    fn put(&mut self, record: Record) -> Result<(), StoreError> {
        self.db.insert(record.key.as_ref(), record.value)
            .map(|_| ())
            .map_err(|e| {
                warn!("Failed to put record to DB: {:?}", e);
                StoreError::ValueTooLarge
            })
    }

    fn remove(&mut self, key: &RecordKey) {
        let _ = self.db.remove(key.as_ref());
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        Box::new(self.db.iter().filter_map(|res| {
            if let Ok((key_bytes, value_bytes)) = res {
                let record = Record {
                    key: RecordKey::new(&key_bytes),
                    value: value_bytes.to_vec(),
                    publisher: None,
                    expires: None,
                };
                Some(Cow::Owned(record))
            } else {
                None
            }
        }))
    }

    fn add_provider(&mut self, _record: ProviderRecord) -> Result<(), StoreError> { Ok(()) }
    fn providers(&self, _key: &RecordKey) -> Vec<ProviderRecord> { Vec::new() }
    fn provided(&self) -> Self::ProvidedIter<'_> { Box::new(iter::empty()) }
    fn remove_provider(&mut self, _key: &RecordKey, _provider: &PeerId) {}
}


#[derive(Debug, Parser)]
#[command(name = "libp2p DCUtR client with Kademlia")]
struct Opts {
    #[arg(long)]
    mode: Mode,
    #[arg(long)]
    secret_key_seed: u8,
    #[arg(long)]
    relay_address: Multiaddr,
    #[arg(long)]
    remote_peer_id: Option<PeerId>,
}

#[derive(Clone, Debug, PartialEq, Parser)]
enum Mode { Dial, Listen }
impl FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dial" => Ok(Mode::Dial),
            "listen" => Ok(Mode::Listen),
            _ => Err("Expected 'dial' or 'listen'".to_string()),
        }
    }
}

// --- DEFINE THE PROTOCOL NAME AS A CONSTANT TO ENSURE 'static LIFETIME ---
const KAD_PROTOCOL_NAME: &str = "/hermes/kad/1.0.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let opts = Opts::parse();

    #[derive(NetworkBehaviour)]
    struct Behaviour {
        relay_client: relay::client::Behaviour,
        ping: ping::Behaviour,
        identify: identify::Behaviour,
        dcutr: dcutr::Behaviour,
        kademlia: kad::Behaviour<SimpleSledStore>,
    }

    let local_key = generate_ed25519(opts.secret_key_seed);
    let db_path = format!("dht-database-{}", opts.secret_key_seed);
    let store = SimpleSledStore::new(&db_path);

    // --- Create Kademlia Config with the custom protocol name ---
    let kad_config = kad::Config::new(StreamProtocol::new(KAD_PROTOCOL_NAME));

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|keypair, relay_behaviour| Behaviour {
            relay_client: relay_behaviour,
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/hermes/0.0.1".to_string(),
                keypair.public(),
            )),
            dcutr: dcutr::Behaviour::new(keypair.public().to_peer_id()),
            kademlia: kad::Behaviour::with_config(keypair.public().to_peer_id(), store, kad_config),
        })?
        .build();

    // --- Create the RoutingTable instance ---
    let mut routing_table = routing_table::RoutingTable::new(*swarm.local_peer_id());

    swarm.behaviour_mut().kademlia.set_mode(Some(kad::Mode::Server));
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Wait to listen on all interfaces.
    block_on(async {
        let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse();
        loop {
            futures::select! {
                event = swarm.next() => {
                    match event.unwrap() {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Listening on address: {address}");
                        }
                        event => panic!("{event:?}"),
                    }
                }
                _ = delay => {
                    // Likely listening on all interfaces now, thus continuing by breaking the loop.
                    break;
                }
            }
        }
    });

    // Connect to the relay server to learn our local public address and bootstrap Kademlia.
    swarm.dial(opts.relay_address.clone()).unwrap();
    block_on(async {
        let mut learned_observed_addr = false;
        let mut told_relay_observed_addr = false;

        loop {
            match swarm.next().await.unwrap() {
                SwarmEvent::NewListenAddr { .. } => {}
                SwarmEvent::Dialing { .. } => {}
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, opts.relay_address.clone());
                }
                SwarmEvent::Behaviour(BehaviourEvent::Ping(_)) => {}
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Sent { .. })) => {
                    tracing::info!("Told relay its public address");
                    told_relay_observed_addr = true;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                    info: identify::Info { observed_addr, .. },
                    ..
                })) => {
                    tracing::info!(address=%observed_addr, "Relay told us our observed address");
                    learned_observed_addr = true;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Kademlia(_)) => {}
                event => panic!("{event:?}"),
            }

            if learned_observed_addr && told_relay_observed_addr {
                break;
            }
        }
    });

    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
        tracing::warn!("Failed to bootstrap DHT: {:?}", e);
    }

    match opts.mode {
        Mode::Dial => {
            let remote_peer_id = opts.remote_peer_id.expect("Dial mode requires a remote peer ID");
            let relay_addr = opts.relay_address.with(Protocol::P2pCircuit);
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&remote_peer_id, relay_addr.clone());
            swarm.dial(relay_addr.with(Protocol::P2p(remote_peer_id)))?;
        }
        Mode::Listen => {
            swarm.listen_on(opts.relay_address.with(Protocol::P2pCircuit))?;
        }
    }

    println!("
Swarm setup complete. Ready for commands (GET <key>, PUT <key> <value>, GET_PROVIDERS <key>, PUT_PROVIDER <key>, PRINT_RT).");

    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                // --- Pass the routing_table to the input handler ---
                handle_input_line(&mut swarm.behaviour_mut().kademlia, &routing_table, line);
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on address: {address}");
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    tracing::info!(peer=%peer_id, ?endpoint, "Established new connection");
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, endpoint.get_remote_address().clone());
                }
                SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { .. },
                )) => {
                    assert!(opts.mode == Mode::Listen);
                    tracing::info!("Relay accepted our reservation request");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Kademlia(event)) => {
                    // --- Update the routing_table with every Kademlia event ---
                    routing_table.handle_kad_event(&event);

                    match event {
                        kad::Event::OutboundQueryProgressed { result, .. } => match result {
                            kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                                key,
                                providers,
                                ..
                            })) => {
                                for peer in providers {
                                    println!(
                                        "Peer {peer:?} provides key {:?}",
                                        String::from_utf8_lossy(key.as_ref())
                                    );
                                }
                            }
                            kad::QueryResult::GetProviders(Err(err)) => {
                                eprintln!("Failed to get providers: {err:?}");
                            }
                            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(
                                kad::PeerRecord { record, .. },
                            ))) => {
                                println!(
                                    "Got Record: key='{}', value='{}'",
                                    String::from_utf8_lossy(record.key.as_ref()),
                                    String::from_utf8_lossy(&record.value),
                                );
                            }
                            kad::QueryResult::GetRecord(Ok(_)) => {}
                            kad::QueryResult::GetRecord(Err(err)) => {
                                eprintln!("Failed to get record: {err:?}");
                            }
                            kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                                println!(
                                    "Successfully put record with key: '{}'",
                                    String::from_utf8_lossy(key.as_ref())
                                );
                            }
                            kad::QueryResult::PutRecord(Err(err)) => {
                                eprintln!("Failed to put record: {err:?}");
                            }
                            kad::QueryResult::StartProviding(Ok(kad::AddProviderOk { key })) => {
                                println!(
                                    "Successfully put provider record {:?}",
                                    String::from_utf8_lossy(key.as_ref())
                                );
                            }
                            kad::QueryResult::StartProviding(Err(err)) => {
                                eprintln!("Failed to put provider record: {err:?}");
                            }
                            kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk {
                                peer,
                                num_remaining,
                            })) => {
                                tracing::info!(%peer, ?num_remaining, "Bootstrap OK.");
                            }
                            kad::QueryResult::Bootstrap(Err(err)) => {
                                tracing::error!("Bootstrap failed: {err:?}");
                            }
                            _ => {}
                        },
                        kad::Event::RoutingUpdated {
                            peer,
                            ..
                        } => {
                            tracing::info!(%peer, "Routing table updated");
                        }
                        _ => {}
                    }
                },
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    tracing::info!(peer=?peer_id, "Outgoing connection failed: {error}");
                }
                _ => {}
            }
        }
    }
}

// --- Modified handle_input_line to accept routing_table and handle PRINT_RT ---
fn handle_input_line(
    kademlia: &mut kad::Behaviour<SimpleSledStore>,
    routing_table: &routing_table::RoutingTable,
    line: String,
) {
    let mut args = line.split_whitespace();
    match args.next() {
        Some("GET") => {
            if let Some(key) = args.next() {
                kademlia.get_record(kad::RecordKey::new(&key));
            } else {
                eprintln!("Usage: GET <key>");
            }
        }
        Some("GET_PROVIDERS") => {
            if let Some(key) = args.next() {
                kademlia.get_providers(kad::RecordKey::new(&key));
            } else {
                eprintln!("Usage: GET_PROVIDERS <key>");
            }
        }
        Some("PUT") => {
            if let (Some(key), Some(value)) = (args.next(), args.next()) {
                let record = kad::Record {
                    key: kad::RecordKey::new(&key),
                    value: value.as_bytes().to_vec(),
                    publisher: None,
                    expires: None,
                };
                if let Err(e) = kademlia.put_record(record, kad::Quorum::One) {
                    eprintln!("Failed to put record: {:?}", e);
                }
            } else {
                eprintln!("Usage: PUT <key> <value>");
            }
        }
        Some("PUT_PROVIDER") => {
            if let Some(key) = args.next() {
                if let Err(e) = kademlia.start_providing(kad::RecordKey::new(&key)) {
                    eprintln!("Failed to start providing key: {:?}", e);
                }
            } else {
                eprintln!("Usage: PUT_PROVIDER <key>");
            }
        }
        Some("PRINT_RT") => {
            routing_table.print();
        }
        _ => {
            eprintln!("expected GET, GET_PROVIDERS, PUT, PUT_PROVIDER, or PRINT_RT");
        }
    }
}

fn generate_ed25519(secret_key_seed: u8) -> identity::Keypair {
    let mut bytes = [0u8; 32];
    bytes[0] = secret_key_seed;
    identity::Keypair::ed25519_from_bytes(bytes).expect("only errors on wrong length")
}

use libp2p::kad;
use libp2p::PeerId;
use std::collections::BTreeMap;
use std::time::Instant;

/// Represents a peer in the routing table.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The known addresses of the peer.
    pub addresses: Vec<libp2p::Multiaddr>,
    /// The last time this peer was seen.
    pub last_seen: Instant,
}

/// A structure to hold and display the state of the Kademlia routing table.
#[derive(Debug)]
pub struct RoutingTable {
    /// The PeerId of the local node.
    local_peer_id: PeerId,
    /// A map of known peers and their information.
    peers: BTreeMap<PeerId, PeerInfo>,
}

impl RoutingTable {
    /// Creates a new `RoutingTable`.
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            local_peer_id,
            peers: BTreeMap::new(),
        }
    }

    /// Handles a Kademlia event to update the routing table view.
    ///
    /// This function should be called with every `kad::Event` emitted by the
    /// Kademlia behaviour.
    pub fn handle_kad_event(&mut self, event: &kad::Event) {
        if let kad::Event::RoutingUpdated {
            peer,
            addresses,
            ..
        } = event
        {
            self.peers.insert(
                *peer,
                PeerInfo {
                    addresses: addresses.clone().into_vec(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    /// Prints the current state of the routing table to the console.
    pub fn print(&self) {
        println!("--- Routing Table ---");
        println!("Local Peer ID: {}", self.local_peer_id);
        println!("---------------------");
        println!("Known Peers ({}):", self.peers.len());
        for (peer_id, info) in &self.peers {
            println!("  - Peer: {}", peer_id);
            for addr in &info.addresses {
                println!("    - Address: {}", addr);
            }
            println!(
                "    - Last Seen: {:.2?} ago",
                info.last_seen.elapsed()
            );
        }
        println!("---------------------");
    }
}

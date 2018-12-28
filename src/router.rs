use std::collections::HashMap;
use std::iter::FromIterator;

use fcp_cryptoauth::{PublicKey, publickey_to_ipv6addr};

use packets::route::{RoutePacket, RoutePacketBuilder, NodeData};
use encoding_scheme::{EncodingScheme, EncodingSchemeForm};

use operation::{ForwardPath, BackwardPath, Director};
use node_store::{NodeStore, GetNodeResult};
use node::{Address, Node};
use plumbing::RouterTrait;
use session_manager::MySessionHandle;

const PROTOCOL_VERSION: i64 = 18;

/// Wrapper of `NodeStore` that reads/writes network packets.
/// TODO: Check paths are valid before inserting them (eg. send a
/// ping and wait for the reply).
pub struct Router {
    my_pk: PublicKey,
    node_store: NodeStore,
    paths: Vec<(MySessionHandle, PublicKey, ForwardPath)>,
    peers: HashMap<Director, PublicKey>,
}

impl Router {
    pub fn new(my_pk: PublicKey) -> Router {
        Router {
            node_store: NodeStore::new(publickey_to_ipv6addr(&my_pk).into()),
            paths: Vec::new(),
            peers: HashMap::new(),
            my_pk: my_pk,
        }
    }

    /// See `NodeStore::update`.
    pub fn update(&mut self, address: Address, node: Node) {
        self.node_store.update(address, node)
    }

    /// Wrapper for `NodeStore::get_node` that returns RoutePackets that
    /// should be sent in order to fetch the target node.
    pub fn get_node(&self, target: &Address, nb_closest: usize) -> (Option<&Node>, Vec<(&Node, RoutePacket)>) {
        match self.node_store.get_node(target, nb_closest) {
            GetNodeResult::FoundNode(node) => (Some(node), Vec::new()),
            GetNodeResult::ClosestNodes(nodes) => {
                // Ask each of the closest nodes about the target
                let requests = nodes.iter().map(|&(ref _addr, ref node)| {
                    let encoding_scheme = EncodingScheme::from_iter(vec![EncodingSchemeForm { prefix: 0, bit_count: 3, prefix_length: 0 }].iter());
                    let packet = RoutePacketBuilder::new(PROTOCOL_VERSION, b"blah".to_vec())
                            .query("fn".to_owned())
                            .target_address(target.bytes().to_vec())
                            .encoding_index(0)
                            .encoding_scheme(encoding_scheme)
                            .finalize();
                    (*node, packet)
                });
                let requests = requests.collect();
                (None, requests)
            }
            GetNodeResult::Nothing => {
                // TODO: do something
                (None, Vec::new())
            }
        }
    }

    /// Reply to `gp` queries by sending a list of my peers.
    fn on_getpeers(&mut self, packet: &RoutePacket, requester_pk: &PublicKey) -> Vec<RoutePacket> {
        let mut nodes = Vec::new();
        {
            // Add myself
            let mut my_pk = [0u8; 32];
            my_pk.copy_from_slice(&self.my_pk.0);
            nodes.push(NodeData {
                public_key: my_pk,
                path: ForwardPath::self_interface().0,
                version: 18,
            });
        }
        for (&director, pk) in self.peers.iter() {
            if pk != requester_pk {
                let path = ForwardPath::from(director);
                nodes.push(NodeData {
                    public_key: pk.0,
                    path: path.into(),
                    version: 18, // TODO
                });
            }
        }
        // TODO: only send the peers closest to the specified target address.

        let encoding_scheme = EncodingScheme::from_iter(vec![EncodingSchemeForm { prefix: 0, bit_count: 3, prefix_length: 0 }].iter());
        let response = RoutePacketBuilder::new(18, packet.transaction_id.clone())
                .nodes_vec(nodes)
                .encoding_index(0) // This switch uses only one encoding scheme
                .encoding_scheme(encoding_scheme)
                .finalize();
        vec![response]
    }
}

impl RouterTrait for Router {
    fn on_route_packet(&mut self, packet: &RoutePacket, path: BackwardPath, handle: MySessionHandle, pk: PublicKey) -> Vec<RoutePacket> {
        let responses = match packet.query.as_ref().map(String::as_ref) {
            Some("gp") => self.on_getpeers(packet, &pk),
            _ => Vec::new(),
        };
        let node = Node::new(pk.0, path.reverse(), packet.protocol_version as u64);
        let addr = publickey_to_ipv6addr(&pk).into();
        self.update(addr, node);
        responses
    }
}


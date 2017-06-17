use route_packet::{RoutePacket, RoutePacketBuilder};
use operation::Label;
use std::iter::FromIterator;
use encoding_scheme::{EncodingScheme, EncodingSchemeForm};

use node_store::{NodeStore, GetNodeResult};
use node::{Address, Node};

const PROTOCOL_VERSION: i64 = 18;


/// Wrapper of `NodeStore` that reads/writes network packets.
/// TODO: Check paths are valid before inserting them (eg. send a
/// ping and wait for the reply).
pub struct Router {
    node_store: NodeStore,
}

impl Router {
    pub fn new(my_address: Address) -> Router {
        Router {
            node_store: NodeStore::new(my_address),
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

    /// Called when a RoutePacket is received from the network.
    /// Optionally returns RoutePackets to send back.
    pub fn on_route_packet(&mut self, label: &Label, packet: &RoutePacket) -> Result<Vec<(Label, RoutePacket)>, ()> {
        Ok(Vec::new())
    }
}

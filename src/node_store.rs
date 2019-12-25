use simple_kbuckets::Table;

use node::{Address, Node, ADDRESS_BITS};

/// Returns by a request to find a node's path and public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GetNodeResult<'a> {
    /// The exact node, if it was found.
    FoundNode(&'a Node),
    /// Nodes close to the searched node. They should be queried about
    /// the searched node.
    ClosestNodes(Vec<(Address, &'a Node)>),
    /// This table knows of no node at all. It should be bootstrapped
    /// using an external way (ie. find some peers).
    Nothing,
}

pub struct NodeStore {
    pub table: Table<Address, Node>,
}

impl NodeStore {
    /// Creates a new empty NodeStore.
    pub fn new(my_address: Address) -> NodeStore {
        let bucket_size = 32;
        let max_distance = ADDRESS_BITS;
        NodeStore {
            table: Table::new(my_address, bucket_size, max_distance),
        }
    }

    /// Inserts a node in the NodeStore, poping nodes from full
    /// buckets if necessary.
    pub fn update(&mut self, address: Address, node: Node) {
        self.table.update(address, node);
    }

    /// Retrurns an ordered vector of nodes, which are the closest to the
    /// target address this NodeStore knows about.
    pub fn find_closest_nodes(&self, target: &Address, count: usize) -> Vec<(Address, &Node)> {
        self.table.find(target, count)
    }

    /// Tries to get a node. On failure, returns `nb_closest` nodes (or all
    /// nodes in the store, if `nb_closest` is too high) that should be
    /// queried about the searched node.
    pub fn get_node(&self, target: &Address, nb_closest: usize) -> GetNodeResult {
        let closest_nodes = self.find_closest_nodes(target, nb_closest);
        match closest_nodes.clone().get(0) {
            // TODO: do not clone
            Some(&(ref closest_addr, ref closest_node)) => {
                if closest_addr == target {
                    GetNodeResult::FoundNode(closest_node)
                } else {
                    GetNodeResult::ClosestNodes(closest_nodes)
                }
            }
            None => GetNodeResult::Nothing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use node::Address;
    use node::Node;
    use operation::ForwardPath;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    #[test]
    #[cfg(not(feature = "sfcp"))]
    fn test_get_one_node() {
        let mut ns = NodeStore::new(Address::from(
            Ipv6Addr::from_str("fc8f:a188:1b5:4de9:b0cb:5729:23a1:60f9").unwrap(),
        ));
        let addr =
            Address::from(Ipv6Addr::from_str("fc7c:8316:ec7d:1308:d3c2:6db7:5ad9:6ebc").unwrap());
        let target =
            Address::from(Ipv6Addr::from_str("fcb9:326d:37d5:c57b:7ee5:28b5:7aa5:525").unwrap());
        let node = Node::new(
            [
                14, 212, 108, 34, 167, 28, 34, 202, 98, 134, 15, 159, 58, 151, 12, 228, 58, 163,
                181, 163, 40, 102, 66, 125, 212, 44, 203, 100, 174, 56, 120, 61,
            ],
            ForwardPath([0, 0, 0, 0, 0, 0, 0, 11]),
            17,
        );
        ns.update(addr.clone(), node.clone());
        let res = ns.get_node(&target, 42);
        assert_eq!(res, GetNodeResult::ClosestNodes(vec![(addr, &node)]));
    }
}

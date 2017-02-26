//! Contains the `RoutePacket` structure, which is used to represent
//! a packet exchanged by switches and routers to advertise routes.

use std::collections::HashMap;
use std::string::FromUtf8Error;
use std::hash::{Hash, Hasher};
use std::cmp::Ordering;

use simple_bencode;
use simple_bencode::Value as BValue;
use simple_bencode::decoding_helpers::HelperDecodeError;

use encoding_scheme::EncodingScheme;
use operation::Label;

const PUBLIC_KEY_LENGTH: usize = 32;
const PATH_LENGTH: usize = 8;

/// Represents a cjdns node, with its public key, path through the network,
/// and protocol version.
#[derive(Debug, Clone, Eq, PartialOrd)]
pub struct NodeData {
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
    pub path: Label,
    pub version: u64,
}

impl PartialEq for NodeData {
    fn eq(&self, other: &NodeData) -> bool {
        self.public_key == other.public_key
    }
}

impl Ord for NodeData {
    fn cmp(&self, other: &NodeData) -> Ordering {
        self.public_key.cmp(&other.public_key)
    }
}

impl Hash for NodeData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key.hash(state);
    }
}

/// A packet exchanged by switches and routers to advertise routes.
///
/// Described here: https://github.com/cjdelisle/cjdns/blob/cjdns-v18/doc/Whitepaper.md#the-router
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RoutePacket {
    /// The type of query. May be absent (a response), `fn` (find node),
    /// `gp` (get peers), `pn` (ping node), etc.
    pub query: Option<String>,
    /// The index Encoding Scheme Form in `encoding_scheme` used for
    /// sending this route packet.
    pub encoding_index: Option<i64>,
    /// The Encoding Scheme of the emitted. See
    /// https://github.com/cjdelisle/cjdns/blob/cjdns-v18/doc/Whitepaper.md#encoding-schemes
    pub encoding_scheme: Option<EncodingScheme>,
    /// Used for responding to `fn` and `gp` queries. Should be written
    /// and read using `RoutePacket::write_nodes` and `RoutePacket::read_nodes`
    pub nodes: Option<Vec<u8>>,
    /// Used for responding to `fn` and `gp` queries. Should be written
    /// and read using `RoutePacket::write_nodes` and `RoutePacket::read_nodes`
    pub node_protocol_versions: Option<Vec<u8>>,
    /// The address the emitted wants to reach. Used for `fn` and `gp` queries.
    pub target_address: Option<Vec<u8>>,
    /// An opaque identifier decided by query emitters to recognize the answer
    /// to their query.
    pub transaction_id: Vec<u8>,
    /// The protocol version of the emitter. Maps to the cjdns version.
    pub protocol_version: i64,
}

/// An error returned by `RoutePacket::decode`
pub enum DecodeError {
    BencodeDecodeError(simple_bencode::DecodeError),
    BadType(String),
    MissingKey(String),
    UnicodeDecodeError(FromUtf8Error),
}

impl RoutePacket {
    /// Deserialize a `RoutePacket` from its bencoded representation.
    pub fn decode(v: &[u8]) -> Result<RoutePacket, HelperDecodeError> {
        let bvalue = simple_bencode::decode(v);
        let mut map = match bvalue {
            Ok(BValue::Dictionary(map)) => map,
            Ok(v) => return Err(HelperDecodeError::BadType(format!("Expected dict at root, got: {:?}", v))),
            Err(e) => return Err(HelperDecodeError::BencodeDecodeError(e)),
        };
        //println!("{:?}", map);
        //println!("{:?}", map.keys().collect::<Vec<_>>().into_iter().map(|v| String::from_utf8(v.clone()).unwrap()).collect::<Vec<String>>()); // DEBUG: to show the keys in the messages
        let query = try!(simple_bencode::decoding_helpers::pop_value_utf8_string_option(&mut map, "q".to_owned()));
        let encoding_index = try!(simple_bencode::decoding_helpers::pop_value_integer_option(&mut map, "ei".to_owned()));
        let encoding_scheme = try!(simple_bencode::decoding_helpers::pop_value_bytestring_option(&mut map, "es".to_owned())).map(EncodingScheme::new);
        let nodes = try!(simple_bencode::decoding_helpers::pop_value_bytestring_option(&mut map, "n".to_owned()));
        let node_protocol_versions = try!(simple_bencode::decoding_helpers::pop_value_bytestring_option(&mut map, "np".to_owned()));
        let target_address = try!(simple_bencode::decoding_helpers::pop_value_bytestring_option(&mut map, "tar".to_owned()));
        let transaction_id = try!(simple_bencode::decoding_helpers::pop_value_bytestring(&mut map, "txid".to_owned()));
        let protocol_version = try!(simple_bencode::decoding_helpers::pop_value_integer(&mut map, "p".to_owned()));
        Ok(RoutePacket {
            query: query,
            encoding_index: encoding_index,
            encoding_scheme: encoding_scheme,
            nodes: nodes,
            node_protocol_versions: node_protocol_versions,
            target_address: target_address,
            transaction_id: transaction_id,
            protocol_version: protocol_version,
            })
    }

    /// Deserialize a `RoutePacket` to its bencode representation.
    pub fn encode(self) -> Vec<u8> {
        let mut map = HashMap::new();
        self.query.map(|q| map.insert(b"q".to_vec(), BValue::String(q.into_bytes().to_vec())));
        self.encoding_index.map(|ei| map.insert(b"ei".to_vec(), BValue::Integer(ei)));
        self.encoding_scheme.map(|es| map.insert(b"es".to_vec(), BValue::String(es.into_bytes())));
        self.nodes.map(|n| map.insert(b"n".to_vec(), BValue::String(n)));
        self.node_protocol_versions.map(|np| map.insert(b"np".to_vec(), BValue::String(np)));
        self.target_address.map(|tar| map.insert(b"tar".to_vec(), BValue::String(tar)));
        map.insert(b"txid".to_vec(), BValue::String(self.transaction_id));
        map.insert(b"p".to_vec(), BValue::Integer(self.protocol_version));
        simple_bencode::encode(&BValue::Dictionary(map))
    }

    /// Check `self.nodes` and `self.node_protocol_versions` are consistant,
    /// and return (nb, nodes, version_length, versions), which are
    /// useful for decoding.
    fn check_nodes(&self) -> Result<(usize, &Vec<u8>, usize, &Vec<u8>), String> {
        match (&self.nodes, &self.node_protocol_versions) { // the & are hacks to help the borrow checker by not moving the values in a tuple.
            (&Some(ref nodes), &Some(ref versions)) => {
                match versions.get(0) {
                    Some(&version_length) => {
                        let version_length = version_length as usize;
                        if nodes.len() % (PUBLIC_KEY_LENGTH+PATH_LENGTH) != 0 {
                            Err("Node list ('n') does not contain an integer number of items.".to_owned())
                        }
                        else if (versions.len()-1) % version_length != 0 {
                            Err("Node version list ('np') does not contain an integer number of items.".to_owned())
                        }
                        else if nodes.len() / (PUBLIC_KEY_LENGTH+PATH_LENGTH) != (versions.len()-1) / version_length {
                            Err("Length mismatch between node list ('n') and node version list ('np')".to_owned())
                        }
                        else {
                            let nb = (versions.len()-1) / version_length;
                            Ok((nb, nodes, version_length, versions))
                        }
                    },
                    None => Err("Version string ('np') empty.".to_owned()),
                }
            }
            _ => Err("Node list ('n') and/or node version list ('np') is not provided.".to_owned())
        }
    }

    /// Parses `self.nodes` and `self.node_protocol_versions` together.
    pub fn read_nodes(&self) -> Result<Vec<NodeData>, String> {
        let (nb, nodes, version_length, versions) = try!(self.check_nodes());

        let mut result = Vec::new();
        result.reserve(nb);
        for i in 0..nb {
            let node_start = i*(PUBLIC_KEY_LENGTH+PATH_LENGTH);

            let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
            public_key.copy_from_slice(&nodes[node_start..node_start+PUBLIC_KEY_LENGTH]);

            let mut path = [0u8; 8];
            path.copy_from_slice(&nodes[node_start+PUBLIC_KEY_LENGTH..node_start+PUBLIC_KEY_LENGTH+PATH_LENGTH]);

            let mut version = 0u64;
            for j in 1+i*version_length..1+(i+1)*version_length { // 1+ is the offset caused by the first byte being decoded as 'version_length'
                version = (version << 8) + (versions[j] as u64);
            }

            let node = NodeData {
                public_key: public_key,
                path: path,
                version: version,
            };
            result.push(node);
        }
        Ok(result)
    }

    /// Writes `self.nodes` and `self.node_protocol_versions` together.
    pub fn write_nodes(&mut self, nodes: Vec<NodeData>) {
        assert!(nodes.iter().all(|n| n.version < 256));
        let mut node_version_bytes = vec![1u8];
        node_version_bytes.extend(nodes.iter().map(|n| n.version as u8));

        let mut node_bytes = vec![0u8; nodes.len()*(PUBLIC_KEY_LENGTH+PATH_LENGTH)];
        for (i, node) in nodes.iter().enumerate() {
            let bytes_start = i*(PUBLIC_KEY_LENGTH+PATH_LENGTH);
            node_bytes[bytes_start..bytes_start+PUBLIC_KEY_LENGTH].copy_from_slice(&node.public_key);
            node_bytes[bytes_start+PUBLIC_KEY_LENGTH..bytes_start+PUBLIC_KEY_LENGTH+PATH_LENGTH].copy_from_slice(&node.path);
        }

        self.node_protocol_versions = Some(node_version_bytes);
        self.nodes = Some(node_bytes);
    }
}

/// Helper for constructing incrementally a `RoutePacket`.
///
/// Methods map to `RoutePacket`'s attributes.
pub struct RoutePacketBuilder {
    packet: RoutePacket,
}

impl RoutePacketBuilder {
    pub fn new(protocol_version: i64, transaction_id: Vec<u8>) -> RoutePacketBuilder {
        RoutePacketBuilder {
            packet: RoutePacket {
                query: None,
                encoding_index: None,
                encoding_scheme: None,
                nodes: None,
                node_protocol_versions: None,
                target_address: None,
                transaction_id: transaction_id,
                protocol_version: protocol_version,
            }
        }
    }

    pub fn query(mut self, query: String) -> RoutePacketBuilder {
        self.packet.query = Some(query);
        self
    }
    pub fn encoding_index(mut self, encoding_index: i64) -> RoutePacketBuilder {
        self.packet.encoding_index = Some(encoding_index);
        self
    }
    pub fn encoding_scheme(mut self, encoding_scheme: EncodingScheme) -> RoutePacketBuilder {
        self.packet.encoding_scheme = Some(encoding_scheme);
        self
    }
    pub fn nodes(mut self, nodes: Vec<u8>) -> RoutePacketBuilder {
        self.packet.nodes = Some(nodes);
        self
    }
    pub fn node_protocol_versions(mut self, node_protocol_versions: Vec<u8>) -> RoutePacketBuilder {
        self.packet.node_protocol_versions = Some(node_protocol_versions);
        self
    }
    /// Write `nodes` and `node_protocol_versions` in a single step,
    /// using `RoutePacket::write_nodes`.
    pub fn nodes_vec(mut self, nodes: Vec<NodeData>) -> RoutePacketBuilder {
        self.packet.write_nodes(nodes);
        self
    }
    pub fn target_address(mut self, target_address: Vec<u8>) -> RoutePacketBuilder {
        self.packet.target_address = Some(target_address);
        self
    }

    /// Finally produce the RoutePacket
    pub fn finalize(self) -> RoutePacket {
        self.packet
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fn() {
        let s = "d1:pi18e1:q2:fn3:tar16:abcdefghhijklmno4:txid5:12345e".as_bytes();
        let m = RoutePacketBuilder::new(18, b"12345".to_vec())
                .query("fn".to_owned())
                .target_address(b"abcdefghhijklmno".to_vec())
                .finalize();

        let s_decoded = RoutePacket::decode(s);
        let m_encoded = m.clone().encode();

        assert_eq!(s_decoded.unwrap(), m);
        assert_eq!(m_encoded, s);
    }

    #[test]
    fn test_n() {
        let s = "d1:n80:cdefghijklmnopqrstuvwxyzabcdefghi1234567qponmlkjihgzyxwvutsrstuvwxyzabcde23456781:pi18e4:txid5:12345e".as_bytes();
        let m = RoutePacketBuilder::new(18, b"12345".to_vec())
                .nodes(b"cdefghijklmnopqrstuvwxyzabcdefghi1234567qponmlkjihgzyxwvutsrstuvwxyzabcde2345678".to_vec())
                .finalize();

        let s_decoded = RoutePacket::decode(s);
        let m_encoded = m.clone().encode();

        assert_eq!(s_decoded.unwrap(), m);
        assert_eq!(m_encoded, s);
    }

    #[test]
    fn test_gp() {
        let s = b"d002:eii0e2:es5:a\x14E\x81\x001:pi17e1:q2:gp3:tar8:\x00\x00\x00\x00\x00\x00\x00\x004:txid12:\x0b\xf2\x17\xf4\x92\xa4\xc4d\xc6\x03[\xdde";

        RoutePacket::decode(s).unwrap();
    }

    #[test]
    fn test_read_write_nodes() {
        let mut packet = RoutePacket::decode(&vec![100,50,58,101,105,105,48,101,50,58,101,115,53,58,97,20,69,129,0,49,58,110,49,50,48,58,130,223,186,81,37,25,242,89,134,192,176,47,101,127,172,39,50,222,248,255,202,29,7,104,145,198,13,140,88,35,113,111,0,0,0,0,0,0,0,21,14,212,108,34,167,28,34,202,98,134,15,159,58,151,12,228,58,163,181,163,40,102,66,125,212,44,203,100,174,56,120,61,0,0,0,0,0,0,0,19,2,134,254,75,44,62,116,254,79,92,235,47,82,76,129,250,190,138,148,250,65,218,166,83,148,144,15,83,7,157,10,20,0,0,0,0,0,0,0,1,50,58,110,112,52,58,1,18,17,18,49,58,112,105,49,56,101,52,58,116,120,105,100,52,58,98,108,97,104,101]).unwrap();
        let nodes = packet.read_nodes().unwrap();
        let expected1 = NodeData {
                public_key: [130,223,186,81,37,25,242,89,134,192,176,47,101,127,172,39,50,222,248,255,202,29,7,104,145,198,13,140,88,35,113,111],
                path: [0, 0, 0, 0, 0, 0, 0, 0x15],
                version: 18,
            };
        let expected2 = NodeData {
                public_key: [14,212,108,34,167,28,34,202,98,134,15,159,58,151,12,228,58,163,181,163,40,102,66,125,212,44,203,100,174,56,120,61],
                path: [0, 0, 0, 0, 0, 0, 0, 0x13],
                version: 17,
            };
        let expected3 = NodeData {
                public_key: [2,134,254,75,44,62,116,254,79,92,235,47,82,76,129,250,190,138,148,250,65,218,166,83,148,144,15,83,7,157,10,20],
                path: [0, 0, 0, 0, 0, 0, 0, 0x01],
                version: 18,
            };
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0], expected1);
        assert_eq!(nodes[1], expected2);
        assert_eq!(nodes[2], expected3);

        packet.write_nodes(vec![]);
        assert_eq!(packet.read_nodes().unwrap(), vec![]);

        packet.write_nodes(vec![expected1.clone(), expected2.clone(), expected3.clone()]);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0], expected1);
        assert_eq!(nodes[1], expected2);
        assert_eq!(nodes[2], expected3);
    }
}

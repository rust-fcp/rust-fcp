use std::collections::HashMap;
use std::string::FromUtf8Error;

use simple_bencode;
use simple_bencode::Value as BValue;
use simple_bencode::decoding_helpers::HelperDecodeError;

use byteorder::BigEndian;
use byteorder::ByteOrder;

use encoding_scheme::EncodingScheme;

const PUBLIC_KEY_LENGTH: usize = 32;
const PATH_LENGTH: usize = 8;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Node {
    pub public_key: Vec<u8>,
    pub path: u64,
    pub version: u64,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RoutePacket {
    pub query: Option<String>,
    pub encoding_index: Option<i64>,
    pub encoding_scheme: Option<EncodingScheme>,
    pub nodes: Option<Vec<u8>>,
    pub node_protocol_versions: Option<Vec<u8>>,
    pub target_address: Option<Vec<u8>>,
    pub transaction_id: Vec<u8>,
    pub protocol_version: i64,
}

pub enum DecodeError {
    BencodeDecodeError(simple_bencode::DecodeError),
    BadType(String),
    MissingKey(String),
    UnicodeDecodeError(FromUtf8Error),
}

impl RoutePacket {
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

    /// Check self.nodes and self.node_protocol_versions are consistant,
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
    ///
    /// ```
    /// # use fcp_switching::route_packet::*;
    /// # let packet = RoutePacket::decode(&vec![100,50,58,101,105,105,48,101,50,58,101,115,53,58,97,20,69,129,0,49,58,110,49,50,48,58,130,223,186,81,37,25,242,89,134,192,176,47,101,127,172,39,50,222,248,255,202,29,7,104,145,198,13,140,88,35,113,111,0,0,0,0,0,0,0,21,14,212,108,34,167,28,34,202,98,134,15,159,58,151,12,228,58,163,181,163,40,102,66,125,212,44,203,100,174,56,120,61,0,0,0,0,0,0,0,19,2,134,254,75,44,62,116,254,79,92,235,47,82,76,129,250,190,138,148,250,65,218,166,83,148,144,15,83,7,157,10,20,0,0,0,0,0,0,0,1,50,58,110,112,52,58,1,18,17,18,49,58,112,105,49,56,101,52,58,116,120,105,100,52,58,98,108,97,104,101]).unwrap();
    /// // let packet = RoutePacket::decode(<< d2:eii0e2:es5:a\x14E\x81\x001:n120:\x82\xdf\xbaQ%\x19\xf2Y\x86\xc0\xb0/e\x7f\xac\'2\xde\xf8\xff\xca\x1d\x07h\x91\xc6\r\x8cX#qo\x00\x00\x00\x00\x00\x00\x00\x15\x0e\xd4l"\xa7\x1c"\xcab\x86\x0f\x9f:\x97\x0c\xe4:\xa3\xb5\xa3(fB}\xd4,\xcbd\xae8x=\x00\x00\x00\x00\x00\x00\x00\x13\x02\x86\xfeK,>t\xfeO\\\xeb/RL\x81\xfa\xbe\x8a\x94\xfaA\xda\xa6S\x94\x90\x0fS\x07\x9d\n\x14\x00\x00\x00\x00\x00\x00\x00\x012:np4:\x01\x12\x11\x121:pi18e4:txid4:blahe >>)
    /// let nodes = packet.read_nodes().unwrap();
    /// let expected1 = Node {
    ///         public_key: vec![130,223,186,81,37,25,242,89,134,192,176,47,101,127,172,39,50,222,248,255,202,29,7,104,145,198,13,140,88,35,113,111],
    ///         path: 0x15,
    ///         version: 18,
    ///     };
    /// let expected2 = Node {
    ///         public_key: vec![14,212,108,34,167,28,34,202,98,134,15,159,58,151,12,228,58,163,181,163,40,102,66,125,212,44,203,100,174,56,120,61],
    ///         path: 0x13,
    ///         version: 17,
    ///     };
    /// let expected3 = Node {
    ///         public_key: vec![2,134,254,75,44,62,116,254,79,92,235,47,82,76,129,250,190,138,148,250,65,218,166,83,148,144,15,83,7,157,10,20],
    ///         path: 0x01,
    ///         version: 18,
    ///     };
    /// assert_eq!(nodes.len(), 3);
    /// assert_eq!(nodes[0], expected1);
    /// assert_eq!(nodes[1], expected2);
    /// assert_eq!(nodes[2], expected3);
    /// ```
    pub fn read_nodes(&self) -> Result<Vec<Node>, String> {
        let (nb, nodes, version_length, versions) = try!(self.check_nodes());

        let mut result = Vec::new();
        result.reserve(nb);
        for i in 0..nb {
            let node_start = i*(PUBLIC_KEY_LENGTH+PATH_LENGTH);

            let public_key = nodes[node_start..node_start+PUBLIC_KEY_LENGTH].to_vec();

            let path = BigEndian::read_u64(&nodes[node_start+PUBLIC_KEY_LENGTH..node_start+PUBLIC_KEY_LENGTH+PATH_LENGTH]);

            let mut version = 0u64;
            for j in 1+i*version_length..1+(i+1)*version_length { // 1+ is the offset caused by the first byte being decoded as 'version_length'
                version = (version << 8) + (versions[j] as u64);
            }

            let node = Node {
                public_key: public_key,
                path: path,
                version: version,
            };
            result.push(node);
        }
        Ok(result)
    }
}

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
    pub fn target_address(mut self, target_address: Vec<u8>) -> RoutePacketBuilder {
        self.packet.target_address = Some(target_address);
        self
    }

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
}

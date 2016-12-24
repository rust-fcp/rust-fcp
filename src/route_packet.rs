use std::collections::HashMap;
use std::string::FromUtf8Error;

use simple_bencode;
use simple_bencode::Value as BValue;
use simple_bencode::decoding_helpers::HelperDecodeError;

#[derive(Debug)]
#[derive(Eq)]
#[derive(PartialEq)]
#[derive(Clone)]
pub enum RoutePacket {
    GetPeers { encoding_scheme: Option<Vec<u8>>, encoding_index: i64, transaction_id: Vec<u8>, version: i64 },
    SendPeers { encoding_scheme: Option<Vec<u8>>, encoding_index: i64, transaction_id: Vec<u8>, version: i64 },
    FindNode { target_address: String, transaction_id: Vec<u8> },
    Nodes { nodes: String, transaction_id: Vec<u8> },
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
        println!("{:?}", map.keys().collect::<Vec<_>>().into_iter().map(|v| String::from_utf8(v.clone()).unwrap()).collect::<Vec<String>>()); // DEBUG: to show the keys in the messages
        let transaction_id = try!(simple_bencode::decoding_helpers::pop_value_bytestring(&mut map, "txid".to_owned()));
        match simple_bencode::decoding_helpers::pop_value_utf8_string(&mut map, "q".to_owned()) {
            Err(HelperDecodeError::MissingKey(_)) => { // Answer to a query
                let nodes = simple_bencode::decoding_helpers::pop_value_utf8_string(&mut map, "n".to_owned());
                let encoding_index = simple_bencode::decoding_helpers::pop_value_integer(&mut map, "ei".to_owned());
                match (nodes, encoding_index) {
                    (Ok(nodes), Err(HelperDecodeError::MissingKey(_))) =>
                        Ok(RoutePacket::Nodes { nodes: nodes, transaction_id: transaction_id }),
                    (Err(HelperDecodeError::MissingKey(_)), Ok(encoding_index)) => {
                        let version = try!(simple_bencode::decoding_helpers::pop_value_integer(&mut map, "p".to_owned()));
                        let encoding_scheme = match simple_bencode::decoding_helpers::pop_value_bytestring(&mut map, "es".to_owned()) {
                            Ok(s) => Some(s),
                            Err(HelperDecodeError::MissingKey(_)) => None,
                            Err(e) => return Err(e),
                        };
                        Ok(RoutePacket::SendPeers { encoding_index: encoding_index, encoding_scheme: encoding_scheme, transaction_id: transaction_id, version: version })
                    },
                    (Ok(_), Ok(_)) => panic!("Received both 'n' and 'ei' keys in a route package."),
                    (_, _) => panic!("Received neither 'q', 'n', or 'ei' key in a route packet."),
                }
            },
            Err(e) => Err(e),
            Ok(query_type) => {
                match query_type.as_ref() {
                    "gp" => {
                        let version = try!(simple_bencode::decoding_helpers::pop_value_integer(&mut map, "p".to_owned()));
                        let encoding_index = try!(simple_bencode::decoding_helpers::pop_value_integer(&mut map, "ei".to_owned()));
                        let encoding_scheme = match simple_bencode::decoding_helpers::pop_value_bytestring(&mut map, "es".to_owned()) {
                            Ok(s) => Some(s),
                            Err(HelperDecodeError::MissingKey(_)) => None,
                            Err(e) => return Err(e),
                        };
                        Ok(RoutePacket::GetPeers { encoding_index: encoding_index, encoding_scheme: encoding_scheme, transaction_id: transaction_id, version: version })
                    },
                    "fn" => {
                        let target_address = try!(simple_bencode::decoding_helpers::pop_value_utf8_string(&mut map, "tar".to_owned()));
                        Ok(RoutePacket::FindNode { target_address: target_address, transaction_id: transaction_id })
                    }
                    _ => Err(HelperDecodeError::BadType(format!("Unknown value for 'q' field: '{}'.", query_type))),
                }
            },
        }
    }

    pub fn encode(self) -> Vec<u8> {
        let mut map = HashMap::new();
        match self {
            RoutePacket::Nodes { nodes, transaction_id } => {
                map.insert(b"n".to_vec(), BValue::String(nodes.into_bytes()));
                map.insert(b"txid".to_vec(), BValue::String(transaction_id));
            },
            RoutePacket::GetPeers { encoding_index, encoding_scheme, transaction_id, version } => {
                map.insert(b"ei".to_vec(), BValue::Integer(encoding_index));
                match encoding_scheme {
                    Some(encoding_scheme) => {
                        map.insert(b"es".to_vec(), BValue::String(encoding_scheme));
                    },
                    None => ()
                }
                map.insert(b"q".to_vec(), BValue::String(b"gp".to_vec()));
                map.insert(b"p".to_vec(), BValue::Integer(version));
                map.insert(b"txid".to_vec(), BValue::String(transaction_id));
            },
            RoutePacket::SendPeers { encoding_index, encoding_scheme, transaction_id, version } => {
                map.insert(b"ei".to_vec(), BValue::Integer(encoding_index));
                match encoding_scheme {
                    Some(encoding_scheme) => {
                        map.insert(b"es".to_vec(), BValue::String(encoding_scheme));
                    },
                    None => ()
                }
                map.insert(b"p".to_vec(), BValue::Integer(version));
                map.insert(b"txid".to_vec(), BValue::String(transaction_id));
            },
            RoutePacket::FindNode { target_address, transaction_id } => {
                map.insert(b"q".to_vec(), BValue::String(b"fn".to_vec()));
                map.insert(b"tar".to_vec(), BValue::String(target_address.into_bytes()));
                map.insert(b"txid".to_vec(), BValue::String(transaction_id));
            }
        }
        simple_bencode::encode(&BValue::Dictionary(map))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fn() {
        let s = "d1:q2:fn3:tar16:abcdefghhijklmno4:txid5:12345e".as_bytes();
        let m = RoutePacket::FindNode {
            target_address: "abcdefghhijklmno".to_owned(),
            transaction_id: b"12345".to_vec()
        };

        let s_decoded = RoutePacket::decode(s);
        let m_encoded = m.clone().encode();

        assert_eq!(s_decoded.unwrap(), m);
        assert_eq!(m_encoded, s);
    }

    #[test]
    fn test_n() {
        let s = "d1:n80:cdefghijklmnopqrstuvwxyzabcdefghi1234567qponmlkjihgzyxwvutsrstuvwxyzabcde23456784:txid5:12345e".as_bytes();
        let m = RoutePacket::Nodes {
            nodes: "cdefghijklmnopqrstuvwxyzabcdefghi1234567qponmlkjihgzyxwvutsrstuvwxyzabcde2345678".to_owned(),
            transaction_id: b"12345".to_vec()
        };

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

use std::collections::HashMap;
use std::string::FromUtf8Error;

use simple_bencode;
use simple_bencode::Value as BValue;
use simple_bencode::decoding_helpers::HelperDecodeError;

#[derive(Debug)]
#[derive(Eq)]
#[derive(PartialEq)]
#[derive(Clone)]
pub struct RoutePacket {
    pub query: Option<String>,
    pub encoding_index: Option<i64>,
    pub encoding_scheme: Option<Vec<u8>>,
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
        let encoding_scheme = try!(simple_bencode::decoding_helpers::pop_value_bytestring_option(&mut map, "es".to_owned()));
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
        self.encoding_scheme.map(|es| map.insert(b"es".to_vec(), BValue::String(es)));
        self.nodes.map(|n| map.insert(b"n".to_vec(), BValue::String(n)));
        self.node_protocol_versions.map(|np| map.insert(b"np".to_vec(), BValue::String(np)));
        self.target_address.map(|tar| map.insert(b"tar".to_vec(), BValue::String(tar)));
        map.insert(b"txid".to_vec(), BValue::String(self.transaction_id));
        map.insert(b"p".to_vec(), BValue::Integer(self.protocol_version));
        simple_bencode::encode(&BValue::Dictionary(map))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fn() {
        let s = "d1:pi18e1:q2:fn3:tar16:abcdefghhijklmno4:txid5:12345e".as_bytes();
        let m = RoutePacket {
            query: Some("fn".to_owned()),
            encoding_index: None,
            encoding_scheme: None,
            nodes: None,
            node_protocol_versions: None,
            target_address: Some(b"abcdefghhijklmno".to_vec()),
            transaction_id: b"12345".to_vec(),
            protocol_version: 18,
        };

        let s_decoded = RoutePacket::decode(s);
        let m_encoded = m.clone().encode();

        assert_eq!(s_decoded.unwrap(), m);
        assert_eq!(m_encoded, s);
    }

    #[test]
    fn test_n() {
        let s = "d1:n80:cdefghijklmnopqrstuvwxyzabcdefghi1234567qponmlkjihgzyxwvutsrstuvwxyzabcde23456781:pi18e4:txid5:12345e".as_bytes();
        let m = RoutePacket {
            query: None,
            encoding_index: None,
            encoding_scheme: None,
            nodes: Some(b"cdefghijklmnopqrstuvwxyzabcdefghi1234567qponmlkjihgzyxwvutsrstuvwxyzabcde2345678".to_vec()),
            node_protocol_versions: None,
            target_address: None,
            transaction_id: b"12345".to_vec(),
            protocol_version: 18,
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

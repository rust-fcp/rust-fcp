use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use bencode;

#[derive(Debug)]
#[derive(Eq)]
#[derive(PartialEq)]
pub enum RoutePacket {
    FindNode { target_address: String, transaction_id: String },
    Nodes { nodes: String, transaction_id: String },
}

impl RoutePacket {
    pub fn new_from_slice(v: &[u8]) -> Result<RoutePacket, <bencode::Decoder as Decoder>::Error> {
        let mut bencode = bencode::from_buffer(v).unwrap();
        let mut decoder = bencode::Decoder::new(&mut bencode);
        RoutePacket::decode(&mut decoder)
    }
}

impl Decodable for RoutePacket {
    fn decode<D: Decoder>(d: &mut D) -> Result<RoutePacket, D::Error> {
        d.read_struct("RoutePacket", 3, |d| {
            let query_res = d.read_struct_field("q", 0, D::read_str);
            match query_res {
                Ok(query) => {
                    match query.as_ref() {
                        "fn" => {
                            let target_address = try!(d.read_struct_field("tar", 0, D::read_str));
                            let transaction_id = try!(d.read_struct_field("txid", 1, D::read_str));
                            Ok(RoutePacket::FindNode { target_address: target_address, transaction_id: transaction_id })
                        },
                        _ => Err(d.error(&format!("Unknown query type: {}", query))),
                    }
                },
                Err(_) => { // 'q' is not given (or not readable, TODO: fix this)
                    let nodes = try!(d.read_struct_field("n", 0, D::read_str));
                    let transaction_id = try!(d.read_struct_field("txid", 1, D::read_str));
                    Ok(RoutePacket::Nodes { nodes: nodes, transaction_id: transaction_id })
                },
            }
        })
    }
}

impl Encodable for RoutePacket {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("RoutePacket", 3, |s| {
            match *self {
                RoutePacket::FindNode { ref target_address, ref transaction_id } => {
                    try!(s.emit_struct_field("q", 0, |s| {
                        s.emit_str("fn")
                    }));
                    try!(s.emit_struct_field("tar", 1, |s| {
                        s.emit_str(target_address)
                    }));
                    try!(s.emit_struct_field("txid", 2, |s| {
                        s.emit_str(transaction_id)
                    }));
                    Ok(())
                },
                RoutePacket::Nodes { ref nodes, ref transaction_id } => {
                    try!(s.emit_struct_field("n", 0, |s| {
                        s.emit_str(nodes)
                    }));
                    try!(s.emit_struct_field("txid", 1, |s| {
                        s.emit_str(transaction_id)
                    }));
                    Ok(())
                },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use bencode;
    use super::*;
    use rustc_serialize::Decodable;

    #[test]
    fn test_fn() {
        let s = "d1:q2:fn3:tar16:abcdefghhijklmno4:txid5:12345e".as_bytes();
        let m = RoutePacket::FindNode {
            target_address: "abcdefghhijklmno".to_owned(),
            transaction_id: "12345".to_owned()
        };

        let mut bencode = bencode::from_buffer(s).unwrap();
        let mut decoder = bencode::Decoder::new(&mut bencode);
        let s_decoded = RoutePacket::decode(&mut decoder);

        let m_encoded = bencode::encode(&m);

        assert_eq!(s_decoded, Ok(m));
        assert_eq!(m_encoded.unwrap(), s);
    }

    #[test]
    fn test_n() {
        let s = "d1:n80:cdefghijklmnopqrstuvwxyzabcdefghi1234567qponmlkjihgzyxwvutsrstuvwxyzabcde23456784:txid5:12345e".as_bytes();
        let m = RoutePacket::Nodes {
            nodes: "cdefghijklmnopqrstuvwxyzabcdefghi1234567qponmlkjihgzyxwvutsrstuvwxyzabcde2345678".to_owned(),
            transaction_id: "12345".to_owned()
        };

        let mut bencode = bencode::from_buffer(s).unwrap();
        let mut decoder = bencode::Decoder::new(&mut bencode);
        let s_decoded = RoutePacket::decode(&mut decoder);

        let m_encoded = bencode::encode(&m);

        assert_eq!(s_decoded, Ok(m));
        assert_eq!(m_encoded.unwrap(), s);
    }

    #[test]
    fn test_gp() {
        let s = b"d002:eii0e2:es5:a\x14E\x81\x001:pi17e1:q2:gp3:tar8:\x00\x00\x00\x00\x00\x00\x00\x004:txid12:\x0b\xf2\x17\xf4\x92\xa4\xc4d\xc6\x03[\xdde";

        let mut bencode = bencode::from_buffer(s).unwrap();
        let mut decoder = bencode::Decoder::new(&mut bencode);
        RoutePacket::decode(&mut decoder).unwrap();
    }
}

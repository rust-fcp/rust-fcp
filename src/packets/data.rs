/// https://github.com/cjdelisle/cjdns/blob/cjdns-v18/wire/DataHeader.h
use std::fmt;

use byteorder::BigEndian;
use byteorder::ByteOrder;

use packets::route::RoutePacket;

pub const DATAPACKET_VERSION: u8 = 1;

/// https://github.com/cjdelisle/cjdns/blob/cjdns-v20/wire/ContentType.h#L18
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// ContentType <= 255: it's mapped on IPv6's Next Header field. See
    /// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    Ip6Content(u8, Vec<u8>),
    /// aka CJDHT packet, ContentType 256
    RoutePacket(RoutePacket),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    raw: Vec<u8>,
}

impl DataPacket {
    pub fn new_from_raw(raw: Vec<u8>) -> Option<DataPacket> {
        if raw.len() >= 4 {
            Some(DataPacket { raw })
        } else {
            None
        }
    }
    pub fn new(version: u8, payload: &Payload) -> DataPacket {
        assert!(version <= 0b1111);
        let mut raw = vec![version << 4, 0, 0, 0];
        match *payload {
            Payload::Ip6Content(next_header, ref content) => {
                BigEndian::write_u16(&mut raw[2..4], next_header as u16);
                raw.extend(content) // TODO: do not copy
            }
            Payload::RoutePacket(ref route_packet) => {
                BigEndian::write_u16(&mut raw[2..4], 256);
                let encoded_route_packet = route_packet.clone().encode(); // TODO: do not copy
                raw.extend(encoded_route_packet) // TODO: do not copy
            }
        }
        DataPacket { raw: raw }
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn version(&self) -> u8 {
        self.raw[0] >> 4
    }

    pub fn unused1(&self) -> u8 {
        self.raw[0] & 0b00011111
    }

    pub fn unused2(&self) -> u8 {
        self.raw[1]
    }

    pub fn content_type(&self) -> u16 {
        BigEndian::read_u16(&self.raw[2..4])
    }

    pub fn payload(&self) -> Result<Payload, String> {
        let content_type = self.content_type();
        match content_type {
            0..=255 => Ok(Payload::Ip6Content(
                content_type as u8,
                self.raw[4..].to_vec(),
            )),
            256 => {
                match RoutePacket::decode(&self.raw[4..]) {
                    Ok(packet) => Ok(Payload::RoutePacket(packet)),
                    Err(e) => Err(format!("Could not decode route packet: {:?}", e)), // TODO: proper error handling
                }
            }
            _ => panic!(format!(
                "Unknown Data Packet Content-Type: {}",
                content_type
            )),
        }
    }
}

impl fmt::Display for DataPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DataPacket(version={}, payload={:?})",
            self.version(),
            self.clone().payload()
        )
    }
}

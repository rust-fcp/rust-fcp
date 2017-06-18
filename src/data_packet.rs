/// https://github.com/cjdelisle/cjdns/blob/cjdns-v18/wire/DataHeader.h

use std::fmt;

use byteorder::BigEndian;
use byteorder::ByteOrder;

use route_packet;

#[derive(Debug, Clone)]
pub enum Payload {
    RoutePacket(route_packet::RoutePacket),
}

#[derive(Debug, Clone)]
pub struct DataPacket {
    pub raw: Vec<u8>,
}

impl DataPacket {
    pub fn new(version: u8, payload: &Payload) -> DataPacket {
        assert!(version <= 0b1111);
        let mut raw = vec![version << 4, 0, 0, 0];
        match *payload {
            Payload::RoutePacket(ref route_packet) => {
                BigEndian::write_u16(&mut raw[2..4], 256);
                let encoded_route_packet = route_packet.clone().encode(); // TODO: do not copy
                raw.extend(encoded_route_packet) // TODO: do not copy
            }
        }
        DataPacket { raw: raw }
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
            256 => {
                match route_packet::RoutePacket::decode(&self.raw[4..]) {
                    Ok(packet) => Ok(Payload::RoutePacket(packet)),
                    Err(e) => Err(format!("Could not decode route packet: {:?}", e)), // TODO: proper error handling
                }
            },
            _ => panic!(format!("Unknown Data Packet Content-Type: {}", content_type)),
        }
    }
}

impl fmt::Display for DataPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DataPacket(version={}, payload={:?})", self.version(), self.clone().payload())
    }
}

/// https://github.com/cjdelisle/cjdns/blob/cjdns-v18/wire/DataHeader.h

use byteorder::BigEndian;
use byteorder::ByteOrder;

use route_packet;

pub enum Payload {
    RoutePacket(route_packet::RoutePacket),
}

#[derive(Debug)]
pub struct DataPacket {
    pub raw: Vec<u8>,
}

impl DataPacket {
    pub fn version(&self) -> u8 {
        self.raw[0] >> 3
    }

    pub fn unused1(&self) -> u8 {
        self.raw[0] & 0b00011111
    }

    pub fn unused2(&self) -> u8 {
        self.raw[1]
    }

    pub fn content_type(&self) -> u16 {
        BigEndian::read_u16(&self.raw[2..3])
    }

    pub fn payload(self) -> Result<Payload, ()> {
        let content_type = self.content_type();
        match content_type {
            256 => {
                match route_packet::RoutePacket::new_from_slice(&self.raw[4..]) {
                    Ok(packet) => Ok(Payload::RoutePacket(packet)),
                    Err(_) => Err(()), // TODO: proper error handling
                }
            },
            _ => unimplemented!()
        }
    }
}

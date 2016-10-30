//! Contains the `SwitchHeader` structure, storing the packet header
//! used by the Switch, as defined by
//! https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#in-memory-representation

use byteorder::BigEndian;
use byteorder::ByteOrder;

use operation::{switch, reverse_label, Director, RoutingDecision, Label};
use control::ControlPacket;

#[derive(Debug)]
pub enum PacketType {
    Opaque,
    SwitchControlMessage,
}

#[derive(Debug)]
pub enum Payload {
    CryptoAuthHandshake(Vec<u8>),
    Control(ControlPacket),
    Other(u32, Vec<u8>), // First argument is the session handle
}



#[derive(Debug)]
pub struct SwitchPacket {
    pub raw: Vec<u8>,
}

impl SwitchPacket {
    pub fn new(route_label: &[u8; 8], type_: &PacketType, payload: Payload) -> SwitchPacket {
        let mut raw = vec![0u8; 12];
        raw[0..8].copy_from_slice(route_label);
        raw[8] = match *type_ {
            PacketType::Opaque => 0u8,
            PacketType::SwitchControlMessage => 1u8,
        };
        match payload {
            Payload::CryptoAuthHandshake(mut msg) => {
                let session_state = BigEndian::read_u32(&msg[0..4]);
                assert!(session_state < 4);
                assert!(session_state != 0xffffffff);
                raw.append(&mut msg);
            },
            Payload::Control(mut msg) => {
                raw.append(&mut vec![0xff, 0xff, 0xff, 0xff]);
                raw.append(&mut msg.encode());
            },
            Payload::Other(session_handle, mut msg) => {
                assert!(session_handle >= 4);
                assert!(session_handle != 0xffffffff);
                let mut raw_handle = vec![0u8; 4];
                BigEndian::write_u32(&mut raw_handle, session_handle);
                raw.append(&mut raw_handle);
                raw.append(&mut msg);
            },
        }
        SwitchPacket { raw: raw }
    }

    /// Returns the type of the packet. Errors with the type number if
    /// the type number is unknown.
    pub fn packet_type(&self) -> Result<PacketType, u8> {
        match self.raw[8] {
            0u8 => Ok(PacketType::Opaque),
            1u8 => Ok(PacketType::SwitchControlMessage),
            n => Err(n),
        }
    }

    /// Returns the address label of the packet.
    pub fn label(&self) -> Label {
        let mut label = [0u8; 8];
        label.copy_from_slice(&self.raw[0..8]);
        label
    }

    pub fn derivation(&self) -> [u8; 2] {
        let mut d = [0u8; 2];
        d.copy_from_slice(&self.raw[8..10]);
        d
    }

    pub fn additional(&self) -> [u8; 2] {
        let mut a = [0u8; 2];
        a.copy_from_slice(&self.raw[10..12]);
        a
    }

    /// Returns a reference to the content of the packet.
    pub fn payload(&self) -> Option<Payload> {
        match BigEndian::read_u32(&self.raw[12..16]) {
            0 | 1 | 2 | 3 => Some(Payload::CryptoAuthHandshake(self.raw[12..].to_vec())),
            0xffffffff => ControlPacket::decode(&self.raw[16..].to_vec()).map(Payload::Control),
            handle => Some(Payload::Other(handle, self.raw[16..].to_vec())),
        }
    }

    pub fn switch(&mut self, director_length: u8, reversed_origin_iface: &Director) -> RoutingDecision {
        let (new_label, decision) = switch(&self.label(), director_length, reversed_origin_iface);
        self.raw[0..8].copy_from_slice(&new_label);
        decision
    }

    pub fn reverse_label(&mut self) {
        // TODO: do this in-place/no-copy.
        let mut label = [0u8; 8];
        reverse_label(&mut label);
        self.raw[0..8].copy_from_slice(&label);
    }

}

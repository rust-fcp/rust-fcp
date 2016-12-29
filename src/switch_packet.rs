//! Contains the `SwitchHeader` structure, storing the packet header
//! used by the Switch, as defined by
//! https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#in-memory-representation

use byteorder::BigEndian;
use byteorder::ByteOrder;

use operation::{switch, reverse_label, Director, RoutingDecision, Label};
use control::ControlPacket;

#[derive(Debug)]
pub enum Payload {
    Control(ControlPacket),
    CryptoAuthHandshake(Vec<u8>),
    CryptoAuthData(u32, Vec<u8>), // First argument is the session handle
}



#[derive(Debug)]
pub struct SwitchPacket {
    pub raw: Vec<u8>,
}

impl SwitchPacket {
    pub fn new(route_label: &[u8; 8], payload: Payload) -> SwitchPacket {
        let mut raw = vec![0u8; 12];
        raw[0..8].copy_from_slice(route_label);
        match payload {
            Payload::Control(msg) => {
                raw.append(&mut vec![0xff, 0xff, 0xff, 0xff]);
                raw.append(&mut msg.encode());
            },
            Payload::CryptoAuthHandshake(mut msg) => {
                let session_state = BigEndian::read_u32(&msg[0..4]);
                assert!(session_state < 4);
                assert!(session_state != 0xffffffff);
                raw.append(&mut msg);
            },
            Payload::CryptoAuthData(session_handle, mut msg) => {
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

    /// Returns a new packet, constructed as a reply of a received one.
    pub fn new_reply(received: &SwitchPacket, payload: Payload) -> SwitchPacket {
        let mut response_label = received.label();
        reverse_label(&mut response_label);
        SwitchPacket::new(&response_label, payload)
    }

    /// Returns the address label of the packet.
    pub fn label(&self) -> Label {
        let mut label = [0u8; 8];
        label.copy_from_slice(&self.raw[0..8]);
        label
    }

    pub fn congest(&self) -> u8 {
        self.raw[8] >> 1
    }

    pub fn suppress_errors(&self) -> bool {
        self.raw[8] & 0b00000001 == 1
    }

    pub fn version(&self) -> u8 {
        self.raw[9] >> 6
    }

    pub fn label_shift(&self) -> u8 {
        self.raw[9] & 0b00111111
    }

    pub fn penalty(&self) -> [u8; 2] {
        let mut a = [0u8; 2];
        a.copy_from_slice(&self.raw[10..12]);
        a
    }

    /// Returns a reference to the content of the packet.
    pub fn payload(&self) -> Option<Payload> {
        match BigEndian::read_u32(&self.raw[12..16]) {
            0xffffffff => ControlPacket::decode(&self.raw[16..].to_vec()).map(Payload::Control),
            0 | 1 | 2 | 3 => Some(Payload::CryptoAuthHandshake(self.raw[12..].to_vec())),
            handle => Some(Payload::CryptoAuthData(handle, self.raw[16..].to_vec())),
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

#[cfg(test)]
mod test {
    use hex::FromHex;
    use super::*;
    use super::super::operation::RoutingDecision;
    use super::super::control::ControlPacket;

    #[test]
    fn switch_and_reply() {
        let mut received = SwitchPacket { raw: Vec::from_hex("800000000000000100440000ffffffff9986000309f9110200000011467c6febbde26264a38cd12e").unwrap() };
        let decision = received.switch(4, &0b1100);
        let opaque_data = match decision {
            RoutingDecision::SelfInterface(_) => {
                match received.payload() {
                    Some(Payload::Control(ControlPacket::Ping { opaque_data, .. })) => {
                        opaque_data
                    },
                    _ => panic!("parsed as non-Ping."),
                }
            }
            _ => panic!("routed to non-self interface."),
        };
        let control_response = ControlPacket::Pong { version: 17, opaque_data: opaque_data };
        let mut response = SwitchPacket::new_reply(&received, Payload::Control(control_response));
        let decision = response.switch(4, &0b1000);
        assert_eq!(decision, RoutingDecision::Forward(0b0011));
        assert_eq!(response.raw, Vec::from_hex("800000000000000100000000ffffffff33b000049d74e35b00000011467c6febbde26264a38cd12e").unwrap());
    }
}

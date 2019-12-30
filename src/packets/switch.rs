//! Contains the `SwitchPacket` structure, storing the packet header
//! used by the Switch, as defined by
//! https://github.com/cjdelisle/cjdns/blob/cjdns-v18/doc/Whitepaper.md#in-memory-representation

use std::fmt;

use byteorder::BigEndian;
use byteorder::ByteOrder;
use hex::ToHex;

use fcp_cryptoauth::handshake_packet::HandshakePacket;

use operation::{
    reverse_label, switch, BackwardPath, Director, ForwardPath, Label, RoutingDecision,
    LABEL_LENGTH,
};
use packets::control::ControlPacket;
use session_manager::SessionHandle;

pub enum Payload {
    Control(ControlPacket),
    CryptoAuthHello(Vec<u8>),
    CryptoAuthKey(Vec<u8>),
    CryptoAuthData(SessionHandle, Vec<u8>),
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Payload::Control(packet) => f
                .write_str("Payload::Control(")
                .and_then(|_| packet.fmt(f))
                .and_then(|_| f.write_str(")")),
            Payload::CryptoAuthHello(raw) => {
                let packet = HandshakePacket { raw: raw.to_vec() };
                f.write_str("Payload::CryptoAuthHello(")
                    .and_then(|_| packet.fmt(f))
                    .and_then(|_| f.write_str(")"))
            }
            Payload::CryptoAuthKey(raw) => {
                let packet = HandshakePacket { raw: raw.to_vec() };
                f.write_str("Payload::CryptoAuthHello(")
                    .and_then(|_| packet.fmt(f))
                    .and_then(|_| f.write_str(")"))
            }
            Payload::CryptoAuthData(handle, raw) => {
                write!(f, "Payload::CryptoAuthData({:?}, {:?})", handle, raw)
            }
        }
    }
}

pub struct SwitchPacket {
    pub raw: Vec<u8>,
}

impl SwitchPacket {
    /// Returns a new packet, constructed from its route and its payload.
    #[cfg(not(feature = "sfcp"))]
    pub fn new(path: ForwardPath, payload: Payload) -> SwitchPacket {
        let mut raw = vec![0u8; 12];
        raw[0..8].copy_from_slice(&Label::from(path));
        match payload {
            Payload::Control(msg) => {
                raw.append(&mut vec![0xff, 0xff, 0xff, 0xff]);
                raw.append(&mut msg.encode());
            }
            Payload::CryptoAuthHello(mut msg) | Payload::CryptoAuthKey(mut msg) => {
                let session_state = BigEndian::read_u32(&msg[0..4]);
                assert!(session_state < 4);
                assert!(session_state != 0xffffffff);
                raw.append(&mut msg);
            }
            Payload::CryptoAuthData(session_handle, mut msg) => {
                assert!(session_handle.0 >= 4);
                assert!(session_handle.0 != 0xffffffff);
                let mut raw_handle = vec![0u8; 4];
                BigEndian::write_u32(&mut raw_handle, session_handle.0);
                raw.append(&mut raw_handle);
                raw.append(&mut msg);
            }
        }
        SwitchPacket { raw: raw }
    }

    /// Returns a new packet, constructed from its route and its payload.
    #[cfg(feature = "sfcp")]
    pub fn new(path: ForwardPath, payload: Payload) -> SwitchPacket {
        let mut raw = vec![0u8; 20];
        raw[0..16].copy_from_slice(&Label::from(path));
        match payload {
            Payload::Control(msg) => {
                raw.append(&mut vec![0xff, 0xff, 0xff, 0xff]);
                raw.append(&mut msg.encode());
            }
            Payload::CryptoAuthHello(mut msg) | Payload::CryptoAuthKey(mut msg) => {
                let session_state = BigEndian::read_u32(&msg[0..4]);
                assert!(session_state < 4);
                assert!(session_state != 0xffffffff);
                raw.append(&mut msg);
            }
            Payload::CryptoAuthData(session_handle, mut msg) => {
                assert!(session_handle.0 >= 4);
                assert!(session_handle.0 != 0xffffffff);
                let mut raw_handle = vec![0u8; 4];
                BigEndian::write_u32(&mut raw_handle, session_handle.0);
                raw.append(&mut raw_handle);
                raw.append(&mut msg);
            }
        }
        SwitchPacket { raw: raw }
    }

    /// Returns a new packet, constructed as a reply of a received one.
    pub fn new_reply(received: &SwitchPacket, payload: Payload) -> SwitchPacket {
        let path = BackwardPath::from(received.label()).reverse();
        SwitchPacket::new(path, payload)
    }

    /// Returns the address label of the packet.
    pub fn label(&self) -> Label {
        let mut label = [0u8; LABEL_LENGTH];
        label.copy_from_slice(&self.raw[0..LABEL_LENGTH]);
        label
    }

    #[cfg(not(feature = "sfcp"))]
    pub fn congest(&self) -> u8 {
        self.raw[8] >> 1
    }

    #[cfg(not(feature = "sfcp"))]
    pub fn suppress_errors(&self) -> bool {
        self.raw[8] & 0b00000001 == 1
    }

    #[cfg(feature = "sfcp")]
    pub fn suppress_errors(&self) -> bool {
        self.raw[17] & 0b10000000 != 0
    }

    #[cfg(not(feature = "sfcp"))]
    pub fn version(&self) -> u8 {
        self.raw[9] >> 6
    }

    #[cfg(not(feature = "sfcp"))]
    pub fn label_shift(&self) -> u8 {
        self.raw[9] & 0b00111111
    }

    #[cfg(feature = "sfcp")]
    pub fn label_shift(&self) -> u8 {
        self.raw[17] & 0b01111111
    }

    #[cfg(not(feature = "sfcp"))]
    pub fn penalty(&self) -> [u8; 2] {
        let mut a = [0u8; 2];
        a.copy_from_slice(&self.raw[10..12]);
        a
    }

    /// Returns a reference to the content of the packet.
    #[cfg(not(feature = "sfcp"))]
    pub fn payload(&self) -> Option<Payload> {
        match BigEndian::read_u32(&self.raw[12..16]) {
            0xffffffff => ControlPacket::decode(&self.raw[16..].to_vec()).map(Payload::Control),
            0 | 1 => Some(Payload::CryptoAuthHello(self.raw[12..].to_vec())),
            2 | 3 => Some(Payload::CryptoAuthKey(self.raw[12..].to_vec())),
            handle => Some(Payload::CryptoAuthData(
                SessionHandle(handle),
                self.raw[16..].to_vec(),
            )),
        }
    }

    /// Returns a reference to the content of the packet.
    #[cfg(feature = "sfcp")]
    pub fn payload(&self) -> Option<Payload> {
        match BigEndian::read_u32(&self.raw[20..24]) {
            0xffffffff => ControlPacket::decode(&self.raw[24..].to_vec()).map(Payload::Control),
            0 | 1 => Some(Payload::CryptoAuthHello(self.raw[20..].to_vec())),
            2 | 3 => Some(Payload::CryptoAuthKey(self.raw[20..].to_vec())),
            handle => Some(Payload::CryptoAuthData(
                SessionHandle(handle),
                self.raw[20..].to_vec(),
            )),
        }
    }

    /// Make this packet advance one logical hop.
    ///
    /// Using the Director Length of this switch, determines what interface
    /// the packet will go next, update the label of the packet to take that
    /// switching into account (pops the interface from the path, and puts it
    /// on the reverse path), then returns the interface.
    ///
    /// See the doc of `fcp::operation::switch` for more details.
    pub fn switch(
        &mut self,
        director_length: u8,
        reversed_origin_iface: &Director,
    ) -> RoutingDecision {
        let (new_label, decision) = switch(&self.label(), director_length, reversed_origin_iface);
        self.raw[0..LABEL_LENGTH].copy_from_slice(&new_label);
        decision
    }

    /// Inverses the path and the return path.
    pub fn reverse_label(&mut self) {
        // TODO: do this in-place/no-copy.
        let mut label = [0u8; LABEL_LENGTH];
        reverse_label(&mut label);
        self.raw[0..LABEL_LENGTH].copy_from_slice(&label);
    }
}

impl fmt::Debug for SwitchPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ds = f.debug_struct("SwitchPacket");
        let ds = ds.field("raw", &self.raw.to_vec().to_hex())
            .field("label", &self.label())
            .field("payload", &self.payload());

        #[cfg(not(feature = "sfcp"))]
        let ds = ds.field("version", &self.version());

        ds.finish()
    }
}

#[cfg(test)]
mod test {
    use super::super::super::operation::RoutingDecision;
    use super::super::super::packets::control::ControlPacket;
    use super::*;
    use hex::FromHex;

    #[test]
    #[cfg(not(feature = "sfcp"))]
    fn switch_and_reply() {
        let mut received = SwitchPacket {
            raw: Vec::from_hex(
                "800000000000000100440000ffffffff9986000309f9110200000011467c6febbde26264a38cd12e",
            )
            .unwrap(),
        };
        let decision = received.switch(4, &0b1100);
        let opaque_data = match decision {
            RoutingDecision::SelfInterface(_) => match received.payload() {
                Some(Payload::Control(ControlPacket::Ping { opaque_data, .. })) => opaque_data,
                _ => panic!("parsed as non-Ping."),
            },
            _ => panic!("routed to non-self interface."),
        };
        let control_response = ControlPacket::Pong {
            version: 17,
            opaque_data: opaque_data,
        };
        let mut response = SwitchPacket::new_reply(&received, Payload::Control(control_response));
        let decision = response.switch(4, &0b1000);
        assert_eq!(decision, RoutingDecision::Forward(0b0011));
        assert_eq!(
            response.raw,
            Vec::from_hex(
                "800000000000000100000000ffffffff33b000049d74e35b00000011467c6febbde26264a38cd12e"
            )
            .unwrap()
        );
    }
}

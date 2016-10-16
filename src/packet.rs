//! Contains the `SwitchHeader` structure, storing the packet header
//! used by the Switch, as defined by
//! https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#in-memory-representation

use operation::{switch, reverse_label, Director, RoutingDecision, Label};

pub enum PacketType {
    Opaque,
    SwitchControlMessage,
}

pub struct SwitchPacket {
    pub raw: Vec<u8>,
}

impl SwitchPacket {
    pub fn new(route_label: &[u8; 8], type_: &PacketType, mut payload: Vec<u8>) -> SwitchPacket {
        let mut raw = Vec::with_capacity(12 + payload.len());
        raw.resize(12, 0);
        raw[0..8].copy_from_slice(route_label);
        raw[8] = match *type_ {
            PacketType::Opaque => 0u8,
            PacketType::SwitchControlMessage => 1u8,
        };
        raw.append(&mut payload);
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

    /// Returns a reference to the content of the packet.
    pub fn payload(&self) -> &[u8] {
        &self.raw[12..]
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

use std::collections::HashMap;

use fcp_cryptoauth::{CAWrapper, PublicKey, SecretKey, Credentials};

use operation::{RoutingDecision, Director};
use switch_packet::SwitchPacket;

/// Used to represent a connection to a *direct peer* of this switch.
///
pub struct Interface<PeerId: Clone, InterfaceData: Copy> {
    /// Used for routing too -- it is the Director.
    pub id: Director,
    /// A point-to-point (aka outer) CryptoAuth session.
    pub ca_session: CAWrapper<PeerId>,
    /// Arbitrary data. Can be used to store a socket address, for instance
    pub data: InterfaceData,
}

/// A switch that only forwards packets.
///
/// This is not a switch as per the FCP's definition, because the FCP
/// requires switch to send packets and reply to them. This is done
/// by connecting something to the self-interface of this switch.
pub struct PassiveSwitch {
    /// My public key, both for outer and inner CryptoAuth sessions.
    pub my_pk: PublicKey,
    /// My public key, both for outer and inner CryptoAuth sessions.
    pub my_sk: SecretKey,
    /// CryptoAuth sessions used to talk to switches/routers. Their packets
    /// themselves are wrapped in SwitchPackets, which are wrapped in the
    /// outer CryptoAuth sessions.
    pub e2e_conns: HashMap<u32, ([u8; 8], CAWrapper<()>)>,
    /// Credentials of peers which are allowed to connect to us.
    pub allowed_peers: HashMap<Credentials, String>,
}

impl PassiveSwitch {
    /// Instanciates a switch.
    pub fn new(my_pk: PublicKey, my_sk: SecretKey, allowed_peers: HashMap<Credentials, String>) -> PassiveSwitch {
        PassiveSwitch {
            my_pk: my_pk,
            my_sk: my_sk,
            e2e_conns: HashMap::new(),
            allowed_peers: allowed_peers,
            }
    }

    /// Takes a 3-bit interface id, and reverse its bits.
    /// Used to compute reverse paths.
    fn reverse_iface_id(&self, iface_id: u64) -> u64 {
        match iface_id {
            0b000 => 0b000,
            0b001 => 0b100,
            0b010 => 0b010,
            0b011 => 0b110,
            0b100 => 0b001,
            0b101 => 0b101,
            0b110 => 0b011,
            0b111 => 0b111,
            _ => panic!("Iface id greater than 0b111"),
        }
    }

    /// Send a packet to the appropriate interface.
    ///
    /// If the packet is forwarded to the self-interface, returns
    /// `(Some(packet), None)`.
    /// Else, returns `(None, Some((director, raw_packets)))`; `raw_packet` is
    /// expected to be sent as-is over the network (eg. in a UDP datagram).
    pub fn forward<PeerId: Clone, InterfaceData: Copy>(&mut self, mut packet: SwitchPacket, interfaces: &mut Vec<Interface<PeerId, InterfaceData>>, from_interface: Director)
            -> (Option<SwitchPacket>, Option<(InterfaceData, Vec<Vec<u8>>)>) {
        // Logically advance the packet through an interface.
        let routing_decision = packet.switch(3, &(self.reverse_iface_id(from_interface) as u64));
        match routing_decision {
            RoutingDecision::SelfInterface(_) => {
                // Packet is sent to myself
                (Some(packet), None)
            }
            RoutingDecision::Forward(director) => {
                // Packet is sent to a peer.
                for interface in interfaces.iter_mut() {
                    if interface.id as u64 == director {
                        // Wrap the packet with the outer CryptoAuth session
                        // of this peer, and send it.
                        let raw_packets = interface.ca_session.wrap_message(&packet.raw);
                        return (None, Some((interface.data, raw_packets)))
                    }
                }
                panic!(format!("Iface {} not found for packet: {:?}", director, packet));
            }
        }
    }
}

use std::collections::HashMap;

use fcp_cryptoauth::{CAWrapper, PublicKey, SecretKey, Credentials};

use operation::{RoutingDecision, Director};
use switch_packet::SwitchPacket;

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
    /// Credentials of peers which are allowed to connect to us.
    pub allowed_peers: HashMap<Credentials, String>,
}

impl PassiveSwitch {
    /// Instanciates a switch.
    pub fn new(my_pk: PublicKey, my_sk: SecretKey, allowed_peers: HashMap<Credentials, String>) -> PassiveSwitch {
        PassiveSwitch {
            my_pk: my_pk,
            my_sk: my_sk,
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
    /// Else, returns `(None, Some((director, switch_packets)))`; `switch_packet` is
    /// expected to be sent to a NetworkAdapter.
    pub fn forward(&self, mut packet: SwitchPacket, from_interface: Director)
            -> (Option<SwitchPacket>, Option<(Director, SwitchPacket)>) {
        // Logically advance the packet through an interface.
        let routing_decision = packet.switch(3, &(self.reverse_iface_id(from_interface) as u64));
        match routing_decision {
            RoutingDecision::SelfInterface(_) => {
                // Packet is sent to myself
                (Some(packet), None)
            }
            RoutingDecision::Forward(director) => {
                // Packet is sent to a peer.
                return (None, Some((director, packet)))
            }
        }
    }
}

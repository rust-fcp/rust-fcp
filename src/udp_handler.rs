use std::net::{UdpSocket, SocketAddr};
use std::collections::HashMap;

use fcp_cryptoauth::{CAWrapper, PublicKey, SecretKey, Credentials};
use switch_packet::SwitchPacket;

use passive_switch::Interface;

pub struct UdpHandler<PeerId: Clone> {
    pub sock: UdpSocket,
    pub my_pk: PublicKey,
    pub my_sk: SecretKey,
    pub allowed_peers: HashMap<Credentials, PeerId>,
    pub interfaces: Vec<Interface<PeerId, SocketAddr>>,
}

impl<PeerId: Clone> UdpHandler<PeerId> {
    pub fn new(
            sock: UdpSocket,
            my_pk: PublicKey,
            my_sk: SecretKey,
            allowed_peers: HashMap<Credentials, PeerId>,
            interfaces: Vec<Interface<PeerId, SocketAddr>>,
            )
            -> UdpHandler<PeerId> {
        UdpHandler {
            sock: sock,
            my_pk: my_pk,
            my_sk: my_sk,
            allowed_peers: allowed_peers,
            interfaces: interfaces
        }
    }

    // Find what interface a UDP packet is coming from, using its emitted
    // IP address.
    fn get_incoming_iface_and_open(
            &mut self,
            from_addr: SocketAddr, buf: Vec<u8>)
            -> (&Interface<PeerId, SocketAddr>, Vec<Vec<u8>>) {
        let mut iface_exists = false;
        for candidate_interface in self.interfaces.iter_mut() {
            if candidate_interface.data == from_addr {
                iface_exists = true;
                break
            }
        }

        if iface_exists {
            // Workaround for https://github.com/rust-lang/rust/issues/38614
            for candidate_interface in self.interfaces.iter_mut() {
                if candidate_interface.data == from_addr {
                    let messages = candidate_interface.ca_session.unwrap_message(buf).unwrap();
                    return (candidate_interface, messages);
                }
            }
            panic!("The impossible happened.");
        }
        else {
            // Not a known interface; create one
            let next_iface_id = (0..0b1000).filter(|candidate| self.interfaces.iter().find(|iface| iface.id == *candidate).is_none()).next().unwrap();
            let (ca_session, message) = CAWrapper::new_incoming_connection(self.my_pk.clone(), self.my_sk.clone(), Credentials::None, Some(self.allowed_peers.clone()), None, buf).unwrap();
            let new_iface = Interface { id: next_iface_id, ca_session: ca_session, data: from_addr };
            self.interfaces.push(new_iface);
            let interface = self.interfaces.last_mut().unwrap();
            (interface, vec![message])
        }
    }

    /// Called when a UDP packet is received.
    fn on_outer_ca_message(&mut self, from_addr: SocketAddr, buf: Vec<u8>)
            -> (&Interface<PeerId, SocketAddr>, Vec<SwitchPacket>) {
        let (interface, messages) = self.get_incoming_iface_and_open(from_addr, buf);
        (interface, messages.into_iter().map(|raw| SwitchPacket { raw: raw }).collect())
    }

    pub fn receive_one(&mut self)
            -> (&Interface<PeerId, SocketAddr>, Vec<SwitchPacket>) {
        let mut buf = vec![0u8; 4096];
        let (nb_bytes, addr) = self.sock.recv_from(&mut buf).unwrap();
        assert!(nb_bytes < 4096);
        buf.truncate(nb_bytes);
        self.on_outer_ca_message(addr, buf)
    }
}

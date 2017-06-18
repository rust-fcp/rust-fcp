use std::net::{UdpSocket, SocketAddr};
use std::collections::HashMap;

use fcp_cryptoauth::{CAWrapper, PublicKey, SecretKey, Credentials};

use switch_packet::SwitchPacket;
use operation::Director;
use plumbing::NetworkAdapterTrait;

pub struct UdpPeer<PeerId: Clone> {
    pub ca_session: CAWrapper<PeerId>,
    pub addr: SocketAddr,
}

pub struct UdpAdapter<PeerId: Clone> {
    pub sock: UdpSocket,
    pub my_pk: PublicKey,
    pub my_sk: SecretKey,
    pub allowed_peers: HashMap<Credentials, PeerId>,
    pub peers: HashMap<Director, UdpPeer<PeerId>>,
}

impl<PeerId: Clone> UdpAdapter<PeerId> {
    pub fn new(
            sock: UdpSocket,
            my_pk: PublicKey,
            my_sk: SecretKey,
            allowed_peers: HashMap<Credentials, PeerId>,
            peers: HashMap<Director, UdpPeer<PeerId>>,
            )
            -> UdpAdapter<PeerId> {
        UdpAdapter {
            sock: sock,
            my_pk: my_pk,
            my_sk: my_sk,
            allowed_peers: allowed_peers,
            peers: peers,
        }
    }

    // Find what interface a UDP packet is coming from, using its emitted
    // IP address.
    fn get_incoming_director_and_open(&mut self, from_addr: SocketAddr, datagram: Vec<u8>)
            -> (Director, Vec<Vec<u8>>) {
        for (director, peer) in self.peers.iter_mut() {
            if peer.addr == from_addr {
                let messages = peer.ca_session.unwrap_message(datagram).unwrap();
                return (*director, messages);
            }
        }

        // Not a known interface; create one
        let director = (0..0b1000).filter(|candidate| !self.peers.contains_key(&candidate)).next().unwrap();
        let (ca_session, message) = CAWrapper::new_incoming_connection(self.my_pk.clone(), self.my_sk.clone(), Credentials::None, Some(self.allowed_peers.clone()), None, datagram).unwrap();
        let peer = UdpPeer { ca_session: ca_session, addr: from_addr };
        self.peers.insert(director, peer);
        (director, vec![message])
    }

    /// Called when a UDP packet is received.
    fn on_outer_ca_message(&mut self, from_addr: SocketAddr, datagram: Vec<u8>)
            -> (Director, Vec<SwitchPacket>) {
        let (director, messages) = self.get_incoming_director_and_open(from_addr, datagram);
        (director, messages.into_iter().map(|raw| SwitchPacket { raw: raw }).collect())
    }
}

impl<PeerId: Clone> NetworkAdapterTrait for UdpAdapter<PeerId> {
    fn send_to(&mut self, to: Director, packet: &SwitchPacket) {
        let (addr, datagrams) = {
            let peer = self.peers.get_mut(&to).unwrap();
            let datagrams = peer.ca_session.wrap_message(&packet.raw);
            (peer.addr, datagrams)
        };
        for datagram in datagrams {
            self.sock.send_to(&datagram, addr).unwrap();
        }
    }

    fn recv_from(&mut self) -> (Director, Vec<SwitchPacket>) {
        let mut datagram = vec![0u8; 4096];
        let (nb_bytes, addr) = self.sock.recv_from(&mut datagram).unwrap();
        assert!(nb_bytes < 4096);
        datagram.truncate(nb_bytes);
        self.on_outer_ca_message(addr, datagram)
    }

}

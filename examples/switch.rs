extern crate hex;
extern crate rand;
extern crate byteorder;
extern crate fcp_cryptoauth;
extern crate fcp;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};
use std::iter::FromIterator;
use std::collections::HashMap;

use fcp_cryptoauth::*;

use fcp::switch_packet::SwitchPacket;
use fcp::operation::{Director, ForwardPath, BackwardPath};
use fcp::control::ControlPacket;
use fcp::route_packet::{RoutePacket, RoutePacketBuilder, NodeData};
use fcp::data_packet::DataPacket;
use fcp::data_packet::Payload as DataPayload;
use fcp::encoding_scheme::{EncodingScheme, EncodingSchemeForm};
use fcp::passive_switch::PassiveSwitch;
use fcp::udp_adapter::{UdpAdapter, UdpPeer};
use fcp::utils::{make_reply, new_from_raw_content};
use fcp::router::Router;
use fcp::plumbing::Plumbing;
use fcp::session_manager::{SessionManager, SessionHandle};
use fcp::plumbing::NetworkAdapterTrait;

use hex::ToHex;
use rand::Rng;

/// Main data structure of the switch.
struct UdpSwitch {
    plumbing: Plumbing<Router, UdpAdapter<String>>, 
}

impl UdpSwitch {
    /// Instanciates a switch.
    fn new(sock: UdpSocket, peers: HashMap<Director, UdpPeer<String>>, my_pk: PublicKey, my_sk: SecretKey, allowed_peers: HashMap<Credentials, String>) -> UdpSwitch {
        let udp_adapter = UdpAdapter::new(sock, my_pk.clone(), my_sk.clone(), allowed_peers.clone(), peers);
        let session_manager = SessionManager {
            my_pk: my_pk.clone(),
            my_sk: my_sk.clone(),
            e2e_conns: HashMap::new(),
        };
        let plumbing = Plumbing {
            network_adapter: udp_adapter,
            switch: PassiveSwitch::new(my_pk, my_sk, allowed_peers),
            router: Router::new(my_pk),
            session_manager: session_manager,
        };
        UdpSwitch {
            plumbing: plumbing,
        }
    }

    /// Sometimes (random) sends a switch as a reply to the packet.
    fn random_send_switch_ping(&mut self, handle: SessionHandle, path: ForwardPath) {
        if rand::thread_rng().next_u32() > 0xafffffff {
            let ping = ControlPacket::Ping { version: 18, opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8] };
            let packet_response = new_from_raw_content(path, ping.encode(), Some(handle));
            self.plumbing.dispatch(packet_response, 0b001);
        }
    }
            
    /// Sometimes (random) sends a `gp` query.
    fn random_send_getpeers(&mut self, handle: SessionHandle, path: ForwardPath) {
        if rand::thread_rng().next_u32() > 0xafffffff {
            let encoding_scheme = EncodingScheme::from_iter(vec![EncodingSchemeForm { prefix: 0, bit_count: 3, prefix_length: 0 }].iter());
            let route_packet = RoutePacketBuilder::new(18, b"blah".to_vec())
                    .query("gp".to_owned())
                    .encoding_index(0)
                    .encoding_scheme(encoding_scheme)
                    .target_address(vec![0, 0, 0, 0, 0, 0, 0, 0])
                    .finalize();
            let getpeers_message = DataPacket::new(1, &DataPayload::RoutePacket(route_packet));
            let mut responses = Vec::new();
            {
                let &mut (_path, ref mut inner_conn) = self.plumbing.session_manager.get_mut(handle).unwrap();
                println!("Sending data packet: {}", getpeers_message);
                for packet_response in inner_conn.wrap_message_immediately(&getpeers_message.raw) {
                    responses.push(new_from_raw_content(path, packet_response, Some(handle)));
                }
            }
            for response in responses {
                self.plumbing.dispatch(response, 0b001);
            }
        }
    }

    fn dispatch(&mut self, packet: SwitchPacket, from_interface: Director) {
        self.plumbing.dispatch(packet, from_interface);
    }

    fn loop_(&mut self) {
        loop {
            let mut packets = Vec::new();
            let mut targets = Vec::new();
            for (handle, &mut (path, ref mut conn)) in self.plumbing.session_manager.e2e_conns.iter_mut() {
                for ca_message in conn.upkeep() {
                    packets.push(new_from_raw_content(path, ca_message, Some(*handle)));
                }
                targets.push((*handle, path))
            }
            for packet in packets {
                let packet = self.plumbing.dispatch(packet, 0b001);
            }
            for (handle, path) in targets {
                self.random_send_switch_ping(handle, path);
                self.random_send_getpeers(handle, path)
            }

            let (director, messages) = self.plumbing.network_adapter.recv_from();
            for message in messages.into_iter() {
                self.dispatch(message, director);
            }
        }
    }
}

pub fn main() {
    fcp_cryptoauth::init();

    let my_sk = SecretKey::from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e").unwrap();
    let my_pk = PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let their_pk = PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
    let login = "foo".to_owned().into_bytes();
    let password = "bar".to_owned().into_bytes();
    let credentials = Credentials::LoginPassword {
        login: login,
        password: password,
    };
    let mut allowed_peers = HashMap::new();
    allowed_peers.insert(credentials.clone(), "my peer".to_owned());

    let sock = UdpSocket::bind("[::1]:12345").unwrap();
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 54321);

    let conn = CAWrapper::new_outgoing_connection(
            my_pk, my_sk.clone(), their_pk, credentials, Some(allowed_peers.clone()), "my peer".to_owned(), None);

    let mut peers = HashMap::new();
    peers.insert(0b011, UdpPeer { ca_session: conn, addr: dest });

    let mut switch = UdpSwitch::new(sock, peers, my_pk, my_sk, allowed_peers);

    switch.loop_();
}

extern crate hex;
extern crate rand;
extern crate byteorder;
extern crate fcp_cryptoauth;
extern crate fcp;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};
use std::collections::HashMap;

use fcp_cryptoauth::*;

use fcp::switch_packet::SwitchPacket;
use fcp::switch_packet::Payload as SwitchPayload;
use fcp::operation::{reverse_label, Director};
use fcp::control::ControlPacket;
use fcp::data_packet::DataPacket;
use fcp::data_packet::Payload as DataPayload;
use fcp::passive_switch::{PassiveSwitch, Interface};
use fcp::udp_handler::UdpHandler;
use fcp::utils::make_reply;
use fcp::router::Router;

use hex::ToHex;
use rand::Rng;

/// Main data structure of the switch.
struct UdpSwitch {
    udp_handler: UdpHandler<String>,
    inner: PassiveSwitch,
    router: Router,
}

impl UdpSwitch {
    /// Instanciates a switch.
    fn new(sock: UdpSocket, interfaces: Vec<Interface<String, SocketAddr>>, my_pk: PublicKey, my_sk: SecretKey, allowed_peers: HashMap<Credentials, String>) -> UdpSwitch {
        UdpSwitch {
            udp_handler: UdpHandler::new(sock, my_pk.clone(), my_sk.clone(), allowed_peers.clone(), interfaces),
            inner: PassiveSwitch::new(my_pk, my_sk, allowed_peers),
            router: Router::new(my_pk),
            }
    }

    /// Sometimes (random) sends a switch as a reply to the packet.
    fn random_send_switch_ping(&mut self, switch_packet: &SwitchPacket) {
        if rand::thread_rng().next_u32() > 0xafffffff {
            let ping = ControlPacket::Ping { version: 18, opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8] };
            let packet_response = SwitchPacket::new_reply(&switch_packet, SwitchPayload::Control(ping));
            self.dispatch(packet_response, 0b001);
        }
    }

    fn dispatch(&mut self, packet: SwitchPacket, from_interface: Director) {
        let (to_self, forward) = self.inner.forward(packet, &mut self.udp_handler.interfaces, from_interface);
        to_self.map(|packet| self.on_self_interface_switch_packet(&packet));
        forward.map(|(addr, packets)| {
            for packet in packets {
                self.udp_handler.sock.send_to(&packet, addr).unwrap();
            }
        });
    }
            
    /// Sometimes (random) sends a `gp` query.
    fn random_send_getpeers(&mut self) {
        if rand::thread_rng().next_u32() > 0xafffffff {
            let messages = self.router.upkeep();
            let mut packets = Vec::new();
            for (handle, label, route_message) in messages {
                let &mut (_path, ref mut inner_conn) = self.inner.e2e_conns.get_mut(&handle).unwrap();
                let data_packet = DataPacket::new(1, &DataPayload::RoutePacket(route_message));
                for packet_content in inner_conn.wrap_message_immediately(&data_packet.raw) {
                    let packet = SwitchPacket::new(&label, SwitchPayload::CryptoAuthData(handle, packet_content));
                    packets.push(packet);
                }
            }
            for packet in packets {
                self.dispatch(packet, 0b001);
            }
        }
    }

    /// Called when a CryptoAuth message is received through an end-to-end
    /// session.
    fn on_inner_ca_message(&mut self, switch_packet: &SwitchPacket, handle: u32, ca_message: Vec<u8>) {
        let data_packet = DataPacket { raw: ca_message };
        println!("Received data packet: {}", data_packet);

        let their_pk = self.inner.e2e_conns.get(&handle).unwrap().1.their_pk().clone();

        let route_packets = match data_packet.payload().unwrap() {
            DataPayload::RoutePacket(route_packet) => {
                self.router.on_route_packet(&route_packet, switch_packet.label(), handle, their_pk)
            }
        };
        for route_packet in route_packets.into_iter() {
            let getpeers_response = DataPacket::new(1, &DataPayload::RoutePacket(route_packet));
            let responses: Vec<_>;
            {
                let &mut (_path, ref mut inner_conn) = self.inner.e2e_conns.get_mut(&handle).unwrap();
                let tmp = inner_conn.wrap_message_immediately(&getpeers_response.raw);
                responses = tmp.into_iter().map(|r| make_reply(&switch_packet, r, inner_conn)).collect();
            }
            for response in responses {
                self.dispatch(response, 0b001);
            }
        }

        self.random_send_getpeers()
    }

    /// Called when a switch packet is sent to the self interface
    fn on_self_interface_switch_packet(&mut self, switch_packet: &SwitchPacket) {
        match switch_packet.payload() {
            Some(SwitchPayload::Control(ControlPacket::Ping { opaque_data, .. })) => {
                // If it is a ping packet, just reply to it.
                let control_response = ControlPacket::Pong { version: 18, opaque_data: opaque_data };
                let packet_response = SwitchPacket::new_reply(switch_packet, SwitchPayload::Control(control_response));
                self.dispatch(packet_response, 0b001);

                self.random_send_switch_ping(switch_packet);
            },
            Some(SwitchPayload::Control(ControlPacket::Pong { opaque_data, .. })) => {
                // If it is a pong packet, print it.
                assert_eq!(opaque_data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
                println!("Received pong (label: {}).", switch_packet.label().to_vec().to_hex());
            },
            Some(SwitchPayload::CryptoAuthHandshake(handshake)) => {
                // If it is a CryptoAuth handshake packet (ie. if someone is
                // connecting to us), create a new session for this node.
                // All CA handshake we receive will be sessions started by
                // other peers, because this switch never starts sessions
                // (routers do, not switches).
                let mut handle;
                loop {
                    handle = rand::thread_rng().next_u32();
                    if !self.inner.e2e_conns.contains_key(&handle) {
                        break
                    }
                };
                let (inner_conn, inner_packet) = CAWrapper::new_incoming_connection(self.inner.my_pk, self.inner.my_sk.clone(), Credentials::None, None, Some(handle), handshake.clone()).unwrap();
                let path = {
                    let mut path = switch_packet.label();
                    reverse_label(&mut path);
                    path
                };
                self.inner.e2e_conns.insert(handle, (path, inner_conn));
                self.on_inner_ca_message(switch_packet, handle, inner_packet);
                self.random_send_switch_ping(switch_packet);
            },
            Some(SwitchPayload::CryptoAuthData(handle, ca_message)) => {
                // If it is a CryptoAuth data packet, first read the session
                // handle to know which CryptoAuth session to use to
                // decrypt it.
                let inner_packets = match self.inner.e2e_conns.get_mut(&handle) {
                    Some(&mut (_path, ref mut inner_conn)) => {
                        match inner_conn.unwrap_message(ca_message) {
                            Ok(inner_packets) => inner_packets,
                            Err(e) => panic!("CA error: {:?}", e),
                        }
                    }
                    None => panic!("Received unknown handle.")
                };
                for inner_packet in inner_packets {
                    self.on_inner_ca_message(switch_packet, handle, inner_packet)
                }
            }
            _ => panic!("Can only handle Pings, Pongs, and CA."),
        }
    }

    fn loop_(&mut self) {
        loop {
            for interface in self.udp_handler.interfaces.iter_mut() {
                for packet in interface.ca_session.upkeep() {
                    self.udp_handler.sock.send_to(&packet, interface.data).unwrap();
                }
            }

            let (director, messages) = {
                let (interface, messages) = self.udp_handler.receive_one();
                (interface.id, messages)
            };
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

    let interfaces = vec![Interface { id: 0b011, ca_session: conn, data: dest }];

    let mut switch = UdpSwitch::new(sock, interfaces, my_pk, my_sk, allowed_peers);

    switch.loop_();
}

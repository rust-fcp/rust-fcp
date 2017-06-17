extern crate hex;
extern crate rand;
extern crate byteorder;
extern crate fcp_cryptoauth;
extern crate fcp;

use byteorder::BigEndian;
use byteorder::ByteOrder;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};
use std::iter::FromIterator;
use std::collections::HashMap;

use fcp_cryptoauth::*;

use fcp::switch_packet::SwitchPacket;
use fcp::switch_packet::Payload as SwitchPayload;
use fcp::operation::{RoutingDecision, reverse_label, Director};
use fcp::control::ControlPacket;
use fcp::route_packet::{RoutePacket, RoutePacketBuilder, NodeData};
use fcp::data_packet::DataPacket;
use fcp::data_packet::Payload as DataPayload;
use fcp::encoding_scheme::{EncodingScheme, EncodingSchemeForm};
use fcp::passive_switch::{PassiveSwitch, Interface};
use fcp::udp_handler::UdpHandler;

use hex::ToHex;
use rand::Rng;

/// Creates a reply switch packet to an other switch packet.
/// The content of the reply is given as a byte array (returned CryptoAuth's
/// `wrap_messages`).
fn make_reply(replied_to_packet: &SwitchPacket, reply_content: Vec<u8>, inner_conn: &CAWrapper<()>) -> SwitchPacket {
    let first_four_bytes = BigEndian::read_u32(&reply_content[0..4]);
    if first_four_bytes < 4 {
        // If it is a CryptoAuth handshake packet, send it as is.
        SwitchPacket::new_reply(&replied_to_packet, SwitchPayload::CryptoAuthHandshake(reply_content))
    }
    else if first_four_bytes == 0xffffffff {
        // Control packet
        unimplemented!()
    }
    else {
        // Otherwise, it is a CryptoAuth data packet. We have to prepend
        // the session handle to the reply.
        // This handle is used by the peer to know this packet is coming
        // from us.
        let peer_handle = inner_conn.peer_session_handle().unwrap();
        SwitchPacket::new_reply(&replied_to_packet, SwitchPayload::CryptoAuthData(peer_handle, reply_content))
    }
}

/// Main data structure of the switch.
struct UdpSwitch {
    udp_handler: UdpHandler<String>,
    inner: PassiveSwitch,
}

impl UdpSwitch {
    /// Instanciates a switch.
    fn new(sock: UdpSocket, interfaces: Vec<Interface<String, SocketAddr>>, my_pk: PublicKey, my_sk: SecretKey, allowed_peers: HashMap<Credentials, String>) -> UdpSwitch {
        UdpSwitch {
            udp_handler: UdpHandler::new(sock, my_pk.clone(), my_sk.clone(), allowed_peers.clone(), interfaces),
            inner: PassiveSwitch::new(my_pk, my_sk, allowed_peers),
            }
    }

    /// Sometimes (random) sends a switch as a reply to the packet.
    fn random_send_switch_ping(&mut self, switch_packet: &SwitchPacket) {
        if rand::thread_rng().next_u32() > 0xafffffff {
            let ping = ControlPacket::Ping { version: 18, opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8] };
            let mut packet_response = SwitchPacket::new_reply(&switch_packet, SwitchPayload::Control(ping));
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
            

    /// Reply to `gp` queries by sending a list of my peers.
    fn reply_getpeers(&mut self, switch_packet: &SwitchPacket, route_packet: &RoutePacket, handle: u32) {
        let mut nodes = Vec::new();
        {
            // Add myself
            let mut my_pk = [0u8; 32];
            my_pk.copy_from_slice(&self.inner.my_pk.0);
            nodes.push(NodeData {
                public_key: my_pk,
                path: [0, 0, 0, 0, 0, 0, 0, 0b001],
                version: 18,
            });
        }
        for (peer_handle, &(path, ref inner_conn)) in self.inner.e2e_conns.iter() {
            if *peer_handle != handle {
                // If the peer is not the one asking for the list of peers,
                // add it to the list.
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&inner_conn.their_pk().0);
                nodes.push(NodeData {
                    public_key: pk,
                    path: path,
                    version: 18, // TODO
                });
                println!("Announcing one peer, with path: {}", path.to_vec().to_hex());
            }
        }
        // TODO: only send the peers closest to the specified target address.

        let encoding_scheme = EncodingScheme::from_iter(vec![EncodingSchemeForm { prefix: 0, bit_count: 3, prefix_length: 0 }].iter());
        let route_packet = RoutePacketBuilder::new(18, route_packet.transaction_id.clone())
                .nodes_vec(nodes)
                .encoding_index(0) // This switch uses only one encoding scheme
                .encoding_scheme(encoding_scheme)
                .finalize();
        let getpeers_response = DataPacket::new(1, &DataPayload::RoutePacket(route_packet));
        let responses: Vec<_>;
        {
            let &mut (_path, ref mut inner_conn) = self.inner.e2e_conns.get_mut(&handle).unwrap();
            println!("Sending data packet: {}", getpeers_response);
            let tmp = inner_conn.wrap_message_immediately(&getpeers_response.raw);
            responses = tmp.into_iter().map(|r| make_reply(&switch_packet, r, &inner_conn)).collect();
        }
        for mut response in responses {
            self.dispatch(response, 0b001);
        }
    }

    /// Sometimes (random) sends a `gp` query.
    fn random_send_getpeers(&mut self, reply_to: &SwitchPacket, handle: u32) {
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
                let &mut (_path, ref mut inner_conn) = self.inner.e2e_conns.get_mut(&handle).unwrap();
                println!("Sending data packet: {}", getpeers_message);
                for packet_response in inner_conn.wrap_message_immediately(&getpeers_message.raw) {
                    responses.push(make_reply(reply_to, packet_response, inner_conn));
                }
            }
            for mut response in responses {
                self.dispatch(response, 0b001);
            }
        }
    }

    /// Called when a CryptoAuth message is received through an end-to-end
    /// session.
    fn on_inner_ca_message(&mut self, switch_packet: &SwitchPacket, handle: u32, ca_message: Vec<u8>) {
        let data_packet = DataPacket { raw: ca_message };
        println!("Received data packet: {}", data_packet);

        // If it is a query, reply to it.
        match data_packet.payload().unwrap() {
            DataPayload::RoutePacket(route_packet) => {
                if route_packet.query == Some("gp".to_owned()) {
                    self.reply_getpeers(switch_packet, &route_packet, handle);
                }
            }
        }

        self.random_send_getpeers(switch_packet, handle)
    }

    /// Called when a switch packet is sent to the self interface
    fn on_self_interface_switch_packet(&mut self, switch_packet: &SwitchPacket) {
        match switch_packet.payload() {
            Some(SwitchPayload::Control(ControlPacket::Ping { opaque_data, .. })) => {
                // If it is a ping packet, just reply to it.
                let control_response = ControlPacket::Pong { version: 18, opaque_data: opaque_data };
                let mut packet_response = SwitchPacket::new_reply(switch_packet, SwitchPayload::Control(control_response));
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

extern crate hex;
extern crate rand;
extern crate byteorder;
extern crate fcp_cryptoauth;
extern crate fcp_switching;

use byteorder::BigEndian;
use byteorder::ByteOrder;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};
use std::collections::HashMap;

use fcp_cryptoauth::wrapper::*;

use fcp_switching::switch_packet::{SwitchPacket, PacketType};
use fcp_switching::switch_packet::Payload as SwitchPayload;
use fcp_switching::operation::{RoutingDecision, reverse_label};
use fcp_switching::control::ControlPacket;
use fcp_switching::route_packet::RoutePacket;
use fcp_switching::data_packet::DataPacket;
use fcp_switching::data_packet::Payload as DataPayload;

use hex::ToHex;
use rand::Rng;

struct Interface {
    id: u8,
    ca_session: Wrapper<String>,
    addr: SocketAddr,
}

fn make_reply(switch_packet: &SwitchPacket, packet_response: Vec<u8>, inner_conn: &Wrapper<()>) -> SwitchPacket {
    if BigEndian::read_u32(&packet_response[0..4]) < 4 {
        SwitchPacket::new_reply(&switch_packet, &PacketType::Opaque, SwitchPayload::CryptoAuthHandshake(packet_response)).unwrap()
    }
    else {
        let peer_handle = inner_conn.peer_session_handle().unwrap();
        SwitchPacket::new_reply(&switch_packet, &PacketType::Opaque, SwitchPayload::Other(peer_handle, packet_response)).unwrap()
    }
}

struct Switch {
    sock: UdpSocket,
    interfaces: Vec<Interface>,
    my_pk: PublicKey,
    my_sk: SecretKey,
    inner_conns: HashMap<u32, ([u8; 8], Wrapper<()>)>,
    allowed_peers: HashMap<Credentials, String>,
}

impl Switch {
    fn new(sock: UdpSocket, interfaces: Vec<Interface>, my_pk: PublicKey, my_sk: SecretKey, allowed_peers: HashMap<Credentials, String>) -> Switch {
        Switch {
            sock: sock,
            interfaces: interfaces,
            inner_conns: HashMap::new(),
            my_pk: my_pk,
            my_sk: my_sk,
            allowed_peers: allowed_peers,
            }
    }

    fn reverse_iface_id(&self, iface_id: u8) -> u8 {
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

    fn random_send_switch_ping(&mut self, switch_packet: &SwitchPacket) {
        if rand::thread_rng().next_u32() > 0xafffffff {
            let ping = ControlPacket::Ping { version: 18, opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8] };
            let mut packet_response = SwitchPacket::new_reply(&switch_packet, &PacketType::Opaque, SwitchPayload::Control(ping)).unwrap();
            self.send(&mut packet_response, 0b001);
        }
    }

    fn send(&mut self, packet: &mut SwitchPacket, from_interface: u8) {
        match packet.switch(3, &(self.reverse_iface_id(from_interface) as u64)) {
            RoutingDecision::SelfInterface(_) => {
                self.on_self_interface_switch_packet(packet);
            }
            RoutingDecision::Forward(iface_id) => {
                let mut sent = false;
                for interface in self.interfaces.iter_mut() {
                    if interface.id as u64 == iface_id {
                        sent = true;
                        for packet in interface.ca_session.wrap_message(&packet.raw) {
                            self.sock.send_to(&packet, interface.addr).unwrap();
                        }
                    }
                }
                if !sent {
                    panic!(format!("Iface {} not found for packet: {:?}", iface_id, packet));
                }
            }
        }
    }

    fn reply_getpeers(&mut self, switch_packet: &SwitchPacket, route_packet: &RoutePacket, handle: u32) {
        let mut nodes = Vec::new();
        let mut node_protocol_versions = vec![1u8];
        nodes.reserve(40 * (self.inner_conns.len()+1));
        {
            // Add myself
            let mut node = [0u8; 40];
            node[0..32].copy_from_slice(&self.my_pk.0);
            BigEndian::write_u64(&mut node[32..40], 0b001u64);
            nodes.extend(node.iter());
            node_protocol_versions.push(18);
        }
        for (peer_handle, &(path, ref inner_conn)) in self.inner_conns.iter() {
            if true || *peer_handle != handle {
                let mut node = [0u8; 40];
                node[0..32].copy_from_slice(&inner_conn.their_pk().0);
                node[32..40].copy_from_slice(&path);
                nodes.extend(node.iter());
                node_protocol_versions.push(18); // TODO
                println!("Announcing one peer, with path: {}", path.to_vec().to_hex());
            }
        }
        let getpeers_response = DataPacket::new(1, &DataPayload::RoutePacket(RoutePacket { query: None, nodes: Some(nodes), node_protocol_versions: Some(node_protocol_versions), encoding_index: Some(0), encoding_scheme: None, transaction_id: route_packet.transaction_id.clone(), protocol_version: 18, target_address: None }));
        let responses: Vec<_>;
        {
            let &mut (_path, ref mut inner_conn) = self.inner_conns.get_mut(&handle).unwrap();
            println!("Sending data packet: {}", getpeers_response);
            let tmp = inner_conn.wrap_message_immediately(&getpeers_response.raw);
            responses = tmp.into_iter().map(|r| make_reply(&switch_packet, r, &inner_conn)).collect();
        }
        for mut response in responses {
            self.send(&mut response, 0b001);
        }
    }

    fn on_inner_ca_message(&mut self, switch_packet: &SwitchPacket, handle: u32, ca_message: Vec<u8>) {
        let data_packet = DataPacket { raw: ca_message };
        println!("Received data packet: {}", data_packet);
        match data_packet.payload().unwrap() {
            DataPayload::RoutePacket(route_packet) => {
                if route_packet.query == Some("gp".to_owned()) {
                    self.reply_getpeers(switch_packet, &route_packet, handle);
                }
                else if route_packet.query == Some("fn".to_owned()) {
                    self.reply_getpeers(switch_packet, &route_packet, handle);
                }
                else if route_packet.query == Some("pn".to_owned()) {
                    self.reply_getpeers(switch_packet, &route_packet, handle);
                }
            }
        }
        if rand::thread_rng().next_u32() > 0xafffffff {
            let getpeers_message = DataPacket::new(1, &DataPayload::RoutePacket(RoutePacket { query: Some("gp".to_owned()), nodes: None, node_protocol_versions: None, encoding_index: Some(0), encoding_scheme: None, transaction_id: b"blah".to_vec(), protocol_version: 18, target_address: Some(vec![0, 0, 0, 0, 0, 0, 0, 0]) }));
            let mut responses = Vec::new();
            {
                let &mut (_path, ref mut inner_conn) = self.inner_conns.get_mut(&handle).unwrap();
                println!("Sending data packet: {}", getpeers_message);
                for packet_response in inner_conn.wrap_message_immediately(&getpeers_message.raw) {
                    responses.push(make_reply(&switch_packet, packet_response, inner_conn));
                }
            }
            for mut response in responses {
                self.send(&mut response, 0b001);
            }
        }
    }

    fn on_self_interface_switch_packet(&mut self, switch_packet: &SwitchPacket) {
        match switch_packet.payload() {
            Some(SwitchPayload::Control(ControlPacket::Ping { opaque_data, .. })) => {
                let control_response = ControlPacket::Pong { version: 18, opaque_data: opaque_data };
                let mut packet_response = SwitchPacket::new_reply(switch_packet, &PacketType::Opaque, SwitchPayload::Control(control_response)).unwrap();
                self.send(&mut packet_response, 0b001);

                self.random_send_switch_ping(switch_packet);
            },
            Some(SwitchPayload::Control(ControlPacket::Pong { opaque_data, .. })) => {
                assert_eq!(opaque_data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
                println!("Received pong (label: {}).", switch_packet.label().to_vec().to_hex());
            },
            Some(SwitchPayload::CryptoAuthHandshake(handshake)) => {
                let mut handle;
                loop {
                    handle = rand::thread_rng().next_u32();
                    if !self.inner_conns.contains_key(&handle) {
                        break
                    }
                };
                let (inner_conn, inner_packet) = Wrapper::new_incoming_connection(self.my_pk, self.my_sk.clone(), Credentials::None, None, Some(handle), handshake.clone()).unwrap();
                let path = {
                    let mut path = switch_packet.label();
                    reverse_label(&mut path);
                    path
                };
                self.inner_conns.insert(handle, (path, inner_conn));
                self.on_inner_ca_message(switch_packet, handle, inner_packet);
                self.random_send_switch_ping(switch_packet);
            },
            Some(SwitchPayload::Other(handle, ca_message)) => {
                let inner_packets = match self.inner_conns.get_mut(&handle) {
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

    fn get_incoming_iface_and_open(&mut self, from_addr: SocketAddr, buf: Vec<u8>) -> (&Interface, Vec<Vec<u8>>) {
        let mut iface_exists = false;
        for candidate_interface in self.interfaces.iter_mut() {
            if candidate_interface.addr == from_addr {
                iface_exists = true;
                break
            }
        }

        if iface_exists {
            // Workaround for https://github.com/rust-lang/rust/issues/38614
            for candidate_interface in self.interfaces.iter_mut() {
                if candidate_interface.addr == from_addr {
                    let messages = candidate_interface.ca_session.unwrap_message(buf).unwrap();
                    return (candidate_interface, messages);
                }
            }
            panic!("The impossible happened.");
        }
        else {
            // Not a known interface; create one
            let next_iface_id = (0..0b1000).filter(|candidate| self.interfaces.iter().find(|iface| iface.id == *candidate).is_none()).next().unwrap();
            let (ca_session, message) = Wrapper::new_incoming_connection(self.my_pk.clone(), self.my_sk.clone(), Credentials::None, Some(self.allowed_peers.clone()), None, buf).unwrap();
            let new_iface = Interface { id: next_iface_id, ca_session: ca_session, addr: from_addr };
            self.interfaces.push(new_iface);
            let interface = self.interfaces.last_mut().unwrap();
            (interface, vec![message])
        }
    }

    fn on_outer_ca_message(&mut self, from_addr: SocketAddr, buf: Vec<u8>) {
        let (iface_id, messages) = {
            let (interface, messages) = self.get_incoming_iface_and_open(from_addr, buf);
            (interface.id, messages)
        };
        for message in messages {
            let mut switch_packet = SwitchPacket { raw: message };
            self.send(&mut switch_packet, iface_id)
        }
    }

    fn loop_(&mut self) {
        loop {
            for interface in self.interfaces.iter_mut() {
                for packet in interface.ca_session.upkeep() {
                    self.sock.send_to(&packet, interface.addr).unwrap();
                }
            }

            let mut buf = vec![0u8; 1024];
            let (nb_bytes, addr) = self.sock.recv_from(&mut buf).unwrap();
            assert!(nb_bytes < 1024);
            buf.truncate(nb_bytes);
            self.on_outer_ca_message(addr, buf);
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

    let conn = Wrapper::new_outgoing_connection(
            my_pk, my_sk.clone(), their_pk, credentials, Some(allowed_peers.clone()), "my peer".to_owned(), None);

    let interfaces = vec![Interface { id: 0b011, ca_session: conn, addr: dest }];

    let mut switch = Switch::new(sock, interfaces, my_pk, my_sk, allowed_peers);

    switch.loop_();
}

extern crate hex;
extern crate rand;
extern crate byteorder;
extern crate fcp_cryptoauth;
extern crate fcp;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};
use std::iter::FromIterator;
use std::collections::HashMap;
use std::str::FromStr;

use fcp_cryptoauth::*;
use fcp_cryptoauth::keys::ToBase32;

use fcp::switch_packet::SwitchPacket;
use fcp::switch_packet::Payload as SwitchPayload;
use fcp::operation::{reverse_label, Director, Label};
use fcp::control::ControlPacket;
use fcp::route_packet::{RoutePacket, RoutePacketBuilder, NodeData};
use fcp::data_packet::DataPacket;
use fcp::data_packet::Payload as DataPayload;
use fcp::encoding_scheme::{EncodingScheme, EncodingSchemeForm};
use fcp::passive_switch::PassiveSwitch;
use fcp::udp_adapter::{UdpAdapter, UdpPeer};
use fcp::utils::{make_reply, new_from_raw_content};
use fcp::plumbing::Plumbing;
use fcp::session_manager::{SessionManager, SessionHandle};
use fcp::plumbing::NetworkAdapterTrait;

use fcp::node::{Address, Node};
use fcp::router::Router;

use rand::Rng;

/// Main data structure of the switch.
struct Pinger {
    plumbing: Plumbing<Router, UdpAdapter<String>>, 

    ping_targets: Vec<Address>,
    ping_nodes: Vec<Node>,
    address_to_handle: HashMap<Address, u32>,
}

impl Pinger {
    /// Instanciates a switch.
    fn new(sock: UdpSocket, peers: HashMap<Director, UdpPeer<String>>, my_pk: PublicKey, my_sk: SecretKey, allowed_peers: HashMap<Credentials, String>, ping_targets: Vec<Address>) -> Pinger {
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
        Pinger {
            plumbing: plumbing,

            ping_targets: ping_targets,
            ping_nodes: Vec::new(),
            address_to_handle: HashMap::new(),
            }
    }

    /// Sometimes (random) sends a switch as a reply to the packet.
    fn random_send_switch_ping(&mut self, handle: SessionHandle, label: &Label) {
        if rand::thread_rng().next_u32() > 0xafffffff {
            let ping = ControlPacket::Ping { version: 18, opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8] };
            let packet_response = new_from_raw_content(label, ping.encode(), Some(handle));
            self.plumbing.dispatch(packet_response, 0b001);
        }
    }

    fn send_message_to_node(&mut self, node: &Node, message: DataPacket) {
        let node_pk = PublicKey::from_slice(node.public_key()).unwrap();
        let addr = publickey_to_ipv6addr(&node_pk).into();
        let handle_opt = self.address_to_handle.get(&addr).map(|h| *h);
        match handle_opt {
            Some(handle) => self.send_message_to_handle(handle, message),
            None => {
                println!("Creating CA session for node {}", Ipv6Addr::from(&addr));
                let credentials = Credentials::None;
                let path = node.path().clone();
                let handle = self.plumbing.session_manager.add_outgoing(path, node_pk, credentials);
                self.address_to_handle.insert(addr.into(), handle);
                self.send_message_to_handle(handle, message)
            }
        }
    }

    fn send_message_to_handle(&mut self, handle: u32, message: DataPacket) {
        let mut packets = Vec::new();
        {
            let &mut (path, ref mut inner_conn) = self.plumbing.session_manager.get_mut(handle).unwrap();
            println!("Sending inner ca message to handle {} with path {:?}: {}", handle, path, message);
            for packet_response in inner_conn.wrap_message_immediately(&message.raw) {
                let switch_packet = SwitchPacket::new(&path, SwitchPayload::CryptoAuthData(inner_conn.peer_session_handle().unwrap(), packet_response));
                packets.push(switch_packet);
            }
        }
        for packet in packets {
            self.dispatch(packet, 0b001);
        }
    }


    fn ping_node(&mut self, node: &Node) {
        let node_pk = PublicKey::from_slice(node.public_key()).unwrap();
        let addr = publickey_to_ipv6addr(&node_pk);
        println!("Pinging node {}", Ipv6Addr::from(addr));
        let encoding_scheme = EncodingScheme::from_iter(vec![EncodingSchemeForm { prefix: 0, bit_count: 3, prefix_length: 0 }].iter());
        let route_packet = RoutePacketBuilder::new(18, b"blah".to_vec())
                .query("pn".to_owned())
                .encoding_index(0)
                .encoding_scheme(encoding_scheme)
                .target_address(vec![0, 0, 0, 0, 0, 0, 0, 0])
                .finalize();
        let ping_message = DataPacket::new(1, &DataPayload::RoutePacket(route_packet));
        self.send_message_to_node(node, ping_message);
    }

    fn try_connect_ping_target(&mut self, address: &Address) {
        println!("Trying to connect to {}", Ipv6Addr::from(address));
        let (node_opt, messages) = {
            let (node_opt, messages) = self.plumbing.router.get_node(address, 42);
            let messages: Vec<_> = messages.into_iter().map(|(node, msg)| (node.clone(), msg)).collect();
            (node_opt.cloned(), messages)
        };
        if let Some(node) = node_opt {
            println!("Found node. pk: {}", PublicKey(*node.public_key()).to_base32());
            self.ping_nodes.push(node);
        };
        println!("{} router messages", messages.len());
        for (query_node, message) in messages {
            let message = DataPacket::new(1, &DataPayload::RoutePacket(message));
            self.send_message_to_node(&query_node, message);
        }
    }

    /// Sometimes (random) sends `pn` queries.
    fn random_ping_node(&mut self) {
        if rand::thread_rng().next_u32() > 0xafffffff || true {
            println!("Pinging nodes.");
            for address in self.ping_targets.clone() {
                if !self.address_to_handle.contains_key(&address) {
                    self.try_connect_ping_target(&address)
                }
            }
            for node in self.ping_nodes.clone() {
                self.ping_node(&node);
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
            for (handle, &mut (label, ref mut conn)) in self.plumbing.session_manager.e2e_conns.iter_mut() {
                for ca_message in conn.upkeep() {
                    packets.push(new_from_raw_content(&label, ca_message, Some(*handle)));
                }
                targets.push((*handle, label))
            }
            for packet in packets {
                let packet = self.plumbing.dispatch(packet, 0b001);
            }
            for (handle, label) in targets {
                self.random_send_switch_ping(handle, &label);
            }

            self.random_ping_node();

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
    let their_pk = PublicKey::from_base32(b"g0pt6kwnwj8ndktjhs7pmcl14rg6uugn8kt4nykudtl96r27sch0.k").unwrap();
    let login = "foo".to_owned().into_bytes();
    let password = "bar".to_owned().into_bytes();
    let credentials = Credentials::LoginPassword {
        login: login,
        password: password,
    };

    let mut allowed_peers = HashMap::new();
    allowed_peers.insert(credentials.clone(), "my peer".to_owned());

    let ping_targets = vec![
        Address::from(&Ipv6Addr::from_str("fcd6:9c33:dd06:3320:8dbe:ab19:c87:f6e3").unwrap()),
        Address::from(&Ipv6Addr::from_str("fcb9:326d:37d5:c57b:7ee5:28b5:7aa5:525").unwrap()),
        ];


    let sock = UdpSocket::bind("[::1]:12345").unwrap();
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 20984);

    let conn = CAWrapper::new_outgoing_connection(
            my_pk, my_sk.clone(), their_pk, credentials, Some(allowed_peers.clone()), "my peer".to_owned(), None);

    let mut peers = HashMap::new();
    peers.insert(0b011, UdpPeer { ca_session: conn, addr: dest });

    let mut pinger = Pinger::new(sock, peers, my_pk, my_sk, allowed_peers, ping_targets);

    pinger.loop_();
}

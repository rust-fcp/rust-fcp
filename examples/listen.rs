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
use fcp_switching::operation::RoutingDecision;
use fcp_switching::control::ControlPacket;
use fcp_switching::route_packet::RoutePacket;
use fcp_switching::data_packet::DataPacket;
use fcp_switching::data_packet::Payload as DataPayload;

use hex::ToHex;
use rand::Rng;

fn random_send_ping<PeerId: Clone>(conn: &mut Wrapper<PeerId>, sock: &UdpSocket, dest: &SocketAddr, switch_packet: &SwitchPacket) {
    if rand::thread_rng().next_u32() > 0x7fffffff {
        let ping = ControlPacket::Ping { version: 17, opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8] };
        let mut packet_response = SwitchPacket::new_reply(&switch_packet, &PacketType::Opaque, SwitchPayload::Control(ping)).unwrap();
        packet_response.switch(4, &0b1000);
        println!("{}", packet_response.label().to_vec().to_hex());
        println!("Sending Ping SwitchPacket: {}", packet_response.raw.to_hex());
        for packet in conn.wrap_message(&packet_response.raw) {
            sock.send_to(&packet, dest).unwrap();
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
    allowed_peers.insert(credentials.clone(), "my peer");

    let sock = UdpSocket::bind("[::1]:12345").unwrap();
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 54321);

    let mut conn = Wrapper::new_outgoing_connection(
            my_pk, my_sk.clone(), their_pk, credentials, Some(allowed_peers.clone()), "my peer", None);

    let mut inner_conn: Option<Wrapper<()>> = None;


    loop {
        for packet in conn.upkeep() {
            sock.send_to(&packet, dest).unwrap();
        }

        let mut buf = vec![0u8; 1024];
        let (nb_bytes, _addr) = sock.recv_from(&mut buf).unwrap();
        assert!(nb_bytes < 1024);
        buf.truncate(nb_bytes);
        println!("Received packet: {}", buf.to_hex());
        for message in conn.unwrap_message(buf).unwrap() {
            let mut switch_packet = SwitchPacket { raw: message };
            println!("Received switch packet: {}. Type: {:?}, Label: {}, payload: {:?}", switch_packet.raw.to_hex(), switch_packet.packet_type(), switch_packet.label().to_hex(), switch_packet.payload());
            let decision = switch_packet.switch(4, &0b1100);
            match decision {
                RoutingDecision::SelfInterface(_) => {
                    match switch_packet.payload() {
                        Some(SwitchPayload::Control(ControlPacket::Ping { opaque_data, .. })) => {
                            let control_response = ControlPacket::Pong { version: 17, opaque_data: opaque_data };
                            let mut packet_response = SwitchPacket::new_reply(&switch_packet, &PacketType::Opaque, SwitchPayload::Control(control_response)).unwrap();
                            packet_response.switch(4, &0b1000);
                            println!("Sending Pong SwitchPacket: {}", packet_response.raw.to_hex());
                            for packet in conn.wrap_message(&packet_response.raw) {
                                sock.send_to(&packet, dest).unwrap();
                            }

                            random_send_ping(&mut conn, &sock, &dest, &switch_packet);
                        },
                        Some(SwitchPayload::Control(ControlPacket::Pong { opaque_data, .. })) => {
                            assert_eq!(opaque_data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
                            println!("Received pong.");
                        },
                        Some(SwitchPayload::CryptoAuthHandshake(handshake)) => {
                            if !inner_conn.is_some() {
                                let (new_inner_conn, inner_packet) = Wrapper::new_incoming_connection(my_pk, my_sk.clone(), Credentials::None, None, Some(0x12345678), handshake.clone()).unwrap();
                                inner_conn = Some(new_inner_conn);
                                println!("Received CA handshake, containing: {}", inner_packet.to_hex());
                            };
                            let mut inner_conn2 = inner_conn.unwrap();
                            match inner_conn2.unwrap_message(handshake) {
                                Ok(inner_packets) => {
                                    let inner_packet = inner_packets.get(0).unwrap().clone();
                                    println!("Received CA handshake, containing: {}", inner_packet.to_hex());
                                    println!("ie: {}", DataPacket { raw: inner_packet });
                                    let getpeers_message = DataPacket::new(2, &DataPayload::RoutePacket(RoutePacket::GetPeers { transaction_id: b"blah".to_vec() }));
                                    let mut getpeers_serialized = vec![]; // Session handle
                                    getpeers_serialized.extend(getpeers_message.raw);
                                    println!("Sending getpeers: {}", getpeers_serialized.to_hex());
                                    for packet_response in inner_conn2.wrap_message_immediately(&getpeers_serialized) {
                                        let mut switch_packet_response = SwitchPacket::new_reply(&switch_packet, &PacketType::Opaque, SwitchPayload::CryptoAuthHandshake(packet_response)).unwrap();
                                        assert_eq!(switch_packet_response.switch(4, &0b0001), RoutingDecision::Forward(0b0011));
                                        println!("Sending switch packet: {}", switch_packet_response.raw.to_hex());
                                        for packet in conn.wrap_message(&switch_packet_response.raw) {
                                            sock.send_to(&packet, dest).unwrap();
                                        }
                                    }
                                },
                                Err(e) => println!("CA error: {:?}", e),
                            }
                            inner_conn = Some(inner_conn2);
                            random_send_ping(&mut conn, &sock, &dest, &switch_packet);
                        },
                        _ => panic!("Can only handle Pings, Pongs, and CA handshake."),
                    }
                },
                RoutingDecision::Forward(director) => panic!(format!("Can only route to self interface, but switch wanted to forward to director {}.", director)),
            }
        }
    }
}


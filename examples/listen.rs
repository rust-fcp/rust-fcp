extern crate hex;
extern crate rand;
extern crate fcp_cryptoauth;
extern crate fcp_switching;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};
use std::collections::HashMap;

use fcp_cryptoauth::wrapper::*;

use fcp_switching::packet::{SwitchPacket, PacketType, Payload};
use fcp_switching::operation::RoutingDecision;
use fcp_switching::control::ControlPacket;

use hex::ToHex;
use rand::Rng;

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
            my_pk, my_sk, their_pk, credentials, Some(allowed_peers), "my peer");


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
            println!("Received switch packet: {}. Type: {:?}, Label: {}, derivation: {}, additional: {}, payload: {:?}", switch_packet.raw.to_hex(), switch_packet.packet_type(), switch_packet.label().to_hex(), switch_packet.derivation().to_vec().to_hex(), switch_packet.additional().to_vec().to_hex(), switch_packet.payload());
            let decision = switch_packet.switch(4, &0b1100);
            match decision {
                RoutingDecision::SelfInterface(_) => {
                    match switch_packet.payload() {
                        Some(Payload::Control(ControlPacket::Ping { opaque_data, .. })) => {
                            let control_response = ControlPacket::Pong { version: 17, opaque_data: opaque_data };
                            let mut packet_response = SwitchPacket::new_reply(&switch_packet, &PacketType::Opaque, Payload::Control(control_response)).unwrap();
                            packet_response.switch(4, &0b1000);
                            println!("Sending Pong SwitchPacket: {}", packet_response.raw.to_hex());
                            for packet in conn.wrap_message(&packet_response.raw) {
                                sock.send_to(&packet, dest).unwrap();
                            }

                            if rand::thread_rng().next_u32() > 0x7fffffff {
                                let ping = ControlPacket::Ping { version: 17, opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8] };
                                let mut packet_response = SwitchPacket::new_reply(&switch_packet, &PacketType::Opaque, Payload::Control(ping)).unwrap();
                                packet_response.switch(4, &0b1000);
                                println!("{}", packet_response.label().to_vec().to_hex());
                                println!("Sending Ping SwitchPacket: {}", packet_response.raw.to_hex());
                                for packet in conn.wrap_message(&packet_response.raw) {
                                    sock.send_to(&packet, dest).unwrap();
                                }
                            }
                        },
                        Some(Payload::Control(ControlPacket::Pong { opaque_data, .. })) => {
                            assert_eq!(opaque_data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
                            println!("Received pong.");
                        },
                        Some(Payload::CryptoAuthHandshake(_)) => {
                            println!("Received CA handshake, ending.");
                            return
                        },
                        _ => panic!("Can only handle Pings, Pongs, and CA handshake."),
                    }
                },
                _ => panic!("Can only route to self interface."),
            }
        }
    }
}

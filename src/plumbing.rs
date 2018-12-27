use std::collections::VecDeque;
use std::net::Ipv6Addr;

use fcp_cryptoauth::{PublicKey, publickey_to_ipv6addr};

use passive_switch::PassiveSwitch;
use packets::switch::SwitchPacket;
use packets::switch::Payload as SwitchPayload;
use packets::route::RoutePacket;
use operation::{BackwardPath, ForwardPath, Director};
use packets::control::ControlPacket;
use session_manager::SessionManager;
use packets::data::DataPacket;
use packets::data::Payload as DataPayload;
use utils::{new_from_raw_content, make_reply};
use session_manager::SessionHandle;

pub trait RouterTrait {
    /// Called when a RoutePacket is received from the network.
    /// Optionally returns RoutePackets to send back.
    fn on_route_packet(&mut self, packet: &RoutePacket, path: BackwardPath, handle: SessionHandle, pk: PublicKey) -> Vec<RoutePacket>;
}

pub trait NetworkAdapterTrait {
    fn send_to(&mut self, to: Director, packet: &SwitchPacket);
    fn recv_from(&mut self) -> (Director, Vec<SwitchPacket>);

    fn directors(&self) -> Vec<Director>;
    fn get_pk(&self, dir: Director) -> Option<&PublicKey>;
}

pub struct Plumbing<Router: RouterTrait, NetworkAdapter: NetworkAdapterTrait> {
    pub router: Router,
    pub network_adapter: NetworkAdapter,
    pub switch: PassiveSwitch,
    pub session_manager: SessionManager,
    /// If not `None`, holds a list of the opaque data received in Pong
    /// packets. Use only when debugging, as it is a DoS vulnerability.
    pub pongs: Option<VecDeque<Vec<u8>>>,
    /// Received "content" packets. Contains 3-tuples `(src_addr, next_header, content)`.
    pub rx_buffer: VecDeque<(Ipv6Addr, u8, Vec<u8>)>,
}

impl<Router: RouterTrait, NetworkAdapter: NetworkAdapterTrait> Plumbing<Router, NetworkAdapter> {
    fn on_control_packet(&mut self, packet: ControlPacket, path: BackwardPath) {
        match packet {
            ControlPacket::Ping { opaque_data, .. } => {
                // If it is a ping packet, just reply to it.
                let control_response = ControlPacket::Pong { version: 18, opaque_data: opaque_data };
                let packet_response = SwitchPacket::new(path.reverse(), SwitchPayload::Control(control_response));
                self.dispatch(packet_response, 0b001);

            },
            ControlPacket::Pong { opaque_data, .. } => {
                if let Some(ref mut pongs) = self.pongs {
                    pongs.push_back(opaque_data);
                }
            },
            _ => panic!("Can only handle Pings and Pongs."),
        }
    }

    /// Called when a switch packet is sent to the self interface
    fn on_self_interface_switch_packet(&mut self, switch_packet: &SwitchPacket)
            -> Option<(SessionHandle, Vec<DataPacket>)> {
        match switch_packet.payload() {
            Some(SwitchPayload::Control(control_packet)) => {
                self.on_control_packet(control_packet, switch_packet.label().into());
                None
            },
            Some(SwitchPayload::CryptoAuthHello(handshake)) => {
                // If it is a CryptoAuth handshake Hello packet (ie. if someone is
                // connecting to us), create a new session for this node.
                let (handle, inner_packet) = self.session_manager.on_hello(handshake, switch_packet);
                Some((handle, vec![DataPacket { raw: inner_packet }]))
            },
            Some(SwitchPayload::CryptoAuthKey(handshake)) => {
                // If it is a CryptoAuth handshake Key packet (ie. if someone is
                // replies to our connection attempt), find its session and
                // update it.
                let (handle, inner_packet) = self.session_manager.on_key(handshake, switch_packet).unwrap();
                Some((handle, vec![DataPacket { raw: inner_packet }]))
            },
            Some(SwitchPayload::CryptoAuthData(handle, ca_message)) => {
                // If it is a CryptoAuth data packet, first read the session
                // handle to know which CryptoAuth session to use to
                // decrypt it.
                let inner_packets = self.session_manager.unwrap_message(handle, ca_message);
                Some((handle, inner_packets))
            }
            _ => panic!("Can only handle Pings, Pongs, and CA."),
        }
    }

    /// Called when a CryptoAuth-wrapped message is received through an end-to-end
    /// session.
    fn on_data_packet(&mut self, data_packet: &DataPacket, handle: SessionHandle, path: BackwardPath) {
        let mut responses = Vec::new();
        {
            let session = self.session_manager.get_session(handle).unwrap();

            let route_packets = match data_packet.payload().unwrap() {
                DataPayload::Ip6Content(next_header, ref content) => {
                    let their_pk = session.conn.their_pk();
                    let their_ipv6_addr = publickey_to_ipv6addr(their_pk);
                    self.rx_buffer.push_back(
                        (their_ipv6_addr, next_header, content.clone())); // TODO: do not clone
                    Vec::new()
                }
                DataPayload::RoutePacket(route_packet) => {
                    self.router.on_route_packet(&route_packet, path, handle, session.conn.their_pk().clone())
                }
            };
            for route_packet in route_packets.into_iter() {
                let getpeers_response = DataPacket::new(1, &DataPayload::RoutePacket(route_packet));
                responses.extend(session.conn
                        .wrap_message_immediately(&getpeers_response.raw)
                        .into_iter()
                        .map(|r| new_from_raw_content(path.reverse(), r, Some(handle))));
            }
        }
        for response in responses {
            self.dispatch(response, 0b001);
        }
    }

    pub fn dispatch(&mut self, packet: SwitchPacket, from_interface: Director)
            -> Option<(SessionHandle, Vec<DataPacket>)> {
        let path = BackwardPath::from(packet.label());
        let (to_self, forward) = self.switch.forward(packet, from_interface);
        for (interface, packet) in forward { self.network_adapter.send_to(interface, &packet) };

        to_self
            .and_then(|packet| self.on_self_interface_switch_packet(&packet))
            .map(|(handle, packets)| {
                for packet in packets.iter() {
                    self.on_data_packet(&packet, handle, path)
                }
                (handle, packets)
            })
    }

    pub fn upkeep(&mut self) -> Vec<(SessionHandle, Vec<DataPacket>)> {
        let (director, messages) = self.network_adapter.recv_from();
        let mut to_self = Vec::new();
        for message in messages.into_iter() {
            if let Some(pkts) = self.dispatch(message, director) {
                to_self.push(pkts);
            }
        }
        to_self
    }
}

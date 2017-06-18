use fcp_cryptoauth::PublicKey;

use passive_switch::PassiveSwitch;
use switch_packet::SwitchPacket;
use switch_packet::Payload as SwitchPayload;
use route_packet::RoutePacket;
use operation::{Label, Director};
use control::ControlPacket;
use session_manager::SessionManager;
use data_packet::DataPacket;
use data_packet::Payload as DataPayload;
use utils::{new_from_raw_content, make_reply};
use session_manager::SessionHandle;

pub trait RouterTrait {
    /// Called when a RoutePacket is received from the network.
    /// Optionally returns RoutePackets to send back.
    fn on_route_packet(&mut self, packet: &RoutePacket, path: Label, handle: u32, pk: PublicKey) -> Vec<RoutePacket>;
}

pub trait NetworkAdapterTrait {
    fn send_to(&mut self, to: Director, packet: &SwitchPacket);
    fn recv_from(&mut self) -> (Director, Vec<SwitchPacket>);
}

pub struct Plumbing<Router: RouterTrait, NetworkAdapter: NetworkAdapterTrait> {
    pub router: Router,
    pub network_adapter: NetworkAdapter,
    pub switch: PassiveSwitch,
    pub session_manager: SessionManager,
}

impl<Router: RouterTrait, NetworkAdapter: NetworkAdapterTrait> Plumbing<Router, NetworkAdapter> {
    fn on_control_packet(&mut self, packet: ControlPacket, switch_packet: &SwitchPacket) {
        match packet {
            ControlPacket::Ping { opaque_data, .. } => {
                // If it is a ping packet, just reply to it.
                let control_response = ControlPacket::Pong { version: 18, opaque_data: opaque_data };
                let packet_response = SwitchPacket::new_reply(switch_packet, SwitchPayload::Control(control_response));
                self.dispatch(packet_response, 0b001);

            },
            ControlPacket::Pong { .. } => {
                // If it is a pong packet, print it.

                // TODO

                //assert_eq!(opaque_data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
                //println!("Received pong (label: {}).", switch_packet.label().to_vec().to_hex());
            },
            _ => panic!("Can only handle Pings and Pongs."),
        }
    }

    /// Called when a switch packet is sent to the self interface
    fn on_self_interface_switch_packet(&mut self, switch_packet: &SwitchPacket)
            -> Option<(SessionHandle, Vec<DataPacket>)> {
        match switch_packet.payload() {
            Some(SwitchPayload::Control(control_packet)) => {
                self.on_control_packet(control_packet, switch_packet);
                None
            },
            Some(SwitchPayload::CryptoAuthHandshake(handshake)) => {
                // If it is a CryptoAuth handshake packet (ie. if someone is
                // connecting to us), create a new session for this node.
                // All CA handshake we receive will be sessions started by
                // other peers, because this switch never starts sessions
                // (routers do, not switches).
                let (handle, inner_packet) = self.session_manager.on_handshake(handshake, switch_packet);
                Some((handle, vec![DataPacket { raw: inner_packet }]))
            },
            Some(SwitchPayload::CryptoAuthData(handle, ca_message)) => {
                // If it is a CryptoAuth data packet, first read the session
                // handle to know which CryptoAuth session to use to
                // decrypt it.
                let inner_packets = match self.session_manager.get_mut(handle) {
                    Some(&mut (_path, ref mut inner_conn)) => {
                        match inner_conn.unwrap_message(ca_message) {
                            Ok(inner_packets) => inner_packets,
                            Err(e) => panic!("CA error: {:?}", e),
                        }
                    }
                    None => panic!("Received unknown handle.")
                };
                let data_packets = inner_packets.into_iter().map(|p| DataPacket { raw: p }).collect();
                Some((handle, data_packets))
            }
            _ => panic!("Can only handle Pings, Pongs, and CA."),
        }
    }

    /// Called when a CryptoAuth-wrapped message is received through an end-to-end
    /// session.
    fn on_data_packet(&mut self, data_packet: &DataPacket, handle: SessionHandle, label: Label) {
        let mut responses = Vec::new();
        {
            let &mut (_path, ref mut conn) = self.session_manager.get_mut(handle).unwrap();

            let route_packets = match data_packet.payload().unwrap() {
                DataPayload::RoutePacket(route_packet) => {
                    self.router.on_route_packet(&route_packet, label, handle, conn.their_pk().clone())
                }
            };
            for route_packet in route_packets.into_iter() {
                let getpeers_response = DataPacket::new(1, &DataPayload::RoutePacket(route_packet));
                responses.extend(conn
                        .wrap_message_immediately(&getpeers_response.raw)
                        .into_iter()
                        .map(|r| new_from_raw_content(&label, r, conn.peer_session_handle())));
            }
        }
        for response in responses {
            self.dispatch(response, 0b001);
        }
    }

    pub fn dispatch(&mut self, packet: SwitchPacket, from_interface: Director)
            -> Option<(SessionHandle, Vec<DataPacket>)> {
        let label = packet.label();
        let (to_self, forward) = self.switch.forward(packet, from_interface);
        for (interface, packet) in forward { self.network_adapter.send_to(interface, &packet) };

        to_self
            .and_then(|packet| self.on_self_interface_switch_packet(&packet))
            .map(|(handle, packets)| {
                for packet in packets.iter() {
                    self.on_data_packet(&packet, handle, label)
                }
                (handle, packets)
            })
    }
}

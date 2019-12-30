use std::collections::VecDeque;
use std::net::Ipv6Addr;

use fcp_cryptoauth::{publickey_to_ipv6addr, PublicKey};

use operation::{BackwardPath, Director, ForwardPath};
use packets::control::ControlPacket;
use packets::data::DataPacket;
use packets::data::Payload as DataPayload;
use packets::data::DATAPACKET_VERSION;
use packets::route::RoutePacket;
use packets::switch::Payload as SwitchPayload;
use packets::switch::SwitchPacket;
use passive_switch::PassiveSwitch;
use session_manager::MySessionHandle;
use session_manager::SessionManager;
use utils::new_from_raw_content;

pub struct Ip6Content {
    pub addr: Ipv6Addr,
    pub next_header: u8,
    pub content: Vec<u8>,
}

pub trait RouterTrait {
    /// Called when a RoutePacket is received from the network.
    /// Optionally returns RoutePackets to send back.
    fn on_route_packet(
        &mut self,
        packet: &RoutePacket,
        path: BackwardPath,
        handle: MySessionHandle,
        pk: PublicKey,
    ) -> Vec<RoutePacket>;
}

pub trait NetworkAdapterTrait {
    fn send_to(&mut self, to: Director, packet: &SwitchPacket);
    fn recv_from(&mut self) -> Option<(Director, Vec<SwitchPacket>)>;

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
    /// Received "content" packets.
    pub rx_buffer: VecDeque<Ip6Content>,
}

impl<Router: RouterTrait, NetworkAdapter: NetworkAdapterTrait> Plumbing<Router, NetworkAdapter> {
    fn on_control_packet(&mut self, packet: ControlPacket, path: BackwardPath) {
        match packet {
            ControlPacket::Ping { opaque_data, .. } => {
                // If it is a ping packet, just reply to it.
                let control_response = ControlPacket::Pong {
                    version: 18,
                    opaque_data: opaque_data,
                };
                let packet_response =
                    SwitchPacket::new(path.reverse(), SwitchPayload::Control(control_response));
                self.dispatch(packet_response, 0b001);
            }
            ControlPacket::Pong { opaque_data, .. } => {
                if let Some(ref mut pongs) = self.pongs {
                    pongs.push_back(opaque_data);
                }
            }
            _ => panic!("Can only handle Pings and Pongs."),
        }
    }

    /// Called when a switch packet is sent to the self interface
    fn on_self_interface_switch_packet(
        &mut self,
        switch_packet: &SwitchPacket,
    ) -> Option<(MySessionHandle, Vec<DataPacket>)> {
        match switch_packet.payload() {
            Some(SwitchPayload::Control(control_packet)) => {
                self.on_control_packet(control_packet, switch_packet.label().into());
                None
            }
            Some(SwitchPayload::CryptoAuthHello(handshake)) => {
                // If it is a CryptoAuth handshake Hello packet (ie. if someone is
                // connecting to us), create a new session for this node.
                let (handle, inner_packet) =
                    self.session_manager.on_hello(handshake, switch_packet);
                if inner_packet.len() > 0 {
                    let inner_packet = DataPacket::new_from_raw(inner_packet)
                        .expect("Could not decode data packet");
                    Some((handle, vec![inner_packet]))
                } else {
                    Some((handle, vec![]))
                }
            }
            Some(SwitchPayload::CryptoAuthKey(handshake)) => {
                // If it is a CryptoAuth handshake Key packet (ie. if someone is
                // replies to our connection attempt), find its session and
                // update it.
                Some(self.session_manager.on_key(handshake, switch_packet))
            }
            Some(SwitchPayload::CryptoAuthData(handle, ca_message)) => {
                // If it is a CryptoAuth data packet, first read the session
                // handle to know which CryptoAuth session to use to
                // decrypt it.
                let handle = MySessionHandle(handle);
                let inner_packets = self.session_manager.unwrap_message(handle, ca_message);
                Some((handle, inner_packets))
            }
            _ => panic!("Can only handle Pings, Pongs, and CA."),
        }
    }

    /// Called when a CryptoAuth-wrapped message is received through an end-to-end
    /// session.
    fn on_data_packet(
        &mut self,
        data_packet: &DataPacket,
        handle: MySessionHandle,
        path: BackwardPath,
    ) {
        let mut responses = Vec::new();
        {
            let session = self.session_manager.get_session(handle).unwrap();

            let route_packets = match data_packet.payload().unwrap() {
                DataPayload::Ip6Content(next_header, ref content) => {
                    let their_pk = session.conn.their_pk();
                    let their_ipv6_addr = publickey_to_ipv6addr(their_pk);
                    self.rx_buffer.push_back(Ip6Content {
                        addr: their_ipv6_addr,
                        next_header,
                        content: content.clone(), // TODO: do not clone
                    });
                    Vec::new()
                }
                DataPayload::RoutePacket(route_packet) => self.router.on_route_packet(
                    &route_packet,
                    path,
                    handle,
                    session.conn.their_pk().clone(),
                ),
            };
            for route_packet in route_packets.into_iter() {
                responses.extend(session.wrap_route_packet(path.reverse(), route_packet));
            }
        }
        for response in responses {
            self.dispatch(response, 0b001);
        }
    }

    pub fn dispatch(
        &mut self,
        packet: SwitchPacket,
        from_interface: Director,
    ) -> Option<(MySessionHandle, Vec<DataPacket>)> {
        let (to_self, forward) = self.switch.forward(packet, from_interface);
        for (interface, packet) in forward {
            self.network_adapter.send_to(interface, &packet)
        }

        if let Some(packet) = to_self.as_ref() {
            let switched_path = BackwardPath(packet.label());

            if let Some((handle, packets)) = self.on_self_interface_switch_packet(&packet) {
                for packet in packets.iter() {
                    self.on_data_packet(&packet, handle, switched_path)
                }
                Some((handle, packets))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn upkeep(&mut self) -> Vec<(MySessionHandle, Vec<DataPacket>)> {
        let mut to_self = Vec::new();
        if let Some((director, messages)) = self.network_adapter.recv_from() {
            for message in messages.into_iter() {
                if let Some(pkts) = self.dispatch(message, director) {
                    to_self.push(pkts);
                }
            }
        }
        self.upkeep2();
        to_self
    }

    fn upkeep2(&mut self) {
        for message in self.session_manager.upkeep() {
            let to_self = self.dispatch(message, 0b001);
            assert!(to_self.is_none());
        }
    }

    pub fn send_hello(&mut self, path: ForwardPath, pk: PublicKey) {
        let _my_handle = self.session_manager.add_outgoing(Some(path), pk);
        self.upkeep2();
    }

    pub fn send_content_to_path(
        &mut self,
        path: ForwardPath,
        pk: PublicKey,
        ip6_next_header: u8,
        content: Vec<u8>,
        immediately: bool,
    ) {
        let (their_handle, messages) = {
            let session = self.session_manager.get_or_make_session_for_pk(pk);
            let data_payload = DataPayload::Ip6Content(ip6_next_header, content);
            let data_packet = DataPacket::new(DATAPACKET_VERSION, &data_payload);
            let messages = if immediately {
                session.conn.wrap_message_immediately(&data_packet.raw())
            } else {
                session.conn.wrap_message(&data_packet.raw())
            };
            (session.their_handle(), messages)
        };

        for message in messages {
            let switch_packet = new_from_raw_content(path, message, their_handle);
            self.dispatch(switch_packet, 0b001);
        }
    }

    pub fn send_content(&mut self, _ip6_content: &Ip6Content) {
        unimplemented!("send_content");
    }
}

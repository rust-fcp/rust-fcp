use std::collections::HashMap;

use fcp_cryptoauth::{peek_pk_key, CAWrapper, Credentials, PublicKey, SecretKey};
use rand;
use rand::Rng;

use operation::{BackwardPath, ForwardPath};
use packets::data::DataPacket;
use packets::data::Payload as DataPayload;
use packets::data::DATAPACKET_VERSION;
use packets::route::RoutePacket;
use packets::switch::SwitchPacket;
use utils::new_from_raw_content;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct SessionHandle(pub u32);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct MySessionHandle(pub SessionHandle);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TheirSessionHandle(pub SessionHandle);

pub struct Session {
    pub path: Option<ForwardPath>,
    pub conn: CAWrapper<()>,
}

impl Session {
    pub fn their_handle(&self) -> Option<TheirSessionHandle> {
        self.conn
            .peer_session_handle()
            .map(SessionHandle)
            .map(TheirSessionHandle)
    }

    pub fn wrap_route_packet(
        &mut self,
        path: ForwardPath,
        route_packet: RoutePacket,
    ) -> Vec<SwitchPacket> {
        let data_packet =
            DataPacket::new(DATAPACKET_VERSION, &DataPayload::RoutePacket(route_packet));

        self.conn
            .wrap_message_immediately(&data_packet.raw())
            .into_iter()
            .map(|r| new_from_raw_content(path, r, self.their_handle()))
            .collect()
    }
}

pub struct SessionManager {
    pub my_pk: PublicKey,
    pub my_sk: SecretKey,
    /// CryptoAuth sessions used to talk to switches/routers. Their packets
    /// themselves are wrapped in SwitchPackets, which are wrapped in the
    /// outer CryptoAuth sessions.
    pub sessions: HashMap<MySessionHandle, Session>,

    /// Map from peer public keys to the session handle I use to decrypt their messages
    pub pk_to_my_handle: HashMap<PublicKey, MySessionHandle>,
}

impl SessionManager {
    pub fn new(my_pk: PublicKey, my_sk: SecretKey) -> SessionManager {
        SessionManager {
            my_pk: my_pk,
            my_sk: my_sk,
            sessions: HashMap::new(),
            pk_to_my_handle: HashMap::new(),
        }
    }

    fn gen_handle(&mut self) -> MySessionHandle {
        loop {
            let handle = MySessionHandle(SessionHandle(rand::thread_rng().next_u32()));
            if !self.sessions.contains_key(&handle) {
                return handle;
            }
        }
    }
    pub fn add_outgoing(
        &mut self,
        path: Option<ForwardPath>,
        node_pk: PublicKey,
    ) -> MySessionHandle {
        let handle = self.gen_handle();
        let conn = CAWrapper::new_outgoing_connection(
            self.my_pk.clone(),
            self.my_sk.clone(),
            node_pk,
            Credentials::None,
            None,
            (),
            Some((handle.0).0),
        );
        self.pk_to_my_handle.insert(node_pk, handle);
        self.sessions.insert(
            handle,
            Session {
                path: path,
                conn: conn,
            },
        );
        handle
    }

    pub fn on_hello(
        &mut self,
        packet: Vec<u8>,
        switch_packet: &SwitchPacket,
    ) -> (MySessionHandle, Vec<u8>) {
        let handle = self.gen_handle();
        let (conn, message) = CAWrapper::new_incoming_connection(
            self.my_pk,
            self.my_sk.clone(),
            Credentials::None,
            None,
            Some((handle.0).0),
            packet,
        )
        .unwrap();
        let path = BackwardPath::from(switch_packet.label()).reverse();
        self.sessions.insert(
            handle,
            Session {
                path: Some(path),
                conn: conn,
            },
        );
        (handle, message)
    }

    pub fn on_key(
        &mut self,
        packet: Vec<u8>,
        switch_packet: &SwitchPacket,
    ) -> (MySessionHandle, Vec<DataPacket>) {
        let pk: PublicKey = peek_pk_key(&packet[..]).expect("Invalid Key packet.");
        let my_handle = *self
            .pk_to_my_handle
            .get(&pk)
            .expect("Got Key message from a node I never sent a Hello to.");
        let path = BackwardPath::from(switch_packet.label()).reverse();
        self.sessions
            .get_mut(&my_handle)
            .expect("Invalid handle")
            .path = Some(path);
        (my_handle, self.unwrap_message(my_handle, packet))
    }

    pub fn unwrap_message(&mut self, handle: MySessionHandle, packet: Vec<u8>) -> Vec<DataPacket> {
        let session = self.sessions.get_mut(&handle).unwrap();
        let raw_packets = session.conn.unwrap_message(packet).unwrap();
        raw_packets
            .into_iter()
            .map(|raw| DataPacket::new_from_raw(raw).expect("Could not decode data packet"))
            .collect()
    }

    pub fn get_session(&mut self, handle: MySessionHandle) -> Option<&mut Session> {
        self.sessions.get_mut(&handle)
    }

    pub fn get_session_for_pk(&mut self, pk: PublicKey) -> Option<&mut Session> {
        for (_handle, session) in self.sessions.iter_mut() {
            if *session.conn.their_pk() == pk {
                return Some(session);
            }
        }
        None
    }

    pub fn get_or_make_session_for_pk(&mut self, pk: PublicKey) -> &mut Session {
        if self.get_session_for_pk(pk).is_none() {
            let handle = self.add_outgoing(None, pk);
            self.sessions.get_mut(&handle).unwrap()
        } else {
            self.get_session_for_pk(pk).unwrap()
        }
    }

    pub fn upkeep(&mut self) -> Vec<SwitchPacket> {
        let mut packets = Vec::new();
        for (_my_handle, ref mut session) in self.sessions.iter_mut() {
            let their_handle = session
                .conn
                .peer_session_handle()
                .map(SessionHandle)
                .map(TheirSessionHandle);
            for ca_message in session.conn.upkeep() {
                if let Some(path) = session.path {
                    packets.push(new_from_raw_content(path, ca_message, their_handle));
                }
            }
        }
        packets
    }
}

#[cfg(test)]
mod tests {}

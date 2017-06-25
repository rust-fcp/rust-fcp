use std::collections::HashMap;

use rand;
use rand::Rng;
use fcp_cryptoauth::{CAWrapper, PublicKey, SecretKey, Credentials};

use operation::{ForwardPath, BackwardPath};
use packets::switch::SwitchPacket;
use packets::data::DataPacket;
use utils::new_from_raw_content;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct SessionHandle(pub u32);

pub struct Session {
    pub path: ForwardPath,
    pub conn: CAWrapper<()>,
}

pub struct SessionManager {
    pub my_pk: PublicKey,
    pub my_sk: SecretKey,
    /// CryptoAuth sessions used to talk to switches/routers. Their packets
    /// themselves are wrapped in SwitchPackets, which are wrapped in the
    /// outer CryptoAuth sessions.
    pub sessions: HashMap<SessionHandle, Session>,

    pub path_to_handle: HashMap<BackwardPath, SessionHandle>,
}

impl SessionManager {
    pub fn new(my_pk: PublicKey, my_sk: SecretKey) -> SessionManager {
        SessionManager {
            my_pk: my_pk,
            my_sk: my_sk,
            sessions: HashMap::new(),
            path_to_handle: HashMap::new(),
        }
    }

    fn gen_handle(&mut self) -> SessionHandle {
        loop {
            let handle = SessionHandle(rand::thread_rng().next_u32());
            if !self.sessions.contains_key(&handle) {
                return handle;
            }
        }
    }
    pub fn add_outgoing(&mut self, path: ForwardPath, node_pk: PublicKey, credentials: Credentials) -> SessionHandle {
        let conn = CAWrapper::new_outgoing_connection(
                self.my_pk.clone(), self.my_sk.clone(),
                node_pk,
                credentials, None,
                (), None);
        let handle = self.gen_handle();
        self.path_to_handle.insert(path.clone().reverse(), handle);
        self.sessions.insert(handle, Session { path: path, conn: conn });
        handle
    }

    pub fn on_hello(&mut self, packet: Vec<u8>, switch_packet: &SwitchPacket) -> (SessionHandle, Vec<u8>) {
        let handle = self.gen_handle();
        let (conn, message) = CAWrapper::new_incoming_connection(self.my_pk, self.my_sk.clone(), Credentials::None, None, Some(handle.0), packet).unwrap();
        let path = BackwardPath::from(switch_packet.label()).reverse();
        self.sessions.insert(handle, Session { path: path, conn: conn });
        (handle, message)
    }

    pub fn on_key(&mut self, packet: Vec<u8>, switch_packet: &SwitchPacket) -> Option<(SessionHandle, Vec<u8>)> {
        // TODO: use pk instead of path to find the session.
        self.path_to_handle.get(&BackwardPath::from(switch_packet.label()))
            .cloned()
            .map(|handle| {
            let (conn, message) = CAWrapper::new_incoming_connection(self.my_pk, self.my_sk.clone(), Credentials::None, None, Some(handle.0), packet).unwrap();
            let path = BackwardPath::from(switch_packet.label()).reverse();
            self.sessions.insert(handle, Session { path: path, conn: conn });
            (handle, message)
        })
    }


    pub fn unwrap_message(&mut self, handle: SessionHandle, packet: Vec<u8>) -> Vec<DataPacket> {
        let session = self.sessions.get_mut(&handle).unwrap();
        let raw_packets = session.conn.unwrap_message(packet).unwrap();
        raw_packets.into_iter().map(|raw| DataPacket { raw: raw }).collect()
    }

    pub fn get_session(&mut self, handle: SessionHandle) -> Option<&mut Session> {
        self.sessions.get_mut(&handle)
    }

    pub fn upkeep(&mut self) -> Vec<SwitchPacket> {
        let mut packets = Vec::new();
        for (handle, ref mut session) in self.sessions.iter_mut() {
            for ca_message in session.conn.upkeep() {
                packets.push(new_from_raw_content(session.path, ca_message, Some(*handle)));
            }
        }
        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}

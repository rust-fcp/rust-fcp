use std::collections::HashMap;

use rand;
use rand::Rng;
use fcp_cryptoauth::{CAWrapper, PublicKey, SecretKey, Credentials};

use operation::{ForwardPath, BackwardPath};
use switch_packet::SwitchPacket;

pub type SessionHandle = u32;

pub struct SessionManager {
    pub my_pk: PublicKey,
    pub my_sk: SecretKey,
    /// CryptoAuth sessions used to talk to switches/routers. Their packets
    /// themselves are wrapped in SwitchPackets, which are wrapped in the
    /// outer CryptoAuth sessions.
    pub e2e_conns: HashMap<SessionHandle, (ForwardPath, CAWrapper<()>)>,
}

impl SessionManager {
    fn gen_handle(&mut self) -> SessionHandle {
        loop {
            let handle = rand::thread_rng().next_u32();
            if !self.e2e_conns.contains_key(&handle) {
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
        self.e2e_conns.insert(handle, (path, conn));
        handle
    }

    pub fn on_handshake(&mut self, packet: Vec<u8>, switch_packet: &SwitchPacket) -> (SessionHandle, Vec<u8>)  {
        // TODO: handle Key packets
        let handle = self.gen_handle();
        let (inner_conn, inner_packet) = CAWrapper::new_incoming_connection(self.my_pk, self.my_sk.clone(), Credentials::None, None, Some(handle), packet).unwrap();
        let path = BackwardPath::from(switch_packet.label()).reverse();
        self.e2e_conns.insert(handle, (path, inner_conn));
        (handle, inner_packet)
    }

    pub fn get_mut(&mut self, handle: SessionHandle) -> Option<&mut (ForwardPath, CAWrapper<()>)> {
        self.e2e_conns.get_mut(&handle)
    }
}

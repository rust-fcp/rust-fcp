use std::collections::VecDeque;
use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;

use fcp_cryptoauth::PublicKey;

use plumbing::NetworkAdapterTrait;
use packets::switch::SwitchPacket;
use operation::Director;

pub struct MockNetworkAdapter {
    pub peers: HashMap<Director, PublicKey>,
    pub out_queues: HashMap<Director, Rc<RefCell<VecDeque<SwitchPacket>>>>,
    pub in_queues: HashMap<Director, Rc<RefCell<VecDeque<SwitchPacket>>>>,
}

impl NetworkAdapterTrait for MockNetworkAdapter {
    fn send_to(&mut self, to: Director, packet: &SwitchPacket) {
        let queue = self.out_queues.get(&to).expect("Unknown director");
        queue.borrow_mut().push_back(SwitchPacket { raw: packet.raw.clone() })
    }

    fn recv_from(&mut self) -> (Director, Vec<SwitchPacket>) {
        for (dir, queue) in self.in_queues.iter() {
            if let Some(pkt) = queue.borrow_mut().pop_front() {
                return (*dir, vec![pkt]);
            }
        }
        panic!("No packet");
    }

    fn directors(&self) -> Vec<Director> {
        self.peers.keys().cloned().collect()
    }
    fn get_pk(&self, dir: Director) -> Option<&PublicKey> {
        self.peers.get(&dir)
    }
}


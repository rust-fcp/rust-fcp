use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::rc::Rc;

use fcp_cryptoauth::PublicKey;

use operation::Director;
use packets::switch::SwitchPacket;
use plumbing::NetworkAdapterTrait;

pub struct MockNetworkAdapter {
    pub peers: HashMap<Director, PublicKey>,
    pub out_queues: HashMap<Director, Rc<RefCell<VecDeque<SwitchPacket>>>>,
    pub in_queues: HashMap<Director, Rc<RefCell<VecDeque<SwitchPacket>>>>,
}

impl NetworkAdapterTrait for MockNetworkAdapter {
    fn send_to(&mut self, to: Director, packet: &SwitchPacket) {
        let queue = self.out_queues.get(&to).expect("Unknown director");
        queue.borrow_mut().push_back(SwitchPacket {
            raw: packet.raw.clone(),
        })
    }

    fn recv_from(&mut self) -> Option<(Director, Vec<SwitchPacket>)> {
        for (dir, queue) in self.in_queues.iter() {
            if let Some(pkt) = queue.borrow_mut().pop_front() {
                return Some((*dir, vec![pkt]));
            }
        }
        None
    }

    fn directors(&self) -> Vec<Director> {
        self.peers.keys().cloned().collect()
    }
    fn get_pk(&self, dir: Director) -> Option<&PublicKey> {
        self.peers.get(&dir)
    }
}

extern crate fcp;
extern crate fcp_cryptoauth;

use std::collections::VecDeque;
use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;

use fcp_cryptoauth::*;

use fcp::packets::control::ControlPacket;
use fcp::packets::switch::SwitchPacket;
use fcp::packets::switch::Payload as SwitchPayload;
use fcp::passive_switch::PassiveSwitch;
use fcp::operation::Director;
use fcp::plumbing::{Plumbing,NetworkAdapterTrait};
use fcp::router::Router;
use fcp::session_manager::SessionManager;
use fcp::operation::ForwardPath;

#[cfg(not(feature="sfcp"))]
use fcp::operation::label_from_u64;
#[cfg(feature="sfcp")]
use fcp::operation::label_from_u128;

#[derive(Default)]
struct MockNetworkAdapter {
    out_queues: HashMap<Director, Rc<RefCell<VecDeque<SwitchPacket>>>>,
    in_queues: HashMap<Director, Rc<RefCell<VecDeque<SwitchPacket>>>>,
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
}

type MockPlumbing = Plumbing<Router, MockNetworkAdapter>;

fn setup_nodes() -> (PublicKey, MockPlumbing, PublicKey, MockPlumbing) {
    let sk1 = SecretKey::from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e").unwrap();
    let pk1 = PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let sk2 = SecretKey::from_hex(b"824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8").unwrap();
    let pk2 = PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    let login = "node2_login".to_owned().into_bytes();
    let password = "node2_pass".to_owned().into_bytes();
    let credentials = Credentials::LoginPassword {
        login: login,
        password: password,
    };
    let mut allowed_peers = HashMap::new();
    allowed_peers.insert(credentials.clone(), "node2".to_owned());

    let queue_1to2 = Rc::new(RefCell::new(VecDeque::new()));
    let queue_2to1 = Rc::new(RefCell::new(VecDeque::new()));

    let mut in_queues1 = HashMap::new();
    let mut out_queues1 = HashMap::new();
    let mut in_queues2 = HashMap::new();
    let mut out_queues2 = HashMap::new();

    in_queues1.insert(0b010, queue_1to2.clone());
    out_queues2.insert(0b011, queue_1to2.clone());
    out_queues1.insert(0b010, queue_2to1.clone());
    in_queues2.insert(0b011, queue_2to1.clone());

    let session_manager1 = SessionManager::new(pk1.clone(), sk1.clone());
    let node1 = Plumbing {
        router: Router::new(pk1.clone()),
        network_adapter: MockNetworkAdapter {
            in_queues: in_queues1,
            out_queues: out_queues1,
        },
        switch: PassiveSwitch::new(pk1.clone(), sk1.clone(), allowed_peers),
        session_manager: session_manager1,
        pongs: Some(VecDeque::new()),
    };

    let session_manager2 = SessionManager::new(pk2.clone(), sk2.clone());
    let node2 = Plumbing {
        router: Router::new(pk2.clone()),
        network_adapter: MockNetworkAdapter {
            in_queues: in_queues2,
            out_queues: out_queues2,
        },
        switch: PassiveSwitch::new(pk2.clone(), sk2.clone(), HashMap::new()),
        session_manager: session_manager2,
        pongs: Some(VecDeque::new()),
    };

    (pk1, node1, pk2, node2)
}


#[test]
fn switchctrl_ping_peer() {
    fcp_cryptoauth::init();

    let (pk1, mut node1, pk2, mut node2) = setup_nodes();

    assert_eq!(node1.session_manager.upkeep().len(), 0);
    assert_eq!(node2.session_manager.upkeep().len(), 0);

    #[cfg(not(feature="sfcp"))]
    let path = ForwardPath(label_from_u64(0b001_010));
    #[cfg(feature="sfcp")]
    let path = ForwardPath(label_from_u128(0b001_010));

    let handle_1to2 = node1.session_manager.add_outgoing(path, pk2, Credentials::None);

    let ctrl_pkt = ControlPacket::Ping { version: 18, opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8] };
    let switch_pkt = SwitchPacket::new(path, SwitchPayload::Control(ctrl_pkt));
    println!("{:?}", switch_pkt);
    let to_self1 = node1.dispatch(switch_pkt, 0b001);
    assert!(to_self1.is_none());

    let to_self2 = node2.upkeep();
    assert_eq!(to_self2.len(), 0);

    assert_eq!(node1.pongs.as_ref().unwrap().len(), 0);
    assert_eq!(node2.pongs.as_ref().unwrap().len(), 0);

    let to_self1 = node1.upkeep();
    assert_eq!(to_self1.len(), 0);

    assert_eq!(node1.pongs.as_ref().unwrap().len(), 1);
    assert_eq!(node2.pongs.as_ref().unwrap().len(), 0);
}

extern crate fcp;
extern crate fcp_cryptoauth;

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::rc::Rc;

use fcp_cryptoauth::*;

use fcp::mocks::MockNetworkAdapter;
use fcp::operation::ForwardPath;
use fcp::packets::control::ControlPacket;
use fcp::packets::data::DataPacket;
use fcp::packets::data::Payload as DataPayload;
use fcp::packets::switch::Payload as SwitchPayload;
use fcp::packets::switch::SwitchPacket;
use fcp::passive_switch::PassiveSwitch;
use fcp::plumbing::Plumbing;
use fcp::router::Router;
use fcp::session_manager::SessionManager;

#[cfg(feature = "sfcp")]
use fcp::operation::label_from_u128;
#[cfg(not(feature = "sfcp"))]
use fcp::operation::label_from_u64;

pub type MockPlumbing = Plumbing<Router, MockNetworkAdapter>;

fn setup_nodes() -> (
    PublicKey,
    MockPlumbing,
    PublicKey,
    MockPlumbing,
    PublicKey,
    MockPlumbing,
) {
    let sk1 =
        SecretKey::from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e")
            .unwrap();
    let pk1 =
        PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let sk2 =
        SecretKey::from_hex(b"824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8")
            .unwrap();
    let pk2 =
        PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    let sk3 =
        SecretKey::from_hex(b"3e620844d1343a2e557110238c4ab19eee44ca0cb7654cef50dea82e59bd2ce2")
            .unwrap();
    let pk3 =
        PublicKey::from_base32(b"0gqdmv240dd33zrm1w44x0k99nf5sk8xkwgyvwwv4tgxj9v7tdm0.k").unwrap();
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
    let queue_3to2 = Rc::new(RefCell::new(VecDeque::new()));
    let queue_2to3 = Rc::new(RefCell::new(VecDeque::new()));

    let mut peers1 = HashMap::new();
    let mut in_queues1 = HashMap::new();
    let mut out_queues1 = HashMap::new();
    let mut peers2 = HashMap::new();
    let mut in_queues2 = HashMap::new();
    let mut out_queues2 = HashMap::new();
    let mut peers3 = HashMap::new();
    let mut in_queues3 = HashMap::new();
    let mut out_queues3 = HashMap::new();

    peers1.insert(0b010, pk2);
    in_queues1.insert(0b010, queue_2to1.clone());
    out_queues1.insert(0b010, queue_1to2.clone());

    peers2.insert(0b011, pk1);
    in_queues2.insert(0b011, queue_1to2.clone());
    out_queues2.insert(0b011, queue_2to1.clone());

    peers2.insert(0b100, pk3);
    in_queues2.insert(0b100, queue_3to2.clone());
    out_queues2.insert(0b100, queue_2to3.clone());

    peers3.insert(0b101, pk2);
    in_queues3.insert(0b101, queue_2to3.clone());
    out_queues3.insert(0b101, queue_3to2.clone());

    let session_manager1 = SessionManager::new(pk1.clone(), sk1.clone());
    let node1 = Plumbing {
        router: Router::new(pk1.clone()),
        network_adapter: MockNetworkAdapter {
            peers: peers1,
            in_queues: in_queues1,
            out_queues: out_queues1,
        },
        switch: PassiveSwitch::new(pk1.clone(), sk1.clone(), allowed_peers),
        session_manager: session_manager1,
        pongs: Some(VecDeque::new()),
        rx_buffer: VecDeque::new(),
    };

    let session_manager2 = SessionManager::new(pk2.clone(), sk2.clone());
    let node2 = Plumbing {
        router: Router::new(pk2.clone()),
        network_adapter: MockNetworkAdapter {
            peers: peers2,
            in_queues: in_queues2,
            out_queues: out_queues2,
        },
        switch: PassiveSwitch::new(pk2.clone(), sk2.clone(), HashMap::new()),
        session_manager: session_manager2,
        pongs: Some(VecDeque::new()),
        rx_buffer: VecDeque::new(),
    };

    let session_manager3 = SessionManager::new(pk3.clone(), sk3.clone());
    let node3 = Plumbing {
        router: Router::new(pk3.clone()),
        network_adapter: MockNetworkAdapter {
            peers: peers3,
            in_queues: in_queues3,
            out_queues: out_queues3,
        },
        switch: PassiveSwitch::new(pk3.clone(), sk3.clone(), HashMap::new()),
        session_manager: session_manager3,
        pongs: Some(VecDeque::new()),
        rx_buffer: VecDeque::new(),
    };

    (pk1, node1, pk2, node2, pk3, node3)
}

#[test]
fn switchctrl_ping_path() {
    fcp_cryptoauth::init();

    let (_pk1, mut node1, _pk2, mut node2, _pk3, mut node3) = setup_nodes();

    assert_eq!(node1.session_manager.upkeep().len(), 0);
    assert_eq!(node2.session_manager.upkeep().len(), 0);

    #[cfg(not(feature = "sfcp"))]
    let path = ForwardPath(label_from_u64(0b001_100_010));
    #[cfg(feature = "sfcp")]
    let path = ForwardPath(label_from_u128(0b001_100_010));

    let ctrl_pkt = ControlPacket::Ping {
        version: 18,
        opaque_data: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };
    let switch_pkt = SwitchPacket::new(path, SwitchPayload::Control(ctrl_pkt));
    let to_self1 = node1.dispatch(switch_pkt, 0b001);
    assert!(to_self1.is_none());

    let to_self2 = node2.upkeep();
    assert_eq!(to_self2.len(), 0);

    let to_self3 = node3.upkeep();
    assert_eq!(to_self3.len(), 0);

    let to_self2 = node2.upkeep();
    assert_eq!(to_self2.len(), 0);

    assert_eq!(node1.pongs.as_ref().unwrap().len(), 0);
    assert_eq!(node2.pongs.as_ref().unwrap().len(), 0);
    assert_eq!(node3.pongs.as_ref().unwrap().len(), 0);

    let to_self1 = node1.upkeep();
    assert_eq!(to_self1.len(), 0);

    assert_eq!(node1.pongs.as_ref().unwrap().len(), 1);
    assert_eq!(node2.pongs.as_ref().unwrap().len(), 0);
    assert_eq!(node3.pongs.as_ref().unwrap().len(), 0);
}

#[test]
fn nodata_session_path() {
    fcp_cryptoauth::init();

    let (_pk1, mut node1, _pk2, mut node2, pk3, mut node3) = setup_nodes();

    assert_eq!(node1.session_manager.upkeep().len(), 0);
    assert_eq!(node2.session_manager.upkeep().len(), 0);

    #[cfg(not(feature = "sfcp"))]
    let path = ForwardPath(label_from_u64(0b001_100_010));
    #[cfg(feature = "sfcp")]
    let path = ForwardPath(label_from_u128(0b001_100_010));

    node1.send_hello(path, pk3);

    let to_self2 = node2.upkeep();
    assert_eq!(to_self2.len(), 0);

    let to_self3 = node3.upkeep();
    assert_eq!(to_self3.len(), 1);
    let (_handle, ref msgs) = to_self3[0];
    assert_eq!(msgs.len(), 0);

    let to_self2 = node2.upkeep();
    assert_eq!(to_self2.len(), 0);

    let to_self1 = node1.upkeep();
    assert_eq!(to_self1.len(), 1);
    let (_handle, ref msgs) = to_self1[0];
    assert_eq!(msgs.len(), 0);
}

#[test]
fn data_1_to_3_session_path() {
    fcp_cryptoauth::init();

    let (_pk1, mut node1, _pk2, mut node2, pk3, mut node3) = setup_nodes();

    assert_eq!(node1.session_manager.upkeep().len(), 0);
    assert_eq!(node2.session_manager.upkeep().len(), 0);
    assert_eq!(node3.session_manager.upkeep().len(), 0);

    #[cfg(not(feature = "sfcp"))]
    let path = ForwardPath(label_from_u64(0b001_100_010));
    #[cfg(feature = "sfcp")]
    let path = ForwardPath(label_from_u128(0b001_100_010));

    node1.send_content_to_path(path, pk3, 123, vec![1, 2, 3, 4, 5], true);

    let to_self2 = node2.upkeep();
    assert_eq!(to_self2.len(), 0);

    let to_self3 = node3.upkeep();
    assert_eq!(to_self3.len(), 1);
    let (_handle, ref msgs) = to_self3[0];
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs,
        &vec![DataPacket::new(
            1,
            &DataPayload::Ip6Content(123, vec![1, 2, 3, 4, 5])
        )]
    );

    let to_self2 = node2.upkeep();
    assert_eq!(to_self2.len(), 0);

    let to_self1 = node1.upkeep();
    assert_eq!(to_self1.len(), 1);
    let (_handle, ref msgs) = to_self1[0];
    assert_eq!(msgs.len(), 0);
}

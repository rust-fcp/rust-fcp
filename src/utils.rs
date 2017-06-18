use byteorder::BigEndian;
use byteorder::ByteOrder;
use fcp_cryptoauth::CAWrapper;

use operation::{ForwardPath, BackwardPath, reverse_label};
use packets::switch::SwitchPacket;
use packets::switch::Payload as SwitchPayload;
use session_manager::SessionHandle;

/// Creates a switch packet from a raw payload.
/// The content of the packet is given as a byte array (returned by CryptoAuth's
/// `wrap_messages`).
pub fn new_from_raw_content(path: ForwardPath, content: Vec<u8>, handle: Option<SessionHandle>) -> SwitchPacket {
    let first_four_bytes = BigEndian::read_u32(&content[0..4]);
    if first_four_bytes < 4 {
        // If it is a CryptoAuth handshake packet, send it as is.
        SwitchPacket::new(path, SwitchPayload::CryptoAuthHandshake(content))
    }
    else if first_four_bytes == 0xffffffff {
        // Control packet
        unimplemented!()
    }
    else {
        // Otherwise, it is a CryptoAuth data packet. We have to prepend
        // the session handle to the reply.
        // This handle is used by the peer to know this packet is coming
        // from us.
        let peer_handle = handle.unwrap();
        SwitchPacket::new(path, SwitchPayload::CryptoAuthData(peer_handle, content))
    }
}

/// Creates a reply switch packet to an other switch packet.
/// The content of the reply is given as a byte array (returned by CryptoAuth's
/// `wrap_messages`).
pub fn make_reply<PeerId: Clone>(replied_to_packet: &SwitchPacket, reply_content: Vec<u8>, inner_conn: &CAWrapper<PeerId>) -> SwitchPacket {
    let path = BackwardPath::from(replied_to_packet.label()).reverse();
    new_from_raw_content(path, reply_content, inner_conn.peer_session_handle().map(SessionHandle))
}

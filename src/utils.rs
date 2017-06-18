use byteorder::BigEndian;
use byteorder::ByteOrder;
use fcp_cryptoauth::CAWrapper;

use operation::{Label, reverse_label};
use switch_packet::SwitchPacket;
use switch_packet::Payload as SwitchPayload;
use session_manager::SessionHandle;

/// Creates a switch packet from a raw payload.
/// The content of the packet is given as a byte array (returned by CryptoAuth's
/// `wrap_messages`).
pub fn new_from_raw_content(label: &Label, content: Vec<u8>, handle: Option<SessionHandle>) -> SwitchPacket {
    let first_four_bytes = BigEndian::read_u32(&content[0..4]);
    if first_four_bytes < 4 {
        // If it is a CryptoAuth handshake packet, send it as is.
        SwitchPacket::new(label, SwitchPayload::CryptoAuthHandshake(content))
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
        SwitchPacket::new(label, SwitchPayload::CryptoAuthData(peer_handle, content))
    }
}

/// Creates a reply switch packet to an other switch packet.
/// The content of the reply is given as a byte array (returned by CryptoAuth's
/// `wrap_messages`).
pub fn make_reply<PeerId: Clone>(replied_to_packet: &SwitchPacket, reply_content: Vec<u8>, inner_conn: &CAWrapper<PeerId>) -> SwitchPacket {
    let mut label = replied_to_packet.label();
    reverse_label(&mut label);
    new_from_raw_content(&label, reply_content, inner_conn.peer_session_handle())
}

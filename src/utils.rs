use byteorder::BigEndian;
use byteorder::ByteOrder;
use fcp_cryptoauth::CAWrapper;

use switch_packet::SwitchPacket;
use switch_packet::Payload as SwitchPayload;


/// Creates a reply switch packet to an other switch packet.
/// The content of the reply is given as a byte array (returned CryptoAuth's
/// `wrap_messages`).
pub fn make_reply<PeerId: Clone>(replied_to_packet: &SwitchPacket, reply_content: Vec<u8>, inner_conn: &CAWrapper<PeerId>) -> SwitchPacket {
    let first_four_bytes = BigEndian::read_u32(&reply_content[0..4]);
    if first_four_bytes < 4 {
        // If it is a CryptoAuth handshake packet, send it as is.
        SwitchPacket::new_reply(&replied_to_packet, SwitchPayload::CryptoAuthHandshake(reply_content))
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
        let peer_handle = inner_conn.peer_session_handle().unwrap();
        SwitchPacket::new_reply(&replied_to_packet, SwitchPayload::CryptoAuthData(peer_handle, reply_content))
    }
}

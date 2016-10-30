//! Switch control packets.

use byteorder::BigEndian;
use byteorder::ByteOrder;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq)]
#[derive(PartialEq)]
pub enum ErrorType {
    /// No error, everything is ok.
    None,
    /// The switch label was malformed.
    MalformedAddress,
    /// Packet dropped because link is congested.
    Flood,
    /// Packet dropped because node has oversent its limit.
    LinkLimitExceeded,
    /// Message too big to send.
    OversizeMessage,
    /// Message smaller than expected headers.
    UndersizeMessage,
    /// Authentication failed.
    Authentication,
    /// Header is invalid or checksum failed.
    Invalid,
    /// Message could not be sent to its destination through no fault of the sender.
    Undeliverable,
    /// The route enters and leaves through the same interface in one switch.
    LoopRoute,
    /// The switch is unable to represent the return path.
    ReturnPathInvalid,
}

impl ErrorType {
    fn new(type_number: u32) -> Option<ErrorType> {
        match type_number {
            0 => Some(ErrorType::None),
            1 => Some(ErrorType::MalformedAddress),
            2 => Some(ErrorType::Flood),
            3 => Some(ErrorType::LinkLimitExceeded),
            4 => Some(ErrorType::OversizeMessage),
            5 => Some(ErrorType::UndersizeMessage),
            6 => Some(ErrorType::Authentication),
            7 => Some(ErrorType::Invalid),
            8 => Some(ErrorType::UndersizeMessage),
            9 => Some(ErrorType::LoopRoute),
            10 => Some(ErrorType::ReturnPathInvalid),
            _ => None,
        }
    }
    fn type_number(&self) -> u32 {
        match *self {
            ErrorType::None => 0,
            ErrorType::MalformedAddress => 1,
            ErrorType::Flood => 2,
            ErrorType::LinkLimitExceeded => 3,
            ErrorType::OversizeMessage => 4, 
            ErrorType::UndersizeMessage => 5,
            ErrorType::Authentication => 6,
            ErrorType::Invalid => 7,
            ErrorType::Undeliverable => 8,
            ErrorType::LoopRoute => 9,
            ErrorType::ReturnPathInvalid => 10,
        }
    }
}

const PING_MAGIC: u32 = 0x09f91102;
const PONG_MAGIC: u32 = 0x9d74e35b;
const KEYPING_MAGIC: u32 = 0x01234567;
const KEYPONG_MAGIC: u32 = 0x89abcdef;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq)]
#[derive(PartialEq)]
pub enum ControlPacket {
    Error { type_: ErrorType, cause: Vec<u8> },
    Ping { version: u32, opaque_data: Vec<u8> },
    Pong { version: u32, opaque_data: Vec<u8> },
    KeyPing { version: u32, opaque_data: Vec<u8>, key: Vec<u8> },
    KeyPong { version: u32, opaque_data: Vec<u8>, key: Vec<u8> },
}

impl ControlPacket {
    /// Returns a ControlPacket from its raw representation
    pub fn decode(raw: &[u8]) -> Option<ControlPacket> {
        let checksum = BigEndian::read_u16(&raw[0..2]); // TODO: check checksum
        let type_ = BigEndian::read_u16(&raw[2..4]);
        match type_ {
            2 => if raw.len() < 8 { return None },
            3 | 4 => if raw.len() < 18 { return None }, // PING or PONG
            5 | 6 => if raw.len() < 52 { return None }, // KEYPING or KEYPONG
            _ => return None // unknown type
        }

        let res = match type_ {
            2 => {
                let type_number = BigEndian::read_u32(&raw[4..8]);
                match ErrorType::new(type_number) {
                    Some(type_) => {
                        ControlPacket::Error {
                            type_: type_,
                            cause: raw[8..].to_vec(),
                        }
                    }
                    None => return None,
                }
            },
            3 => {
                let magic = BigEndian::read_u32(&raw[4..8]);
                let version = BigEndian::read_u32(&raw[8..12]);
                assert_eq!(magic, PING_MAGIC);
                let opaque_data = raw[12..].to_vec();
                ControlPacket::Ping {
                    version: version,
                    opaque_data: opaque_data,
                }
            },
            4 => {
                let magic = BigEndian::read_u32(&raw[4..8]);
                let version = BigEndian::read_u32(&raw[8..12]);
                assert_eq!(magic, PONG_MAGIC);
                let opaque_data = raw[12..].to_vec();
                ControlPacket::Pong {
                    version: version,
                    opaque_data: opaque_data,
                }
            },
            5 => {
                let magic = BigEndian::read_u32(&raw[4..8]);
                let version = BigEndian::read_u32(&raw[8..12]);
                assert_eq!(magic, KEYPING_MAGIC);
                let opaque_data = raw[56..].to_vec();
                ControlPacket::KeyPing {
                    version: version,
                    opaque_data: opaque_data,
                    key: raw[12..56].to_vec(),
                }
            },
            6 => {
                let magic = BigEndian::read_u32(&raw[4..8]);
                let version = BigEndian::read_u32(&raw[8..12]);
                assert_eq!(magic, KEYPONG_MAGIC);
                let opaque_data = raw[56..].to_vec();
                ControlPacket::KeyPong {
                    version: version,
                    opaque_data: opaque_data,
                    key: raw[12..56].to_vec(),
                }
            },
            _ => panic!("The impossible happened.")
        };
        Some(res)
    }

    /// Return the magic number of this type of packet.
    fn type_number(&self) -> u16 {
        match *self {
            ControlPacket::Error { ..} => 2,
            ControlPacket::Ping { .. } => 3,
            ControlPacket::Pong { .. } => 4,
            ControlPacket::KeyPing { .. } => 5,
            ControlPacket::KeyPong { .. } => 6,
        }
    }

    fn checksum(raw: &[u8]) -> u16 {
        let mut sum = 0u32;
        let length = raw.len();
        let mut i = 0;
        while i < length {
            if i+1 < length {
                sum += ((raw[i] as u32) << 8) + (raw[i+1] as u32);
            }
            else {
                sum += (raw[i] as u32) << 8;
            }
            if sum & 0x80000000 != 0 {
                // We are close to an overflow. Sum the carries.
                sum = (sum & 0xffff) + (sum >> 16);
            }
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !sum as u16
    }

    /// Returns the raw representation of a ControlPacket
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0; 8];
        match *self {
            ControlPacket::Error { ref type_, ref cause } => {
                buf[3] = 2;
                BigEndian::write_u32(&mut buf[4..8], type_.type_number());
                buf.extend_from_slice(cause);
            },
            ControlPacket::Ping { ref version, ref opaque_data } => {
                buf[3] = 3;
                BigEndian::write_u32(&mut buf[4..8], PING_MAGIC);
                buf.extend_from_slice(&vec![0; 4]);
                BigEndian::write_u32(&mut buf[8..12], *version);
                buf.extend_from_slice(opaque_data);
            }
            ControlPacket::Pong { ref version, ref opaque_data } => {
                buf[3] = 4;
                BigEndian::write_u32(&mut buf[4..8], PONG_MAGIC);
                buf.extend_from_slice(&vec![0; 4]);
                BigEndian::write_u32(&mut buf[8..12], *version);
                buf.extend_from_slice(opaque_data);
            }
            ControlPacket::KeyPing { ref version, ref opaque_data, ref key } => {
                buf[3] = 5;
                BigEndian::write_u32(&mut buf[4..8], KEYPING_MAGIC);
                buf.extend_from_slice(&vec![0; 4]);
                BigEndian::write_u32(&mut buf[8..12], *version);
                buf.extend_from_slice(key);
                buf.extend_from_slice(opaque_data);
            }
            ControlPacket::KeyPong { ref version, ref opaque_data, ref key } => {
                buf[3] = 6;
                BigEndian::write_u32(&mut buf[4..8], KEYPONG_MAGIC);
                buf.extend_from_slice(&vec![0; 4]);
                BigEndian::write_u32(&mut buf[8..12], *version);
                buf.extend_from_slice(key);
                buf.extend_from_slice(opaque_data);
            }
        }
        let checksum = ControlPacket::checksum(&buf);
        BigEndian::write_u16(&mut buf[0..2], checksum);
        buf
    }
}

#[cfg(test)]
mod test {
    //! From cjd's tests:
    //! https://github.com/cjdelisle/cjdnsctrl/blob/ba4a953e0484fb3e4d9b7d3a1463c91b43e4aa63/test.js
    use super::*;
    use hex::{ToHex, FromHex};

    #[test]
    fn ping() {
        let raw = Vec::from_hex("a2e5000309f91102000000124d160b1eee2929e12e19a3b1").unwrap();
        let msg = ControlPacket::Ping { version: 18, opaque_data: Vec::from_hex("4d160b1eee2929e12e19a3b1").unwrap() };
        assert_eq!(msg.encode(), raw);
        assert_eq!(ControlPacket::decode(&raw), Some(msg));
    }

    #[test]
    fn pong() {
        let raw = Vec::from_hex("497400049d74e35b0000001280534c66df69e44b496d5bc8").unwrap();
        let msg = ControlPacket::Pong { version: 18, opaque_data: Vec::from_hex("80534c66df69e44b496d5bc8").unwrap() };
        assert_eq!(msg.encode(), raw);
        assert_eq!(ControlPacket::decode(&raw), Some(msg));
    }

    #[test]
    fn keyping() {
        use fcp_cryptoauth::keys::decode_base32;
        let raw = Vec::from_hex("994b00050123456700000012a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f02e29842b42aedb6bce2ead3").unwrap();
        let key = decode_base32(b"3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu740k3m22fplqvqwpspy93").unwrap();
        let msg = ControlPacket::KeyPing { version: 18, opaque_data: vec![], key: key };
        assert_eq!(msg.encode(), raw);
        assert_eq!(ControlPacket::decode(&raw), Some(msg));
    }

    #[test]
    fn keypong() {
        use fcp_cryptoauth::keys::decode_base32;
        let raw = Vec::from_hex("3b96000689abcdef000000126bd2e8e50faca3d987623d6a043c17c0d9e9004e145f8dd90615d34edbb36d6a02e29842b42aedb6bce2ead3").unwrap();
        let key = decode_base32(b"cmnkylz1dx8mx3bdxku80yw20gqmg0s9nsrusdv0psnxnfhqfmu40k3m22fplqvqwpspy93").unwrap();
        let msg = ControlPacket::KeyPong { version: 18, opaque_data: vec![], key: key };
        assert_eq!(msg.encode(), raw);
        assert_eq!(ControlPacket::decode(&raw), Some(msg));
    }

    #[test]
    fn error() {
        let raw = Vec::from_hex("bce300020000000a62c1d23a648114010379000000012d7c000006c378e071c46aefad3aa295fff396371d10678e9833807de083a4a40da39bf0f68f15c4380afbe92405196242a74bb304a8285088579f94fb01867be2171aa8d2c7b54198a89bbdb80c668e9c05").unwrap();
        let msg = ControlPacket::decode(&raw).unwrap();
        match msg {
            ControlPacket::Error { type_, .. } => assert_eq!(type_, ErrorType::ReturnPathInvalid),
            _ => assert!(false),
        }
    }
}

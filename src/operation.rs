//! Implements switching operations described in the Whitepaper:
//! shifting routes and reversing bits.

extern crate byteorder;
use byteorder::ByteOrder;
use byteorder::BigEndian;

/// An encoding of a path in the network
pub type Label = u64;
/// An interface identifier, unique to a node.
pub type Director = u64;

/// Representation of where the packet should be sent, according to the label.
#[derive(Eq)]
#[derive(PartialEq)]
#[derive(Debug)]
pub enum RoutingDecision {
    /// The packet should be routing to the self interface.
    /// The argument will usually be 1, but may be any number
    /// whose binary representation has 0001 as least significant bits, as per
    /// https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#self-interface-director
    SelfInterface(Director),
    /// The packet should be forwarded to the interface identified
    /// by the argument
    Forward(Director),
}

/// Shift bits to the right, and puts the discarded bits to the right and return them
fn right_shift_collect(bits: &mut u64, shift: u8) -> u64 {
    assert!(shift < 64);
    let mask = (0b1u64 << shift) - 1;
    let collected_bits = *bits & mask;
    *bits >>= shift;
    collected_bits
}

#[test]
fn test_right_shift_collect() {
    let mut bits: u64 = 0b0000000000000000000000000_0001_101011_011010_100101101_10111_0100011;
    assert_eq!(0b0100011, right_shift_collect(&mut bits, 7));
    assert_eq!(0b0000000_0000000000000000000000000_0001_101011_011010_100101101_10111, bits);

    assert_eq!(0b10111, right_shift_collect(&mut bits, 5));
    assert_eq!(0b00000_0000000_0000000000000000000000000_0001_101011_011010_100101101, bits);

    assert_eq!(0, right_shift_collect(&mut bits, 0));
    assert_eq!(0b00000_0000000_0000000000000000000000000_0001_101011_011010_100101101, bits);

    let mut bits: u64 = 0b1111111111111111111111111111111111111111111111111111111111111111;
    assert_eq!(0b0111111111111111111111111111111111111111111111111111111111111111, right_shift_collect(&mut bits, 63));
    assert_eq!(0b1, bits);
}

/// Performs a switch operation on the label (using constant director length),
/// as defined by
/// https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#operation :
/// extracts the director and shifts the other bits to the right, and put
/// the reversed origin interface at the left of the label
///
/// # Examples
///
/// Canonical case, inspired from
/// https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#example :
///
/// ```
/// # use fcp_switching::operation::*;
/// let mut label: Label = 0b000000000000000000000000000000000_0001_011010_100101101_10111_0100011;
///
/// assert_eq!(RoutingDecision::Forward(0b0100011), switch(&mut label, 7, &0b1000000));
/// assert_eq!(0b1000000_000000000000000000000000000000000_0001_011010_100101101_10111, label);
///
/// assert_eq!(RoutingDecision::Forward(0b10111), switch(&mut label, 5, &0b11001));
/// assert_eq!(0b11001_1000000_000000000000000000000000000000000_0001_011010_100101101, label);
///
/// assert_eq!(RoutingDecision::Forward(0b100101101), switch(&mut label, 9, &0b110110011));
/// assert_eq!(0b110110011_11001_1000000_000000000000000000000000000000000_0001_011010, label);
///
/// assert_eq!(RoutingDecision::Forward(0b011010), switch(&mut label, 6, &0b010101));
/// assert_eq!(0b010101_110110011_11001_1000000_000000000000000000000000000000000_0001, label);
///
/// assert_eq!(RoutingDecision::SelfInterface(0b0001), switch(&mut label, 4, &0b0110));
/// assert_eq!(0b0110_010101_110110011_11001_1000000_000000000000000000000000000000000, label);
/// ```
///
/// Supports non-canonical self-interfaces:
/// 
/// ```
/// # use fcp_switching::operation::*;
/// let mut label: Label = 0b010101_110110011_11001_1000000_0000000000000000000000000000000_110001;
/// assert_eq!(RoutingDecision::SelfInterface(0b110001), switch(&mut label, 6, &0b100110));
/// assert_eq!(0b100110_010101_110110011_11001_1000000_0000000000000000000000000000000, label);
/// ```
pub fn switch(label: &mut Label, director_length: u8, reversed_origin_iface: &Director) -> RoutingDecision {
    let director = right_shift_collect(label, director_length);
    assert!(reversed_origin_iface < &(0b1u64 << director_length));
    *label += reversed_origin_iface << (64 - director_length);
    if director & 0b1111 == 0b0001 {
        // If it is a self-interface director, as defined by
        // https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#self-interface-director
        RoutingDecision::SelfInterface(director)
    }
    else {
        RoutingDecision::Forward(director)
    }
}

const BYTE_REVERSE_TABLE: [u8; 256] = [
        0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
        0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
        0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
        0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
        0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
        0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
        0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
        0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
        0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
        0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
        0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
        0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
        0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
        0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
        0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
        0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
        0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
        0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
        0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
        0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
        0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
        0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
        0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
        0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
        0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
        0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
        0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
        0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
        0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
        0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
        0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
        0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
        ];

/// Reverse the bits in a label.
///
/// TODO: rewrite this more efficiently?
///
/// # Examples
///
/// ```
/// # use fcp_switching::operation::*;
/// let label: Label = 0b110110011_11001_1000000_000000000000000000000000000_0001_101011_011010;
/// let rev_label = reverse_label(&label);
/// println!("{:b}", label);
/// println!("{:b}", rev_label);
/// assert_eq!(0b010110_110101_1000_000000000000000000000000000_0000001_10011_110011011, rev_label);
/// ```
pub fn reverse_label(label: &Label) -> Label {
    let mut old_bytes = [0u8; 8];
    let mut new_bytes = [0u8; 8];
    BigEndian::write_u64(&mut old_bytes, *label);
    for i in 0..8 {
        new_bytes[i] = BYTE_REVERSE_TABLE[old_bytes[7-i] as usize];
    }
    BigEndian::read_u64(&new_bytes)
}


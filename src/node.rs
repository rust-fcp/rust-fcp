use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::Ipv6Addr;

use simple_kbuckets::Key;

use operation::ForwardPath;

pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Rotates an IPv6 address 64 bits, which is a required preprocessing
/// for computing the XOR metric.
/// See https://github.com/cjdelisle/cjdns/blob/cjdns-v18/doc/Whitepaper.md#the-router
fn rotate_64(i: &[u8; 16]) -> [u8; 16] {
    [
        i[8], i[9], i[10], i[11], i[12], i[13], i[14], i[15], i[0], i[1], i[2], i[3], i[4], i[5],
        i[6], i[7],
    ]
}

pub const ADDRESS_BITS: usize = 16 * 8;

/// Wrapper of `Ipv6Addr` that implements `simple_kbuckets::Key`
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Address {
    bytes: [u8; 16],
}

impl Address {
    pub fn new(bytes: &[u8; 16]) -> Address {
        Address {
            bytes: rotate_64(bytes),
        }
    }
    pub fn bytes(&self) -> [u8; 16] {
        rotate_64(&self.bytes)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let ipv6addr = Ipv6Addr::from(self);
        write!(f, "Address::from(Ipv6Addr::from_str(\"{}\"))", ipv6addr)
    }
}

impl<'a> From<&'a Ipv6Addr> for Address {
    fn from(ipv6addr: &Ipv6Addr) -> Address {
        Address::new(&ipv6addr.octets())
    }
}
impl From<Ipv6Addr> for Address {
    fn from(ipv6addr: Ipv6Addr) -> Address {
        Address::from(&ipv6addr)
    }
}
impl<'a> From<&'a Address> for Ipv6Addr {
    fn from(addr: &Address) -> Ipv6Addr {
        Ipv6Addr::from(addr.bytes())
    }
}
impl From<Address> for Ipv6Addr {
    fn from(addr: Address) -> Ipv6Addr {
        Ipv6Addr::from(&addr)
    }
}

impl Key for Address {
    fn bitxor(&self, other: &Self) -> Self {
        let mut bytes = [0; 16];
        for i in 0..bytes.len() {
            bytes[i] = self.bytes[i] ^ other.bytes[i];
        }
        Address { bytes: bytes }
    }
    fn bits(&self) -> usize {
        self.bytes.to_vec().bits()
    }
}

/// Data of the hash table
#[derive(Clone, Debug)]
pub struct Node {
    public_key: [u8; PUBLIC_KEY_LENGTH],
    path: ForwardPath,
    version: u64,
}

impl Node {
    pub fn new(pk: [u8; PUBLIC_KEY_LENGTH], path: ForwardPath, version: u64) -> Node {
        Node {
            public_key: pk,
            path: path,
            version: version,
        }
    }
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.public_key
    }
    pub fn path(&self) -> ForwardPath {
        self.path
    }
    pub fn version(&self) -> u64 {
        self.version
    }
}

impl Eq for Node {}
impl PartialEq for Node {
    fn eq(&self, other: &Node) -> bool {
        self.public_key == other.public_key
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Node) -> Ordering {
        self.public_key.cmp(&other.public_key)
    }
}
impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Node) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for Node {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key.hash(state);
    }
}

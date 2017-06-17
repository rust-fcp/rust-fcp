extern crate hex;
extern crate byteorder;
extern crate simple_bencode;
extern crate simple_kbuckets;
extern crate fcp_cryptoauth;

#[cfg(test)]
extern crate fcp_cryptoauth;

pub mod operation;
pub mod control;
pub mod switch_packet;
pub mod data_packet;
pub mod route_packet;
pub mod encoding_scheme;
pub mod node;
pub mod node_store;
pub mod router;
pub mod passive_switch;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

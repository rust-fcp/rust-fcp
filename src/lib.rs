extern crate hex;
extern crate byteorder;
extern crate simple_bencode;

#[cfg(test)]
extern crate fcp_cryptoauth;

pub mod operation;
pub mod control;
pub mod switch_packet;
pub mod data_packet;
pub mod route_packet;
pub mod encoding_scheme;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

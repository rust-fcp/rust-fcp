extern crate hex;
extern crate bencode;
extern crate byteorder;
extern crate rustc_serialize;

#[cfg(test)]
extern crate fcp_cryptoauth;

pub mod operation;
pub mod control;
pub mod switch_packet;
pub mod data_packet;
pub mod route_packet;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

extern crate hex;
extern crate byteorder;

#[cfg(test)]
extern crate fcp_cryptoauth;

pub mod operation;
pub mod control;
pub mod switch_packet;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

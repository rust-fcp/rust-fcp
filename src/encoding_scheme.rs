//! Contains structures used for announcing and decoding the Encoding
//! Scheme, as defined in https://github.com/cjdelisle/cjdns/blob/cjdns-v18/doc/Whitepaper.md#encoding-schemes
//!
//! EncodingScheme can be constructed either from bytes (ie. from the network)
//! or from an interator on `EncodingSchemeForm`.
//! Its content can be accessed either by writing it to bytes (ie. to the
//! network) or by turning it `into_iter`ator of `EncodingSchemeForm`.

use std::iter::FromIterator;

/// An item of the Encoding Scheme.
/// See https://github.com/cjdelisle/cjdns/blob/cjdns-v18/doc/Whitepaper.md#definitions
/// for its definition.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct EncodingSchemeForm {
    pub prefix: u64,
    pub bit_count: u8,
    pub prefix_length: u8,
}

/// A list of `EncodingSchemeForm`. Can be serialized to/deserialized from
/// bytes, and constructed from/read to an iterator of `EncodingSchemeForm`.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EncodingScheme {
    bytes: Vec<u8>,
}

impl EncodingScheme {
    pub fn new(bytes: Vec<u8>) -> EncodingScheme {
        EncodingScheme { bytes: bytes }
    }

    pub fn bytes(&self) -> &Vec<u8> {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl IntoIterator for EncodingScheme {
    type Item = EncodingSchemeForm;
    type IntoIter = EncodingSchemeIterator;

    fn into_iter(self) -> EncodingSchemeIterator {
        EncodingSchemeIterator { bytes: self.bytes, window: 0, bits_in_window: 0, bytes_offset: 0 }
    }
}

/// Iterator of `EncodingSchemeForm`, constructed from an instance of
/// `EncodingScheme`
#[derive(Debug)]
pub struct EncodingSchemeIterator {
    bytes: Vec<u8>,
    window: u64, // integer view of a slice of the buffer (in little endian)
    bits_in_window: u8,
    bytes_offset: usize,
}

impl Iterator for EncodingSchemeIterator {
    type Item = EncodingSchemeForm;

    fn next(&mut self) -> Option<EncodingSchemeForm> {
        // Load new bytes in the window, so it is larger than any possible form
        while self.bits_in_window < 5+5+0b11111 {
            let byte = *self.bytes.get(self.bytes_offset).unwrap_or(&0);
            self.window = self.window + ((byte as u64) << self.bits_in_window);
            self.bytes_offset += 1;
            self.bits_in_window += 8;
        }

        if self.window == 0 {
            None
        }
        else {
            assert!(self.bytes_offset <= self.bytes.len()+(5+5+0b11111)/8);
            let prefix_length = self.window as u8 & 0b11111;
            self.window >>= 5;
            self.bits_in_window -= 5;

            let bit_count = self.window as u8 & 0b11111;
            self.window >>= 5;
            self.bits_in_window -= 5;

            let prefix_mask = (0b1 << prefix_length) -1; // mask for the prefix_length last digits
            let prefix = self.window & prefix_mask;
            self.window >>= prefix_length;
            self.bits_in_window -= prefix_length;

            Some(EncodingSchemeForm { prefix: prefix, bit_count: bit_count, prefix_length: prefix_length })
        }
    }
}

impl<'a> FromIterator<&'a EncodingSchemeForm> for EncodingScheme {
    fn from_iter<T: IntoIterator<Item=&'a EncodingSchemeForm>>(forms: T) -> Self {
        let mut bytes = Vec::<u8>::new();
        let mut window = 0u64;
        let mut bits_in_window = 0u8;
        println!("---");
        for form in forms {
            assert!(form.prefix_length <= 0b11111);
            assert!(form.bit_count <= 0b11111);
            assert!(form.prefix < (1 << form.prefix_length));

            window += (form.prefix as u64) << (5+5+bits_in_window);
            window += (form.bit_count as u64) << (5+bits_in_window);
            window += (form.prefix_length as u64) << (bits_in_window);

            bits_in_window += 5+5+form.prefix_length;

            while bits_in_window >= 8 {
                bytes.push((window & 0b11111111) as u8);
                window >>= 8;
                bits_in_window -= 8;
            }
        }

        if bits_in_window > 0 {
            assert!(bits_in_window < 8);
            assert!(window <= 0b11111111);
            bytes.push(window as u8);
        }

        EncodingScheme::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::iter::FromIterator;
    use super::*;

    #[test]
    fn test_trivial() {
        let encoding = vec![0b011_00000, 0b00];
        let forms = vec![EncodingSchemeForm { prefix: 0, bit_count: 3, prefix_length: 0 }];

        assert_eq!(EncodingScheme::new(encoding.clone()).into_bytes(), encoding);
        assert_eq!(EncodingScheme::from_iter(forms.iter()).into_bytes(), encoding);
        assert_eq!(EncodingScheme::new(encoding.clone()).into_iter().collect::<Vec<_>>(), forms);
        assert_eq!(EncodingScheme::from_iter(forms.iter()).into_iter().collect::<Vec<_>>(), forms);
    }

    /// From https://github.com/cjdelisle/cjdns/blob/cjdns-v18/switch/test/EncodingScheme_test.c#L121-L158
    #[test]
    fn test_three() {
        let encoding = b"\x4f\xf4\xff\x29\xd9\xff\x7f\x89\xee\xff\x07".to_vec();
        let forms = vec![
            EncodingSchemeForm {
                prefix_length: 15,
                bit_count: 2,
                prefix: ((1<<15)-1) ^ (1<<1),
            },
            EncodingSchemeForm {
                prefix_length: 20,
                bit_count: 4,
                prefix: ((1<<20)-1) ^ (1<<2),
            },
            EncodingSchemeForm {
                prefix_length: 18,
                bit_count: 8,
                prefix: ((1<<18)-1) ^ (1<<3),
            }
        ];

        assert_eq!(EncodingScheme::new(encoding.clone()).into_bytes(), encoding);
        assert_eq!(EncodingScheme::from_iter(forms.iter()).into_bytes(), encoding);
        assert_eq!(EncodingScheme::new(encoding.clone()).into_iter().collect::<Vec<_>>(), forms);
        assert_eq!(EncodingScheme::from_iter(forms.iter()).into_iter().collect::<Vec<_>>(), forms);
    }
}

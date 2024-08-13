mod header;

use crate::calculate_hmac;
use aes::cipher::KeyIvInit;
use aes::Aes256;
use anyhow::anyhow;
use cbc::cipher::block_padding::{Pkcs7, UnpadError};
use cbc::cipher::BlockDecryptMut;
use cbc::Decryptor;
pub use header::Header;
use hex::{FromHex, ToHex};

#[derive(Debug, Eq, PartialEq)]
pub struct Cipher {
    header: Header,
    ciphertext: Box<[u8]>,
}

impl Cipher {
    /// Create a new encrypted payload from a header and ciphertext.
    #[must_use]
    pub fn new(header: Header, ciphertext: Box<[u8]>) -> Self {
        Self { header, ciphertext }
    }

    #[must_use]
    pub fn is_hmac_valid(&self, key: &[u8]) -> bool {
        calculate_hmac(self.header.iv(), &self.ciphertext, key, self.header.key())
            .map(|hmac| hmac == self.header.hmac())
            .unwrap_or(false)
    }

    /// Decrypt the ciphertext.
    ///
    /// # Errors
    /// Returns an [`UnpadError`] on errors.
    pub fn decrypt(mut self, key: &[u8]) -> Result<Box<[u8]>, UnpadError> {
        Decryptor::<Aes256>::new(key.into(), self.header.iv().into())
            .decrypt_padded_mut::<Pkcs7>(&mut self.ciphertext)
            .map(Box::from)
    }
}

impl FromHex for Cipher {
    type Error = anyhow::Error;

    fn from_hex<T>(hex: T) -> Result<Self, Self::Error>
    where
        T: AsRef<[u8]>,
    {
        Self::try_from(Vec::<u8>::from_hex(hex)?.as_slice())
    }
}

impl TryFrom<&[u8]> for Cipher {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::new(
            Header::try_from(bytes)?,
            bytes
                .get(Header::SIZE..)
                .ok_or_else(|| anyhow!("Too few bytes: {}", bytes.len()))?
                .into(),
        ))
    }
}

impl ToHex for Cipher {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        self.header
            .encode_hex::<String>()
            .chars()
            .chain(self.ciphertext.encode_hex::<String>().chars())
            .collect()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        self.header
            .encode_hex_upper::<String>()
            .chars()
            .chain(self.ciphertext.encode_hex_upper::<String>().chars())
            .collect()
    }
}

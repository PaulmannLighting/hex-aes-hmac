pub use crate::cipher::Cipher;
use crate::Error;
use hex::FromHex;

pub trait Decrypt {
    /// Decrypt the cipher text using the key.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    fn decrypt(&self, key: &[u8]) -> Result<Box<[u8]>, Error>;
}

impl Decrypt for &str {
    fn decrypt(&self, key: &[u8]) -> Result<Box<[u8]>, Error> {
        let payload = Cipher::from_hex(self)?;

        if !payload.is_hmac_valid(key) {
            return Err(Error::InvalidHmac);
        }

        Ok(payload.decrypt(key)?)
    }
}

impl Decrypt for String {
    fn decrypt(&self, key: &[u8]) -> Result<Box<[u8]>, Error> {
        self.as_str().decrypt(key)
    }
}

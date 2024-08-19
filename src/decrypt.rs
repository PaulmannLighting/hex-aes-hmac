use crate::{Cipher, Error};
use hex::FromHex;

pub trait Decrypt {
    /// Decrypt the cipher text using the key.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    fn decrypt(&self, key: &[u8]) -> Result<Box<[u8]>, Error>;
}

impl<T> Decrypt for T
where
    T: AsRef<str>,
{
    fn decrypt(&self, key: &[u8]) -> Result<Box<[u8]>, Error> {
        let payload = Cipher::from_hex(self.as_ref())?;

        if !payload.is_hmac_valid(key) {
            return Err(Error::InvalidHmac);
        }

        Ok(payload.decrypt(key)?)
    }
}

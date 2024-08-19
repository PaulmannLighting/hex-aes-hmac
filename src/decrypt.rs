pub use crate::cipher::Cipher;
use anyhow::anyhow;
use hex::FromHex;

pub trait Decrypt {
    /// Decrypt the cipher text using the key.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    fn decrypt(&self, key: &[u8]) -> anyhow::Result<Box<[u8]>>;
}

impl Decrypt for &str {
    fn decrypt(&self, key: &[u8]) -> anyhow::Result<Box<[u8]>> {
        let payload = Cipher::from_hex(self)?;

        if !payload.is_hmac_valid(key) {
            return Err(anyhow!("Invalid HMAC checksum"));
        }

        payload.decrypt(key).map_err(|error| anyhow!("{error}"))
    }
}

impl Decrypt for String {
    fn decrypt(&self, key: &[u8]) -> anyhow::Result<Box<[u8]>> {
        self.as_str().decrypt(key)
    }
}

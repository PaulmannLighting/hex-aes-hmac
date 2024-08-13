use aes::Aes256;
use anyhow::anyhow;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use cbc::Encryptor;
pub use cipher::{Cipher, Header};
use hex::FromHex;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;

mod cipher;

pub trait Encrypt {
    /// Encrypt the plaintext using the key.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    fn encrypt(&mut self, plaintext: &[u8], key: &[u8]) -> anyhow::Result<Cipher>;
}

impl<T> Encrypt for T
where
    T: CryptoRng + RngCore,
{
    fn encrypt(&mut self, plaintext: &[u8], key: &[u8]) -> anyhow::Result<Cipher> {
        let mut iv = [0; 16];
        self.fill_bytes(&mut iv);
        let mut hmac_key = [0; 16];
        self.fill_bytes(&mut hmac_key);
        let payload = Encryptor::<Aes256>::new(key.into(), iv.as_slice().into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        Ok(Cipher::new(
            Header::new(iv, hmac_key, calculate_hmac(&iv, &payload, key, &hmac_key)?),
            payload.into(),
        ))
    }
}

fn calculate_hmac(
    iv: &[u8],
    payload: &[u8],
    key: &[u8],
    hmac_key: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(hex::encode(hmac_key).as_bytes())?;
    mac.update(hex::encode(iv).as_bytes());
    mac.update(hex::encode(payload).as_bytes());
    mac.update(hex::encode(key).as_bytes());
    Ok(mac.finalize().into_bytes().as_slice().try_into()?)
}

pub trait Decrypt {
    /// Decrypt the cipher text using the key.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    fn decrypt(&self, key: &[u8]) -> anyhow::Result<Box<[u8]>>;
}

impl Decrypt for String {
    fn decrypt(&self, key: &[u8]) -> anyhow::Result<Box<[u8]>> {
        let payload = Cipher::from_hex(self)?;

        if !payload.is_hmac_valid(key) {
            return Err(anyhow!("Invalid HMAC checksum"));
        }

        payload.decrypt(key).map_err(|error| anyhow!("{error}"))
    }
}

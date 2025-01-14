use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use cbc::Encryptor;
use rand::{CryptoRng, RngCore};

use crate::{
    cipher::{IV_SIZE, KEY_SIZE},
    hmac::hmac,
    Cipher, Header,
};

/// Trait to encrypt a plaintext.
pub trait Encrypt {
    /// Encrypt the plaintext using the key.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] on errors.
    fn encrypt(&mut self, plaintext: &[u8], key: &[u8]) -> crate::Result<Cipher>;
}

impl<T> Encrypt for T
where
    T: CryptoRng + RngCore,
{
    fn encrypt(&mut self, plaintext: &[u8], key: &[u8]) -> crate::Result<Cipher> {
        let mut iv = [0; IV_SIZE];
        self.fill_bytes(&mut iv);
        let mut hmac_key = [0; KEY_SIZE];
        self.fill_bytes(&mut hmac_key);
        let payload = Encryptor::<Aes256>::new(key.into(), iv.as_slice().into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        hmac(&iv, &payload, key, &hmac_key)
            .map(|hmac| Cipher::new(Header::new(iv, hmac_key, hmac), payload.into()))
    }
}

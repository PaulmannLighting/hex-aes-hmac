use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn hmac(iv: &[u8], payload: &[u8], key: &[u8], hmac_key: &[u8]) -> crate::Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(hex::encode(hmac_key).as_bytes())?;
    mac.update(hex::encode(iv).as_bytes());
    mac.update(hex::encode(payload).as_bytes());
    mac.update(hex::encode(key).as_bytes());
    Ok(mac.finalize().into_bytes().as_slice().try_into()?)
}

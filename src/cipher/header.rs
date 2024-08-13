use anyhow::anyhow;
use hex::ToHex;

const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 16;
const HMAC_SIZE: usize = 32;

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    iv: [u8; IV_SIZE],
    key: [u8; KEY_SIZE],
    hmac: [u8; HMAC_SIZE],
}

impl Header {
    pub const SIZE: usize = IV_SIZE + KEY_SIZE + HMAC_SIZE;

    #[must_use]
    pub const fn new(iv: [u8; IV_SIZE], key: [u8; KEY_SIZE], hmac: [u8; HMAC_SIZE]) -> Self {
        Self { iv, key, hmac }
    }

    #[must_use]
    pub const fn iv(&self) -> &[u8] {
        &self.iv
    }

    #[must_use]
    pub const fn key(&self) -> &[u8] {
        &self.key
    }

    #[must_use]
    pub const fn hmac(&self) -> &[u8] {
        &self.hmac
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            iv: bytes
                .get(0..KEY_SIZE)
                .ok_or_else(|| anyhow!("Too few bytes: {}", bytes.len()))?
                .try_into()?,
            key: bytes
                .get(KEY_SIZE..IV_SIZE + KEY_SIZE)
                .ok_or_else(|| anyhow!("Too few bytes: {}", bytes.len()))?
                .try_into()?,
            hmac: bytes
                .get(IV_SIZE + KEY_SIZE..Self::SIZE)
                .ok_or_else(|| anyhow!("Too few bytes: {}", bytes.len()))?
                .try_into()?,
        })
    }
}

impl ToHex for Header {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        self.iv
            .encode_hex::<String>()
            .chars()
            .chain(self.key.encode_hex::<String>().chars())
            .chain(self.hmac.encode_hex::<String>().chars())
            .collect()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        self.iv
            .encode_hex_upper::<String>()
            .chars()
            .chain(self.key.encode_hex_upper::<String>().chars())
            .chain(self.hmac.encode_hex_upper::<String>().chars())
            .collect()
    }
}

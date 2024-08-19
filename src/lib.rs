mod cipher;
mod decrypt;
mod encrypt;
mod error;
mod hmac;

pub use cipher::{Cipher, Header};
pub use decrypt::Decrypt;
pub use encrypt::Encrypt;
pub use error::{Error, Kind};
pub type Result<T> = std::result::Result<T, Error>;

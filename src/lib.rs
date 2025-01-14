//! Decryption of AES encrypted text with HMAC validation.

pub use cipher::{Cipher, Header};
pub use decrypt::Decrypt;
pub use encrypt::Encrypt;
pub use error::{Error, Kind};

/// A specialized [`Result`] type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

mod cipher;
mod decrypt;
mod encrypt;
mod error;
mod hmac;

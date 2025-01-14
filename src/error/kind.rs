use std::error::Error;
use std::fmt::Display;

/// The kind of missing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// The initialization vector is missing.
    Iv,
    /// The key is missing.
    Key,
    /// The HMAC is missing.
    Hmac,
    /// The header is missing.
    Header,
}

impl Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Iv => write!(f, "iv"),
            Self::Key => write!(f, "key"),
            Self::Hmac => write!(f, "hmac"),
            Self::Header => write!(f, "header"),
        }
    }
}

impl Error for Kind {}

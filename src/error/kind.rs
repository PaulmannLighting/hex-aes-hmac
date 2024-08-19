use std::error::Error;
use std::fmt::Display;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Iv,
    Key,
    Hmac,
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

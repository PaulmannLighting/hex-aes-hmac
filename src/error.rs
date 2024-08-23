mod kind;

use aes::cipher::block_padding::UnpadError;
use aes::cipher::InvalidLength;
use hex::FromHexError;
pub use kind::Kind;
use std::array::TryFromSliceError;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug)]
pub enum Error {
    InvalidLength(InvalidLength),
    TryFromSliceError(TryFromSliceError),
    FromHexError(FromHexError),
    UnpadError(UnpadError),
    MissingBytes(Kind),
    InvalidHmac,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(error) => Display::fmt(error, f),
            Self::TryFromSliceError(error) => Display::fmt(error, f),
            Self::FromHexError(error) => Display::fmt(error, f),
            Self::UnpadError(error) => Display::fmt(error, f),
            Self::MissingBytes(kind) => write!(f, "Missing bytes: {kind}"),
            Self::InvalidHmac => f.write_str("Invalid HMAC"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidLength(error) => Some(error),
            Self::TryFromSliceError(error) => Some(error),
            Self::FromHexError(error) => Some(error),
            Self::MissingBytes(kind) => Some(kind),
            Self::UnpadError(_) | Self::InvalidHmac => None,
        }
    }
}

impl From<InvalidLength> for Error {
    fn from(error: InvalidLength) -> Self {
        Self::InvalidLength(error)
    }
}

impl From<TryFromSliceError> for Error {
    fn from(error: TryFromSliceError) -> Self {
        Self::TryFromSliceError(error)
    }
}

impl From<FromHexError> for Error {
    fn from(error: FromHexError) -> Self {
        Self::FromHexError(error)
    }
}

impl From<UnpadError> for Error {
    fn from(error: UnpadError) -> Self {
        Self::UnpadError(error)
    }
}

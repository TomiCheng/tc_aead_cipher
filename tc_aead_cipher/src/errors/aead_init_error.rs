//! Common AEAD initialization errors.

use core::convert::Infallible;
use core::error::Error;
use core::fmt;
use core::fmt::Display;

/// A failure while initializing an AEAD construction; `E` is the underlying
/// cipher's initialization error, `Infallible` for constructions without one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadInitError<E = Infallible> {
    /// The key length is unsupported by a construction that keys itself.
    InvalidKeyLength { actual: usize },
    /// The underlying block cipher's block size is unsupported by the construction.
    InvalidBlockSize { actual: usize, required: usize },
    /// The nonce length is outside the range supported by the construction.
    InvalidNonceLength { actual: usize },
    /// The initial associated data is longer than the construction can count.
    InvalidInitialAadLength { actual: usize },
    /// The requested authentication-tag size is unsupported.
    InvalidMacSize { actual: usize },
    /// The requested counter-length parameter is unsupported.
    InvalidCounterSize { actual: usize },
    /// The same key and nonce would be reused for encryption.
    NonceReuse,
    /// A composed primitive failed despite validated internal invariants.
    InternalFailure,
    /// Initialization of the underlying cipher failed.
    Cipher(E),
}

impl<E> Display for AeadInitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { actual } => {
                write!(f, "invalid AEAD key length: {actual} bytes")
            }
            Self::InvalidBlockSize { actual, required } => {
                write!(
                    f,
                    "invalid AEAD block cipher size: requires {required} bytes, got {actual}"
                )
            }
            Self::InvalidNonceLength { actual } => {
                write!(f, "invalid AEAD nonce length: {actual} bytes")
            }
            Self::InvalidInitialAadLength { actual } => {
                write!(
                    f,
                    "invalid AEAD initial associated data length: {actual} bytes"
                )
            }
            Self::InvalidMacSize { actual } => {
                write!(f, "invalid AEAD authentication-tag size: {actual} bytes")
            }
            Self::InvalidCounterSize { actual } => {
                write!(f, "invalid AEAD counter size: {actual} bytes")
            }
            Self::NonceReuse => f.write_str("key and nonce cannot be reused for AEAD encryption"),
            Self::InternalFailure => f.write_str("internal AEAD primitive failure"),
            Self::Cipher(_) => f.write_str("underlying cipher initialization failed"),
        }
    }
}

impl<E: Error + 'static> Error for AeadInitError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cipher(error) => Some(error),
            _ => None,
        }
    }
}

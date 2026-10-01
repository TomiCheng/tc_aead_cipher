//! Common AEAD processing errors.

use core::convert::Infallible;
use core::error::Error;
use core::fmt;
use core::fmt::Display;

/// A failure while processing or finalizing an AEAD operation; `E` is the
/// underlying cipher's error, `Infallible` for constructions without one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadError<E = Infallible> {
    /// The cipher has not been initialized.
    NotInitialized,
    /// Associated data was supplied after message processing started.
    AadAfterData,
    /// Associated data exceeds the engine's fixed buffer capacity.
    AadTooLong { maximum: usize, actual: usize },
    /// The current operation has already been finalized.
    AlreadyFinalized,
    /// The output buffer is shorter than required.
    OutputTooShort { required: usize, available: usize },
    /// The ciphertext does not contain a complete authentication tag.
    CiphertextTooShort { minimum: usize, actual: usize },
    /// Authentication-tag verification failed.
    AuthenticationFailed,
    /// The algorithm's input-length limit would be exceeded.
    InputTooLong,
    /// The complete packet length is not a multiple of the required block size.
    InputNotBlockAligned { block_size: usize, actual: usize },
    /// A composed primitive failed despite validated internal invariants.
    InternalFailure,
    /// A failure reported by the underlying cipher.
    Cipher(E),
}

impl<E> Display for AeadError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("AEAD cipher not initialized"),
            Self::AadAfterData => {
                f.write_str("associated data cannot be added after message processing starts")
            }
            Self::AadTooLong { maximum, actual } => write!(
                f,
                "associated data is too long: maximum {maximum} bytes, got {actual}"
            ),
            Self::AlreadyFinalized => f.write_str("AEAD operation already finalized"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::CiphertextTooShort { minimum, actual } => write!(
                f,
                "ciphertext is too short: requires at least {minimum} bytes, has {actual}"
            ),
            Self::AuthenticationFailed => f.write_str("authentication tag verification failed"),
            Self::InputTooLong => f.write_str("AEAD input length limit exceeded"),
            Self::InputNotBlockAligned { block_size, actual } => write!(
                f,
                "AEAD input length must be a multiple of {block_size} bytes, got {actual}"
            ),
            Self::InternalFailure => f.write_str("internal AEAD primitive failure"),
            Self::Cipher(_) => f.write_str("underlying cipher failed"),
        }
    }
}

impl<E: Error + 'static> Error for AeadError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cipher(error) => Some(error),
            _ => None,
        }
    }
}

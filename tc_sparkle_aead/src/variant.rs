//! SCHWAEMM parameter sets.

use core::fmt::{Display, Formatter};

/// SCHWAEMM parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SparkleVariant {
    /// SCHWAEMM128-128: 128-bit key, nonce, tag, and rate.
    Schwaemm128_128,
    /// SCHWAEMM256-128: 128-bit key and tag with a 256-bit nonce and rate.
    Schwaemm256_128,
    /// SCHWAEMM192-192: 192-bit key, nonce, tag, and rate.
    Schwaemm192_192,
    /// SCHWAEMM256-256: 256-bit key, nonce, tag, and rate.
    Schwaemm256_256,
}

impl SparkleVariant {
    /// Returns the required key length in bytes. Constant time.
    pub const fn key_bytes(self) -> usize {
        match self {
            Self::Schwaemm128_128 | Self::Schwaemm256_128 => BYTES_128,
            Self::Schwaemm192_192 => BYTES_192,
            Self::Schwaemm256_256 => BYTES_256,
        }
    }

    /// Returns the required nonce length in bytes. Constant time.
    pub const fn nonce_bytes(self) -> usize {
        match self {
            Self::Schwaemm128_128 => BYTES_128,
            Self::Schwaemm192_192 => BYTES_192,
            Self::Schwaemm256_128 | Self::Schwaemm256_256 => BYTES_256,
        }
    }

    /// Returns the authentication-tag length in bytes. Constant time.
    pub const fn tag_bytes(self) -> usize {
        self.key_bytes()
    }

    pub(crate) const fn state_words(self) -> usize {
        match self {
            Self::Schwaemm128_128 => 8,
            Self::Schwaemm256_128 | Self::Schwaemm192_192 => 12,
            Self::Schwaemm256_256 => 16,
        }
    }

    pub(crate) const fn slim_steps(self) -> usize {
        match self {
            Self::Schwaemm256_256 => 8,
            _ => 7,
        }
    }

    pub(crate) const fn big_steps(self) -> usize {
        match self {
            Self::Schwaemm128_128 => 10,
            Self::Schwaemm256_128 | Self::Schwaemm192_192 => 11,
            Self::Schwaemm256_256 => 12,
        }
    }
}

impl Display for SparkleVariant {
    /// Writes the variant's name. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Schwaemm128_128 => f.write_str("SCHWAEMM128-128"),
            Self::Schwaemm256_128 => f.write_str("SCHWAEMM256-128"),
            Self::Schwaemm192_192 => f.write_str("SCHWAEMM192-192"),
            Self::Schwaemm256_256 => f.write_str("SCHWAEMM256-256"),
        }
    }
}

/// Number of bytes in a 128-bit SCHWAEMM parameter.
pub(crate) const BYTES_128: usize = 16;
/// Number of bytes in a 192-bit SCHWAEMM parameter.
pub(crate) const BYTES_192: usize = 24;
/// Number of bytes in a 256-bit SCHWAEMM parameter.
pub(crate) const BYTES_256: usize = 32;

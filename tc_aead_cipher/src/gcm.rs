mod engine;
mod ghash;

pub(crate) const BLOCK_BYTES: usize = 16;
/// Smallest supported authentication-tag size in bytes.
pub(crate) const MIN_MAC_BYTES: usize = 4;
/// Largest supported authentication-tag size in bytes.
pub(crate) const MAX_MAC_BYTES: usize = 16;

pub(crate) use ghash::Multiplier;

pub use engine::GcmBlockCipher;

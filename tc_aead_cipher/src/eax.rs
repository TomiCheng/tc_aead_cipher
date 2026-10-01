mod engine;

/// Smallest supported authentication-tag size in bytes.
pub(crate) const MIN_MAC_BYTES: usize = 4;
/// Largest supported block and authentication-tag size in bytes.
pub(crate) const MAX_BLOCK_BYTES: usize = 16;

pub use engine::EaxBlockCipher;

mod engine;

/// Block size required by OCB in bytes.
pub(crate) const BLOCK_BYTES: usize = 16;
/// Smallest supported authentication-tag size in bytes.
pub(crate) const MIN_MAC_BYTES: usize = 8;
/// Largest supported authentication-tag size in bytes.
pub(crate) const MAX_MAC_BYTES: usize = 16;
/// Largest supported nonce size in bytes.
pub(crate) const MAX_NONCE_BYTES: usize = 15;

pub use engine::OcbBlockCipher;

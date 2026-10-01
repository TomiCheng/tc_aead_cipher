mod engine;

pub(crate) const BLOCK_BYTES: usize = 16;
/// Smallest CCM nonce size in bytes.
pub(crate) const MIN_NONCE_BYTES: usize = 7;
/// Largest CCM nonce size in bytes.
pub(crate) const MAX_NONCE_BYTES: usize = 13;
/// Smallest CCM authentication-tag size in bytes.
pub(crate) const MIN_MAC_BYTES: usize = 4;
/// Largest CCM authentication-tag size in bytes.
pub(crate) const MAX_MAC_BYTES: usize = 16;

pub use engine::CcmBlockCipher;

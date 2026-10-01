mod engine;
mod polyval;

/// Block size required by GCM-SIV in bytes.
pub(crate) const BLOCK_BYTES: usize = 16;
/// Nonce size required by GCM-SIV in bytes.
pub(crate) const NONCE_BYTES: usize = 12;
/// Authentication-tag size required by GCM-SIV in bytes.
pub(crate) const MAC_BYTES: usize = 16;
/// Maximum AAD or plaintext length allowed by RFC 8452.
pub(crate) const MAX_INPUT_BYTES: u64 = 1 << 36;

pub use engine::GcmSivBlockCipher;

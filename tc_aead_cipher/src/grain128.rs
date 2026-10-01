mod engine;

/// Secret-key length in bytes.
pub(crate) const KEY_BYTES: usize = 16;
/// Nonce length in bytes.
pub(crate) const NONCE_BYTES: usize = 12;
/// Authentication-tag length in bytes.
pub(crate) const TAG_BYTES: usize = 8;

pub use engine::FixedGrain128Aead;
#[cfg(feature = "alloc")]
pub use engine::Grain128Aead;

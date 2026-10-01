mod engine;

/// Smallest KCCM authentication-tag size in bytes.
pub(crate) const MIN_MAC_BYTES: usize = 8;
/// Largest KCCM authentication-tag size in bytes.
pub(crate) const MAX_MAC_BYTES: usize = 64;

pub use engine::KccmBlockCipher;

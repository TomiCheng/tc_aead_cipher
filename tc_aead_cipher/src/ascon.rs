mod engine;
mod legacy_engine;

/// Secret-key length in bytes.
const KEY_BYTES: usize = 16;
/// Nonce length in bytes.
const NONCE_BYTES: usize = 16;
/// Authentication-tag length in bytes.
const TAG_BYTES: usize = 16;

pub use engine::AsconAead128;
pub use legacy_engine::{AsconLegacyEngine, AsconLegacyVariant};

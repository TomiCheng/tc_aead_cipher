/// Parameters that carry associated data for [`AeadCipherInit::init`](crate::AeadCipherInit::init)
/// to absorb before any [`AeadCipher::process_aad_bytes`](crate::AeadCipher::process_aad_bytes)
/// call.
pub trait InitialAadParams {
    /// Returns the associated data `init` absorbs, empty for none. It stays
    /// part of every message that [`AeadCipher::reset`](crate::AeadCipher::reset)
    /// restarts.
    fn initial_aad(&self) -> &[u8];
}

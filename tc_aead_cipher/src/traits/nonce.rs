/// Parameters that carry the nonce.
pub trait NonceParams {
    /// Returns the nonce. The lengths a construction accepts are checked by
    /// its `init`.
    fn nonce(&self) -> &[u8];
}

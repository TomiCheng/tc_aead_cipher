/// Parameters that carry the nonce.
pub trait NonceParams {
    /// Returns the nonce. The lengths a construction accepts are checked by
    /// its `init`.
    ///
    /// Constant time in this crate's containers, which return their value
    /// without inspecting it; other implementations define their own timing.
    fn nonce(&self) -> &[u8];
}

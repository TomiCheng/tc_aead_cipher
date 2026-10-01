/// Parameters that carry the authentication-tag size.
pub trait MacSizeParams {
    /// Returns the tag size in bytes, not bits as in Bouncy Castle. The sizes
    /// a construction accepts are checked by its `init`.
    ///
    /// Constant time in this crate's containers, which return their value
    /// without inspecting it; other implementations define their own timing.
    fn mac_size(&self) -> usize;
}

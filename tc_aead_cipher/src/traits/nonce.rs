pub trait NonceParams {
    fn nonce(&self) -> &[u8];
}

pub trait InitialAadParams {
    fn initial_aad(&self) -> &[u8];
}

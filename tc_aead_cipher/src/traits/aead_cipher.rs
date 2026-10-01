use core::error::Error;
use tc_block_cipher::CipherDirection;

pub trait AeadCipher {
    type Error: Error;

    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// When decrypting, the output is not authenticated until `do_final`
    /// succeeds; discard it if `do_final` fails.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    fn mac(&self) -> Option<&[u8]>;

    fn reset(&mut self);

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error>;

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error>;
}

pub trait AeadCipherInit<P: ?Sized> {
    type Error: Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}

use core::error::Error;
use tc_block_cipher::CipherDirection;

/// An incremental AEAD engine: associated data first, then the message, then
/// [`do_final`](Self::do_final).
///
/// Each message runs under the key and nonce of the last
/// [`AeadCipherInit::init`]. Associated data is authenticated but neither
/// encrypted nor written to the output. Encryption appends the tag to the
/// ciphertext; decryption expects it at the end of the input and verifies it
/// in `do_final`.
///
/// Each engine documents its timing. Lengths are public throughout: the
/// lengths of the message, the associated data and the nonce, and the tag
/// size, decide how much work is done, and the result of a tag check shows in
/// the outcome. A construction over a block cipher is constant time exactly
/// when that cipher is.
pub trait AeadCipher {
    /// The error returned while processing a message. Engines over a block
    /// cipher report the cipher's own failures through
    /// [`AeadError::Cipher`](crate::AeadError::Cipher).
    type Error: Error;

    /// Adds associated data to the current message.
    ///
    /// It may be supplied in any number of calls, but all of it must come
    /// before the message data; adding it once message processing has started
    /// fails with [`AeadError::AadAfterData`](crate::AeadError::AadAfterData).
    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Encrypts or decrypts `input`, writes the output that is ready and
    /// returns its length.
    ///
    /// An engine may hold input back: decryption keeps the bytes that may turn
    /// out to be the tag, and constructions that need the whole message, such
    /// as CCM and GCM-SIV, write nothing before `do_final`. `output` must hold
    /// at least [`update_output_len`](Self::update_output_len) of
    /// `input.len()` bytes.
    ///
    /// When decrypting, the output is not authenticated until `do_final`
    /// succeeds; discard it if `do_final` fails.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Completes the message, writes the remaining output and returns its
    /// length.
    ///
    /// Encryption writes the rest of the ciphertext followed by the tag.
    /// Decryption verifies the tag and writes the rest of the plaintext only
    /// when it matches; otherwise it fails with
    /// [`AeadError::AuthenticationFailed`](crate::AeadError::AuthenticationFailed).
    /// `output` must hold at least [`output_len`](Self::output_len) of `0`
    /// bytes. The engine is finalized afterwards; see [`reset`](Self::reset)
    /// for what may follow.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Returns the tag of the last successful `do_final`, the bytes that
    /// encryption appended to the ciphertext or decryption verified, or
    /// `None` before one and after any later call that changes the message.
    fn mac(&self) -> Option<&[u8]>;

    /// Discards the current message and returns to the state right after
    /// `init`, including any initial associated data, so that another
    /// message can follow under the same key and nonce.
    ///
    /// Encryption that may already have released output under the nonce is
    /// not restarted, because a second message would reuse the nonce; it
    /// stays finalized until the next `init`. Constructions built to tolerate
    /// nonce reuse, such as GCM-SIV, restart in either direction.
    fn reset(&mut self);

    /// Returns how many bytes [`process_bytes`](Self::process_bytes) writes
    /// for `input_len` further bytes of input, counting the input the engine
    /// already holds.
    ///
    /// Fails with [`AeadError::InputTooLong`](crate::AeadError::InputTooLong)
    /// when the count does not fit in `usize`.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error>;

    /// Returns how many bytes `process_bytes` and `do_final` write together
    /// for `input_len` further bytes of input, counting the input the engine
    /// already holds and the tag; `output_len(0)` sizes the `do_final`
    /// buffer.
    ///
    /// Fails with [`AeadError::InputTooLong`](crate::AeadError::InputTooLong)
    /// when the count does not fit in `usize`.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error>;
}

/// Prepares an [`AeadCipher`] from a parameter value of type `P`.
///
/// An engine implements it for each parameter type it accepts;
/// [`AeadParamsRef`](crate::AeadParamsRef) serves the common case. Parameter
/// types only carry values: lengths and sizes are validated here.
pub trait AeadCipherInit<P: ?Sized> {
    /// The error returned when `init` rejects the parameters or the
    /// underlying cipher fails to key itself.
    type Error: Error;

    /// Starts a new message in `direction` under the key, nonce, tag size and
    /// initial associated data in `params`, discarding any previous state.
    ///
    /// A failed `init` leaves the engine uninitialized. Engines that track
    /// it refuse an encryption `init` that repeats the key and nonce of the
    /// previous `init` on the same instance with
    /// [`AeadInitError::NonceReuse`](crate::AeadInitError::NonceReuse);
    /// nothing tracks nonces across instances, so callers must still never
    /// reuse a nonce under one key.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}

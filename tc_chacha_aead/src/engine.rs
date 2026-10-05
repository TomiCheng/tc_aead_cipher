//! ChaCha20-Poly1305 and XChaCha20-Poly1305 authenticated-encryption engines.

use core::fmt::{self, Display, Formatter};

use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams, MacSizeParams,
    NonceParams,
};
use tc_block_cipher::{CipherDirection, KeyParams};
use tc_chacha::{ChaCha7539Engine, XChaCha20Engine};
use tc_constant_time::fixed_time_eq;
use tc_macs::{KeyRef, Mac, MacError, MacInit};
use tc_poly1305::Poly1305;
use tc_stream_cipher::{
    CipherDirection as StreamDirection, InitError as StreamInitError, KeyWithIvRef, StreamCipher,
    StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

use crate::{KEY_BYTES, NONCE_BYTES, TAG_BYTES, XNONCE_BYTES};

const BLOCK_BYTES: usize = 64;
const MAC_BLOCK_BYTES: usize = 16;
const DECRYPT_BUFFER_BYTES: usize = BLOCK_BYTES + TAG_BYTES;
// Block zero keys Poly1305, so the 32-bit counter leaves 2^32 - 1 blocks for
// the message.
const DATA_LIMIT: u64 = (u32::MAX as u64) * BLOCK_BYTES as u64;
const MAX_NONCE_BYTES: usize = XNONCE_BYTES;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Uninitialized,
    EncryptInit,
    EncryptAad,
    EncryptData,
    EncryptFinal,
    DecryptInit,
    DecryptAad,
    DecryptData,
    DecryptFinal,
}

trait ChaChaStream: StreamCipher<Error = StreamError> {
    const NONCE_BYTES: usize;

    /// Keys the stream at block zero.
    fn start(&mut self, key: &[u8], nonce: &[u8]) -> Result<(), StreamInitError>;
}

impl ChaChaStream for ChaCha7539Engine {
    const NONCE_BYTES: usize = NONCE_BYTES;

    fn start(&mut self, key: &[u8], nonce: &[u8]) -> Result<(), StreamInitError> {
        StreamCipherInit::init(
            self,
            StreamDirection::Encrypt,
            &KeyWithIvRef::new(key, nonce),
        )
    }
}

impl ChaChaStream for XChaCha20Engine {
    const NONCE_BYTES: usize = XNONCE_BYTES;

    fn start(&mut self, key: &[u8], nonce: &[u8]) -> Result<(), StreamInitError> {
        StreamCipherInit::init(
            self,
            StreamDirection::Encrypt,
            &KeyWithIvRef::new(key, nonce),
        )
    }
}

struct Core<C> {
    chacha: C,
    poly1305: Poly1305,
    initial_poly1305: Poly1305,
    buffer: [u8; DECRYPT_BUFFER_BYTES],
    buffer_pos: usize,
    key: [u8; KEY_BYTES],
    nonce: [u8; MAX_NONCE_BYTES],
    nonce_len: usize,
    has_key_nonce: bool,
    aad_count: u64,
    initial_aad_count: u64,
    data_count: u64,
    state: State,
    mac: Option<[u8; TAG_BYTES]>,
}

impl<C> Core<C>
where
    C: ChaChaStream,
{
    const fn new(chacha: C) -> Self {
        Self {
            chacha,
            poly1305: Poly1305::new(),
            initial_poly1305: Poly1305::new(),
            buffer: [0; DECRYPT_BUFFER_BYTES],
            buffer_pos: 0,
            key: [0; KEY_BYTES],
            nonce: [0; MAX_NONCE_BYTES],
            nonce_len: 0,
            has_key_nonce: false,
            aad_count: 0,
            initial_aad_count: 0,
            data_count: 0,
            state: State::Uninitialized,
            mac: None,
        }
    }

    fn check_aad(&mut self) -> Result<(), AeadError> {
        self.state = match self.state {
            State::EncryptInit => State::EncryptAad,
            State::DecryptInit => State::DecryptAad,
            State::EncryptAad | State::DecryptAad => self.state,
            State::EncryptData | State::DecryptData => return Err(AeadError::AadAfterData),
            State::EncryptFinal | State::DecryptFinal => {
                return Err(AeadError::AlreadyFinalized);
            }
            State::Uninitialized => return Err(AeadError::NotInitialized),
        };
        Ok(())
    }

    fn current_direction(&self) -> Result<CipherDirection, AeadError> {
        match self.state {
            State::EncryptInit | State::EncryptAad | State::EncryptData => {
                Ok(CipherDirection::Encrypt)
            }
            State::DecryptInit | State::DecryptAad | State::DecryptData => {
                Ok(CipherDirection::Decrypt)
            }
            State::EncryptFinal | State::DecryptFinal => Err(AeadError::AlreadyFinalized),
            State::Uninitialized => Err(AeadError::NotInitialized),
        }
    }

    fn start_data(&mut self) -> Result<CipherDirection, AeadError> {
        match self.state {
            State::EncryptInit | State::EncryptAad => {
                self.finish_aad(State::EncryptData)?;
                Ok(CipherDirection::Encrypt)
            }
            State::DecryptInit | State::DecryptAad => {
                self.finish_aad(State::DecryptData)?;
                Ok(CipherDirection::Decrypt)
            }
            State::EncryptData => Ok(CipherDirection::Encrypt),
            State::DecryptData => Ok(CipherDirection::Decrypt),
            State::EncryptFinal | State::DecryptFinal => Err(AeadError::AlreadyFinalized),
            State::Uninitialized => Err(AeadError::NotInitialized),
        }
    }

    fn finish_aad(&mut self, next: State) -> Result<(), AeadError> {
        self.pad_mac(self.aad_count)?;
        self.state = next;
        Ok(())
    }

    fn finish_data(&mut self, next: State) -> Result<[u8; TAG_BYTES], AeadError> {
        self.pad_mac(self.data_count)?;

        let mut lengths = [0u8; MAC_BLOCK_BYTES];
        lengths[..8].copy_from_slice(&self.aad_count.to_le_bytes());
        lengths[8..].copy_from_slice(&self.data_count.to_le_bytes());
        self.update_mac(&lengths)?;

        let mut tag = [0u8; TAG_BYTES];
        self.poly1305.do_final(&mut tag).map_err(map_mac_error)?;
        self.state = next;
        Ok(tag)
    }

    fn pad_mac(&mut self, count: u64) -> Result<(), AeadError> {
        const ZEROS: [u8; MAC_BLOCK_BYTES - 1] = [0; MAC_BLOCK_BYTES - 1];
        let partial = count as usize & (MAC_BLOCK_BYTES - 1);
        if partial != 0 {
            self.update_mac(&ZEROS[..MAC_BLOCK_BYTES - partial])?;
        }
        Ok(())
    }

    fn update_mac(&mut self, input: &[u8]) -> Result<(), AeadError> {
        self.poly1305.update(input).map_err(map_mac_error)
    }

    fn process_data(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), AeadError> {
        let input_len = input.len() as u64;
        if self.data_count > DATA_LIMIT.saturating_sub(input_len) {
            return Err(AeadError::InputTooLong);
        }
        self.chacha
            .process_bytes(input, output)
            .map_err(map_stream_error)?;
        self.data_count += input_len;
        Ok(())
    }

    fn process_encrypt_bytes(
        &mut self,
        mut input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AeadError> {
        let mut written = 0;

        if self.buffer_pos != 0 {
            let available = BLOCK_BYTES - self.buffer_pos;
            if input.len() < available {
                self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
                self.buffer_pos += input.len();
                return Ok(0);
            }

            self.buffer[self.buffer_pos..BLOCK_BYTES].copy_from_slice(&input[..available]);
            input = &input[available..];
            let block: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
            self.process_data(&block, &mut output[..BLOCK_BYTES])?;
            self.update_mac(&output[..BLOCK_BYTES])?;
            written = BLOCK_BYTES;
            self.buffer_pos = 0;
        }

        while input.len() >= BLOCK_BYTES {
            self.process_data(
                &input[..BLOCK_BYTES],
                &mut output[written..written + BLOCK_BYTES],
            )?;
            self.update_mac(&output[written..written + BLOCK_BYTES])?;
            input = &input[BLOCK_BYTES..];
            written += BLOCK_BYTES;
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_pos = input.len();
        Ok(written)
    }

    fn process_decrypt_bytes(
        &mut self,
        mut input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AeadError> {
        let mut written = 0;

        while self.buffer_pos.saturating_add(input.len()) >= DECRYPT_BUFFER_BYTES {
            if self.buffer_pos < BLOCK_BYTES {
                let needed = BLOCK_BYTES - self.buffer_pos;
                self.buffer[self.buffer_pos..BLOCK_BYTES].copy_from_slice(&input[..needed]);
                input = &input[needed..];
                self.buffer_pos = BLOCK_BYTES;
            }

            let block: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
            self.update_mac(&block)?;
            self.process_data(&block, &mut output[written..written + BLOCK_BYTES])?;
            written += BLOCK_BYTES;
            self.buffer.copy_within(BLOCK_BYTES..self.buffer_pos, 0);
            self.buffer_pos -= BLOCK_BYTES;
        }

        self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
        self.buffer_pos += input.len();
        Ok(written)
    }

    /// Constant time: only the input length decides the work.
    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), AeadError> {
        self.check_aad()?;
        self.mac = None;
        let input_len = input.len() as u64;
        self.aad_count = self
            .aad_count
            .checked_add(input_len)
            .ok_or(AeadError::InputTooLong)?;
        self.update_mac(input)
    }

    /// Constant time: only the input length decides the work.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AeadError> {
        let direction = self.current_direction()?;
        let required = self.update_output_len(input.len())?;
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let pending_data = match direction {
            CipherDirection::Encrypt => self.buffer_pos.saturating_add(input.len()),
            CipherDirection::Decrypt => self
                .buffer_pos
                .saturating_add(input.len())
                .saturating_sub(TAG_BYTES),
        } as u64;
        if self.data_count > DATA_LIMIT.saturating_sub(pending_data) {
            return Err(AeadError::InputTooLong);
        }

        self.mac = None;
        let started_direction = self.start_data()?;
        debug_assert_eq!(started_direction, direction);
        match direction {
            CipherDirection::Encrypt => self.process_encrypt_bytes(input, output),
            CipherDirection::Decrypt => self.process_decrypt_bytes(input, output),
        }
    }

    /// Constant time: the tag is compared in fixed time.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AeadError> {
        let direction = self.current_direction()?;
        let required = self.output_len(0)?;
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        if direction == CipherDirection::Decrypt && self.buffer_pos < TAG_BYTES {
            self.mac = None;
            return Err(AeadError::CiphertextTooShort {
                minimum: TAG_BYTES,
                actual: self.buffer_pos,
            });
        }

        self.mac = None;
        let started_direction = self.start_data()?;
        debug_assert_eq!(started_direction, direction);

        match direction {
            CipherDirection::Encrypt => {
                let message_len = self.buffer_pos;
                let final_input: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
                self.process_data(&final_input[..message_len], &mut output[..message_len])?;
                self.update_mac(&output[..message_len])?;
                let tag = self.finish_data(State::EncryptFinal)?;
                output[message_len..message_len + TAG_BYTES].copy_from_slice(&tag);
                self.mac = Some(tag);
                self.clear_buffer();
                Ok(message_len + TAG_BYTES)
            }
            CipherDirection::Decrypt => {
                let message_len = self.buffer_pos - TAG_BYTES;
                let final_input: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
                self.update_mac(&final_input[..message_len])?;
                self.process_data(&final_input[..message_len], &mut output[..message_len])?;
                let mut expected_tag = self.finish_data(State::DecryptFinal)?;
                let mut received_tag = [0u8; TAG_BYTES];
                received_tag.copy_from_slice(&self.buffer[message_len..message_len + TAG_BYTES]);
                self.clear_buffer();

                if !fixed_time_eq(&expected_tag, &received_tag) {
                    output[..message_len].zeroize();
                    expected_tag.zeroize();
                    received_tag.zeroize();
                    return Err(AeadError::AuthenticationFailed);
                }

                expected_tag.zeroize();
                self.mac = Some(received_tag);
                Ok(message_len)
            }
        }
    }

    /// Constant time.
    fn mac(&self) -> Option<&[u8]> {
        self.mac.as_ref().map(|mac| mac.as_slice())
    }

    /// Constant time: depends only on public lengths.
    fn update_output_len(&self, input_len: usize) -> Result<usize, AeadError> {
        let total = match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(TAG_BYTES),
            State::DecryptData | State::DecryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?
                .saturating_sub(TAG_BYTES),
            State::EncryptData | State::EncryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?,
            State::Uninitialized | State::EncryptInit | State::EncryptAad => input_len,
        };
        Ok(total - total % BLOCK_BYTES)
    }

    /// Constant time: depends only on public lengths.
    fn output_len(&self, input_len: usize) -> Result<usize, AeadError> {
        Ok(match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(TAG_BYTES),
            State::DecryptData | State::DecryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?
                .saturating_sub(TAG_BYTES),
            State::EncryptData | State::EncryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .and_then(|total| total.checked_add(TAG_BYTES))
                .ok_or(AeadError::InputTooLong)?,
            State::Uninitialized | State::EncryptInit | State::EncryptAad => input_len
                .checked_add(TAG_BYTES)
                .ok_or(AeadError::InputTooLong)?,
        })
    }

    /// Constant time: lengths are checked against public sizes and the key is
    /// compared in fixed time.
    fn init<P>(&mut self, direction: CipherDirection, params: &P) -> Result<(), AeadInitError>
    where
        P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
    {
        // A failed init leaves the engine uninitialized, but keeps the previous
        // key and nonce for the reuse check.
        self.state = State::Uninitialized;
        self.mac = None;
        self.clear_buffer();
        self.aad_count = 0;
        self.initial_aad_count = 0;
        self.data_count = 0;
        // Dropping the old MACs wipes their one-time keys.
        self.poly1305 = Poly1305::new();
        self.initial_poly1305 = Poly1305::new();

        let key = params.key();
        if key.len() != KEY_BYTES {
            return Err(AeadInitError::InvalidKeyLength { actual: key.len() });
        }
        let nonce = params.nonce();
        if nonce.len() != C::NONCE_BYTES {
            return Err(AeadInitError::InvalidNonceLength {
                actual: nonce.len(),
            });
        }
        // RFC 8439 fixes the tag at 16 bytes, as Bouncy Castle does.
        let mac_size = params.mac_size();
        if mac_size != TAG_BYTES {
            return Err(AeadInitError::InvalidMacSize { actual: mac_size });
        }

        // Reuse means the same key and nonce. The nonce is public, so only the
        // key needs a fixed-time comparison.
        let reused = self.has_key_nonce
            && self.nonce_len == nonce.len()
            && self.nonce[..self.nonce_len] == *nonce
            && fixed_time_eq(&self.key, key);
        if direction == CipherDirection::Encrypt && reused {
            return Err(AeadInitError::NonceReuse);
        }

        // The lengths are checked above, so the stream cipher accepts them.
        self.chacha
            .start(key, nonce)
            .map_err(|_| AeadInitError::InternalFailure)?;
        self.key_poly1305()
            .map_err(|_| AeadInitError::InternalFailure)?;

        self.key.copy_from_slice(key);
        self.nonce.fill(0);
        self.nonce[..nonce.len()].copy_from_slice(nonce);
        self.nonce_len = nonce.len();
        self.has_key_nonce = true;
        self.state = match direction {
            CipherDirection::Encrypt => State::EncryptInit,
            CipherDirection::Decrypt => State::DecryptInit,
        };

        let initial_aad = params.initial_aad();
        if !initial_aad.is_empty() {
            self.state = match direction {
                CipherDirection::Encrypt => State::EncryptAad,
                CipherDirection::Decrypt => State::DecryptAad,
            };
            self.aad_count = initial_aad.len() as u64;
            if self.poly1305.update(initial_aad).is_err() {
                self.state = State::Uninitialized;
                return Err(AeadInitError::InternalFailure);
            }
        }
        self.initial_aad_count = self.aad_count;
        self.initial_poly1305 = self.poly1305.clone();
        Ok(())
    }

    /// Keys Poly1305 with the first 32 bytes of keystream block zero, which
    /// leaves the stream at block one for the message.
    fn key_poly1305(&mut self) -> Result<(), AeadError> {
        let mut first_block = [0u8; BLOCK_BYTES];
        let keyed = self
            .chacha
            .process_bytes(&[0; BLOCK_BYTES], &mut first_block)
            .map_err(map_stream_error)
            .and_then(|_| {
                self.poly1305
                    .init(&KeyRef::new(&first_block[..tc_poly1305::KEY_BYTES]))
                    .map_err(|_| AeadError::InternalFailure)
            });
        first_block.zeroize();
        keyed
    }

    fn clear_buffer(&mut self) {
        self.buffer.zeroize();
        self.buffer_pos = 0;
    }

    fn restore_initial_state(&mut self, direction: CipherDirection) {
        self.clear_buffer();
        self.aad_count = self.initial_aad_count;
        self.data_count = 0;
        self.chacha.reset();
        // Poly1305 restarts from its saved state, but the stream still has to
        // pass block zero.
        if self.key_poly1305().is_err() {
            self.state = State::Uninitialized;
            return;
        }
        self.poly1305 = self.initial_poly1305.clone();
        self.state = match (direction, self.initial_aad_count) {
            (CipherDirection::Encrypt, 0) => State::EncryptInit,
            (CipherDirection::Encrypt, _) => State::EncryptAad,
            (CipherDirection::Decrypt, 0) => State::DecryptInit,
            (CipherDirection::Decrypt, _) => State::DecryptAad,
        };
    }

    /// Constant time.
    fn reset(&mut self) {
        self.mac = None;
        self.clear_buffer();
        match self.state {
            // Nothing has been encrypted yet, so the nonce is still unused.
            State::EncryptInit | State::EncryptAad => {
                self.restore_initial_state(CipherDirection::Encrypt)
            }
            State::EncryptData | State::EncryptFinal => {
                self.aad_count = 0;
                self.data_count = 0;
                self.state = State::EncryptFinal;
            }
            State::DecryptInit | State::DecryptAad | State::DecryptData | State::DecryptFinal => {
                self.restore_initial_state(CipherDirection::Decrypt)
            }
            State::Uninitialized => {
                self.aad_count = 0;
                self.data_count = 0;
            }
        }
    }
}

impl<C> Drop for Core<C> {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
        self.buffer.zeroize();
        self.mac.zeroize();
    }
}

/// Incremental ChaCha20-Poly1305 engine from RFC 8439.
///
/// Takes a 32-byte key and a 12-byte nonce; the tag is always 16 bytes, so
/// `init` accepts no other `mac_size`. Decryption retains the trailing tag and
/// verifies it during finalization. Plaintext emitted before successful
/// finalization is unauthenticated and must not be released to consumers. A
/// message holds at most 2^32 - 1 blocks of 64 bytes, about 256 GiB; longer
/// input fails with `AeadError::InputTooLong`.
///
/// Encryption refuses an `init` whose key and nonce match the previous `init`
/// of the same instance. Nothing tracks nonces across instances or restarts,
/// so the caller must still never reuse a nonce under one key. A 12-byte
/// nonce is too short to draw at random for many messages under one key;
/// [`XChaCha20Poly1305Engine`] takes a 24-byte nonce for that.
///
/// ChaCha20 runs on `tc_chacha`'s portable engine, or with the `rustcrypto`
/// feature on RustCrypto's `chacha20`, which uses SIMD where the processor
/// has it. Both produce the same output.
///
/// Constant time on either backend: ChaCha20 is built from additions,
/// rotations and XORs on 32-bit words, RustCrypto picks its SIMD code from
/// public processor features, Poly1305 reduces without branches, and the tag
/// is compared in fixed time. Only public lengths decide how much work is
/// done.
///
/// # Example
///
/// ```
/// use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef};
/// use tc_block_cipher::CipherDirection;
/// use tc_chacha_aead::{ChaCha20Poly1305Engine, KEY_BYTES, NONCE_BYTES, TAG_BYTES};
///
/// let (key, nonce) = ([0x42; KEY_BYTES], [0x24; NONCE_BYTES]);
/// let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, b"header");
/// let plaintext = b"attack at dawn";
/// let mut cipher = ChaCha20Poly1305Engine::new();
///
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(plaintext.len())?];
/// let mut sealed_len = cipher.process_bytes(plaintext, &mut sealed)?;
/// sealed_len += cipher.do_final(&mut sealed[sealed_len..])?;
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(sealed_len)?];
/// let mut opened_len = cipher.process_bytes(&sealed[..sealed_len], &mut opened)?;
/// opened_len += cipher.do_final(&mut opened[opened_len..])?;
/// assert_eq!(&opened[..opened_len], plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct ChaCha20Poly1305Engine {
    core: Core<ChaCha7539Engine>,
}

impl ChaCha20Poly1305Engine {
    /// Creates an uninitialized engine. Constant time.
    pub const fn new() -> Self {
        Self {
            core: Core::new(ChaCha7539Engine::new()),
        }
    }
}

impl Default for ChaCha20Poly1305Engine {
    /// Same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl Display for ChaCha20Poly1305Engine {
    /// Writes the algorithm name. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("ChaCha20-Poly1305")
    }
}

impl AeadCipher for ChaCha20Poly1305Engine {
    type Error = AeadError;

    /// Authenticates `input` as associated data. Constant time: only its
    /// length decides the work.
    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.core.process_aad_bytes(input)
    }

    /// Encrypts or decrypts the input that is ready and holds back the rest.
    /// Constant time: only the input length decides the work.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.process_bytes(input, output)
    }

    /// Processes the rest of the message and appends or verifies the tag.
    /// Constant time: the tag is compared in fixed time, and only the result
    /// reveals whether it matched.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.do_final(output)
    }

    /// Returns the tag of the last successful `do_final`. Constant time.
    fn mac(&self) -> Option<&[u8]> {
        self.core.mac()
    }

    /// Restarts the message when the nonce allows, as described on
    /// `AeadCipher::reset`. Constant time: it rewinds the keystream, restores
    /// the saved Poly1305 state and wipes the buffer.
    fn reset(&mut self) {
        self.core.reset();
    }

    /// Returns the length the next `process_bytes` writes. Constant time:
    /// depends only on public lengths.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.core.update_output_len(input_len)
    }

    /// Returns the length `process_bytes` and `do_final` write together.
    /// Constant time: depends only on public lengths.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.core.output_len(input_len)
    }
}

impl<P> AeadCipherInit<P> for ChaCha20Poly1305Engine
where
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError;

    /// Keys ChaCha20, derives the Poly1305 key from keystream block zero and
    /// authenticates any initial associated data. Encryption refuses a key and
    /// nonce that repeat the previous `init` of this engine. Constant time:
    /// lengths are checked against public sizes and the key is compared in
    /// fixed time.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.core.init(direction, params)
    }
}

/// Incremental XChaCha20-Poly1305 engine with a 24-byte nonce, from the
/// XChaCha draft (draft-irtf-cfrg-xchacha).
///
/// HChaCha20 derives a subkey from the key and the first 16 bytes of the
/// nonce, and ChaCha20-Poly1305 runs under that subkey with the last 8 bytes.
/// The longer nonce can be drawn at random. Otherwise the engine behaves as
/// [`ChaCha20Poly1305Engine`]: a 32-byte key, a 16-byte tag, the same message
/// limit, unauthenticated plaintext until `do_final` succeeds, and refusal of
/// an encryption `init` that repeats the previous key and nonce of the same
/// instance.
///
/// The `rustcrypto` feature moves HChaCha20 and ChaCha20 to RustCrypto's
/// `chacha20`, as for [`ChaCha20Poly1305Engine`].
///
/// Constant time on either backend: HChaCha20 and ChaCha20 are built from
/// additions, rotations and XORs on 32-bit words, RustCrypto picks its SIMD
/// code from public processor features, Poly1305 reduces without branches,
/// and the tag is compared in fixed time. Only public lengths decide how much
/// work is done.
///
/// # Example
///
/// ```
/// use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef};
/// use tc_block_cipher::CipherDirection;
/// use tc_chacha_aead::{KEY_BYTES, TAG_BYTES, XChaCha20Poly1305Engine, XNONCE_BYTES};
///
/// let (key, nonce) = ([0x42; KEY_BYTES], [0x24; XNONCE_BYTES]);
/// let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, b"header");
/// let plaintext = b"attack at dawn";
/// let mut cipher = XChaCha20Poly1305Engine::new();
///
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(plaintext.len())?];
/// let mut sealed_len = cipher.process_bytes(plaintext, &mut sealed)?;
/// sealed_len += cipher.do_final(&mut sealed[sealed_len..])?;
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(sealed_len)?];
/// let mut opened_len = cipher.process_bytes(&sealed[..sealed_len], &mut opened)?;
/// opened_len += cipher.do_final(&mut opened[opened_len..])?;
/// assert_eq!(&opened[..opened_len], plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct XChaCha20Poly1305Engine {
    core: Core<XChaCha20Engine>,
}

impl XChaCha20Poly1305Engine {
    /// Creates an uninitialized engine. Constant time.
    pub const fn new() -> Self {
        Self {
            core: Core::new(XChaCha20Engine::new()),
        }
    }
}

impl Default for XChaCha20Poly1305Engine {
    /// Same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl Display for XChaCha20Poly1305Engine {
    /// Writes the algorithm name. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20-Poly1305")
    }
}

impl AeadCipher for XChaCha20Poly1305Engine {
    type Error = AeadError;

    /// Authenticates `input` as associated data. Constant time: only its
    /// length decides the work.
    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.core.process_aad_bytes(input)
    }

    /// Encrypts or decrypts the input that is ready and holds back the rest.
    /// Constant time: only the input length decides the work.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.process_bytes(input, output)
    }

    /// Processes the rest of the message and appends or verifies the tag.
    /// Constant time: the tag is compared in fixed time, and only the result
    /// reveals whether it matched.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.do_final(output)
    }

    /// Returns the tag of the last successful `do_final`. Constant time.
    fn mac(&self) -> Option<&[u8]> {
        self.core.mac()
    }

    /// Restarts the message when the nonce allows, as described on
    /// `AeadCipher::reset`. Constant time: it rewinds the keystream, restores
    /// the saved Poly1305 state and wipes the buffer.
    fn reset(&mut self) {
        self.core.reset();
    }

    /// Returns the length the next `process_bytes` writes. Constant time:
    /// depends only on public lengths.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.core.update_output_len(input_len)
    }

    /// Returns the length `process_bytes` and `do_final` write together.
    /// Constant time: depends only on public lengths.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.core.output_len(input_len)
    }
}

impl<P> AeadCipherInit<P> for XChaCha20Poly1305Engine
where
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError;

    /// Derives the subkey with HChaCha20, keys ChaCha20, derives the Poly1305
    /// key from keystream block zero and authenticates any initial associated
    /// data. Encryption refuses a key and nonce that repeat the previous
    /// `init` of this engine. Constant time: lengths are checked against
    /// public sizes and the key is compared in fixed time.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.core.init(direction, params)
    }
}

fn map_mac_error(error: MacError) -> AeadError {
    match error {
        MacError::NotInitialised => AeadError::NotInitialized,
        MacError::OutputTooShort {
            required,
            available,
        } => AeadError::OutputTooShort {
            required,
            available,
        },
        _ => AeadError::InternalFailure,
    }
}

fn map_stream_error(error: StreamError) -> AeadError {
    match error {
        StreamError::NotInitialised => AeadError::NotInitialized,
        StreamError::BufferTooShort => AeadError::InternalFailure,
        StreamError::MaxBytesExceeded | StreamError::CounterExhausted => AeadError::InputTooLong,
        _ => AeadError::InternalFailure,
    }
}

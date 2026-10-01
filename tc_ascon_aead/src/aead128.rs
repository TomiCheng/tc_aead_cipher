//! Ascon-AEAD128 authenticated-encryption engine.

use core::fmt::{Display, Formatter};
use tc_block_cipher::{CipherDirection, KeyParams};
use tc_constant_time::{ConstantTimeEq, fixed_time_eq};
use tc_zeroize::Zeroize;

use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams, MacSizeParams,
    NonceParams,
};

/// Secret-key length in bytes.
const KEY_BYTES: usize = 16;
/// Nonce length in bytes.
const NONCE_BYTES: usize = 16;
/// Authentication-tag length in bytes.
const TAG_BYTES: usize = 16;
const ASCON_IV: u64 = 0x0000_1000_808c_0001;
const RATE: usize = 16;
const DECRYPT_BUFFER_BYTES: usize = RATE + TAG_BYTES;
// SP 800-232 permits truncating the tag to 32 bits or more.
const MIN_TAG_BYTES: usize = 4;

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

/// Incremental Ascon-AEAD128 engine from NIST SP 800-232.
///
/// Encryption appends a tag of `mac_size` bytes, 4 to 16: the full 16-byte tag,
/// or its leftmost bytes when truncated as SP 800-232 permits. A truncated tag
/// of `n` bytes is forged with probability about 2^-8n per attempt, and
/// SP 800-232 requires a risk analysis before using one shorter than 8 bytes.
/// Decryption retains the trailing tag and verifies it during finalization.
/// Plaintext emitted before successful finalization is unauthenticated and must
/// not be released to consumers.
///
/// Encryption refuses an `init` whose key and nonce match the previous `init`
/// of the same instance. Nothing tracks nonces across instances or restarts,
/// so the caller must still never reuse a nonce under one key.
///
/// Constant time: the permutation is a bitsliced S-box and linear layer on
/// 64-bit words, without tables or data-dependent branches, and the tag is
/// compared in fixed time. Only public lengths decide how much work is done.
///
/// # Example
///
/// ```
/// use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef};
/// use tc_ascon_aead::AsconAead128Engine;
/// use tc_block_cipher::CipherDirection;
///
/// let (key, nonce) = ([0x42; 16], [0x24; 16]);
/// let params = AeadParamsRef::new(&key, &nonce, 16, b"header");
/// let plaintext = b"attack at dawn";
/// let mut cipher = AsconAead128Engine::new();
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
pub struct AsconAead128Engine {
    buffer: [u8; DECRYPT_BUFFER_BYTES],
    buffer_pos: usize,
    key: [u64; 2],
    nonce: [u64; 2],
    has_key_nonce: bool,
    state_words: [u64; 5],
    state: State,
    mac: Option<[u8; TAG_BYTES]>,
    mac_size: usize,
    initial_buffer: [u8; DECRYPT_BUFFER_BYTES],
    initial_buffer_pos: usize,
    initial_state_words: [u64; 5],
    initial_state: State,
}

impl AsconAead128Engine {
    /// Creates an uninitialized engine. Constant time.
    pub const fn new() -> Self {
        Self {
            buffer: [0; DECRYPT_BUFFER_BYTES],
            buffer_pos: 0,
            key: [0; 2],
            nonce: [0; 2],
            has_key_nonce: false,
            state_words: [0; 5],
            state: State::Uninitialized,
            mac: None,
            mac_size: TAG_BYTES,
            initial_buffer: [0; DECRYPT_BUFFER_BYTES],
            initial_buffer_pos: 0,
            initial_state_words: [0; 5],
            initial_state: State::Uninitialized,
        }
    }

    fn restore_initial_state(&mut self) {
        self.buffer = self.initial_buffer;
        self.buffer_pos = self.initial_buffer_pos;
        self.state_words = self.initial_state_words;
        self.state = self.initial_state;
    }

    fn initialize_state(&mut self) {
        self.state_words = [
            ASCON_IV,
            self.key[0],
            self.key[1],
            self.nonce[0],
            self.nonce[1],
        ];
        self.permute_12();
        self.state_words[3] ^= self.key[0];
        self.state_words[4] ^= self.key[1];
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
                self.finish_aad(State::EncryptData);
                Ok(CipherDirection::Encrypt)
            }
            State::DecryptInit | State::DecryptAad => {
                self.finish_aad(State::DecryptData);
                Ok(CipherDirection::Decrypt)
            }
            State::EncryptData => Ok(CipherDirection::Encrypt),
            State::DecryptData => Ok(CipherDirection::Decrypt),
            State::EncryptFinal | State::DecryptFinal => Err(AeadError::AlreadyFinalized),
            State::Uninitialized => Err(AeadError::NotInitialized),
        }
    }

    fn finish_aad(&mut self, next: State) {
        if matches!(self.state, State::EncryptAad | State::DecryptAad) {
            let mut final_block = [0u8; RATE];
            final_block[..self.buffer_pos].copy_from_slice(&self.buffer[..self.buffer_pos]);
            final_block[self.buffer_pos] = 0x01;
            self.state_words[0] ^= load_u64(&final_block[..8]);
            self.state_words[1] ^= load_u64(&final_block[8..]);
            self.permute_8();
            final_block.zeroize();
        }

        self.state_words[4] ^= 0x8000_0000_0000_0000;
        self.buffer.zeroize();
        self.buffer_pos = 0;
        self.state = next;
    }

    fn finish_data(&mut self, next: State) {
        self.state_words[2] ^= self.key[0];
        self.state_words[3] ^= self.key[1];
        self.permute_12();
        self.state_words[3] ^= self.key[0];
        self.state_words[4] ^= self.key[1];
        self.state = next;
    }

    fn absorb_aad_bytes(&mut self, mut input: &[u8]) {
        if self.buffer_pos > 0 {
            let available = RATE - self.buffer_pos;
            if input.len() < available {
                self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
                self.buffer_pos += input.len();
                return;
            }

            self.buffer[self.buffer_pos..RATE].copy_from_slice(&input[..available]);
            input = &input[available..];
            let block: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
            self.process_aad_block(&block);
            self.buffer_pos = 0;
        }

        while input.len() >= RATE {
            let block: &[u8; RATE] = input[..RATE].try_into().unwrap();
            self.process_aad_block(block);
            input = &input[RATE..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_pos = input.len();
    }

    fn process_aad_block(&mut self, block: &[u8; RATE]) {
        self.state_words[0] ^= load_u64(&block[..8]);
        self.state_words[1] ^= load_u64(&block[8..]);
        self.permute_8();
    }

    fn process_encrypt_block(&mut self, block: &[u8; RATE], output: &mut [u8]) {
        self.state_words[0] ^= load_u64(&block[..8]);
        output[..8].copy_from_slice(&self.state_words[0].to_le_bytes());
        self.state_words[1] ^= load_u64(&block[8..]);
        output[8..RATE].copy_from_slice(&self.state_words[1].to_le_bytes());
        self.permute_8();
    }

    fn process_decrypt_block(&mut self, block: &[u8; RATE], output: &mut [u8]) {
        let ciphertext_0 = load_u64(&block[..8]);
        output[..8].copy_from_slice(&(self.state_words[0] ^ ciphertext_0).to_le_bytes());
        self.state_words[0] = ciphertext_0;

        let ciphertext_1 = load_u64(&block[8..]);
        output[8..RATE].copy_from_slice(&(self.state_words[1] ^ ciphertext_1).to_le_bytes());
        self.state_words[1] = ciphertext_1;
        self.permute_8();
    }

    fn process_encrypt_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> usize {
        let mut written = 0;

        if self.buffer_pos > 0 {
            let available = RATE - self.buffer_pos;
            if input.len() < available {
                self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
                self.buffer_pos += input.len();
                return 0;
            }

            self.buffer[self.buffer_pos..RATE].copy_from_slice(&input[..available]);
            input = &input[available..];
            let block: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
            self.process_encrypt_block(&block, &mut output[..RATE]);
            written = RATE;
            self.buffer_pos = 0;
        }

        while input.len() >= RATE {
            let block: &[u8; RATE] = input[..RATE].try_into().unwrap();
            self.process_encrypt_block(block, &mut output[written..written + RATE]);
            input = &input[RATE..];
            written += RATE;
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_pos = input.len();
        written
    }

    fn process_decrypt_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> usize {
        let mut written = 0;
        while self.buffer_pos.saturating_add(input.len()) >= RATE + self.mac_size {
            if self.buffer_pos < RATE {
                let needed = RATE - self.buffer_pos;
                self.buffer[self.buffer_pos..RATE].copy_from_slice(&input[..needed]);
                input = &input[needed..];
                self.buffer_pos = RATE;
            }

            let block: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
            self.process_decrypt_block(&block, &mut output[written..written + RATE]);
            written += RATE;
            self.buffer.copy_within(RATE..self.buffer_pos, 0);
            self.buffer_pos -= RATE;
        }

        self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
        self.buffer_pos += input.len();
        written
    }

    fn process_final_encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(input.len() < RATE);
        for (index, (&input_byte, output_byte)) in input.iter().zip(output.iter_mut()).enumerate() {
            let lane = index / 8;
            let shift = (index % 8) * 8;
            self.state_words[lane] ^= u64::from(input_byte) << shift;
            *output_byte = (self.state_words[lane] >> shift) as u8;
        }
        self.state_words[input.len() / 8] ^= 1u64 << ((input.len() % 8) * 8);
        self.finish_data(State::EncryptFinal);
    }

    fn process_final_decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(input.len() < RATE);
        for (index, (&ciphertext_byte, output_byte)) in
            input.iter().zip(output.iter_mut()).enumerate()
        {
            let lane = index / 8;
            let shift = (index % 8) * 8;
            *output_byte = ((self.state_words[lane] >> shift) as u8) ^ ciphertext_byte;
            let mask = 0xffu64 << shift;
            self.state_words[lane] =
                (self.state_words[lane] & !mask) | (u64::from(ciphertext_byte) << shift);
        }
        self.state_words[input.len() / 8] ^= 1u64 << ((input.len() % 8) * 8);
        self.finish_data(State::DecryptFinal);
    }

    fn permute_8(&mut self) {
        for constant in [0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b] {
            self.round(constant);
        }
    }

    fn permute_12(&mut self) {
        for constant in [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ] {
            self.round(constant);
        }
    }

    #[inline]
    fn round(&mut self, constant: u64) {
        let sx = self.state_words[2] ^ constant;
        let t0 = self.state_words[0]
            ^ self.state_words[1]
            ^ sx
            ^ self.state_words[3]
            ^ (self.state_words[1] & (self.state_words[0] ^ sx ^ self.state_words[4]));
        let t1 = self.state_words[0]
            ^ sx
            ^ self.state_words[3]
            ^ self.state_words[4]
            ^ ((self.state_words[1] ^ sx) & (self.state_words[1] ^ self.state_words[3]));
        let t2 = self.state_words[1]
            ^ sx
            ^ self.state_words[4]
            ^ (self.state_words[3] & self.state_words[4]);
        let t3 = self.state_words[0]
            ^ self.state_words[1]
            ^ sx
            ^ (!self.state_words[0] & (self.state_words[3] ^ self.state_words[4]));
        let t4 = self.state_words[1]
            ^ self.state_words[3]
            ^ self.state_words[4]
            ^ ((self.state_words[0] ^ self.state_words[4]) & self.state_words[1]);

        self.state_words[0] = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
        self.state_words[1] = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
        self.state_words[2] = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
        self.state_words[3] = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
        self.state_words[4] = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
    }
}

impl Drop for AsconAead128Engine {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
        self.state_words.zeroize();
        self.initial_state_words.zeroize();
        self.buffer.zeroize();
        self.initial_buffer.zeroize();
        self.mac.zeroize();
    }
}

impl Default for AsconAead128Engine {
    /// Same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl Display for AsconAead128Engine {
    /// Writes the algorithm name. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-AEAD128")
    }
}

impl AeadCipher for AsconAead128Engine {
    type Error = AeadError;

    /// Absorbs `input` as associated data. Constant time: only its length
    /// decides the work.
    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        // Report the state even for empty input, which leaves it unchanged.
        self.current_direction()?;
        if matches!(self.state, State::EncryptData | State::DecryptData) {
            return Err(AeadError::AadAfterData);
        }
        if input.is_empty() {
            return Ok(());
        }
        self.check_aad()?;
        self.mac = None;
        self.absorb_aad_bytes(input);
        Ok(())
    }

    /// Encrypts or decrypts the input that is ready and holds back the rest.
    /// Constant time: only the input length decides the work.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.current_direction()?;
        let required = self.update_output_len(input.len())?;
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        self.mac = None;
        let started_direction = self.start_data()?;
        debug_assert_eq!(started_direction, direction);
        Ok(match direction {
            CipherDirection::Encrypt => self.process_encrypt_bytes(input, output),
            CipherDirection::Decrypt => self.process_decrypt_bytes(input, output),
        })
    }

    /// Processes the rest of the message and appends or verifies the tag.
    /// Constant time: the tag is compared in fixed time, and only the result
    /// reveals whether it matched.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.current_direction()?;
        let required = self.output_len(0)?;
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        if direction == CipherDirection::Decrypt && self.buffer_pos < self.mac_size {
            self.mac = None;
            return Err(AeadError::CiphertextTooShort {
                minimum: self.mac_size,
                actual: self.buffer_pos,
            });
        }

        self.mac = None;
        let started_direction = self.start_data()?;
        debug_assert_eq!(started_direction, direction);
        match direction {
            CipherDirection::Encrypt => {
                let message_len = self.buffer_pos;
                let final_input: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
                self.process_final_encrypt(&final_input[..message_len], &mut output[..message_len]);

                let mut tag = [0u8; TAG_BYTES];
                tag[..8].copy_from_slice(&self.state_words[3].to_le_bytes());
                tag[8..].copy_from_slice(&self.state_words[4].to_le_bytes());
                output[message_len..message_len + self.mac_size]
                    .copy_from_slice(&tag[..self.mac_size]);
                self.mac = Some(tag);
                self.buffer.zeroize();
                self.buffer_pos = 0;
                Ok(message_len + self.mac_size)
            }
            CipherDirection::Decrypt => {
                let message_len = self.buffer_pos - self.mac_size;
                let mut received_tag = [0u8; TAG_BYTES];
                received_tag[..self.mac_size]
                    .copy_from_slice(&self.buffer[message_len..message_len + self.mac_size]);
                let final_input: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
                self.process_final_decrypt(&final_input[..message_len], &mut output[..message_len]);

                let mut expected_tag = [0u8; TAG_BYTES];
                expected_tag[..8].copy_from_slice(&self.state_words[3].to_le_bytes());
                expected_tag[8..].copy_from_slice(&self.state_words[4].to_le_bytes());
                self.buffer.zeroize();
                self.buffer_pos = 0;

                if !fixed_time_eq(
                    &expected_tag[..self.mac_size],
                    &received_tag[..self.mac_size],
                ) {
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

    /// Returns the tag of the last successful `do_final`. Constant time.
    fn mac(&self) -> Option<&[u8]> {
        self.mac.as_ref().map(|mac| &mac[..self.mac_size])
    }

    /// Restarts the message when the nonce allows, as described on
    /// `AeadCipher::reset`. Constant time: it restores fixed-size state and
    /// wipes the buffers.
    fn reset(&mut self) {
        self.mac = None;
        self.buffer.zeroize();
        self.buffer_pos = 0;
        match self.state {
            // Nothing has been encrypted yet, so the nonce is still unused.
            State::EncryptInit | State::EncryptAad => self.restore_initial_state(),
            State::EncryptData | State::EncryptFinal => {
                self.state = State::EncryptFinal;
            }
            State::DecryptInit | State::DecryptAad | State::DecryptData | State::DecryptFinal => {
                self.restore_initial_state()
            }
            State::Uninitialized => {}
        }
    }

    /// Returns the length the next `process_bytes` writes. Constant time:
    /// depends only on public lengths.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let total = match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(self.mac_size),
            State::DecryptData | State::DecryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?
                .saturating_sub(self.mac_size),
            State::EncryptData | State::EncryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?,
            State::Uninitialized | State::EncryptInit | State::EncryptAad => input_len,
        };
        Ok(total - total % RATE)
    }

    /// Returns the length `process_bytes` and `do_final` write together.
    /// Constant time: depends only on public lengths.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        Ok(match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(self.mac_size),
            State::DecryptData | State::DecryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?
                .saturating_sub(self.mac_size),
            State::EncryptData | State::EncryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .and_then(|total| total.checked_add(self.mac_size))
                .ok_or(AeadError::InputTooLong)?,
            State::Uninitialized | State::EncryptInit | State::EncryptAad => input_len
                .checked_add(self.mac_size)
                .ok_or(AeadError::InputTooLong)?,
        })
    }
}

impl<P> AeadCipherInit<P> for AsconAead128Engine
where
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError;

    /// Loads the key and nonce, runs the initialization and absorbs any initial
    /// associated data. Encryption refuses a key and nonce that repeat the
    /// previous `init` of this engine. Constant time: lengths are checked
    /// against public sizes, the key is compared in fixed time, and the state
    /// is set up without data-dependent branches.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.state = State::Uninitialized;
        self.mac = None;
        self.buffer.zeroize();
        self.buffer_pos = 0;
        self.state_words.zeroize();
        self.initial_buffer.zeroize();
        self.initial_buffer_pos = 0;
        self.initial_state_words.zeroize();
        self.initial_state = State::Uninitialized;

        let key = params.key();
        if key.len() != KEY_BYTES {
            return Err(AeadInitError::InvalidKeyLength { actual: key.len() });
        }
        let nonce = params.nonce();
        if nonce.len() != NONCE_BYTES {
            return Err(AeadInitError::InvalidNonceLength {
                actual: nonce.len(),
            });
        }
        let mac_size = params.mac_size();
        if !(MIN_TAG_BYTES..=TAG_BYTES).contains(&mac_size) {
            return Err(AeadInitError::InvalidMacSize { actual: mac_size });
        }

        let mut new_key = [load_u64(&key[..8]), load_u64(&key[8..])];
        let new_nonce = [load_u64(&nonce[..8]), load_u64(&nonce[8..])];
        // Reuse means the same key and nonce. The nonce is public, so only the
        // key needs a fixed-time comparison.
        let reused = self.has_key_nonce
            && self.nonce == new_nonce
            && self.key.ct_eq(&new_key).unwrap_u8() == 1;
        if direction == CipherDirection::Encrypt && reused {
            new_key.zeroize();
            return Err(AeadInitError::NonceReuse);
        }

        self.mac_size = mac_size;
        self.key = new_key;
        new_key.zeroize();
        self.nonce = new_nonce;
        self.has_key_nonce = true;
        self.state = match direction {
            CipherDirection::Encrypt => State::EncryptInit,
            CipherDirection::Decrypt => State::DecryptInit,
        };
        self.initialize_state();

        let initial_aad = params.initial_aad();
        if !initial_aad.is_empty() {
            self.state = match direction {
                CipherDirection::Encrypt => State::EncryptAad,
                CipherDirection::Decrypt => State::DecryptAad,
            };
            self.absorb_aad_bytes(initial_aad);
        }
        self.initial_buffer = self.buffer;
        self.initial_buffer_pos = self.buffer_pos;
        self.initial_state_words = self.state_words;
        self.initial_state = self.state;
        Ok(())
    }
}

fn load_u64(input: &[u8]) -> u64 {
    u64::from_le_bytes(input[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_aead_cipher::AeadParamsRef;

    #[test]
    fn ascon_reports_invalid_key_nonce_and_tag_sizes_as_distinct_aead_errors() {
        let bytes = [0u8; 17];
        let mut engine = AsconAead128Engine::new();
        for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
            for length in [0, 15, 17] {
                let params = AeadParamsRef::new(&bytes[..length], &bytes[..16], 16, &[]);
                assert_eq!(
                    engine.init(direction, &params),
                    Err(AeadInitError::InvalidKeyLength { actual: length })
                );

                let params = AeadParamsRef::new(&bytes[..16], &bytes[..length], 16, &[]);
                assert_eq!(
                    engine.init(direction, &params),
                    Err(AeadInitError::InvalidNonceLength { actual: length })
                );
            }

            for mac_size in [0, 3, 17] {
                let params = AeadParamsRef::new(&bytes[..16], &bytes[..16], mac_size, &[]);
                assert_eq!(
                    engine.init(direction, &params),
                    Err(AeadInitError::InvalidMacSize { actual: mac_size })
                );
            }

            // A tag size alone does not make a nonce fresh, so each init takes its own.
            for mac_size in [4, 8, 12, 16] {
                let nonce = [mac_size as u8; 16];
                let params = AeadParamsRef::new(&bytes[..16], &nonce, mac_size, &[]);
                assert_eq!(engine.init(direction, &params), Ok(()));
            }
        }
    }
}

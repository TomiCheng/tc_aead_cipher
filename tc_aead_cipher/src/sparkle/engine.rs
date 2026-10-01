//! Incremental SCHWAEMM authenticated-encryption engine.

use core::fmt::{Display, Formatter};

use tc_block_cipher::{CipherDirection, KeyParams};
use tc_constant_time::fixed_time_eq;
use tc_zeroize::Zeroize;

use super::{BYTES_256, SparkleVariant};
use crate::{
    AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams, MacSizeParams,
    NonceParams,
};

pub(crate) const MAX_STATE_WORDS: usize = 16;
const MAX_KEY_WORDS: usize = BYTES_256 / 4;
const MAX_RATE_BYTES: usize = BYTES_256;
const MAX_BUFFER_BYTES: usize = BYTES_256 * 2;

pub(crate) const RCON: [u32; 8] = [
    0xb7e1_5162,
    0xbf71_5880,
    0x38b4_da56,
    0x324e_7738,
    0xbb11_85eb,
    0x4f7c_7b57,
    0xcfbf_a1c8,
    0xc2b3_293d,
];

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

/// Incremental engine for the four SCHWAEMM parameter sets.
///
/// Decryption may emit unauthenticated plaintext before
/// [`AeadCipher::do_final`] verifies the tag. Callers must not release that
/// plaintext before finalization succeeds.
pub struct SparkleEngine {
    variant: SparkleVariant,
    buffer: [u8; MAX_BUFFER_BYTES],
    buffer_pos: usize,
    key: [u32; MAX_KEY_WORDS],
    nonce: [u32; MAX_KEY_WORDS],
    state_words: [u32; MAX_STATE_WORDS],
    state: State,
    encrypted: bool,
    mac: Option<[u8; BYTES_256]>,
    initial_buffer: [u8; MAX_BUFFER_BYTES],
    initial_buffer_pos: usize,
    initial_state_words: [u32; MAX_STATE_WORDS],
    initial_state: State,
}

impl SparkleEngine {
    /// Creates an uninitialized engine for `variant`.
    pub const fn new(variant: SparkleVariant) -> Self {
        Self {
            variant,
            buffer: [0; MAX_BUFFER_BYTES],
            buffer_pos: 0,
            key: [0; MAX_KEY_WORDS],
            nonce: [0; MAX_KEY_WORDS],
            state_words: [0; MAX_STATE_WORDS],
            state: State::Uninitialized,
            encrypted: false,
            mac: None,
            initial_buffer: [0; MAX_BUFFER_BYTES],
            initial_buffer_pos: 0,
            initial_state_words: [0; MAX_STATE_WORDS],
            initial_state: State::Uninitialized,
        }
    }

    fn restore_initial_state(&mut self) {
        self.buffer = self.initial_buffer;
        self.buffer_pos = self.initial_buffer_pos;
        self.state_words = self.initial_state_words;
        self.state = self.initial_state;
        self.encrypted = false;
    }

    /// Returns the selected SCHWAEMM parameter set.
    pub const fn variant(&self) -> SparkleVariant {
        self.variant
    }

    /// Returns the required key length in bytes.
    pub const fn key_bytes(&self) -> usize {
        self.variant.key_bytes()
    }

    /// Returns the required nonce length in bytes.
    pub const fn nonce_bytes(&self) -> usize {
        self.variant.nonce_bytes()
    }

    /// Returns the authentication-tag length in bytes.
    pub const fn tag_bytes(&self) -> usize {
        self.variant.tag_bytes()
    }

    fn rate_bytes(&self) -> usize {
        self.variant.nonce_bytes()
    }

    fn rate_words(&self) -> usize {
        self.rate_bytes() / 4
    }

    fn key_words(&self) -> usize {
        self.key_bytes() / 4
    }

    fn decrypt_buffer_bytes(&self) -> usize {
        self.rate_bytes() + self.tag_bytes()
    }

    fn capacity_mask(&self) -> usize {
        let rate_words = self.rate_words();
        let capacity_words = self.key_words();
        if rate_words > capacity_words {
            capacity_words - 1
        } else {
            usize::MAX
        }
    }

    fn domain_constant(&self, value: u32) -> u32 {
        let capacity_branches = self.key_bytes() / 8;
        (value ^ (1_u32 << capacity_branches)) << 24
    }

    fn initialize_state(&mut self) {
        let rate_words = self.rate_words();
        let key_words = self.key_words();
        self.state_words.zeroize();
        self.state_words[..rate_words].copy_from_slice(&self.nonce[..rate_words]);
        self.state_words[rate_words..rate_words + key_words]
            .copy_from_slice(&self.key[..key_words]);
        self.permute(self.variant.big_steps());
    }

    fn check_aad(&mut self) -> Result<(), AeadError> {
        self.state = match self.state {
            State::EncryptInit => State::EncryptAad,
            State::DecryptInit => State::DecryptAad,
            State::EncryptAad | State::DecryptAad => self.state,
            State::EncryptData | State::DecryptData => {
                return Err(AeadError::AadAfterData);
            }
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
            self.process_final_aad();
        }
        self.buffer.zeroize();
        self.buffer_pos = 0;
        self.state = next;
    }

    fn process_aad_block(&mut self, block: &[u8], steps: usize) {
        let rate_words = self.rate_words();
        let half = rate_words / 2;
        let capacity_mask = self.capacity_mask();

        for i in 0..half {
            let j = i + half;
            let state_i = self.state_words[i];
            let state_j = self.state_words[j];
            let data_i = load_u32(&block[i * 4..]);
            let data_j = load_u32(&block[j * 4..]);
            self.state_words[i] = state_j ^ data_i ^ self.state_words[rate_words + i];
            self.state_words[j] =
                state_i ^ state_j ^ data_j ^ self.state_words[rate_words + (j & capacity_mask)];
        }
        self.permute(steps);
    }

    fn absorb_aad_bytes(&mut self, mut input: &[u8]) {
        let rate = self.rate_bytes();

        while self.buffer_pos + input.len() > rate {
            let needed = rate - self.buffer_pos;
            self.buffer[self.buffer_pos..rate].copy_from_slice(&input[..needed]);
            input = &input[needed..];
            let block = self.buffer;
            self.process_aad_block(&block[..rate], self.variant.slim_steps());
            self.buffer_pos = 0;
        }

        self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
        self.buffer_pos += input.len();
    }

    fn process_final_aad(&mut self) {
        let rate = self.rate_bytes();
        let mut block = [0_u8; MAX_RATE_BYTES];
        block[..self.buffer_pos].copy_from_slice(&self.buffer[..self.buffer_pos]);
        if self.buffer_pos < rate {
            self.state_words[self.variant.state_words() - 1] ^= self.domain_constant(0);
            block[self.buffer_pos] = 0x80;
        } else {
            self.state_words[self.variant.state_words() - 1] ^= self.domain_constant(1);
        }
        self.process_aad_block(&block[..rate], self.variant.big_steps());
    }

    fn process_data_block(&mut self, block: &[u8], output: &mut [u8], encrypt: bool) {
        let rate_words = self.rate_words();
        let half = rate_words / 2;
        let capacity_mask = self.capacity_mask();

        for i in 0..half {
            let j = i + half;
            let state_i = self.state_words[i];
            let state_j = self.state_words[j];
            let data_i = load_u32(&block[i * 4..]);
            let data_j = load_u32(&block[j * 4..]);

            if encrypt {
                self.state_words[i] = state_j ^ data_i ^ self.state_words[rate_words + i];
                self.state_words[j] =
                    state_i ^ state_j ^ data_j ^ self.state_words[rate_words + (j & capacity_mask)];
            } else {
                self.state_words[i] = state_i ^ state_j ^ data_i ^ self.state_words[rate_words + i];
                self.state_words[j] =
                    state_i ^ data_j ^ self.state_words[rate_words + (j & capacity_mask)];
            }

            output[i * 4..i * 4 + 4].copy_from_slice(&(data_i ^ state_i).to_le_bytes());
            output[j * 4..j * 4 + 4].copy_from_slice(&(data_j ^ state_j).to_le_bytes());
        }
        self.permute(self.variant.slim_steps());
        self.encrypted = true;
    }

    fn process_encrypt_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> usize {
        let rate = self.rate_bytes();
        let mut written = 0;

        while self.buffer_pos + input.len() > rate {
            let needed = rate - self.buffer_pos;
            self.buffer[self.buffer_pos..rate].copy_from_slice(&input[..needed]);
            input = &input[needed..];
            let block = self.buffer;
            self.process_data_block(&block[..rate], &mut output[written..written + rate], true);
            written += rate;
            self.buffer_pos = 0;
        }

        self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
        self.buffer_pos += input.len();
        written
    }

    fn process_decrypt_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> usize {
        let rate = self.rate_bytes();
        let buffer_size = self.decrypt_buffer_bytes();
        let mut written = 0;

        while self.buffer_pos + input.len() > buffer_size {
            if self.buffer_pos < rate {
                let needed = rate - self.buffer_pos;
                self.buffer[self.buffer_pos..rate].copy_from_slice(&input[..needed]);
                input = &input[needed..];
                self.buffer_pos = rate;
            }

            let block = self.buffer;
            self.process_data_block(&block[..rate], &mut output[written..written + rate], false);
            written += rate;
            self.buffer.copy_within(rate..self.buffer_pos, 0);
            self.buffer_pos -= rate;
        }

        self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
        self.buffer_pos += input.len();
        written
    }

    fn process_final_data(&mut self, message_len: usize, output: &mut [u8], encrypt: bool) {
        let rate = self.rate_bytes();
        if !self.encrypted && message_len == 0 {
            return;
        }

        self.state_words[self.variant.state_words() - 1] ^=
            self.domain_constant(if message_len < rate { 2 } else { 3 });

        let mut block = [0_u8; MAX_RATE_BYTES];
        block[..message_len].copy_from_slice(&self.buffer[..message_len]);
        if message_len < rate {
            if !encrypt {
                for (word, chunk) in self.state_words[..self.rate_words()]
                    .iter()
                    .zip(block.chunks_exact_mut(4))
                {
                    chunk.copy_from_slice(&word.to_le_bytes());
                }
                block[..message_len].copy_from_slice(&self.buffer[..message_len]);
            }
            block[message_len] ^= 0x80;
        }

        let rate_words = self.rate_words();
        let half = rate_words / 2;
        let capacity_mask = self.capacity_mask();
        let mut transformed = [0_u8; MAX_RATE_BYTES];
        for i in 0..half {
            let j = i + half;
            let state_i = self.state_words[i];
            let state_j = self.state_words[j];
            let data_i = load_u32(&block[i * 4..]);
            let data_j = load_u32(&block[j * 4..]);

            if encrypt {
                self.state_words[i] = state_j ^ data_i ^ self.state_words[rate_words + i];
                self.state_words[j] =
                    state_i ^ state_j ^ data_j ^ self.state_words[rate_words + (j & capacity_mask)];
            } else {
                self.state_words[i] = state_i ^ state_j ^ data_i ^ self.state_words[rate_words + i];
                self.state_words[j] =
                    state_i ^ data_j ^ self.state_words[rate_words + (j & capacity_mask)];
            }

            transformed[i * 4..i * 4 + 4].copy_from_slice(&(data_i ^ state_i).to_le_bytes());
            transformed[j * 4..j * 4 + 4].copy_from_slice(&(data_j ^ state_j).to_le_bytes());
        }
        output[..message_len].copy_from_slice(&transformed[..message_len]);
        self.permute(self.variant.big_steps());
    }

    fn add_key_and_make_tag(&mut self) -> [u8; BYTES_256] {
        let rate_words = self.rate_words();
        let key_words = self.key_words();
        for i in 0..key_words {
            self.state_words[rate_words + i] ^= self.key[i];
        }

        let mut tag = [0_u8; BYTES_256];
        for (word, chunk) in self.state_words[rate_words..rate_words + key_words]
            .iter()
            .zip(tag.chunks_exact_mut(4))
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        tag
    }

    fn permute(&mut self, steps: usize) {
        let state_words = self.variant.state_words();

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if state_words == MAX_STATE_WORDS {
            if let Some(sse2) = tc_runtime::intrinsics::x86::Sse2::detect() {
                super::sse2::sparkle_opt16(&mut self.state_words, steps, sse2);
                return;
            }
        }

        sparkle_scalar(&mut self.state_words, state_words, steps);
    }
}

fn sparkle_scalar(state: &mut [u32; MAX_STATE_WORDS], state_words: usize, steps: usize) {
    let branches = state_words / 2;
    let half = branches / 2;

    for step in 0..steps {
        state[1] ^= RCON[step & 7];
        state[3] ^= step as u32;

        for (branch, round_constant) in RCON.iter().copied().enumerate().take(branches) {
            let index = branch * 2;
            let (left, right) = state.split_at_mut(index + 1);
            arx_box(round_constant, &mut left[index], &mut right[0]);
        }

        let mut x = 0_u32;
        let mut y = 0_u32;
        for branch in 0..half {
            x ^= state[branch * 2];
            y ^= state[branch * 2 + 1];
        }
        let x = ell(x);
        let y = ell(y);

        let previous = *state;
        for branch in 0..half {
            let next = (branch + 1) % half;
            state[branch * 2] = previous[next * 2] ^ previous[(next + half) * 2] ^ y;
            state[branch * 2 + 1] = previous[next * 2 + 1] ^ previous[(next + half) * 2 + 1] ^ x;
            state[(branch + half) * 2] = previous[branch * 2];
            state[(branch + half) * 2 + 1] = previous[branch * 2 + 1];
        }
    }
}

impl Drop for SparkleEngine {
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

impl Display for SparkleEngine {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.variant, f)
    }
}

impl AeadCipher for SparkleEngine {
    type Error = AeadError;

    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }
        self.check_aad()?;
        self.mac = None;
        self.absorb_aad_bytes(input);
        Ok(())
    }

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

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.current_direction()?;
        let required = self.output_len(0)?;
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let tag_bytes = self.tag_bytes();
        if direction == CipherDirection::Decrypt && self.buffer_pos < tag_bytes {
            self.mac = None;
            return Err(AeadError::CiphertextTooShort {
                minimum: tag_bytes,
                actual: self.buffer_pos,
            });
        }

        self.mac = None;
        let started_direction = self.start_data()?;
        debug_assert_eq!(started_direction, direction);
        match direction {
            CipherDirection::Encrypt => {
                let message_len = self.buffer_pos;
                self.process_final_data(message_len, &mut output[..message_len], true);
                let tag = self.add_key_and_make_tag();
                output[message_len..message_len + tag_bytes].copy_from_slice(&tag[..tag_bytes]);
                self.mac = Some(tag);
                self.state = State::EncryptFinal;
                self.buffer.zeroize();
                self.buffer_pos = 0;
                Ok(message_len + tag_bytes)
            }
            CipherDirection::Decrypt => {
                let message_len = self.buffer_pos - tag_bytes;
                let mut received_tag = [0_u8; BYTES_256];
                received_tag[..tag_bytes]
                    .copy_from_slice(&self.buffer[message_len..message_len + tag_bytes]);
                self.process_final_data(message_len, &mut output[..message_len], false);
                let expected_tag = self.add_key_and_make_tag();
                self.state = State::DecryptFinal;
                self.buffer.zeroize();
                self.buffer_pos = 0;

                if !fixed_time_eq(&expected_tag[..tag_bytes], &received_tag[..tag_bytes]) {
                    output[..message_len].zeroize();
                    return Err(AeadError::AuthenticationFailed);
                }

                self.mac = Some(received_tag);
                Ok(message_len)
            }
        }
    }

    fn mac(&self) -> Option<&[u8]> {
        self.mac.as_ref().map(|mac| &mac[..self.tag_bytes()])
    }

    fn reset(&mut self) {
        self.mac = None;
        self.buffer.zeroize();
        self.buffer_pos = 0;
        self.encrypted = false;
        match self.state {
            // Nothing has been encrypted yet, so the nonce is still unused.
            State::EncryptInit | State::EncryptAad => self.restore_initial_state(),
            State::EncryptData | State::EncryptFinal => self.state = State::EncryptFinal,
            State::DecryptInit | State::DecryptAad | State::DecryptData | State::DecryptFinal => {
                self.restore_initial_state()
            }
            State::Uninitialized => {}
        }
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let tag_bytes = self.tag_bytes();
        let total = match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(tag_bytes + 1),
            State::DecryptData | State::DecryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?
                .saturating_sub(tag_bytes + 1),
            State::EncryptData | State::EncryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?
                .saturating_sub(1),
            State::Uninitialized | State::EncryptInit | State::EncryptAad => {
                input_len.saturating_sub(1)
            }
        };
        let rate = self.rate_bytes();
        Ok(total - total % rate)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let tag_bytes = self.tag_bytes();
        Ok(match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(tag_bytes),
            State::DecryptData | State::DecryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .ok_or(AeadError::InputTooLong)?
                .saturating_sub(tag_bytes),
            State::EncryptData | State::EncryptFinal => self
                .buffer_pos
                .checked_add(input_len)
                .and_then(|len| len.checked_add(tag_bytes))
                .ok_or(AeadError::InputTooLong)?,
            State::Uninitialized | State::EncryptInit | State::EncryptAad => input_len
                .checked_add(tag_bytes)
                .ok_or(AeadError::InputTooLong)?,
        })
    }
}

impl<P> AeadCipherInit<P> for SparkleEngine
where
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.state = State::Uninitialized;
        self.mac = None;
        self.buffer.zeroize();
        self.buffer_pos = 0;
        self.key.zeroize();
        self.nonce.zeroize();
        self.state_words.zeroize();
        self.initial_buffer.zeroize();
        self.initial_buffer_pos = 0;
        self.initial_state_words.zeroize();
        self.initial_state = State::Uninitialized;
        self.encrypted = false;

        let key = params.key();
        if key.len() != self.key_bytes() {
            return Err(AeadInitError::InvalidKeyLength { actual: key.len() });
        }
        let nonce = params.nonce();
        if nonce.len() != self.nonce_bytes() {
            return Err(AeadInitError::InvalidNonceLength {
                actual: nonce.len(),
            });
        }
        let mac_size = params.mac_size();
        if mac_size != self.tag_bytes() {
            return Err(AeadInitError::InvalidMacSize { actual: mac_size });
        }

        self.key.zeroize();
        for (word, bytes) in self.key.iter_mut().zip(key.chunks_exact(4)) {
            *word = load_u32(bytes);
        }
        self.nonce.zeroize();
        for (word, bytes) in self.nonce.iter_mut().zip(nonce.chunks_exact(4)) {
            *word = load_u32(bytes);
        }
        self.buffer.zeroize();
        self.buffer_pos = 0;
        self.encrypted = false;
        self.mac = None;
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

#[inline]
fn load_u32(input: &[u8]) -> u32 {
    u32::from_le_bytes(input[..4].try_into().unwrap())
}

#[inline]
fn arx_box(rc: u32, x: &mut u32, y: &mut u32) {
    *x = x.wrapping_add(y.rotate_right(31));
    *y ^= x.rotate_right(24);
    *x ^= rc;
    *x = x.wrapping_add(y.rotate_right(17));
    *y ^= x.rotate_right(17);
    *x ^= rc;
    *x = x.wrapping_add(*y);
    *y ^= x.rotate_right(31);
    *x ^= rc;
    *x = x.wrapping_add(y.rotate_right(24));
    *y ^= x.rotate_right(16);
    *x ^= rc;
}

#[inline]
fn ell(x: u32) -> u32 {
    x.rotate_right(16) ^ (x & 0xffff)
}

#[cfg(all(test, any(target_arch = "x86", target_arch = "x86_64")))]
mod tests {
    use super::{MAX_STATE_WORDS, sparkle_scalar};
    use tc_runtime::intrinsics::x86::Sse2;

    #[test]
    fn sparkle_opt16_matches_scalar_permutation() {
        let Some(sse2) = Sse2::detect() else {
            return;
        };

        let mut seed = 0x243f_6a88_u32;
        for steps in [8, 12] {
            for _ in 0..64 {
                let input = core::array::from_fn::<_, MAX_STATE_WORDS, _>(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed
                });
                let mut scalar = input;
                let mut vector = input;

                sparkle_scalar(&mut scalar, MAX_STATE_WORDS, steps);
                super::super::sse2::sparkle_opt16(&mut vector, steps, sse2);

                assert_eq!(vector, scalar);
            }
        }
    }
}

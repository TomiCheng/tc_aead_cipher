//! GCM authenticated-encryption engine.

use super::{BLOCK_BYTES, MAX_MAC_BYTES, MIN_MAC_BYTES, Multiplier};
use crate::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams,
    MacSizeParams, NonceParams,
};
use core::fmt;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};
use tc_constant_time::fixed_time_eq;
use tc_zeroize::Zeroize;

const MAX_BLOCKS: u32 = u32::MAX - 1;
const MAX_BUFFER_BYTES: usize = BLOCK_BYTES + MAX_MAC_BYTES;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Uninitialized,
    Encrypt,
    Decrypt,
    Finalized(CipherDirection),
}

/// Galois/Counter Mode authenticated encryption over a 16-byte block cipher.
///
/// The implementation uses a portable, fixed-work GHASH multiplier. It does
/// not expose the obsolete multiplier or exponentiator injection interfaces
/// found in older Bouncy Castle APIs.
///
/// Encryption refuses an `init` whose key and nonce match the previous `init`
/// of the same instance. Nothing tracks nonces across instances or restarts,
/// so the caller must still never reuse a nonce under one key.
pub struct GcmBlockCipher<C> {
    cipher: C,
    state: State,
    mac_size: usize,
    // H and J0 of the last successful init, compared to refuse nonce reuse.
    has_key_nonce: bool,
    multiplier: Multiplier,
    j0: [u8; BLOCK_BYTES],
    counter: [u8; BLOCK_BYTES],
    blocks_remaining: u32,
    buffer: [u8; MAX_BUFFER_BYTES],
    buffer_pos: usize,
    total_length: u64,
    hash: [u8; BLOCK_BYTES],
    aad_hash: [u8; BLOCK_BYTES],
    aad_block: [u8; BLOCK_BYTES],
    aad_block_pos: usize,
    aad_length: u64,
    aad_finalized: bool,
    data_started: bool,
    initial_aad_hash: [u8; BLOCK_BYTES],
    initial_aad_block: [u8; BLOCK_BYTES],
    initial_aad_block_pos: usize,
    initial_aad_length: u64,
    mac: Option<[u8; MAX_MAC_BYTES]>,
}

impl<C> GcmBlockCipher<C> {
    /// Creates an uninitialized GCM engine around `cipher`.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            state: State::Uninitialized,
            mac_size: 0,
            has_key_nonce: false,
            multiplier: Multiplier::new([0; BLOCK_BYTES]),
            j0: [0; BLOCK_BYTES],
            counter: [0; BLOCK_BYTES],
            blocks_remaining: 0,
            buffer: [0; MAX_BUFFER_BYTES],
            buffer_pos: 0,
            total_length: 0,
            hash: [0; BLOCK_BYTES],
            aad_hash: [0; BLOCK_BYTES],
            aad_block: [0; BLOCK_BYTES],
            aad_block_pos: 0,
            aad_length: 0,
            aad_finalized: false,
            data_started: false,
            initial_aad_hash: [0; BLOCK_BYTES],
            initial_aad_block: [0; BLOCK_BYTES],
            initial_aad_block_pos: 0,
            initial_aad_length: 0,
            mac: None,
        }
    }

    fn direction<E>(&self) -> Result<CipherDirection, AeadError<E>> {
        match self.state {
            State::Encrypt => Ok(CipherDirection::Encrypt),
            State::Decrypt => Ok(CipherDirection::Decrypt),
            State::Finalized(_) => Err(AeadError::AlreadyFinalized),
            State::Uninitialized => Err(AeadError::NotInitialized),
        }
    }

    fn is_decrypting(&self) -> bool {
        matches!(
            self.state,
            State::Decrypt | State::Finalized(CipherDirection::Decrypt)
        )
    }

    fn buffer_capacity(&self) -> usize {
        if self.is_decrypting() {
            BLOCK_BYTES + self.mac_size
        } else {
            BLOCK_BYTES
        }
    }

    fn reset_blank(&mut self) {
        self.counter = self.j0;
        self.blocks_remaining = MAX_BLOCKS;
        self.buffer.fill(0);
        self.buffer_pos = 0;
        self.total_length = 0;
        self.hash.fill(0);
        self.aad_hash.fill(0);
        self.aad_block.fill(0);
        self.aad_block_pos = 0;
        self.aad_length = 0;
        self.aad_finalized = false;
        self.data_started = false;
    }

    fn restore_initial_state(&mut self) {
        self.reset_blank();
        self.aad_hash = self.initial_aad_hash;
        self.aad_block = self.initial_aad_block;
        self.aad_block_pos = self.initial_aad_block_pos;
        self.aad_length = self.initial_aad_length;
    }

    fn save_initial_aad_state(&mut self) {
        self.initial_aad_hash = self.aad_hash;
        self.initial_aad_block = self.aad_block;
        self.initial_aad_block_pos = self.aad_block_pos;
        self.initial_aad_length = self.aad_length;
    }

    fn feed_aad(&mut self, mut input: &[u8]) {
        if self.aad_block_pos != 0 {
            let take = (BLOCK_BYTES - self.aad_block_pos).min(input.len());
            self.aad_block[self.aad_block_pos..self.aad_block_pos + take]
                .copy_from_slice(&input[..take]);
            self.aad_block_pos += take;
            input = &input[take..];
            if self.aad_block_pos < BLOCK_BYTES {
                return;
            }
            ghash_block(&self.multiplier, &mut self.aad_hash, &self.aad_block);
            self.aad_block.fill(0);
            self.aad_block_pos = 0;
        }

        while input.len() >= BLOCK_BYTES {
            let block: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
            ghash_block(&self.multiplier, &mut self.aad_hash, block);
            input = &input[BLOCK_BYTES..];
        }

        self.aad_block[..input.len()].copy_from_slice(input);
        self.aad_block_pos = input.len();
    }

    fn start_data(&mut self) {
        if self.aad_finalized {
            return;
        }

        if self.aad_block_pos != 0 {
            let mut block = [0u8; BLOCK_BYTES];
            block[..self.aad_block_pos].copy_from_slice(&self.aad_block[..self.aad_block_pos]);
            ghash_block(&self.multiplier, &mut self.aad_hash, &block);
        }
        self.hash = self.aad_hash;
        self.aad_finalized = true;
    }
}

impl<C> GcmBlockCipher<C>
where
    C: BlockCipher,
{
    fn calculate_j0(multiplier: &Multiplier, nonce: &[u8]) -> [u8; BLOCK_BYTES] {
        if nonce.len() == 12 {
            let mut j0 = [0u8; BLOCK_BYTES];
            j0[..12].copy_from_slice(nonce);
            j0[15] = 1;
            return j0;
        }

        let nonce_bits = u64::try_from(nonce.len()).unwrap() * 8;
        let mut j0 = [0u8; BLOCK_BYTES];
        let mut remaining = nonce;
        while remaining.len() >= BLOCK_BYTES {
            let block: &[u8; BLOCK_BYTES] = remaining[..BLOCK_BYTES].try_into().unwrap();
            ghash_block(multiplier, &mut j0, block);
            remaining = &remaining[BLOCK_BYTES..];
        }
        if !remaining.is_empty() {
            let mut block = [0u8; BLOCK_BYTES];
            block[..remaining.len()].copy_from_slice(remaining);
            ghash_block(multiplier, &mut j0, &block);
        }

        let mut length_block = [0u8; BLOCK_BYTES];
        length_block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
        ghash_block(multiplier, &mut j0, &length_block);
        j0
    }

    fn check_block_count(&self, block_count: usize) -> Result<(), AeadError<C::Error>> {
        let available = usize::try_from(self.blocks_remaining).unwrap_or(usize::MAX);
        if block_count > available {
            return Err(AeadError::InputTooLong);
        }
        Ok(())
    }

    fn next_counter_block(&mut self) -> Result<[u8; BLOCK_BYTES], AeadError<C::Error>> {
        if self.blocks_remaining == 0 {
            return Err(AeadError::InputTooLong);
        }
        self.blocks_remaining -= 1;

        let value = u32::from_be_bytes(self.counter[12..].try_into().unwrap()).wrapping_add(1);
        self.counter[12..].copy_from_slice(&value.to_be_bytes());
        let mut output = [0u8; BLOCK_BYTES];
        self.cipher
            .process_block(&self.counter, &mut output)
            .map_err(AeadError::Cipher)?;
        Ok(output)
    }

    fn process_full_block(
        &mut self,
        direction: CipherDirection,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8],
    ) -> Result<(), AeadError<C::Error>> {
        self.start_data();
        let counter = self.next_counter_block()?;
        match direction {
            CipherDirection::Encrypt => {
                let ciphertext = core::array::from_fn(|index| input[index] ^ counter[index]);
                output[..BLOCK_BYTES].copy_from_slice(&ciphertext);
                ghash_block(&self.multiplier, &mut self.hash, &ciphertext);
            }
            CipherDirection::Decrypt => {
                ghash_block(&self.multiplier, &mut self.hash, input);
                for index in 0..BLOCK_BYTES {
                    output[index] = input[index] ^ counter[index];
                }
            }
        }
        self.total_length += BLOCK_BYTES as u64;
        Ok(())
    }

    fn calculate_tag(&mut self) -> Result<[u8; MAX_MAC_BYTES], AeadError<C::Error>> {
        let aad_bits = self
            .aad_length
            .checked_mul(8)
            .ok_or(AeadError::InputTooLong)?;
        let data_bits = self
            .total_length
            .checked_mul(8)
            .ok_or(AeadError::InputTooLong)?;
        let mut length_block = [0u8; BLOCK_BYTES];
        length_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        length_block[8..].copy_from_slice(&data_bits.to_be_bytes());
        ghash_block(&self.multiplier, &mut self.hash, &length_block);

        let mut tag_mask = [0u8; BLOCK_BYTES];
        self.cipher
            .process_block(&self.j0, &mut tag_mask)
            .map_err(AeadError::Cipher)?;
        Ok(core::array::from_fn(|index| {
            tag_mask[index] ^ self.hash[index]
        }))
    }
}

impl<C> Display for GcmBlockCipher<C>
where
    C: BlockCipher + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/GCM")
    }
}

impl<C> AeadCipher for GcmBlockCipher<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Error = AeadError<C::Error>;

    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.direction()?;
        if self.data_started {
            return Err(AeadError::AadAfterData);
        }
        let input_len = u64::try_from(input.len()).map_err(|_| AeadError::InputTooLong)?;
        let new_length = self
            .aad_length
            .checked_add(input_len)
            .filter(|length| *length <= u64::MAX / 8)
            .ok_or(AeadError::InputTooLong)?;

        self.mac = None;
        self.feed_aad(input);
        self.aad_length = new_length;
        Ok(())
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction()?;
        let required = self.update_output_len(input.len())?;
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        self.check_block_count(required / BLOCK_BYTES)?;
        if input.is_empty() {
            return Ok(0);
        }

        self.mac = None;
        self.data_started = true;
        let capacity = self.buffer_capacity();
        let mut written = 0;
        for &byte in input {
            self.buffer[self.buffer_pos] = byte;
            self.buffer_pos += 1;
            if self.buffer_pos == capacity {
                let block: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
                self.process_full_block(direction, &block, &mut output[written..])?;
                written += BLOCK_BYTES;

                if direction == CipherDirection::Decrypt {
                    self.buffer.copy_within(BLOCK_BYTES..capacity, 0);
                    self.buffer_pos = self.mac_size;
                } else {
                    self.buffer_pos = 0;
                }
            }
        }
        Ok(written)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction()?;
        let extra = match direction {
            CipherDirection::Encrypt => self.buffer_pos,
            CipherDirection::Decrypt => {
                if self.buffer_pos < self.mac_size {
                    return Err(AeadError::CiphertextTooShort {
                        minimum: self.mac_size,
                        actual: self.buffer_pos,
                    });
                }
                self.buffer_pos - self.mac_size
            }
        };
        let required = if direction == CipherDirection::Encrypt {
            extra + self.mac_size
        } else {
            extra
        };
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        self.check_block_count(usize::from(extra != 0))?;

        self.mac = None;
        self.start_data();
        let result = (|| {
            let mut final_plaintext = [0u8; BLOCK_BYTES];
            if extra != 0 {
                let counter = self.next_counter_block()?;
                let mut ciphertext = [0u8; BLOCK_BYTES];
                ciphertext[..extra].copy_from_slice(&self.buffer[..extra]);
                match direction {
                    CipherDirection::Encrypt => {
                        for index in 0..extra {
                            ciphertext[index] ^= counter[index];
                        }
                        output[..extra].copy_from_slice(&ciphertext[..extra]);
                    }
                    CipherDirection::Decrypt => {
                        for index in 0..extra {
                            final_plaintext[index] = ciphertext[index] ^ counter[index];
                        }
                    }
                }
                ghash_block(&self.multiplier, &mut self.hash, &ciphertext);
                self.total_length += extra as u64;
            }

            let tag = self.calculate_tag()?;
            match direction {
                CipherDirection::Encrypt => {
                    output[extra..extra + self.mac_size].copy_from_slice(&tag[..self.mac_size]);
                }
                CipherDirection::Decrypt => {
                    let received = &self.buffer[extra..extra + self.mac_size];
                    if !fixed_time_eq(&tag[..self.mac_size], received) {
                        return Err(AeadError::AuthenticationFailed);
                    }
                    output[..extra].copy_from_slice(&final_plaintext[..extra]);
                }
            }
            self.mac = Some(tag);
            Ok(required)
        })();

        self.state = State::Finalized(direction);
        self.buffer.fill(0);
        self.buffer_pos = 0;
        if result.is_err() {
            self.mac = None;
        }
        result
    }

    fn mac(&self) -> Option<&[u8]> {
        self.mac.as_ref().map(|mac| &mac[..self.mac_size])
    }

    fn reset(&mut self) {
        self.mac = None;
        self.state = match self.state {
            State::Encrypt if self.data_started => State::Finalized(CipherDirection::Encrypt),
            State::Encrypt => {
                self.restore_initial_state();
                State::Encrypt
            }
            State::Decrypt | State::Finalized(CipherDirection::Decrypt) => {
                self.restore_initial_state();
                State::Decrypt
            }
            State::Finalized(CipherDirection::Encrypt) => {
                self.restore_initial_state();
                State::Finalized(CipherDirection::Encrypt)
            }
            State::Uninitialized => State::Uninitialized,
        };
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let mut total = self
            .buffer_pos
            .checked_add(input_len)
            .ok_or(AeadError::InputTooLong)?;
        // A decryption shorter than the tag outputs nothing yet; do_final
        // reports it.
        if self.is_decrypting() {
            total = total.saturating_sub(self.mac_size);
        }
        Ok(total - total % BLOCK_BYTES)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let total = self
            .buffer_pos
            .checked_add(input_len)
            .ok_or(AeadError::InputTooLong)?;
        if self.is_decrypting() {
            Ok(total.saturating_sub(self.mac_size))
        } else {
            total
                .checked_add(self.mac_size)
                .ok_or(AeadError::InputTooLong)
        }
    }
}

impl<C> AeadBlockCipher for GcmBlockCipher<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }
}

impl<C> GcmBlockCipher<C>
where
    C: BlockCipher,
{
    /// Initializes GCM from separate cipher parameters, nonce, initial AAD,
    /// and tag size.
    ///
    /// This entry point lets constructions such as GMAC reuse the caller's
    /// original block-cipher parameter type without introducing a wrapper type
    /// that the underlying cipher would also have to support.
    pub fn init_with_parts<P>(
        &mut self,
        direction: CipherDirection,
        cipher_params: &P,
        nonce: &[u8],
        initial_aad: &[u8],
        mac_size: usize,
    ) -> Result<(), AeadInitError<<C as BlockCipherInit<P>>::Error>>
    where
        C: BlockCipherInit<P>,
        P: KeyParams + ?Sized,
    {
        self.state = State::Uninitialized;
        self.mac = None;
        if self.cipher.block_size() != BLOCK_BYTES {
            return Err(AeadInitError::InvalidBlockSize {
                actual: self.cipher.block_size(),
                required: BLOCK_BYTES,
            });
        }

        if nonce.is_empty()
            || u64::try_from(nonce.len())
                .ok()
                .and_then(|length| length.checked_mul(8))
                .is_none()
        {
            return Err(AeadInitError::InvalidNonceLength {
                actual: nonce.len(),
            });
        }
        if !(MIN_MAC_BYTES..=MAX_MAC_BYTES).contains(&mac_size) {
            return Err(AeadInitError::InvalidMacSize { actual: mac_size });
        }
        let initial_aad_len = u64::try_from(initial_aad.len())
            .ok()
            .filter(|length| *length <= u64::MAX / 8)
            .ok_or(AeadInitError::InvalidInitialAadLength {
                actual: initial_aad.len(),
            })?;

        self.cipher
            .init(CipherDirection::Encrypt, cipher_params)
            .map_err(AeadInitError::Cipher)?;
        // The cipher was just keyed and has 16-byte blocks, so encrypting one
        // block can fail only if the cipher breaks its own contract.
        let mut h = [0u8; BLOCK_BYTES];
        self.cipher
            .process_block(&[0; BLOCK_BYTES], &mut h)
            .map_err(|_| AeadInitError::InternalFailure)?;
        let multiplier = Multiplier::new(h);
        h.zeroize();
        let mut j0 = Self::calculate_j0(&multiplier, nonce);

        // Reuse means the same H and J0, which is what breaks GCM; unlike the
        // raw key and nonce, these have a fixed size and need no allocation.
        if direction == CipherDirection::Encrypt
            && self.has_key_nonce
            && fixed_time_eq(multiplier.h(), self.multiplier.h()) & fixed_time_eq(&j0, &self.j0)
        {
            j0.zeroize();
            return Err(AeadInitError::NonceReuse);
        }

        self.mac_size = mac_size;
        self.multiplier = multiplier;
        self.j0 = j0;
        self.has_key_nonce = true;

        self.reset_blank();
        self.aad_length = initial_aad_len;
        self.feed_aad(initial_aad);
        self.save_initial_aad_state();
        self.state = match direction {
            CipherDirection::Encrypt => State::Encrypt,
            CipherDirection::Decrypt => State::Decrypt,
        };
        Ok(())
    }
}

impl<C> Drop for GcmBlockCipher<C> {
    fn drop(&mut self) {
        self.j0.zeroize();
        self.counter.zeroize();
        self.buffer.zeroize();
        self.hash.zeroize();
        self.aad_hash.zeroize();
        self.aad_block.zeroize();
        self.initial_aad_hash.zeroize();
        self.initial_aad_block.zeroize();
        self.mac.zeroize();
    }
}

impl<C, P> AeadCipherInit<P> for GcmBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    <C as BlockCipherInit<P>>::Error: 'static,
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.init_with_parts(
            direction,
            params,
            params.nonce(),
            params.initial_aad(),
            params.mac_size(),
        )
    }
}

fn ghash_block(multiplier: &Multiplier, state: &mut [u8; BLOCK_BYTES], block: &[u8; BLOCK_BYTES]) {
    for index in 0..BLOCK_BYTES {
        state[index] ^= block[index];
    }
    multiplier.multiply_h(state);
}

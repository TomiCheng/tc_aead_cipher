//! EAX authenticated-encryption engine.

use super::{MAX_BLOCK_BYTES, MIN_MAC_BYTES};
use crate::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams,
    MacSizeParams, NonceParams,
};
use core::fmt;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};
use tc_constant_time::fixed_time_eq;

const MAX_BUFFER_BYTES: usize = MAX_BLOCK_BYTES * 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Uninitialised,
    Encrypt,
    Decrypt,
    Finalized(CipherDirection),
}

#[derive(Clone, Copy, Default)]
struct CmacState {
    mac: [u8; MAX_BLOCK_BYTES],
    buffer: [u8; MAX_BLOCK_BYTES],
    pos: usize,
}

impl CmacState {
    fn with_domain(block_size: usize, domain: u8) -> Self {
        let mut state = Self::default();
        state.buffer[block_size - 1] = domain;
        state.pos = block_size;
        state
    }

    fn update<C: BlockCipher>(
        &mut self,
        cipher: &mut C,
        block_size: usize,
        mut input: &[u8],
    ) -> Result<(), C::Error> {
        let gap = block_size - self.pos;
        if input.len() > gap {
            self.buffer[self.pos..block_size].copy_from_slice(&input[..gap]);
            self.process_buffer(cipher, block_size)?;
            input = &input[gap..];
            while input.len() > block_size {
                self.buffer[..block_size].copy_from_slice(&input[..block_size]);
                self.pos = block_size;
                self.process_buffer(cipher, block_size)?;
                input = &input[block_size..];
            }
        }
        self.buffer[self.pos..self.pos + input.len()].copy_from_slice(input);
        self.pos += input.len();
        Ok(())
    }

    fn finish<C: BlockCipher>(
        mut self,
        cipher: &mut C,
        block_size: usize,
        k1: &[u8; MAX_BLOCK_BYTES],
        k2: &[u8; MAX_BLOCK_BYTES],
    ) -> Result<[u8; MAX_BLOCK_BYTES], C::Error> {
        let subkey = if self.pos == block_size {
            k1
        } else {
            self.buffer[self.pos] = 0x80;
            self.buffer[self.pos + 1..block_size].fill(0);
            k2
        };
        for ((buffer, mac), subkey) in self.buffer[..block_size]
            .iter_mut()
            .zip(&self.mac[..block_size])
            .zip(&subkey[..block_size])
        {
            *buffer ^= *mac ^ *subkey;
        }
        let mut output = [0u8; MAX_BLOCK_BYTES];
        cipher.process_block(&self.buffer[..block_size], &mut output[..block_size])?;
        Ok(output)
    }

    fn process_buffer<C: BlockCipher>(
        &mut self,
        cipher: &mut C,
        block_size: usize,
    ) -> Result<(), C::Error> {
        for index in 0..block_size {
            self.buffer[index] ^= self.mac[index];
        }
        cipher.process_block(&self.buffer[..block_size], &mut self.mac[..block_size])?;
        self.buffer[..block_size].fill(0);
        self.pos = 0;
        Ok(())
    }
}

/// EAX authenticated encryption over a 64- or 128-bit block cipher.
///
/// One cipher instance is shared by the internal CTR and CMAC states, so `C`
/// does not need to implement `Clone` and no additional cipher factory trait is
/// required.
pub struct EaxBlockCipher<C> {
    cipher: C,
    state: State,
    block_size: usize,
    mac_size: usize,
    k1: [u8; MAX_BLOCK_BYTES],
    k2: [u8; MAX_BLOCK_BYTES],
    nonce_mac: [u8; MAX_BLOCK_BYTES],
    aad_mac: CmacState,
    initial_aad_state: CmacState,
    aad_result: [u8; MAX_BLOCK_BYTES],
    data_mac: CmacState,
    counter: [u8; MAX_BLOCK_BYTES],
    keystream: [u8; MAX_BLOCK_BYTES],
    byte_count: usize,
    buffer: [u8; MAX_BUFFER_BYTES],
    buffer_pos: usize,
    data_started: bool,
    mac: Option<[u8; MAX_BLOCK_BYTES]>,
    // L = E_K(0) of the last successful init; with nonce_mac (N') it
    // identifies the key and initial counter that must not repeat.
    last_l: [u8; MAX_BLOCK_BYTES],
    has_key_nonce: bool,
}

impl<C> EaxBlockCipher<C> {
    /// Creates an uninitialized EAX engine around `cipher`.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            state: State::Uninitialised,
            block_size: 0,
            mac_size: 0,
            k1: [0; MAX_BLOCK_BYTES],
            k2: [0; MAX_BLOCK_BYTES],
            nonce_mac: [0; MAX_BLOCK_BYTES],
            aad_mac: CmacState {
                mac: [0; MAX_BLOCK_BYTES],
                buffer: [0; MAX_BLOCK_BYTES],
                pos: 0,
            },
            initial_aad_state: CmacState {
                mac: [0; MAX_BLOCK_BYTES],
                buffer: [0; MAX_BLOCK_BYTES],
                pos: 0,
            },
            aad_result: [0; MAX_BLOCK_BYTES],
            data_mac: CmacState {
                mac: [0; MAX_BLOCK_BYTES],
                buffer: [0; MAX_BLOCK_BYTES],
                pos: 0,
            },
            counter: [0; MAX_BLOCK_BYTES],
            keystream: [0; MAX_BLOCK_BYTES],
            byte_count: 0,
            buffer: [0; MAX_BUFFER_BYTES],
            buffer_pos: 0,
            data_started: false,
            mac: None,
            last_l: [0; MAX_BLOCK_BYTES],
            has_key_nonce: false,
        }
    }

    fn direction<E>(&self) -> Result<CipherDirection, AeadError<E>> {
        match self.state {
            State::Encrypt => Ok(CipherDirection::Encrypt),
            State::Decrypt => Ok(CipherDirection::Decrypt),
            State::Finalized(_) => Err(AeadError::AlreadyFinalized),
            State::Uninitialised => Err(AeadError::NotInitialized),
        }
    }

    fn is_decrypting(&self) -> bool {
        matches!(
            self.state,
            State::Decrypt | State::Finalized(CipherDirection::Decrypt)
        )
    }

    fn buffer_capacity(&self) -> usize {
        self.block_size + usize::from(self.is_decrypting()) * self.mac_size
    }

    fn reset_packet(&mut self, clear_mac: bool) {
        self.aad_mac = self.initial_aad_state;
        self.data_mac = CmacState::default();
        self.aad_result.fill(0);
        self.counter = self.nonce_mac;
        self.keystream.fill(0);
        self.byte_count = 0;
        self.buffer.fill(0);
        self.buffer_pos = 0;
        self.data_started = false;
        if clear_mac {
            self.mac = None;
        }
    }
}

impl<C: BlockCipher> EaxBlockCipher<C> {
    fn start_data(&mut self) -> Result<(), AeadError<C::Error>> {
        if self.data_started {
            return Ok(());
        }
        self.aad_result = self
            .aad_mac
            .finish(&mut self.cipher, self.block_size, &self.k1, &self.k2)
            .map_err(AeadError::Cipher)?;
        self.data_mac = CmacState::with_domain(self.block_size, 2);
        self.data_started = true;
        Ok(())
    }

    fn crypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), AeadError<C::Error>> {
        for (&input, output) in input.iter().zip(output) {
            if self.byte_count == 0 {
                self.cipher
                    .process_block(
                        &self.counter[..self.block_size],
                        &mut self.keystream[..self.block_size],
                    )
                    .map_err(AeadError::Cipher)?;
            }
            *output = input ^ self.keystream[self.byte_count];
            self.byte_count += 1;
            if self.byte_count == self.block_size {
                self.byte_count = 0;
                increment_be(&mut self.counter[..self.block_size]);
            }
        }
        Ok(())
    }

    fn process_full_block(
        &mut self,
        direction: CipherDirection,
        output: &mut [u8],
    ) -> Result<(), AeadError<C::Error>> {
        let input: [u8; MAX_BLOCK_BYTES] = self.buffer[..MAX_BLOCK_BYTES].try_into().unwrap();
        match direction {
            CipherDirection::Encrypt => {
                self.crypt(&input[..self.block_size], &mut output[..self.block_size])?;
                self.data_mac
                    .update(
                        &mut self.cipher,
                        self.block_size,
                        &output[..self.block_size],
                    )
                    .map_err(AeadError::Cipher)?;
                self.buffer_pos = 0;
            }
            CipherDirection::Decrypt => {
                self.data_mac
                    .update(&mut self.cipher, self.block_size, &input[..self.block_size])
                    .map_err(AeadError::Cipher)?;
                self.crypt(&input[..self.block_size], &mut output[..self.block_size])?;
                let capacity = self.buffer_capacity();
                self.buffer.copy_within(self.block_size..capacity, 0);
                self.buffer_pos = self.mac_size;
            }
        }
        Ok(())
    }

    fn calculate_mac(&mut self) -> Result<[u8; MAX_BLOCK_BYTES], AeadError<C::Error>> {
        let data_result = self
            .data_mac
            .finish(&mut self.cipher, self.block_size, &self.k1, &self.k2)
            .map_err(AeadError::Cipher)?;
        Ok(core::array::from_fn(|index| {
            self.nonce_mac[index] ^ self.aad_result[index] ^ data_result[index]
        }))
    }

    fn derive_subkeys(&mut self) -> Result<[u8; MAX_BLOCK_BYTES], C::Error> {
        let mut l = [0u8; MAX_BLOCK_BYTES];
        self.cipher.process_block(
            &[0u8; MAX_BLOCK_BYTES][..self.block_size],
            &mut l[..self.block_size],
        )?;
        let reduction = if self.block_size == 16 { 0x87 } else { 0x1b };
        double_block(
            &l[..self.block_size],
            &mut self.k1[..self.block_size],
            reduction,
        );
        double_block(
            &self.k1[..self.block_size],
            &mut self.k2[..self.block_size],
            reduction,
        );
        Ok(l)
    }

    fn cmac_domain(&mut self, domain: u8, input: &[u8]) -> Result<[u8; MAX_BLOCK_BYTES], C::Error> {
        let mut state = CmacState::with_domain(self.block_size, domain);
        state.update(&mut self.cipher, self.block_size, input)?;
        state.finish(&mut self.cipher, self.block_size, &self.k1, &self.k2)
    }
}

impl<C: Display> Display for EaxBlockCipher<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/EAX")
    }
}

impl<C> AeadCipher for EaxBlockCipher<C>
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
        self.mac = None;
        self.aad_mac
            .update(&mut self.cipher, self.block_size, input)
            .map_err(AeadError::Cipher)
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
        if input.is_empty() {
            return Ok(0);
        }
        self.start_data()?;
        self.mac = None;

        let capacity = self.buffer_capacity();
        let mut written = 0;
        for &byte in input {
            self.buffer[self.buffer_pos] = byte;
            self.buffer_pos += 1;
            if self.buffer_pos == capacity {
                self.process_full_block(direction, &mut output[written..])?;
                written += self.block_size;
            }
        }
        Ok(written)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction()?;
        self.mac = None;
        self.start_data()?;
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

        let result = (|| {
            let mut final_output = [0u8; MAX_BLOCK_BYTES];
            let mut final_input = [0u8; MAX_BLOCK_BYTES];
            final_input[..extra].copy_from_slice(&self.buffer[..extra]);
            match direction {
                CipherDirection::Encrypt => {
                    self.crypt(&final_input[..extra], &mut final_output[..extra])?;
                    self.data_mac
                        .update(&mut self.cipher, self.block_size, &final_output[..extra])
                        .map_err(AeadError::Cipher)?;
                    let tag = self.calculate_mac()?;
                    output[..extra].copy_from_slice(&final_output[..extra]);
                    output[extra..extra + self.mac_size].copy_from_slice(&tag[..self.mac_size]);
                    self.mac = Some(tag);
                }
                CipherDirection::Decrypt => {
                    self.data_mac
                        .update(&mut self.cipher, self.block_size, &final_input[..extra])
                        .map_err(AeadError::Cipher)?;
                    self.crypt(&final_input[..extra], &mut final_output[..extra])?;
                    let tag = self.calculate_mac()?;
                    if !fixed_time_eq(
                        &tag[..self.mac_size],
                        &self.buffer[extra..extra + self.mac_size],
                    ) {
                        return Err(AeadError::AuthenticationFailed);
                    }
                    output[..extra].copy_from_slice(&final_output[..extra]);
                    self.mac = Some(tag);
                }
            }
            Ok(required)
        })();

        self.state = State::Finalized(direction);
        self.reset_packet(false);
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
            // Encrypting data uses the keystream, so the nonce is spent.
            State::Encrypt if self.data_started => State::Finalized(CipherDirection::Encrypt),
            State::Encrypt => State::Encrypt,
            State::Decrypt | State::Finalized(CipherDirection::Decrypt) => State::Decrypt,
            State::Finalized(CipherDirection::Encrypt) => {
                State::Finalized(CipherDirection::Encrypt)
            }
            State::Uninitialised => return,
        };
        self.reset_packet(true);
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let mut total = self
            .buffer_pos
            .checked_add(input_len)
            .ok_or(AeadError::InputTooLong)?;
        if self.is_decrypting() {
            total = total.saturating_sub(self.mac_size);
        }
        Ok(total - total % self.block_size.max(1))
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

impl<C> AeadBlockCipher for EaxBlockCipher<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }
}

impl<C, P> AeadCipherInit<P> for EaxBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    <C as BlockCipherInit<P>>::Error: 'static,
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.state = State::Uninitialised;
        self.mac = None;
        let block_size = self.cipher.block_size();
        if !matches!(block_size, 8 | 16) {
            return Err(AeadInitError::InvalidBlockSize {
                actual: block_size,
                required: MAX_BLOCK_BYTES,
            });
        }
        let mac_size = params.mac_size();
        if !(MIN_MAC_BYTES..=block_size).contains(&mac_size) {
            return Err(AeadInitError::InvalidMacSize { actual: mac_size });
        }

        self.block_size = block_size;
        self.mac_size = mac_size;
        self.k1.fill(0);
        self.k2.fill(0);
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(AeadInitError::Cipher)?;
        // The cipher was just keyed with a supported block size, so encrypting
        // a block can fail only if the cipher breaks its own contract.
        let mut l = self
            .derive_subkeys()
            .map_err(|_| AeadInitError::InternalFailure)?;
        let nonce_mac = self
            .cmac_domain(0, params.nonce())
            .map_err(|_| AeadInitError::InternalFailure)?;

        // Reuse means the same key and initial counter N', which is what breaks
        // EAX; L stands for the key without keeping a copy of it.
        let reused = self.has_key_nonce
            && fixed_time_eq(&l[..block_size], &self.last_l[..block_size])
                & fixed_time_eq(&nonce_mac[..block_size], &self.nonce_mac[..block_size]);
        if direction == CipherDirection::Encrypt && reused {
            l.fill(0);
            return Err(AeadInitError::NonceReuse);
        }

        let mut initial_aad_state = CmacState::with_domain(self.block_size, 1);
        initial_aad_state
            .update(&mut self.cipher, self.block_size, params.initial_aad())
            .map_err(|_| AeadInitError::InternalFailure)?;
        self.nonce_mac = nonce_mac;
        self.initial_aad_state = initial_aad_state;
        self.reset_packet(true);

        self.last_l = l;
        l.fill(0);
        self.has_key_nonce = true;
        self.state = match direction {
            CipherDirection::Encrypt => State::Encrypt,
            CipherDirection::Decrypt => State::Decrypt,
        };
        Ok(())
    }
}

fn double_block(input: &[u8], output: &mut [u8], reduction: u8) {
    let carry = input[0] >> 7;
    let mut next_bit = 0u8;
    for (&input, output) in input.iter().zip(output.iter_mut()).rev() {
        *output = (input << 1) | next_bit;
        next_bit = input >> 7;
    }
    let last = output.len() - 1;
    output[last] ^= reduction & 0u8.wrapping_sub(carry);
}

fn increment_be(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

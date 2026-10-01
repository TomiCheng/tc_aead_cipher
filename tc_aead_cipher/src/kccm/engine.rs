//! KCCM authenticated-encryption engine.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Display, Formatter};
use tc_constant_time::fixed_time_eq;

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};

use super::{MAX_MAC_BYTES, MIN_MAC_BYTES};
use crate::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams,
    MacSizeParams, NonceParams,
};

const MAX_BLOCK_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Uninitialised,
    Encrypt,
    Decrypt,
    Finalised(CipherDirection),
}

/// DSTU 7624 KCCM with a compile-time `NB` parameter.
///
/// `NB = 4` is the standard practical default. The construction also permits
/// 6 and 8. Message and AAD lengths must be complete cipher blocks.
pub struct KccmBlockCipher<C, const NB: usize = 4> {
    cipher: C,
    state: State,
    data_started: bool,
    block_size: usize,
    mac_size: usize,
    nonce: [u8; MAX_BLOCK_BYTES],
    aad: Vec<u8>,
    initial_aad_len: usize,
    data: Vec<u8>,
    last_key: Vec<u8>,
    last_nonce: [u8; MAX_BLOCK_BYTES],
    has_key_nonce: bool,
    mac: Option<[u8; MAX_MAC_BYTES]>,
}

impl<C> KccmBlockCipher<C, 4> {
    /// Creates an uninitialized KCCM engine using the recommended `Nb = 4`.
    pub const fn new(cipher: C) -> Self {
        Self::with_nb(cipher)
    }
}

impl<C, const NB: usize> KccmBlockCipher<C, NB> {
    /// Creates an uninitialized KCCM engine with the type's `NB` value.
    pub const fn with_nb(cipher: C) -> Self {
        Self {
            cipher,
            state: State::Uninitialised,
            data_started: false,
            block_size: 0,
            mac_size: 0,
            nonce: [0; MAX_BLOCK_BYTES],
            aad: Vec::new(),
            initial_aad_len: 0,
            data: Vec::new(),
            last_key: Vec::new(),
            last_nonce: [0; MAX_BLOCK_BYTES],
            has_key_nonce: false,
            mac: None,
        }
    }

    fn direction<E>(&self) -> Result<CipherDirection, AeadError<E>> {
        match self.state {
            State::Encrypt => Ok(CipherDirection::Encrypt),
            State::Decrypt => Ok(CipherDirection::Decrypt),
            State::Finalised(_) => Err(AeadError::AlreadyFinalized),
            State::Uninitialised => Err(AeadError::NotInitialized),
        }
    }

    fn required_output(&self, additional: usize) -> usize {
        let total = self.data.len().saturating_add(additional);
        match self.state {
            State::Decrypt => total.saturating_sub(self.mac_size),
            _ => total.saturating_add(self.mac_size),
        }
    }

    fn clear_packet(&mut self) {
        self.aad[self.initial_aad_len..].fill(0);
        self.aad.truncate(self.initial_aad_len);
        self.data.fill(0);
        self.data.clear();
        self.data_started = false;
    }
}

impl<C: BlockCipher, const NB: usize> KccmBlockCipher<C, NB> {
    fn process_block(
        &mut self,
        input: &[u8],
    ) -> Result<[u8; MAX_BLOCK_BYTES], AeadError<C::Error>> {
        let mut output = [0u8; MAX_BLOCK_BYTES];
        self.cipher
            .process_block(&input[..self.block_size], &mut output[..self.block_size])
            .map_err(AeadError::Cipher)?;
        Ok(output)
    }

    fn calculate_mac(
        &mut self,
        plaintext: &[u8],
    ) -> Result<[u8; MAX_BLOCK_BYTES], AeadError<C::Error>> {
        let has_aad = !self.aad.is_empty();
        let mut g1 = [0u8; MAX_BLOCK_BYTES];
        let nonce_prefix = self.block_size - NB - 1;
        g1[..nonce_prefix].copy_from_slice(&self.nonce[..nonce_prefix]);
        g1[nonce_prefix..nonce_prefix + 4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
        g1[self.block_size - 1] = flag(has_aad, self.mac_size, NB);
        let mut mac = self.process_block(&g1)?;

        if has_aad {
            let mut length_block = [0u8; MAX_BLOCK_BYTES];
            length_block[..4].copy_from_slice(&(self.aad.len() as u32).to_le_bytes());
            xor_prefix(&mut mac, &length_block, self.block_size);
            mac = self.process_block(&mac)?;

            for offset in (0..self.aad.len()).step_by(self.block_size) {
                for (mac, aad) in mac[..self.block_size]
                    .iter_mut()
                    .zip(&self.aad[offset..offset + self.block_size])
                {
                    *mac ^= *aad;
                }
                mac = self.process_block(&mac)?;
            }
        }

        for block in plaintext.chunks_exact(self.block_size) {
            xor_prefix(&mut mac, block, self.block_size);
            mac = self.process_block(&mac)?;
        }
        Ok(mac)
    }

    fn crypt(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<[u8; MAX_BLOCK_BYTES], AeadError<C::Error>> {
        let nonce = self.nonce;
        let mut state = self.process_block(&nonce)?;
        let mut counter = [0u8; MAX_BLOCK_BYTES];
        counter[0] = 1;

        for (input, output) in input
            .chunks_exact(self.block_size)
            .zip(output.chunks_exact_mut(self.block_size))
        {
            add_le(&mut state[..self.block_size], &counter[..self.block_size]);
            let mask = self.process_block(&state)?;
            for index in 0..self.block_size {
                output[index] = input[index] ^ mask[index];
            }
        }

        add_le(&mut state[..self.block_size], &counter[..self.block_size]);
        self.process_block(&state)
    }

    fn validate_lengths(&self, message_len: usize) -> Result<(), AeadError<C::Error>> {
        if message_len > u32::MAX as usize || self.aad.len() > u32::MAX as usize {
            return Err(AeadError::InputTooLong);
        }
        if message_len % self.block_size != 0 {
            return Err(AeadError::InputNotBlockAligned {
                block_size: self.block_size,
                actual: message_len,
            });
        }
        if self.aad.len() % self.block_size != 0 {
            return Err(AeadError::InputNotBlockAligned {
                block_size: self.block_size,
                actual: self.aad.len(),
            });
        }
        Ok(())
    }

    fn encrypt_packet(&mut self, output: &mut [u8]) -> Result<usize, AeadError<C::Error>> {
        let message_len = self.data.len();
        self.validate_lengths(message_len)?;
        let mut data = core::mem::take(&mut self.data);
        let result = (|| {
            let raw_mac = self.calculate_mac(&data)?;
            let tag_mask = self.crypt(&data, &mut output[..message_len])?;
            for index in 0..self.mac_size {
                output[message_len + index] = raw_mac[index] ^ tag_mask[index];
            }
            let mut mac = [0u8; MAX_MAC_BYTES];
            mac[..self.mac_size].copy_from_slice(&raw_mac[..self.mac_size]);
            self.mac = Some(mac);
            Ok(message_len + self.mac_size)
        })();
        data.fill(0);
        result
    }

    fn decrypt_packet(&mut self, output: &mut [u8]) -> Result<usize, AeadError<C::Error>> {
        if self.data.len() < self.mac_size {
            return Err(AeadError::CiphertextTooShort {
                minimum: self.mac_size,
                actual: self.data.len(),
            });
        }
        let message_len = self.data.len() - self.mac_size;
        self.validate_lengths(message_len)?;
        let mut data = core::mem::take(&mut self.data);
        let mut plaintext = vec![0u8; message_len];
        let result = (|| {
            let tag_mask = self.crypt(&data[..message_len], &mut plaintext)?;
            let mut received_mac = [0u8; MAX_MAC_BYTES];
            for index in 0..self.mac_size {
                received_mac[index] = data[message_len + index] ^ tag_mask[index];
            }
            let raw_mac = self.calculate_mac(&plaintext)?;
            if !fixed_time_eq(&raw_mac[..self.mac_size], &received_mac[..self.mac_size]) {
                return Err(AeadError::AuthenticationFailed);
            }
            output[..message_len].copy_from_slice(&plaintext);
            let mut mac = [0u8; MAX_MAC_BYTES];
            mac[..self.mac_size].copy_from_slice(&raw_mac[..self.mac_size]);
            self.mac = Some(mac);
            Ok(message_len)
        })();
        plaintext.fill(0);
        data.fill(0);
        result
    }
}

impl<C: Display, const NB: usize> Display for KccmBlockCipher<C, NB> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/KCCM")
    }
}

impl<C, const NB: usize> AeadCipher for KccmBlockCipher<C, NB>
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
        self.aad
            .len()
            .checked_add(input.len())
            .filter(|&length| length <= u32::MAX as usize)
            .ok_or(AeadError::InputTooLong)?;
        self.mac = None;
        self.aad.extend_from_slice(input);
        Ok(())
    }

    fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction()?;
        let total = self
            .data
            .len()
            .checked_add(input.len())
            .ok_or(AeadError::InputTooLong)?;
        let message_len = match direction {
            CipherDirection::Encrypt => total,
            CipherDirection::Decrypt => total.saturating_sub(self.mac_size),
        };
        if message_len > u32::MAX as usize {
            return Err(AeadError::InputTooLong);
        }
        self.mac = None;
        self.data_started = true;
        self.data.extend_from_slice(input);
        Ok(0)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction()?;
        let required = self.required_output(0);
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        self.mac = None;
        let result = match direction {
            CipherDirection::Encrypt => self.encrypt_packet(output),
            CipherDirection::Decrypt => self.decrypt_packet(output),
        };
        self.state = State::Finalised(direction);
        self.clear_packet();
        result
    }

    fn mac(&self) -> Option<&[u8]> {
        self.mac.as_ref().map(|mac| &mac[..self.mac_size])
    }

    fn reset(&mut self) {
        self.mac = None;
        self.state = match self.state {
            State::Encrypt => State::Encrypt,
            State::Decrypt | State::Finalised(CipherDirection::Decrypt) => State::Decrypt,
            State::Finalised(CipherDirection::Encrypt) => {
                State::Finalised(CipherDirection::Encrypt)
            }
            State::Uninitialised => {
                self.initial_aad_len = 0;
                self.clear_packet();
                return;
            }
        };
        self.clear_packet();
    }

    fn update_output_len(&self, _input_len: usize) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        Ok(self.required_output(input_len))
    }
}

impl<C, const NB: usize> AeadBlockCipher for KccmBlockCipher<C, NB>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }
}

impl<C, P, const NB: usize> AeadCipherInit<P> for KccmBlockCipher<C, NB>
where
    C: BlockCipher + BlockCipherInit<P>,
    <C as BlockCipherInit<P>>::Error: 'static,
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        if ![4, 6, 8].contains(&NB) {
            return Err(AeadInitError::InvalidCounterSize { actual: NB });
        }
        let block_size = self.cipher.block_size();
        if ![16, 32, 64].contains(&block_size) {
            return Err(AeadInitError::InvalidBlockSize {
                actual: block_size,
                required: 16,
            });
        }
        let nonce = params.nonce();
        if nonce.len() > block_size {
            return Err(AeadInitError::InvalidNonceLength {
                actual: nonce.len(),
            });
        }
        let mac_size = params.mac_size();
        if !(MIN_MAC_BYTES..=MAX_MAC_BYTES).contains(&mac_size)
            || ![8, 16, 32, 48, 64].contains(&mac_size)
            || mac_size > block_size
        {
            return Err(AeadInitError::InvalidMacSize { actual: mac_size });
        }
        let key = params.key();
        let mut padded_nonce = [0u8; MAX_BLOCK_BYTES];
        padded_nonce[..nonce.len()].copy_from_slice(nonce);
        if direction == CipherDirection::Encrypt
            && self.has_key_nonce
            && self.last_key == key
            && self.last_nonce[..block_size] == padded_nonce[..block_size]
        {
            return Err(AeadInitError::NonceReuse);
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(AeadInitError::Cipher)?;
        self.block_size = block_size;
        self.mac_size = mac_size;
        self.nonce = padded_nonce;
        self.initial_aad_len = 0;
        self.clear_packet();
        self.aad.extend_from_slice(params.initial_aad());
        self.initial_aad_len = self.aad.len();
        self.mac = None;
        self.last_key.fill(0);
        self.last_key.clear();
        self.last_key.extend_from_slice(key);
        self.last_nonce = padded_nonce;
        self.has_key_nonce = true;
        self.state = match direction {
            CipherDirection::Encrypt => State::Encrypt,
            CipherDirection::Decrypt => State::Decrypt,
        };
        Ok(())
    }
}

fn flag(has_aad: bool, mac_size: usize, nb: usize) -> u8 {
    let mac_bits = match mac_size {
        8 => 0x20,
        16 => 0x30,
        32 => 0x40,
        48 => 0x50,
        64 => 0x60,
        _ => unreachable!(),
    };
    (if has_aad { 0x80 } else { 0 }) | mac_bits | (nb as u8 - 1)
}

fn xor_prefix(target: &mut [u8], value: &[u8], length: usize) {
    for index in 0..length {
        target[index] ^= value[index];
    }
}

fn add_le(target: &mut [u8], value: &[u8]) {
    let mut carry = 0u16;
    for (target, value) in target.iter_mut().zip(value) {
        carry += u16::from(*target) + u16::from(*value);
        *target = carry as u8;
        carry >>= 8;
    }
}

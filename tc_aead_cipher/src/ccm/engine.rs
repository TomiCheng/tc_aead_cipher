//! Allocation-backed CCM authenticated-encryption engine.

use super::{BLOCK_BYTES, MAX_MAC_BYTES, MAX_NONCE_BYTES, MIN_MAC_BYTES, MIN_NONCE_BYTES};
use crate::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams,
    MacSizeParams, NonceParams,
};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};
use tc_constant_time::fixed_time_eq;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Uninitialised,
    Encrypt,
    Decrypt,
    Finalised(CipherDirection),
}

struct CbcMac<'a, C>
where
    C: BlockCipher,
{
    cipher: &'a mut C,
    state: [u8; BLOCK_BYTES],
    buffer: [u8; BLOCK_BYTES],
    buffer_pos: usize,
}

impl<'a, C> CbcMac<'a, C>
where
    C: BlockCipher,
{
    fn new(cipher: &'a mut C) -> Self {
        Self {
            cipher,
            state: [0; BLOCK_BYTES],
            buffer: [0; BLOCK_BYTES],
            buffer_pos: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), C::Error> {
        if self.buffer_pos != 0 {
            let take = (BLOCK_BYTES - self.buffer_pos).min(input.len());
            self.buffer[self.buffer_pos..self.buffer_pos + take].copy_from_slice(&input[..take]);
            self.buffer_pos += take;
            input = &input[take..];
            if self.buffer_pos < BLOCK_BYTES {
                return Ok(());
            }
            self.process_buffer()?;
        }

        while input.len() >= BLOCK_BYTES {
            let block: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
            self.process_block(block)?;
            input = &input[BLOCK_BYTES..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_pos = input.len();
        Ok(())
    }

    fn pad_to_block(&mut self) -> Result<(), C::Error> {
        if self.buffer_pos != 0 {
            self.buffer[self.buffer_pos..].fill(0);
            self.process_buffer()?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<[u8; BLOCK_BYTES], C::Error> {
        self.pad_to_block()?;
        Ok(self.state)
    }

    fn process_buffer(&mut self) -> Result<(), C::Error> {
        let block = self.buffer;
        self.process_block(&block)?;
        self.buffer.fill(0);
        self.buffer_pos = 0;
        Ok(())
    }

    fn process_block(&mut self, block: &[u8; BLOCK_BYTES]) -> Result<(), C::Error> {
        let input: [u8; BLOCK_BYTES] =
            core::array::from_fn(|index| self.state[index] ^ block[index]);
        let mut output = [0u8; BLOCK_BYTES];
        self.cipher.process_block(&input, &mut output)?;
        self.state = output;
        Ok(())
    }
}

/// Counter with CBC-MAC authenticated encryption over a 16-byte block cipher.
///
/// CCM is a packet construction: [`process_bytes`](AeadCipher::process_bytes)
/// buffers all input and returns zero. [`do_final`](AeadCipher::do_final)
/// authenticates and transforms the complete packet. During decryption no
/// plaintext is copied to the caller until authentication succeeds.
pub struct CcmBlockCipher<C> {
    cipher: C,
    state: State,
    data_started: bool,
    nonce: [u8; MAX_NONCE_BYTES],
    nonce_len: usize,
    mac_size: usize,
    aad: Vec<u8>,
    initial_aad_len: usize,
    data: Vec<u8>,
    last_key: Vec<u8>,
    has_key_nonce: bool,
    mac: Option<[u8; MAX_MAC_BYTES]>,
}

impl<C> CcmBlockCipher<C> {
    /// Creates an uninitialized CCM engine around `cipher`.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            state: State::Uninitialised,
            data_started: false,
            nonce: [0; MAX_NONCE_BYTES],
            nonce_len: 0,
            mac_size: 0,
            aad: Vec::new(),
            initial_aad_len: 0,
            data: Vec::new(),
            last_key: Vec::new(),
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

impl<C> CcmBlockCipher<C>
where
    C: BlockCipher,
{
    fn validate_message_len(&self, message_len: usize) -> Result<(), AeadError<C::Error>> {
        let q = BLOCK_BYTES - 1 - self.nonce_len;
        if q < 8 && (message_len as u64) >= (1u64 << (q * 8)) {
            return Err(AeadError::InputTooLong);
        }
        Ok(())
    }

    fn calculate_mac(&mut self, data: &[u8]) -> Result<[u8; BLOCK_BYTES], AeadError<C::Error>> {
        let q = BLOCK_BYTES - 1 - self.nonce_len;
        let mut b0 = [0u8; BLOCK_BYTES];
        if !self.aad.is_empty() {
            b0[0] |= 0x40;
        }
        b0[0] |= (((self.mac_size - 2) / 2) as u8) << 3;
        b0[0] |= (q - 1) as u8;
        b0[1..1 + self.nonce_len].copy_from_slice(&self.nonce[..self.nonce_len]);
        encode_low_bytes(data.len() as u64, &mut b0[BLOCK_BYTES - q..]);

        let mut mac = CbcMac::new(&mut self.cipher);
        mac.update(&b0).map_err(AeadError::Cipher)?;

        if !self.aad.is_empty() {
            let aad_len = self.aad.len() as u64;
            let mut encoded_len = [0u8; 10];
            let encoded_len = if aad_len < 0xff00 {
                encoded_len[..2].copy_from_slice(&(aad_len as u16).to_be_bytes());
                &encoded_len[..2]
            } else if u32::try_from(aad_len).is_ok() {
                encoded_len[..2].copy_from_slice(&[0xff, 0xfe]);
                encoded_len[2..6].copy_from_slice(&(aad_len as u32).to_be_bytes());
                &encoded_len[..6]
            } else {
                encoded_len[..2].copy_from_slice(&[0xff, 0xff]);
                encoded_len[2..].copy_from_slice(&aad_len.to_be_bytes());
                &encoded_len[..]
            };
            mac.update(encoded_len).map_err(AeadError::Cipher)?;
            mac.update(&self.aad).map_err(AeadError::Cipher)?;
            mac.pad_to_block().map_err(AeadError::Cipher)?;
        }

        mac.update(data).map_err(AeadError::Cipher)?;
        mac.finish().map_err(AeadError::Cipher)
    }

    fn counter_block(&self, counter: u64) -> [u8; BLOCK_BYTES] {
        let q = BLOCK_BYTES - 1 - self.nonce_len;
        let mut block = [0u8; BLOCK_BYTES];
        block[0] = (q - 1) as u8;
        block[1..1 + self.nonce_len].copy_from_slice(&self.nonce[..self.nonce_len]);
        encode_low_bytes(counter, &mut block[BLOCK_BYTES - q..]);
        block
    }

    fn encrypted_mac(
        &mut self,
        raw_mac: &[u8; BLOCK_BYTES],
    ) -> Result<[u8; MAX_MAC_BYTES], AeadError<C::Error>> {
        let counter = self.counter_block(0);
        let mut stream = [0u8; BLOCK_BYTES];
        self.cipher
            .process_block(&counter, &mut stream)
            .map_err(AeadError::Cipher)?;
        Ok(core::array::from_fn(|index| raw_mac[index] ^ stream[index]))
    }

    fn crypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), AeadError<C::Error>> {
        for (block_index, (input, output)) in input
            .chunks(BLOCK_BYTES)
            .zip(output.chunks_mut(BLOCK_BYTES))
            .enumerate()
        {
            let counter = self.counter_block(block_index as u64 + 1);
            let mut stream = [0u8; BLOCK_BYTES];
            self.cipher
                .process_block(&counter, &mut stream)
                .map_err(AeadError::Cipher)?;
            for ((output, input), stream) in output.iter_mut().zip(input).zip(stream) {
                *output = *input ^ stream;
            }
        }
        Ok(())
    }

    fn encrypt_packet(&mut self, output: &mut [u8]) -> Result<usize, AeadError<C::Error>> {
        let message_len = self.data.len();
        self.validate_message_len(message_len)?;
        let mut data = core::mem::take(&mut self.data);
        let result = (|| {
            let raw_mac = self.calculate_mac(&data)?;
            self.crypt(&data, &mut output[..message_len])?;
            let encrypted_mac = self.encrypted_mac(&raw_mac)?;
            output[message_len..message_len + self.mac_size]
                .copy_from_slice(&encrypted_mac[..self.mac_size]);
            self.mac = Some(raw_mac);
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
        self.validate_message_len(message_len)?;
        let mut data = core::mem::take(&mut self.data);
        let mut plaintext = vec![0u8; message_len];
        let result = (|| {
            self.crypt(&data[..message_len], &mut plaintext)?;
            let raw_mac = self.calculate_mac(&plaintext)?;
            let encrypted_mac = self.encrypted_mac(&raw_mac)?;
            let received_tag = &data[message_len..];

            if !fixed_time_eq(&encrypted_mac[..self.mac_size], received_tag) {
                return Err(AeadError::AuthenticationFailed);
            }

            output[..message_len].copy_from_slice(&plaintext);
            self.mac = Some(raw_mac);
            Ok(message_len)
        })();
        plaintext.fill(0);
        data.fill(0);
        result
    }
}

impl<C> Display for CcmBlockCipher<C>
where
    C: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/CCM")
    }
}

impl<C> AeadCipher for CcmBlockCipher<C>
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
        self.validate_message_len(message_len)?;
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

impl<C> AeadBlockCipher for CcmBlockCipher<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }
}

impl<C, P> AeadCipherInit<P> for CcmBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    <C as BlockCipherInit<P>>::Error: 'static,
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        if self.cipher.block_size() != BLOCK_BYTES {
            return Err(AeadInitError::InvalidBlockSize {
                actual: self.cipher.block_size(),
                required: BLOCK_BYTES,
            });
        }

        let nonce = params.nonce();
        if !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&nonce.len()) {
            return Err(AeadInitError::InvalidNonceLength {
                actual: nonce.len(),
            });
        }
        let mac_size = params.mac_size();
        if !(MIN_MAC_BYTES..=MAX_MAC_BYTES).contains(&mac_size) || mac_size % 2 != 0 {
            return Err(AeadInitError::InvalidMacSize { actual: mac_size });
        }
        let key = params.key();
        if direction == CipherDirection::Encrypt
            && self.has_key_nonce
            && self.last_key == key
            && self.nonce_len == nonce.len()
            && self.nonce[..self.nonce_len] == *nonce
        {
            return Err(AeadInitError::NonceReuse);
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(AeadInitError::Cipher)?;

        self.initial_aad_len = 0;
        self.clear_packet();
        self.mac = None;
        self.mac_size = mac_size;
        self.nonce.fill(0);
        self.nonce[..nonce.len()].copy_from_slice(nonce);
        self.nonce_len = nonce.len();
        self.last_key.fill(0);
        self.last_key.clear();
        self.last_key.extend_from_slice(key);
        self.has_key_nonce = true;
        self.aad.extend_from_slice(params.initial_aad());
        self.initial_aad_len = self.aad.len();
        self.state = match direction {
            CipherDirection::Encrypt => State::Encrypt,
            CipherDirection::Decrypt => State::Decrypt,
        };
        Ok(())
    }
}

fn encode_low_bytes(mut value: u64, output: &mut [u8]) {
    for byte in output.iter_mut().rev() {
        *byte = value as u8;
        value >>= 8;
    }
}

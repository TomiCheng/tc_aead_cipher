//! OCB3 authenticated-encryption engine.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Display, Formatter};
use tc_constant_time::fixed_time_eq;

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};

use super::{BLOCK_BYTES, MAX_MAC_BYTES, MAX_NONCE_BYTES, MIN_MAC_BYTES};
use crate::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams,
    MacSizeParams, NonceParams,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Uninitialised,
    Encrypt,
    Decrypt,
    Finalised(CipherDirection),
}

/// OCB3 authenticated encryption over two instances of the same block cipher.
///
/// This implementation buffers the complete packet. In particular,
/// decryption does not copy plaintext to caller memory before authentication
/// succeeds.
pub struct OcbBlockCipher<C> {
    hash_cipher: C,
    main_cipher: C,
    state: State,
    data_started: bool,
    mac_size: usize,
    nonce: [u8; MAX_NONCE_BYTES],
    nonce_len: usize,
    offset_main_0: [u8; BLOCK_BYTES],
    l_star: [u8; BLOCK_BYTES],
    l_dollar: [u8; BLOCK_BYTES],
    l_zero: [u8; BLOCK_BYTES],
    aad: Vec<u8>,
    initial_aad_len: usize,
    data: Vec<u8>,
    last_key: Vec<u8>,
    last_nonce: [u8; MAX_NONCE_BYTES],
    last_nonce_len: usize,
    has_key_nonce: bool,
    mac: Option<[u8; MAX_MAC_BYTES]>,
}

impl<C> OcbBlockCipher<C> {
    /// Creates an uninitialized OCB engine.
    ///
    /// Both arguments must implement the same block-cipher algorithm. The
    /// first is always used for encryption; the second follows the requested
    /// data direction.
    pub const fn new(hash_cipher: C, main_cipher: C) -> Self {
        Self {
            hash_cipher,
            main_cipher,
            state: State::Uninitialised,
            data_started: false,
            mac_size: 0,
            nonce: [0; MAX_NONCE_BYTES],
            nonce_len: 0,
            offset_main_0: [0; BLOCK_BYTES],
            l_star: [0; BLOCK_BYTES],
            l_dollar: [0; BLOCK_BYTES],
            l_zero: [0; BLOCK_BYTES],
            aad: Vec::new(),
            initial_aad_len: 0,
            data: Vec::new(),
            last_key: Vec::new(),
            last_nonce: [0; MAX_NONCE_BYTES],
            last_nonce_len: 0,
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

impl<C: BlockCipher> OcbBlockCipher<C> {
    fn encrypt_hash_block(
        &mut self,
        input: &[u8; BLOCK_BYTES],
    ) -> Result<[u8; BLOCK_BYTES], AeadError<C::Error>> {
        let mut output = [0u8; BLOCK_BYTES];
        self.hash_cipher
            .process_block(input, &mut output)
            .map_err(AeadError::Cipher)?;
        Ok(output)
    }

    fn hash_aad(&mut self) -> Result<[u8; BLOCK_BYTES], AeadError<C::Error>> {
        let mut offset = [0u8; BLOCK_BYTES];
        let mut sum = [0u8; BLOCK_BYTES];
        let full_blocks = self.aad.len() / BLOCK_BYTES;

        for index in 1..=full_blocks {
            xor_in_place(&mut offset, &l_sub(self.l_zero, index.trailing_zeros()));
            let block: &[u8; BLOCK_BYTES] = self.aad
                [(index - 1) * BLOCK_BYTES..index * BLOCK_BYTES]
                .try_into()
                .unwrap();
            let input = xor(*block, offset);
            let encrypted = self.encrypt_hash_block(&input)?;
            xor_in_place(&mut sum, &encrypted);
        }

        let remainder_len = self.aad.len() - full_blocks * BLOCK_BYTES;
        if remainder_len != 0 {
            xor_in_place(&mut offset, &self.l_star);
            let mut final_block = [0u8; BLOCK_BYTES];
            final_block[..remainder_len].copy_from_slice(&self.aad[full_blocks * BLOCK_BYTES..]);
            final_block[remainder_len] = 0x80;
            xor_in_place(&mut final_block, &offset);
            let encrypted = self.encrypt_hash_block(&final_block)?;
            xor_in_place(&mut sum, &encrypted);
        }

        Ok(sum)
    }

    fn process_data(
        &mut self,
        direction: CipherDirection,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<[u8; BLOCK_BYTES], AeadError<C::Error>> {
        let mut offset = self.offset_main_0;
        let mut checksum = [0u8; BLOCK_BYTES];
        let full_blocks = input.len() / BLOCK_BYTES;

        for index in 1..=full_blocks {
            xor_in_place(&mut offset, &l_sub(self.l_zero, index.trailing_zeros()));
            let input_block: &[u8; BLOCK_BYTES] = input
                [(index - 1) * BLOCK_BYTES..index * BLOCK_BYTES]
                .try_into()
                .unwrap();
            let transformed_input = xor(*input_block, offset);
            let mut transformed_output = [0u8; BLOCK_BYTES];
            self.main_cipher
                .process_block(&transformed_input, &mut transformed_output)
                .map_err(AeadError::Cipher)?;
            let result = xor(transformed_output, offset);
            output[(index - 1) * BLOCK_BYTES..index * BLOCK_BYTES].copy_from_slice(&result);
            match direction {
                CipherDirection::Encrypt => xor_in_place(&mut checksum, input_block),
                CipherDirection::Decrypt => xor_in_place(&mut checksum, &result),
            }
        }

        let remainder = &input[full_blocks * BLOCK_BYTES..];
        if !remainder.is_empty() {
            xor_in_place(&mut offset, &self.l_star);
            let pad = self.encrypt_hash_block(&offset)?;
            let output_remainder = &mut output[full_blocks * BLOCK_BYTES..];
            for ((output, input), pad) in output_remainder.iter_mut().zip(remainder).zip(pad) {
                *output = *input ^ pad;
            }

            let mut final_plaintext = [0u8; BLOCK_BYTES];
            match direction {
                CipherDirection::Encrypt => {
                    final_plaintext[..remainder.len()].copy_from_slice(remainder)
                }
                CipherDirection::Decrypt => {
                    final_plaintext[..remainder.len()].copy_from_slice(output_remainder)
                }
            }
            final_plaintext[remainder.len()] = 0x80;
            xor_in_place(&mut checksum, &final_plaintext);
        }

        xor_in_place(&mut checksum, &offset);
        xor_in_place(&mut checksum, &self.l_dollar);
        Ok(checksum)
    }

    fn calculate_tag(
        &mut self,
        checksum: &[u8; BLOCK_BYTES],
        aad_hash: &[u8; BLOCK_BYTES],
    ) -> Result<[u8; MAX_MAC_BYTES], AeadError<C::Error>> {
        let encrypted = self.encrypt_hash_block(checksum)?;
        Ok(xor(encrypted, *aad_hash))
    }

    fn prepare(&mut self) -> Result<(), AeadError<C::Error>> {
        self.l_star = self.encrypt_hash_block(&[0u8; BLOCK_BYTES])?;
        self.l_dollar = double(self.l_star);
        self.l_zero = double(self.l_dollar);
        let nonce = self.nonce;
        self.offset_main_0 = self
            .process_nonce(&nonce[..self.nonce_len])
            .map_err(AeadError::Cipher)?;
        Ok(())
    }

    fn encrypt_packet(&mut self, output: &mut [u8]) -> Result<usize, AeadError<C::Error>> {
        let message_len = self.data.len();
        let mut data = core::mem::take(&mut self.data);
        let result = (|| {
            self.prepare()?;
            let aad_hash = self.hash_aad()?;
            let checksum = self.process_data(CipherDirection::Encrypt, &data, output)?;
            let tag = self.calculate_tag(&checksum, &aad_hash)?;
            output[message_len..message_len + self.mac_size].copy_from_slice(&tag[..self.mac_size]);
            self.mac = Some(tag);
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
        let mut data = core::mem::take(&mut self.data);
        let mut plaintext = vec![0u8; message_len];
        let result = (|| {
            self.prepare()?;
            let aad_hash = self.hash_aad()?;
            let checksum = self.process_data(
                CipherDirection::Decrypt,
                &data[..message_len],
                &mut plaintext,
            )?;
            let tag = self.calculate_tag(&checksum, &aad_hash)?;
            if !fixed_time_eq(&tag[..self.mac_size], &data[message_len..]) {
                return Err(AeadError::AuthenticationFailed);
            }
            output[..message_len].copy_from_slice(&plaintext);
            self.mac = Some(tag);
            Ok(message_len)
        })();
        plaintext.fill(0);
        data.fill(0);
        result
    }
}

impl<C: Display> Display for OcbBlockCipher<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.main_cipher.fmt(f)?;
        f.write_str("/OCB")
    }
}

impl<C> AeadCipher for OcbBlockCipher<C>
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
        self.direction()?;
        self.data
            .len()
            .checked_add(input.len())
            .ok_or(AeadError::InputTooLong)?;
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

impl<C> AeadBlockCipher for OcbBlockCipher<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.main_cipher
    }
}

impl<C, P> AeadCipherInit<P> for OcbBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    <C as BlockCipherInit<P>>::Error: 'static,
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        if self.hash_cipher.block_size() != BLOCK_BYTES
            || self.main_cipher.block_size() != BLOCK_BYTES
        {
            return Err(AeadInitError::InvalidBlockSize {
                actual: self.main_cipher.block_size(),
                required: BLOCK_BYTES,
            });
        }
        let nonce = params.nonce();
        if nonce.len() > MAX_NONCE_BYTES {
            return Err(AeadInitError::InvalidNonceLength {
                actual: nonce.len(),
            });
        }
        let mac_size = params.mac_size();
        if !(MIN_MAC_BYTES..=MAX_MAC_BYTES).contains(&mac_size) {
            return Err(AeadInitError::InvalidMacSize { actual: mac_size });
        }
        let key = params.key();
        if direction == CipherDirection::Encrypt
            && self.has_key_nonce
            && self.last_key == key
            && self.last_nonce_len == nonce.len()
            && self.last_nonce[..self.last_nonce_len] == *nonce
        {
            return Err(AeadInitError::NonceReuse);
        }

        self.hash_cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(AeadInitError::Cipher)?;
        self.main_cipher
            .init(direction, params)
            .map_err(AeadInitError::Cipher)?;

        self.mac_size = mac_size;
        self.nonce.fill(0);
        self.nonce[..nonce.len()].copy_from_slice(nonce);
        self.nonce_len = nonce.len();

        self.initial_aad_len = 0;
        self.clear_packet();
        self.aad.extend_from_slice(params.initial_aad());
        self.initial_aad_len = self.aad.len();
        self.mac = None;
        self.last_key.fill(0);
        self.last_key.clear();
        self.last_key.extend_from_slice(key);
        self.last_nonce.fill(0);
        self.last_nonce[..nonce.len()].copy_from_slice(nonce);
        self.last_nonce_len = nonce.len();
        self.has_key_nonce = true;
        self.state = match direction {
            CipherDirection::Encrypt => State::Encrypt,
            CipherDirection::Decrypt => State::Decrypt,
        };
        Ok(())
    }
}

impl<C: BlockCipher> OcbBlockCipher<C> {
    fn process_nonce(&mut self, nonce: &[u8]) -> Result<[u8; BLOCK_BYTES], C::Error> {
        let mut formatted = [0u8; BLOCK_BYTES];
        formatted[BLOCK_BYTES - nonce.len()..].copy_from_slice(nonce);
        formatted[0] = (self.mac_size as u8) << 4;
        formatted[BLOCK_BYTES - 1 - nonce.len()] |= 1;
        let bottom = usize::from(formatted[BLOCK_BYTES - 1] & 0x3f);
        formatted[BLOCK_BYTES - 1] &= 0xc0;

        let mut ktop = [0u8; BLOCK_BYTES];
        self.hash_cipher.process_block(&formatted, &mut ktop)?;
        let mut stretch = [0u8; 24];
        stretch[..BLOCK_BYTES].copy_from_slice(&ktop);
        for index in 0..8 {
            stretch[BLOCK_BYTES + index] = ktop[index] ^ ktop[index + 1];
        }

        let byte_shift = bottom / 8;
        let bit_shift = bottom % 8;
        Ok(core::array::from_fn(|index| {
            if bit_shift == 0 {
                stretch[byte_shift + index]
            } else {
                (stretch[byte_shift + index] << bit_shift)
                    | (stretch[byte_shift + index + 1] >> (8 - bit_shift))
            }
        }))
    }
}

fn double(input: [u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
    let carry = input[0] >> 7;
    let mut output = [0u8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES - 1 {
        output[index] = (input[index] << 1) | (input[index + 1] >> 7);
    }
    output[BLOCK_BYTES - 1] = (input[BLOCK_BYTES - 1] << 1) ^ (0x87 & carry.wrapping_neg());
    output
}

fn l_sub(mut value: [u8; BLOCK_BYTES], n: u32) -> [u8; BLOCK_BYTES] {
    for _ in 0..n {
        value = double(value);
    }
    value
}

fn xor(left: [u8; BLOCK_BYTES], right: [u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
    core::array::from_fn(|index| left[index] ^ right[index])
}

fn xor_in_place(target: &mut [u8; BLOCK_BYTES], value: &[u8; BLOCK_BYTES]) {
    for (target, value) in target.iter_mut().zip(value) {
        *target ^= *value;
    }
}

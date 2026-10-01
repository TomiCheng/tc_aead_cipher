//! GCM-SIV authenticated-encryption engine.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Display, Formatter};
use tc_constant_time::fixed_time_eq;
use tc_zeroize::Zeroize;

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams, KeyRef};

use super::polyval::Polyval;
use super::{BLOCK_BYTES, MAC_BYTES, MAX_INPUT_BYTES, NONCE_BYTES};
use crate::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, InitialAadParams,
    MacSizeParams, NonceParams,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Uninitialized,
    Encrypt,
    Decrypt,
}

/// GCM-SIV authenticated encryption over a 16-byte block cipher.
///
/// This packet construction buffers all AAD and message bytes until
/// finalization. Its POLYVAL implementation is private and portable; no
/// multiplier or exponentiator strategy is part of the public API.
///
/// Constant time exactly when the cipher is: POLYVAL multiplies bit by bit with
/// masks, and neither the counter increment nor the tag comparison branches on
/// data. Only public lengths decide how much work is done.
///
/// The buffers are `Vec`s, wiped when cleared and on drop. A `Vec` that grows,
/// though, frees its previous allocation without wiping it, so copies of
/// earlier bytes can remain in freed memory until it is reused.
pub struct GcmSivBlockCipher<C> {
    cipher: C,
    state: State,
    auth_key: [u8; BLOCK_BYTES],
    nonce: [u8; NONCE_BYTES],
    aad: Vec<u8>,
    initial_aad_len: usize,
    data: Vec<u8>,
    data_started: bool,
    mac: Option<[u8; MAC_BYTES]>,
}

impl<C> GcmSivBlockCipher<C> {
    /// Creates an uninitialized GCM-SIV engine around `cipher`. Constant time.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            state: State::Uninitialized,
            auth_key: [0; BLOCK_BYTES],
            nonce: [0; NONCE_BYTES],
            aad: Vec::new(),
            initial_aad_len: 0,
            data: Vec::new(),
            data_started: false,
            mac: None,
        }
    }

    fn direction<E>(&self) -> Result<CipherDirection, AeadError<E>> {
        match self.state {
            State::Encrypt => Ok(CipherDirection::Encrypt),
            State::Decrypt => Ok(CipherDirection::Decrypt),
            State::Uninitialized => Err(AeadError::NotInitialized),
        }
    }

    fn output_size<E>(&self, additional: usize) -> Result<usize, AeadError<E>> {
        let total = self
            .data
            .len()
            .checked_add(additional)
            .ok_or(AeadError::InputTooLong)?;
        Ok(match self.state {
            State::Decrypt => total.saturating_sub(MAC_BYTES),
            _ => total
                .checked_add(MAC_BYTES)
                .ok_or(AeadError::InputTooLong)?,
        })
    }

    fn clear_packet(&mut self) {
        self.aad[self.initial_aad_len..].zeroize();
        self.aad.truncate(self.initial_aad_len);
        self.data.zeroize();
        self.data_started = false;
    }

    fn checked_len<E>(
        current: usize,
        additional: usize,
        tag_bytes: usize,
    ) -> Result<usize, AeadError<E>> {
        let total = current
            .checked_add(additional)
            .ok_or(AeadError::InputTooLong)?;
        let content = total.saturating_sub(tag_bytes);
        let content = u64::try_from(content).map_err(|_| AeadError::InputTooLong)?;
        if content > MAX_INPUT_BYTES {
            return Err(AeadError::InputTooLong);
        }
        Ok(total)
    }
}

impl<C> GcmSivBlockCipher<C>
where
    C: BlockCipher,
{
    fn calculate_tag(&mut self, plaintext: &[u8]) -> Result<[u8; MAC_BYTES], AeadError<C::Error>> {
        let aad_len = u64::try_from(self.aad.len()).map_err(|_| AeadError::InputTooLong)?;
        let data_len = u64::try_from(plaintext.len()).map_err(|_| AeadError::InputTooLong)?;
        let mut polyval = Polyval::new(self.auth_key);
        polyval.update_padded(&self.aad);
        polyval.update_padded(plaintext);
        let mut value = polyval.finish(aad_len, data_len);
        for (byte, nonce) in value[..NONCE_BYTES].iter_mut().zip(self.nonce) {
            *byte ^= nonce;
        }
        value[BLOCK_BYTES - 1] &= 0x7f;

        let mut tag = [0u8; MAC_BYTES];
        self.cipher
            .process_block(&value, &mut tag)
            .map_err(AeadError::Cipher)?;
        Ok(tag)
    }

    fn crypt(
        &mut self,
        input: &[u8],
        tag: &[u8; MAC_BYTES],
        output: &mut [u8],
    ) -> Result<(), AeadError<C::Error>> {
        let mut counter = *tag;
        counter[BLOCK_BYTES - 1] |= 0x80;

        for (input, output) in input
            .chunks(BLOCK_BYTES)
            .zip(output.chunks_mut(BLOCK_BYTES))
        {
            let mut mask = [0u8; BLOCK_BYTES];
            self.cipher
                .process_block(&counter, &mut mask)
                .map_err(AeadError::Cipher)?;
            for ((output, input), mask) in output.iter_mut().zip(input).zip(mask) {
                *output = *input ^ mask;
            }
            increment_counter(&mut counter);
        }
        Ok(())
    }

    fn encrypt_packet(&mut self, output: &mut [u8]) -> Result<usize, AeadError<C::Error>> {
        let mut plaintext = core::mem::take(&mut self.data);
        let result = (|| {
            let tag = self.calculate_tag(&plaintext)?;
            let plaintext_len = plaintext.len();
            self.crypt(&plaintext, &tag, &mut output[..plaintext_len])?;
            output[plaintext_len..plaintext_len + MAC_BYTES].copy_from_slice(&tag);
            self.mac = Some(tag);
            Ok(plaintext_len + MAC_BYTES)
        })();
        plaintext.zeroize();
        result
    }

    fn decrypt_packet(&mut self, output: &mut [u8]) -> Result<usize, AeadError<C::Error>> {
        let mut encrypted = core::mem::take(&mut self.data);
        let result = (|| {
            if encrypted.len() < MAC_BYTES {
                return Err(AeadError::CiphertextTooShort {
                    minimum: MAC_BYTES,
                    actual: encrypted.len(),
                });
            }
            let plaintext_len = encrypted.len() - MAC_BYTES;
            let tag: [u8; MAC_BYTES] = encrypted[plaintext_len..].try_into().unwrap();
            let mut plaintext = vec![0u8; plaintext_len];
            let result = (|| {
                self.crypt(&encrypted[..plaintext_len], &tag, &mut plaintext)?;
                let expected = self.calculate_tag(&plaintext)?;
                if !fixed_time_eq(&tag, &expected) {
                    return Err(AeadError::AuthenticationFailed);
                }
                output[..plaintext_len].copy_from_slice(&plaintext);
                self.mac = Some(expected);
                Ok(plaintext_len)
            })();
            plaintext.zeroize();
            result
        })();
        encrypted.zeroize();
        result
    }

    fn derive_keys(&mut self, key_len: usize) -> Result<([u8; BLOCK_BYTES], [u8; 32]), C::Error> {
        let mut input = [0u8; BLOCK_BYTES];
        input[4..].copy_from_slice(&self.nonce);
        let mut block = [0u8; BLOCK_BYTES];
        let mut auth_key = [0u8; BLOCK_BYTES];
        let mut enc_key = [0u8; 32];

        for counter in 0..(2 + key_len / 8) {
            input[..4].copy_from_slice(&(counter as u32).to_le_bytes());
            self.cipher.process_block(&input, &mut block)?;
            if counter < 2 {
                let offset = counter * 8;
                auth_key[offset..offset + 8].copy_from_slice(&block[..8]);
            } else {
                let offset = (counter - 2) * 8;
                enc_key[offset..offset + 8].copy_from_slice(&block[..8]);
            }
        }
        block.zeroize();
        Ok((auth_key, enc_key))
    }
}

impl<C> Display for GcmSivBlockCipher<C>
where
    C: Display,
{
    /// Writes the cipher's name followed by `/GCM-SIV`. Constant time: no key
    /// material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/GCM-SIV")
    }
}

impl<C> AeadCipher for GcmSivBlockCipher<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Error = AeadError<C::Error>;

    /// Buffers `input` as associated data until `do_final`. Constant time: only
    /// its length decides the work.
    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.direction()?;
        if self.data_started {
            return Err(AeadError::AadAfterData);
        }
        Self::checked_len(self.aad.len(), input.len(), 0)?;
        self.mac = None;
        self.aad.extend_from_slice(input);
        Ok(())
    }

    /// Buffers `input` until `do_final` and writes nothing. Constant time: only
    /// its length decides the work.
    fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction()?;
        let tag_bytes = usize::from(direction == CipherDirection::Decrypt) * MAC_BYTES;
        Self::checked_len(self.data.len(), input.len(), tag_bytes)?;
        if !input.is_empty() {
            self.data_started = true;
            self.mac = None;
            self.data.extend_from_slice(input);
        }
        Ok(0)
    }

    /// Processes the rest of the message and appends or verifies the tag.
    /// Constant time exactly when the cipher is: the tag is compared in fixed
    /// time, and only the result reveals whether it matched.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction()?;
        self.mac = None;
        let required = self.output_size(0)?;
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let result = match direction {
            CipherDirection::Encrypt => self.encrypt_packet(output),
            CipherDirection::Decrypt => self.decrypt_packet(output),
        };
        self.clear_packet();
        if result.is_err() {
            self.mac = None;
        }
        result
    }

    /// Returns the tag of the last successful `do_final`. Constant time.
    fn mac(&self) -> Option<&[u8]> {
        self.mac.as_ref().map(<[u8; MAC_BYTES]>::as_slice)
    }

    /// Restarts the message when the nonce allows, as described on
    /// `AeadCipher::reset`. Constant time: it restores fixed-size state and
    /// wipes the buffers.
    fn reset(&mut self) {
        self.mac = None;
        self.clear_packet();
    }

    /// Returns the length the next `process_bytes` writes. Constant time:
    /// depends only on public lengths.
    fn update_output_len(&self, _input_len: usize) -> Result<usize, Self::Error> {
        Ok(0)
    }

    /// Returns the length `process_bytes` and `do_final` write together.
    /// Constant time: depends only on public lengths.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.output_size(input_len)
    }
}

impl<C> AeadBlockCipher for GcmSivBlockCipher<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Cipher = C;

    /// Returns the wrapped block cipher. Constant time.
    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }
}

impl<C, P> AeadCipherInit<P> for GcmSivBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    for<'a> C: BlockCipherInit<KeyRef<'a>, Error = <C as BlockCipherInit<P>>::Error>,
    <C as BlockCipherInit<P>>::Error: 'static,
    P: KeyParams + NonceParams + InitialAadParams + MacSizeParams + ?Sized,
{
    type Error = AeadInitError<<C as BlockCipherInit<P>>::Error>;

    /// Keys the cipher, derives the message keys from the nonce and starts a
    /// message, as described on `AeadCipherInit::init`. Constant time exactly
    /// when the cipher's key setup and block encryption are: validation reads
    /// only public lengths.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.state = State::Uninitialized;
        self.mac = None;
        self.clear_packet();

        if self.cipher.block_size() != BLOCK_BYTES {
            return Err(AeadInitError::InvalidBlockSize {
                actual: self.cipher.block_size(),
                required: BLOCK_BYTES,
            });
        }
        let key = params.key();
        if !matches!(key.len(), 16 | 32) {
            return Err(AeadInitError::InvalidKeyLength { actual: key.len() });
        }
        let nonce = params.nonce();
        if nonce.len() != NONCE_BYTES {
            return Err(AeadInitError::InvalidNonceLength {
                actual: nonce.len(),
            });
        }
        if params.mac_size() != MAC_BYTES {
            return Err(AeadInitError::InvalidMacSize {
                actual: params.mac_size(),
            });
        }
        let initial_aad_len = u64::try_from(params.initial_aad().len()).map_err(|_| {
            AeadInitError::InvalidInitialAadLength {
                actual: params.initial_aad().len(),
            }
        })?;
        if initial_aad_len > MAX_INPUT_BYTES {
            return Err(AeadInitError::InvalidInitialAadLength {
                actual: params.initial_aad().len(),
            });
        }

        self.nonce.copy_from_slice(nonce);
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(AeadInitError::Cipher)?;
        let (auth_key, mut enc_key) = self
            .derive_keys(key.len())
            .map_err(|_| AeadInitError::InternalFailure)?;
        let derived_params = KeyRef::new(&enc_key[..key.len()]);
        let derived_result = self
            .cipher
            .init(CipherDirection::Encrypt, &derived_params)
            .map_err(AeadInitError::Cipher);
        enc_key.zeroize();
        derived_result?;

        self.auth_key = auth_key;
        self.aad.zeroize();
        self.aad.extend_from_slice(params.initial_aad());
        self.initial_aad_len = self.aad.len();
        self.state = match direction {
            CipherDirection::Encrypt => State::Encrypt,
            CipherDirection::Decrypt => State::Decrypt,
        };
        Ok(())
    }
}

impl<C> Drop for GcmSivBlockCipher<C> {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.aad.zeroize();
        self.data.zeroize();
        self.mac.zeroize();
    }
}

// RFC 8452 treats the first 32 bits as a little-endian counter modulo 2^32.
// The counter starts from the public tag, but the increment has no branch
// either way, like GCM's.
fn increment_counter(counter: &mut [u8; BLOCK_BYTES]) {
    let value = u32::from_le_bytes(counter[..4].try_into().unwrap()).wrapping_add(1);
    counter[..4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::{BLOCK_BYTES, increment_counter};

    #[test]
    fn the_counter_increments_its_first_four_bytes_little_endian_modulo_two_to_the_32() {
        let mut counter = [0xaa_u8; BLOCK_BYTES];
        counter[..4].copy_from_slice(&[0xff, 0xff, 0x00, 0x00]);
        increment_counter(&mut counter);
        assert_eq!(counter[..5], [0x00, 0x00, 0x01, 0x00, 0xaa]);

        counter[..4].copy_from_slice(&[0xff; 4]);
        increment_counter(&mut counter);
        assert_eq!(counter[..5], [0x00, 0x00, 0x00, 0x00, 0xaa]);
    }
}

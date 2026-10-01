//! Convenience parameters for AEAD constructions.

use crate::{InitialAadParams, MacSizeParams, NonceParams};
use core::fmt;
use tc_block_cipher::KeyParams;

/// Borrowed key, nonce, initial AAD, and authentication-tag size parameters.
///
/// This type does not validate any value. The consuming AEAD construction
/// owns all key, nonce, and authentication-tag length policy.
///
/// Constant time: no method inspects the key, nonce or associated data.
#[derive(Clone, Copy)]
pub struct AeadParamsRef<'a> {
    key: &'a [u8],
    nonce: &'a [u8],
    initial_aad: &'a [u8],
    mac_size: usize,
}

impl<'a> AeadParamsRef<'a> {
    /// Borrows all byte slices and selects a MAC size in bytes. Constant time.
    pub const fn new(
        key: &'a [u8],
        nonce: &'a [u8],
        mac_size: usize,
        initial_aad: &'a [u8],
    ) -> Self {
        Self {
            key,
            nonce,
            initial_aad,
            mac_size,
        }
    }
}

impl KeyParams for AeadParamsRef<'_> {
    /// Returns the key. Constant time: the bytes are not inspected.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl NonceParams for AeadParamsRef<'_> {
    /// Returns the nonce. Constant time: the bytes are not inspected.
    fn nonce(&self) -> &[u8] {
        self.nonce
    }
}

impl InitialAadParams for AeadParamsRef<'_> {
    /// Returns the initial associated data. Constant time: the bytes are not
    /// inspected.
    fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

impl MacSizeParams for AeadParamsRef<'_> {
    /// Returns the tag size in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac_size
    }
}

impl fmt::Debug for AeadParamsRef<'_> {
    /// Writes the lengths and the tag size, never the bytes. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadParamsRef")
            .field("key_len", &self.key.len())
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .field("mac_size", &self.mac_size)
            .finish()
    }
}

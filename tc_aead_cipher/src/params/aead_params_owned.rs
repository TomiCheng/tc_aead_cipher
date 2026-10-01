//! Owned convenience parameters for AEAD constructions.

use crate::{InitialAadParams, MacSizeParams, NonceParams};
use alloc::vec::Vec;
use core::fmt;
use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned key, nonce, initial AAD, and authentication-tag size parameters,
/// wiped on drop.
///
/// Available with the `alloc` feature. Construction takes the vectors without
/// copying them, and this type does not validate any value. The consuming AEAD
/// construction owns all key, nonce, and authentication-tag length policy.
///
/// Constant time: no method inspects the key, nonce or associated data.
pub struct AeadParamsOwned {
    key: Vec<u8>,
    nonce: Vec<u8>,
    initial_aad: Vec<u8>,
    mac_size: usize,
}

impl AeadParamsOwned {
    /// Takes ownership of all byte vectors and selects a MAC size in bytes.
    /// Constant time.
    pub const fn new(key: Vec<u8>, nonce: Vec<u8>, mac_size: usize, initial_aad: Vec<u8>) -> Self {
        Self {
            key,
            nonce,
            initial_aad,
            mac_size,
        }
    }
}

impl KeyParams for AeadParamsOwned {
    /// Returns the key. Constant time: the bytes are not inspected.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl NonceParams for AeadParamsOwned {
    /// Returns the nonce. Constant time: the bytes are not inspected.
    fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

impl InitialAadParams for AeadParamsOwned {
    /// Returns the initial associated data. Constant time: the bytes are not
    /// inspected.
    fn initial_aad(&self) -> &[u8] {
        &self.initial_aad
    }
}

impl MacSizeParams for AeadParamsOwned {
    /// Returns the tag size in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac_size
    }
}

impl fmt::Debug for AeadParamsOwned {
    /// Writes the lengths and the tag size, never the bytes. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadParamsOwned")
            .field("key_len", &self.key.len())
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .field("mac_size", &self.mac_size)
            .finish()
    }
}

impl Zeroize for AeadParamsOwned {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
        self.initial_aad.zeroize();
    }
}

impl Drop for AeadParamsOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AeadParamsOwned {}

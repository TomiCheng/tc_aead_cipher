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
pub struct AeadParamsOwned {
    key: Vec<u8>,
    nonce: Vec<u8>,
    initial_aad: Vec<u8>,
    mac_size: usize,
}

impl AeadParamsOwned {
    /// Takes ownership of all byte vectors and selects a MAC size in bytes.
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
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl NonceParams for AeadParamsOwned {
    fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

impl InitialAadParams for AeadParamsOwned {
    fn initial_aad(&self) -> &[u8] {
        &self.initial_aad
    }
}

impl MacSizeParams for AeadParamsOwned {
    fn mac_size(&self) -> usize {
        self.mac_size
    }
}

impl fmt::Debug for AeadParamsOwned {
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

//! A cipher's own parameters with owned AEAD values.

use crate::{InitialAadParams, MacSizeParams, NonceParams};
use alloc::vec::Vec;
use core::fmt;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// A cipher's own parameters with an owned nonce and initial associated data
/// and a tag size, wiped on drop.
///
/// Available with the `alloc` feature. A mode keeps the nonce, tag size and
/// initial associated data and initializes its cipher with the inner
/// parameters alone, so a cipher whose parameters are more than a key, such as
/// RC2 with its effective key bits, works under GCM, CCM, EAX, OCB and KCCM.
/// GCM-SIV derives its message keys from the key bytes and does not take it.
/// Construction moves the values rather than copying them, and nothing is
/// validated until the mode is initialized.
///
/// It does not implement `KeyParams`: a mode takes it through an
/// implementation of its own, which strips the AEAD values, rather than the
/// one over `KeyParams`, which hands the whole parameters to the cipher. The
/// engines that carry their own primitive take `AeadParamsOwned` instead.
///
/// Drop wipes the nonce and initial associated data; the inner parameters
/// wipe themselves when their type does. With `TParams: Zeroize`,
/// [`zeroize`](Zeroize::zeroize) wipes them too. `Debug` prints the inner
/// parameters as their type does and only the lengths of the rest.
///
/// Constant time: no method inspects the nonce or associated data.
///
/// # Example
///
/// ```
/// use tc_aead_cipher::{AeadCipher, AeadCipherInit, GcmBlockCipher, ParamsWithAeadOwned};
/// use tc_block_cipher::CipherDirection;
/// use tc_rc_cipher::{Rc564Engine, Rc5ParamsOwned};
///
/// // RC5-64 with 16 rounds, under GCM
/// let rc5 = Rc5ParamsOwned::new(vec![0x42; 16], 16);
/// let params = ParamsWithAeadOwned::new(rc5, vec![0x24; 12], 16, b"header".to_vec());
/// let mut gcm = GcmBlockCipher::new(Rc564Engine::new());
///
/// gcm.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = [0; 14 + 16];
/// let written = gcm.process_bytes(b"attack at dawn", &mut sealed)?;
/// gcm.do_final(&mut sealed[written..])?;
///
/// gcm.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = [0; 14];
/// let written = gcm.process_bytes(&sealed, &mut opened)?;
/// gcm.do_final(&mut opened[written..])?;
/// assert_eq!(&opened, b"attack at dawn");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct ParamsWithAeadOwned<TParams> {
    params: TParams,
    nonce: Vec<u8>,
    initial_aad: Vec<u8>,
    mac_size: usize,
}

impl<TParams> ParamsWithAeadOwned<TParams> {
    /// Takes ownership of `params` and the byte vectors and selects a MAC size
    /// in bytes, without validating them. Constant time: moves the values
    /// without inspecting them.
    pub const fn new(
        params: TParams,
        nonce: Vec<u8>,
        mac_size: usize,
        initial_aad: Vec<u8>,
    ) -> Self {
        Self {
            params,
            nonce,
            initial_aad,
            mac_size,
        }
    }

    /// Returns the inner parameters, which a mode gives its cipher.
    /// Constant time.
    pub const fn params(&self) -> &TParams {
        &self.params
    }
}

impl<TParams> NonceParams for ParamsWithAeadOwned<TParams> {
    /// Returns the nonce. Constant time: the bytes are not inspected.
    fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

impl<TParams> InitialAadParams for ParamsWithAeadOwned<TParams> {
    /// Returns the initial associated data. Constant time: the bytes are not
    /// inspected.
    fn initial_aad(&self) -> &[u8] {
        &self.initial_aad
    }
}

impl<TParams> MacSizeParams for ParamsWithAeadOwned<TParams> {
    /// Returns the tag size in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac_size
    }
}

impl<TParams: fmt::Debug> fmt::Debug for ParamsWithAeadOwned<TParams> {
    /// Writes the inner parameters as their `Debug` does, the lengths and the
    /// tag size, never the bytes. Constant time with respect to the nonce and
    /// associated data, which it never reads; the inner `Debug` and the
    /// formatter set the rest of its timing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParamsWithAeadOwned")
            .field("params", &self.params)
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .field("mac_size", &self.mac_size)
            .finish()
    }
}

impl<TParams: Zeroize> Zeroize for ParamsWithAeadOwned<TParams> {
    /// Overwrites the inner parameters, the nonce and the initial associated
    /// data. Constant time when the inner `zeroize` is.
    fn zeroize(&mut self) {
        self.params.zeroize();
        self.nonce.zeroize();
        self.initial_aad.zeroize();
    }
}

impl<TParams> Drop for ParamsWithAeadOwned<TParams> {
    /// Wipes the nonce and initial associated data; the inner parameters are
    /// dropped after them and wipe themselves when their type does.
    /// Constant time.
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.initial_aad.zeroize();
    }
}

impl<TParams: ZeroizeOnDrop> ZeroizeOnDrop for ParamsWithAeadOwned<TParams> {}

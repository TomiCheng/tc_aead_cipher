//! A cipher's own parameters with borrowed AEAD values.

use crate::{InitialAadParams, MacSizeParams, NonceParams};
use core::fmt;

/// A cipher's own parameters, a nonce and initial associated data, all
/// borrowed, and a tag size.
///
/// No allocation or copying, so it needs no `alloc` feature: GCM and EAX take
/// it without an allocator. A mode keeps the nonce, tag size and initial
/// associated data and initializes its cipher with the inner parameters alone,
/// so a cipher whose parameters are more than a key, such as RC2 with its
/// effective key bits, works under GCM, CCM, EAX, OCB and KCCM. GCM-SIV derives
/// its message keys from the key bytes and does not take it. `TParams` may be
/// unsized, such as a trait object. Nothing is validated until the mode is
/// initialized.
///
/// It does not implement `KeyParams`: a mode takes it through an
/// implementation of its own, which strips the AEAD values, rather than the
/// one over `KeyParams`, which hands the whole parameters to the cipher. The
/// engines that carry their own primitive take [`AeadParamsRef`](crate::AeadParamsRef)
/// instead.
///
/// The caller owns every value and is responsible for wiping it; dropping this
/// view modifies nothing. `Debug` prints the inner parameters as their type
/// does and only the lengths of the rest. `ParamsWithAeadOwned`, with the
/// `alloc` feature, owns them instead.
///
/// Constant time: no method inspects the nonce or associated data.
///
/// # Example
///
/// ```
/// use tc_aead_cipher::{AeadCipher, AeadCipherInit, EaxBlockCipher, ParamsWithAeadRef};
/// use tc_block_cipher::CipherDirection;
/// use tc_rc_cipher::{Rc2Engine, Rc2ParamsRef};
///
/// // RC2 with 40 effective key bits, under EAX, with no allocator
/// let (key, nonce) = ([0x42; 16], [0x24; 8]);
/// let rc2 = Rc2ParamsRef::with_effective_key_bits(&key, 40);
/// let params = ParamsWithAeadRef::new(&rc2, &nonce, 8, b"header");
/// let mut eax = EaxBlockCipher::new(Rc2Engine::new());
///
/// eax.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = [0; 14 + 8];
/// let written = eax.process_bytes(b"attack at dawn", &mut sealed)?;
/// eax.do_final(&mut sealed[written..])?;
///
/// eax.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = [0; 14];
/// let written = eax.process_bytes(&sealed, &mut opened)?;
/// eax.do_final(&mut opened[written..])?;
/// assert_eq!(&opened, b"attack at dawn");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct ParamsWithAeadRef<'a, TParams: ?Sized> {
    params: &'a TParams,
    nonce: &'a [u8],
    initial_aad: &'a [u8],
    mac_size: usize,
}

impl<'a, TParams: ?Sized> ParamsWithAeadRef<'a, TParams> {
    /// Borrows `params` and the byte slices and selects a MAC size in bytes,
    /// without copying or validating them. Constant time: does not inspect
    /// them.
    pub const fn new(
        params: &'a TParams,
        nonce: &'a [u8],
        mac_size: usize,
        initial_aad: &'a [u8],
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
    pub const fn params(&self) -> &'a TParams {
        self.params
    }
}

impl<TParams: ?Sized> Clone for ParamsWithAeadRef<'_, TParams> {
    /// Copies the references. Constant time.
    fn clone(&self) -> Self {
        *self
    }
}

impl<TParams: ?Sized> Copy for ParamsWithAeadRef<'_, TParams> {}

impl<TParams: ?Sized> NonceParams for ParamsWithAeadRef<'_, TParams> {
    /// Returns the nonce. Constant time: the bytes are not inspected.
    fn nonce(&self) -> &[u8] {
        self.nonce
    }
}

impl<TParams: ?Sized> InitialAadParams for ParamsWithAeadRef<'_, TParams> {
    /// Returns the initial associated data. Constant time: the bytes are not
    /// inspected.
    fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

impl<TParams: ?Sized> MacSizeParams for ParamsWithAeadRef<'_, TParams> {
    /// Returns the tag size in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac_size
    }
}

impl<TParams: fmt::Debug + ?Sized> fmt::Debug for ParamsWithAeadRef<'_, TParams> {
    /// Writes the inner parameters as their `Debug` does, the lengths and the
    /// tag size, never the bytes. Constant time with respect to the nonce and
    /// associated data, which it never reads; the inner `Debug` and the
    /// formatter set the rest of its timing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParamsWithAeadRef")
            .field("params", &self.params)
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .field("mac_size", &self.mac_size)
            .finish()
    }
}

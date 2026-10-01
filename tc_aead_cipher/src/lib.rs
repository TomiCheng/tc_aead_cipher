//! Authenticated encryption with associated data (AEAD), ported from Bouncy
//! Castle C#: the [`AeadCipher`] and [`AeadCipherInit`] contracts, and the
//! modes that build them on any engine implementing the `tc_block_cipher`
//! traits, such as `tc_aes::AesEngine`:
//!
//! - [`GcmBlockCipher`] — GCM (NIST SP 800-38D).
//! - [`EaxBlockCipher`] — EAX, over 8- or 16-byte blocks.
//! - `CcmBlockCipher` — CCM (NIST SP 800-38C, RFC 3610).
//! - `GcmSivBlockCipher` — GCM-SIV (RFC 8452), which tolerates nonce reuse.
//! - `OcbBlockCipher` — OCB3 (RFC 7253).
//! - `KccmBlockCipher` — KCCM (DSTU 7624:2014), over 16-, 32- or 64-byte
//!   blocks.
//!
//! Algorithms that carry their own permutation implement the same contracts
//! in their own crates: `tc_ascon_aead`, `tc_grain128_aead` and
//! `tc_sparkle_aead`.
//!
//! The crate is `no_std`, needs no allocator by default and contains no
//! `unsafe` code. The default-off `alloc` feature adds the four modes that
//! buffer the whole message, CCM, GCM-SIV, OCB and KCCM, and
//! `AeadParamsOwned`, which owns and wipes its bytes.
//!
//! Every engine documents its timing. The modes are constant time exactly when
//! their block cipher is, and lengths are public throughout. Decryption may
//! write unauthenticated plaintext before `do_final` verifies the tag, so
//! discard the output when `do_final` fails.
//!
//! # Example
//!
//! ```
//! use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef, GcmBlockCipher};
//! use tc_aes::AesEngine;
//! use tc_block_cipher::CipherDirection;
//!
//! let (key, nonce) = ([0x42; 16], [0x24; 12]);
//! let params = AeadParamsRef::new(&key, &nonce, 16, b"header");
//! let mut gcm = GcmBlockCipher::new(AesEngine::new());
//!
//! gcm.init(CipherDirection::Encrypt, &params)?;
//! let mut sealed = [0; 14 + 16];
//! let written = gcm.process_bytes(b"attack at dawn", &mut sealed)?;
//! gcm.do_final(&mut sealed[written..])?;
//!
//! gcm.init(CipherDirection::Decrypt, &params)?;
//! let mut opened = [0; 14];
//! let written = gcm.process_bytes(&sealed, &mut opened)?;
//! gcm.do_final(&mut opened[written..])?;
//! assert_eq!(&opened, b"attack at dawn");
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod ccm;
mod eax;
mod errors;
mod gcm;
#[cfg(feature = "alloc")]
mod gcm_siv;
#[cfg(feature = "alloc")]
mod kccm;
#[cfg(feature = "alloc")]
mod ocb;
mod params;
mod traits;

#[cfg(feature = "alloc")]
pub use ccm::CcmBlockCipher;
pub use eax::EaxBlockCipher;
pub use errors::{AeadError, AeadInitError};
pub use gcm::GcmBlockCipher;
#[cfg(feature = "alloc")]
pub use gcm_siv::GcmSivBlockCipher;
#[cfg(feature = "alloc")]
pub use kccm::KccmBlockCipher;
#[cfg(feature = "alloc")]
pub use ocb::OcbBlockCipher;
#[cfg(feature = "alloc")]
pub use params::AeadParamsOwned;
pub use params::AeadParamsRef;
pub use traits::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, InitialAadParams, MacSizeParams, NonceParams,
};

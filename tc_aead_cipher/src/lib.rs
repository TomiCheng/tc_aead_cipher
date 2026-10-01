//! Authenticated encryption with associated data (AEAD), ported from Bouncy
//! Castle C#: the [`AeadCipher`] and [`AeadCipherInit`] contracts and the
//! engines that implement them.
//!
//! Modes over any engine that implements the `tc_block_cipher` traits, such as
//! `tc_aes::AesEngine`:
//!
//! - [`GcmBlockCipher`] — GCM (NIST SP 800-38D).
//! - [`EaxBlockCipher`] — EAX, over 8- or 16-byte blocks.
//! - `CcmBlockCipher` — CCM (NIST SP 800-38C, RFC 3610).
//! - `GcmSivBlockCipher` — GCM-SIV (RFC 8452), which tolerates nonce reuse.
//! - `OcbBlockCipher` — OCB3 (RFC 7253).
//! - `KccmBlockCipher` — KCCM (DSTU 7624:2014), over 16-, 32- or 64-byte
//!   blocks.
//!
//! Engines that carry their own permutation or stream cipher:
//!
//! - [`AsconAead128Engine`] — Ascon-AEAD128 (NIST SP 800-232).
//! - [`AsconLegacyEngine`] — Ascon-128, Ascon-128a and Ascon-80pq from
//!   Ascon v1.2, for compatibility.
//! - [`FixedGrain128AeadEngine`] and `Grain128AeadEngine` — Grain-128AEAD.
//! - [`SparkleEngine`] — the SCHWAEMM family built on SPARKLE.
//!
//! The crate is `no_std` and needs no allocator by default. The default-off
//! `alloc` feature adds the four modes that buffer the whole message, CCM,
//! GCM-SIV, OCB and KCCM, the growable `Grain128AeadEngine`, and
//! `AeadParamsOwned`, which owns and wipes its bytes. The only `unsafe` code is
//! the SSE2 form of the SPARKLE permutation, which runs only after run-time
//! detection on x86.
//!
//! Every engine documents its timing. The modes are constant time exactly when
//! their block cipher is; the other engines are constant time. Lengths are
//! public throughout. Decryption may write unauthenticated plaintext before
//! `do_final` verifies the tag, so discard the output when `do_final` fails.
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
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod ascon;
#[cfg(feature = "alloc")]
mod ccm;
mod eax;
mod errors;
mod gcm;
#[cfg(feature = "alloc")]
mod gcm_siv;
mod grain128;
#[cfg(feature = "alloc")]
mod kccm;
#[cfg(feature = "alloc")]
mod ocb;
mod params;
mod sparkle;
mod traits;

pub use ascon::{AsconAead128Engine, AsconLegacyEngine, AsconLegacyVariant};
#[cfg(feature = "alloc")]
pub use ccm::CcmBlockCipher;
pub use eax::EaxBlockCipher;
pub use errors::{AeadError, AeadInitError};
pub use gcm::GcmBlockCipher;
#[cfg(feature = "alloc")]
pub use gcm_siv::GcmSivBlockCipher;
pub use grain128::FixedGrain128AeadEngine;
#[cfg(feature = "alloc")]
pub use grain128::Grain128AeadEngine;
#[cfg(feature = "alloc")]
pub use kccm::KccmBlockCipher;
#[cfg(feature = "alloc")]
pub use ocb::OcbBlockCipher;
#[cfg(feature = "alloc")]
pub use params::AeadParamsOwned;
pub use params::AeadParamsRef;
pub use sparkle::{SparkleEngine, SparkleVariant};
pub use traits::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, InitialAadParams, MacSizeParams, NonceParams,
};

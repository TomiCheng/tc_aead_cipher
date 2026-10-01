//! Authenticated encryption with associated data (AEAD) contracts.

#![no_std]

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

pub use ascon::{AsconAead128, AsconLegacyEngine, AsconLegacyVariant};
#[cfg(feature = "alloc")]
pub use ccm::CcmBlockCipher;
pub use eax::EaxBlockCipher;
pub use errors::{AeadError, AeadInitError};
pub use gcm::GcmBlockCipher;
#[cfg(feature = "alloc")]
pub use gcm_siv::GcmSivBlockCipher;
pub use grain128::FixedGrain128Aead;
#[cfg(feature = "alloc")]
pub use grain128::Grain128Aead;
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

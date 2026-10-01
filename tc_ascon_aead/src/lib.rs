//! Ascon authenticated encryption: Ascon-AEAD128, standardized in NIST
//! SP 800-232, and the Ascon-128, Ascon-128a and Ascon-80pq variants of
//! Ascon v1.2, which the standard supersedes. Both engines implement the
//! `AeadCipher` and `AeadCipherInit` contracts of `tc_aead_cipher`. Ported
//! from Bouncy Castle C#.
//!
//! - [`AsconAead128Engine`] — Ascon-AEAD128, with tags of 4 to 16 bytes.
//! - [`AsconLegacyEngine`] with [`AsconLegacyVariant`] — the Ascon v1.2
//!   variants, for data produced before the standard.
//!
//! The crate is `no_std`, needs no allocator and contains no `unsafe` code.
//! Both engines are constant time: the permutation is bitsliced, without
//! tables or data-dependent branches, and tags are compared in fixed time.
//! Lengths are public.
//!
//! Decryption may write unauthenticated plaintext before `do_final`
//! verifies the tag, so discard the output when `do_final` fails. Each
//! engine's documentation carries a usage example.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod aead128;
mod legacy;

pub use aead128::AsconAead128Engine;
pub use legacy::{AsconLegacyEngine, AsconLegacyVariant};

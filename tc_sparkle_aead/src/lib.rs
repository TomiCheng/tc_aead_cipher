//! SCHWAEMM authenticated encryption, the AEAD family built on the SPARKLE
//! permutation, a finalist of the NIST lightweight cryptography
//! competition. The engine implements the `AeadCipher` and
//! `AeadCipherInit` contracts of `tc_aead_cipher`. Ported from Bouncy
//! Castle C#.
//!
//! - [`SparkleEngine`] with [`SparkleVariant`] — SCHWAEMM128-128,
//!   SCHWAEMM256-128, SCHWAEMM192-192 and SCHWAEMM256-256.
//!
//! The crate is `no_std` and needs no allocator. The engine is constant
//! time: SPARKLE adds, rotates and XORs 32-bit words, and tags are compared
//! in fixed time. Lengths are public. On x86 the 16-word permutation uses
//! SSE2 when run-time detection finds it; that is the crate's only `unsafe`
//! code.
//!
//! Decryption may write unauthenticated plaintext before `do_final`
//! verifies the tag, so discard the output when `do_final` fails. Each
//! engine's documentation carries a usage example.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod engine;
// The SSE2 permutation is the only code in the crate that needs `unsafe`.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod sse2;
mod variant;

pub use engine::SparkleEngine;
pub use variant::SparkleVariant;

//! Grain-128AEAD authenticated encryption, a finalist of the NIST
//! lightweight cryptography competition. The engines implement the
//! `AeadCipher` and `AeadCipherInit` contracts of `tc_aead_cipher`. Ported
//! from Bouncy Castle C#.
//!
//! - [`FixedGrain128AeadEngine`] — holds the associated data in a buffer of
//!   `MAX_AAD_LEN` bytes, without the heap.
//! - `Grain128AeadEngine` (`alloc`) — holds it in a `Vec`.
//!
//! Grain-128AEAD encodes the length of the associated data before the data
//! itself, so both engines hold the associated data until the message
//! starts. Keys are 16 bytes, nonces 12 bytes and tags 8 bytes.
//!
//! The crate is `no_std` and contains no `unsafe` code. It needs no
//! allocator unless its default-off `alloc` feature is enabled. Both
//! engines are constant time: the registers and the accumulator are updated
//! with shifts and masks, and tags are compared in fixed time. Lengths are
//! public.
//!
//! Decryption may write unauthenticated plaintext before `do_final`
//! verifies the tag, so discard the output when `do_final` fails. Each
//! engine's documentation carries a usage example.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod engine;

pub use engine::FixedGrain128AeadEngine;
#[cfg(feature = "alloc")]
pub use engine::Grain128AeadEngine;

//! ChaCha authenticated encryption: ChaCha20-Poly1305 from RFC 8439 and
//! XChaCha20-Poly1305, its 24-byte-nonce extension. Both engines implement the
//! `AeadCipher` and `AeadCipherInit` contracts of `tc_aead_cipher`, over the
//! ChaCha engines of `tc_chacha` and the Poly1305 MAC of `tc_poly1305`. Ported
//! from Bouncy Castle C#.
//!
//! - [`ChaCha20Poly1305Engine`] — ChaCha20-Poly1305, with 12-byte nonces.
//! - [`XChaCha20Poly1305Engine`] — XChaCha20-Poly1305, with 24-byte nonces
//!   that can be drawn at random.
//!
//! Both take 32-byte keys and produce 16-byte tags. The crate is `no_std`,
//! needs no allocator and contains no `unsafe` code.
//!
//! Both engines are constant time: ChaCha20 is built from additions,
//! rotations and XORs, Poly1305 reduces without branches, and tags are
//! compared in fixed time. Lengths are public.
//!
//! Decryption may write unauthenticated plaintext before `do_final`
//! verifies the tag, so discard the output when `do_final` fails. Each
//! engine's documentation carries a usage example.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod engine;

pub use engine::{ChaCha20Poly1305Engine, XChaCha20Poly1305Engine};

/// Secret-key length in bytes, for both engines.
pub const KEY_BYTES: usize = 32;
/// ChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_BYTES: usize = 12;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const XNONCE_BYTES: usize = 24;
/// Authentication-tag length in bytes, the only `mac_size` either engine
/// accepts.
pub const TAG_BYTES: usize = 16;

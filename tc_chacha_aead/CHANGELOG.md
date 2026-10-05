# Changelog

All notable changes to `tc_chacha_aead` are documented in this file.

## 0.1.0 - 2026-10-05

Initial release.

### Added

- `ChaCha20Poly1305Engine`: ChaCha20-Poly1305 from RFC 8439, with 32-byte
  keys, 12-byte nonces and 16-byte tags.
- `XChaCha20Poly1305Engine`: XChaCha20-Poly1305 from the XChaCha draft, with
  24-byte nonces that can be drawn at random.
- `KEY_BYTES`, `NONCE_BYTES`, `XNONCE_BYTES` and `TAG_BYTES`.
- Both engines implement `AeadCipher` and `AeadCipherInit` from
  `tc_aead_cipher`. Encryption refuses an `init` that repeats the previous
  key and nonce of the same instance, comparing the key in fixed time. A
  failed `init` leaves an engine uninitialized, `reset` restarts a message
  unless encryption may already have released output, and `mac()` returns
  the tag that was appended or verified.
- `Display` for both engines, and `const fn new`.
- The default-off `rustcrypto` feature, which enables `tc_chacha/rustcrypto`
  so that ChaCha20 and HChaCha20 run on RustCrypto's `chacha20`, with SIMD
  where the processor has it.
- Tests against the RFC 8439 and XChaCha draft vectors; contract tests of
  split input, initial associated data, `reset`, nonce reuse, failed `init`,
  tampering and size errors; a test that every public API documents whether
  it is constant or variable time; and doctests for both engines.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024. The `rustcrypto`
  feature adds `chacha20` 0.10 and `cipher` 0.5 and follows their minimum Rust
  version, which is 1.85 for `chacha20` 0.10.2 and `cipher` 0.5.2.
- Requires `tc_aead_cipher` 0.1, whose contracts, parameters and errors the
  engines use.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
- Depends on `tc_block_cipher` 0.1, `tc_chacha` 0.1, `tc_constant_time` 0.1,
  `tc_macs` 0.1, `tc_poly1305` 0.1, `tc_stream_cipher` 0.1 and `tc_zeroize`
  0.1, all `tc_*` crates in the default build. Needs no allocator and contains
  no `unsafe` code.
- Both engines are constant time on either backend; lengths are public.
- Tag sizes are in bytes, and only 16 is accepted.

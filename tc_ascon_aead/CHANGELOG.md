# Changelog

All notable changes to `tc_ascon_aead` are documented in this file.

## 0.1.0 - 2026-10-01

Initial release.

### Added

- `AsconAead128Engine`: Ascon-AEAD128 from NIST SP 800-232, with 16-byte keys
  and nonces and tags of 4 to 16 bytes, a truncated tag being the leftmost
  bytes of the full tag.
- `AsconLegacyEngine` with `AsconLegacyVariant`: Ascon-128, Ascon-128a and
  Ascon-80pq from Ascon v1.2, for data produced before the standard.
- Both engines implement `AeadCipher` and `AeadCipherInit` from
  `tc_aead_cipher`. Encryption refuses an `init` that repeats the previous
  key and nonce of the same instance, comparing the key in fixed time. A
  failed `init` leaves an engine uninitialized, `reset`
  restarts a message unless encryption may already have released output, and
  `mac()` returns the tag that was appended or verified.
- `Display` for both engines and the variant, and `const fn new`.
- Tests against the official Ascon-AEAD128 and Ascon v1.2 vectors; contract
  tests of split input, initial associated data, truncated tags, `reset`,
  nonce reuse, tampering and size errors; a test that every public API documents whether
  it is constant or variable time; and doctests for both engines.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Requires `tc_aead_cipher` 0.1, whose contracts, parameters and errors the
  engines use.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
- Depends on `tc_block_cipher` 0.1, `tc_constant_time` 0.1 and `tc_zeroize`
  0.1. Has no features, needs no allocator and contains no `unsafe` code.
- Both engines are constant time; lengths are public.
- Tag sizes are in bytes, not bits as in Bouncy Castle.

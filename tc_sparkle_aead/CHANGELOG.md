# Changelog

All notable changes to `tc_sparkle_aead` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `SparkleEngine` with `SparkleVariant`: SCHWAEMM128-128, SCHWAEMM256-128,
  SCHWAEMM192-192 and SCHWAEMM256-256, the AEAD family built on the SPARKLE
  permutation. On x86, SCHWAEMM256-256 uses an SSE2 permutation after run-time
  detection.
- The engine implements `AeadCipher` and `AeadCipherInit` from
  `tc_aead_cipher`. Encryption refuses an `init` that repeats the previous
  key and nonce of the same instance, comparing the key in fixed time. A
  failed `init` leaves it uninitialized, `reset` restarts a
  message unless encryption may already have released output, and `mac()`
  returns the tag that was appended or verified.
- `Display` for the engine and the variant, and `const fn new`.
- Tests against the official SCHWAEMM vectors for all four parameter sets and
  of the SSE2 permutation against the portable one; contract tests of split
  input, initial associated data, the tag size, `reset`, nonce reuse, tampering and size
  errors; a test that every public API documents whether it is constant or
  variable time; and a doctest.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Requires `tc_aead_cipher` 0.1, whose contracts, parameters and errors the
  engines use.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
- Depends on `tc_block_cipher` 0.1, `tc_constant_time` 0.1 and `tc_zeroize`
  0.1, and on x86 targets on `tc_runtime` 0.1. Has no features and needs no
  allocator.
- The engine is constant time, the SSE2 form included; lengths are public.
- The only `unsafe` code is the SSE2 permutation, used after run-time
  detection.

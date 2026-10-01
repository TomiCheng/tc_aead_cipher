# Changelog

All notable changes to `tc_grain128_aead` are documented in this file.

## 0.1.0 - 2026-10-01

Initial release.

### Added

- `FixedGrain128AeadEngine`, which holds up to `MAX_AAD_LEN` bytes of
  associated data without the heap, and, with the default-off `alloc`
  feature, `Grain128AeadEngine`, which holds it in a `Vec`: Grain-128AEAD with
  16-byte keys, 12-byte nonces and 8-byte tags.
- Both engines implement `AeadCipher` and `AeadCipherInit` from
  `tc_aead_cipher`. Encryption refuses an `init` that repeats the previous
  key and nonce of the same instance, comparing the key in fixed time. A
  failed `init` leaves an engine uninitialized, `reset`
  restarts a message unless encryption may already have released output, and
  `mac()` returns the tag that was appended or verified.
- `Display` for both engines, and `const fn new`.
- Tests against the official and Bouncy Castle Grain-128AEAD vectors; contract
  tests of split input, initial associated data, the fixed capacity, the tag
  size, `reset`, nonce reuse, tampering and size errors; a test that every public API
  documents whether it is constant or variable time; and doctests for both
  engines.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Requires `tc_aead_cipher` 0.1, whose contracts, parameters and errors the
  engines use.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
- Depends on `tc_block_cipher` 0.1, `tc_constant_time` 0.1 and `tc_zeroize`
  0.1. Contains no `unsafe` code.
- Both engines are constant time; lengths are public.
- `Grain128AeadEngine` wipes its `Vec` when cleared and on drop, but a `Vec`
  that grows frees its previous allocation without wiping it.

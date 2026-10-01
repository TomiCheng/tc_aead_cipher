# Changelog

All notable changes to `tc_aead_cipher` are documented in this file.

## 0.1.0 - 2026-10-01

Initial release.

### Added

- The `AeadCipher` contract for associated data, message processing,
  `do_final`, `mac`, `reset` and output sizing over caller-provided buffers;
  `AeadCipherInit`, which starts a message in a direction from parameters of
  type `P`; and `AeadBlockCipher`, which exposes the block cipher under a mode.
- `NonceParams`, `MacSizeParams` and `InitialAadParams`, which parameter types
  implement alongside the cipher's `KeyParams`, and the `AeadParamsRef` and,
  with the default-off `alloc` feature, `AeadParamsOwned` containers. The owned
  form wipes its bytes on drop, and `Debug` writes only the lengths.
- `GcmBlockCipher` and `EaxBlockCipher` over any `tc_block_cipher` engine, and
  with `alloc` the packet modes `CcmBlockCipher`, `GcmSivBlockCipher`,
  `OcbBlockCipher` and `KccmBlockCipher`. `GcmBlockCipher::init_with_parts`
  takes the cipher's own parameter type for constructions such as GMAC.
- `AeadError` and `AeadInitError`, which wrap the cipher's errors and report
  them through `source`.
- Every mode but GCM-SIV refuses an encryption `init` that repeats the
  previous key and nonce of the same instance, comparing a key-derived value
  in fixed time instead of keeping the key. A failed `init` leaves every mode
  uninitialized, and output sizing reports `InputTooLong` instead of
  overflowing.
- `reset` restarts a message under the same nonce unless encryption may
  already have released output; GCM-SIV restarts in either direction.
- `mac()` returns the tag that encryption appended or decryption verified for
  every mode.
- `Display` for every mode, writing the cipher's name followed by the mode's,
  such as `"AES/GCM"`, and `const fn new` for every mode.
- Tests against the NIST and Bouncy Castle GCM vectors, the RFC 8452 and
  RFC 7253 vectors and Bouncy Castle's CCM, EAX and KCCM vectors; contract
  tests of split input, initial associated data, `reset`, nonce reuse, failed
  initialization, tampering, short outputs and size overflow; a test that
  every public API documents whether it is constant or variable time; and
  doctests for every mode.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_block_cipher` 0.1, `tc_constant_time` 0.1 and `tc_zeroize`
  0.1. Contains no `unsafe` code.
- The modes are constant time exactly when their block cipher is. Lengths are
  public.
- Tag sizes are in bytes, not bits as in Bouncy Castle, and CCM and KCCM
  return the transmitted tag from `mac()` where Bouncy Castle returns the MAC
  before its encryption.
- CCM, GCM-SIV, OCB and KCCM keep data in `Vec`s that are wiped when cleared
  and on drop, but a `Vec` that grows frees its previous allocation without
  wiping it. Wiping does not reach the caller's buffers or copies left in
  registers and on the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.

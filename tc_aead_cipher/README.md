# tc_aead_cipher

[![crates.io](https://img.shields.io/crates/v/tc_aead_cipher.svg)](https://crates.io/crates/tc_aead_cipher)
[![docs.rs](https://docs.rs/tc_aead_cipher/badge.svg)](https://docs.rs/tc_aead_cipher)
[![CI](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Authenticated encryption with associated data (AEAD): GCM, GCM-SIV, CCM,
KCCM, EAX and OCB over any engine that implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, such as
[`tc_aes`](https://crates.io/crates/tc_aes), and Ascon, Grain-128AEAD and
SCHWAEMM, which carry their own primitive. Every engine implements the
`AeadCipher` and `AeadCipherInit` contracts defined here. Ported from Bouncy
Castle C#.

The crate is `no_std` and needs no allocator by default. It depends on
`tc_block_cipher`, [`tc_constant_time`](https://crates.io/crates/tc_constant_time)
and [`tc_zeroize`](https://crates.io/crates/tc_zeroize), and on x86 targets
also on [`tc_runtime`](https://crates.io/crates/tc_runtime) for SSE2 detection.

Requires Rust 1.85 or later (edition 2024).

## Types

- `GcmBlockCipher` — GCM over 16-byte blocks, with any non-empty nonce and
  tags of 4 to 16 bytes.
- `EaxBlockCipher` — EAX over 8- or 16-byte blocks, with tags of 4 bytes up
  to the block size.
- `CcmBlockCipher` (`alloc`) — CCM over 16-byte blocks, with 7- to 13-byte
  nonces and even tags of 4 to 16 bytes.
- `GcmSivBlockCipher` (`alloc`) — GCM-SIV over 16-byte blocks, with 16- or
  32-byte keys, 12-byte nonces and 16-byte tags.
- `OcbBlockCipher` (`alloc`) — OCB3 over 16-byte blocks, with nonces of up
  to 15 bytes and tags of 8 to 16 bytes.
- `KccmBlockCipher` (`alloc`) — DSTU 7624 KCCM over 16-, 32- or 64-byte
  blocks, for messages and associated data in whole blocks.
- `AsconAead128Engine` — Ascon-AEAD128 with tags of 4 to 16 bytes.
- `AsconLegacyEngine`, `AsconLegacyVariant` — Ascon-128, Ascon-128a and
  Ascon-80pq from Ascon v1.2, for compatibility.
- `Grain128AeadEngine` (`alloc`), `FixedGrain128AeadEngine` — Grain-128AEAD,
  holding the associated data in a `Vec` or a fixed buffer.
- `SparkleEngine`, `SparkleVariant` — SCHWAEMM128-128, SCHWAEMM256-128,
  SCHWAEMM192-192 and SCHWAEMM256-256.
- `AeadParamsRef`, `AeadParamsOwned` (`alloc`) — a key, nonce, tag size and
  initial associated data, borrowed or owned and wiped on drop.
- `AeadError`, `AeadInitError` — processing and initialization errors that
  wrap the cipher's.

Tag sizes are in bytes, not bits as in Bouncy Castle. Each engine checks its
key, nonce and tag sizes at `init`; the parameter types only carry them.
`mac()` returns the tag that encryption appended or decryption verified, also
for CCM and KCCM, where Bouncy Castle returns the MAC before its encryption.
`Display` writes the algorithm, such as `"AES/GCM"` or `"Ascon-AEAD128"`.

## Traits

- `AeadCipher` — associated data, message processing, `do_final`, `mac`,
  `reset` and output sizing.
- `AeadCipherInit` — starts a message in a direction from parameters of type
  `P`.
- `AeadBlockCipher` — exposes the block cipher under a mode.
- `NonceParams`, `MacSizeParams`, `InitialAadParams` — what a parameter type
  provides alongside the cipher's `KeyParams`.

## Features

- `alloc` (off by default) — adds the modes that buffer the whole message,
  `Grain128AeadEngine` and `AeadParamsOwned`; does not require the standard
  library.

## Usage

```toml
[dependencies]
tc_aead_cipher = "0.1.0"
tc_aes = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef, GcmBlockCipher};
use tc_aes::AesEngine;
use tc_block_cipher::CipherDirection;

let (key, nonce) = ([0x42; 16], [0x24; 12]);
let mut gcm = GcmBlockCipher::new(AesEngine::new());
gcm.init(CipherDirection::Encrypt, &AeadParamsRef::new(&key, &nonce, 16, b"header")).expect("valid sizes");
let mut sealed = [0; 14 + 16];
let written = gcm.process_bytes(b"attack at dawn", &mut sealed).expect("initialized");
gcm.do_final(&mut sealed[written..]).expect("room for the tag");
```

The type documentation carries an executable example for every engine.

## Security

Never encrypt two messages under one key and nonce, except with GCM-SIV,
which then reveals only whether the messages were equal. Encryption refuses an
`init` that repeats the previous key and nonce of the same instance, but
nothing tracks nonces across instances or restarts. Decryption by the
streaming engines may write plaintext before `do_final` verifies the tag;
discard all of it when `do_final` fails.

The six modes are constant time exactly when their block cipher is: GHASH and
POLYVAL multiply with masks, counters and doublings use arithmetic instead of
branches, and every tag is compared in fixed time. `tc_aes::AesEngine`, for
example, is constant time with AES-NI or its `rustcrypto` feature and variable
time otherwise, and the `tc_dstu7624` engines under KCCM are variable time.
The Ascon, Grain-128AEAD and SCHWAEMM engines are constant time. Lengths are
public throughout, and the result of a tag check shows in the outcome.

The engines wipe their keys, derived values and buffered data on drop. The
buffering engines keep data in `Vec`s, which are wiped when cleared, but a
`Vec` that grows frees its previous allocation without wiping it.
Every engine available without `alloc` stays off the heap.
Wiping does not reach the caller's buffers or copies left in registers and on
the stack.

## Validation

GCM is tested against the NIST and Bouncy Castle vectors, GCM-SIV against the
RFC 8452 vectors, OCB against the RFC 7253 vectors, CCM, EAX and KCCM against
Bouncy Castle's vectors, Ascon-AEAD128, Ascon v1.2 and SCHWAEMM against their
official known-answer vectors, and Grain-128AEAD against the official and
Bouncy Castle vectors. Contract tests cover associated data and messages
split across calls, initial associated data, `reset`, nonce-reuse
detection, failed initialization, tampering, short outputs and size overflow.
A test requires every public API to document whether it is constant or
variable time.

Missing public documentation is rejected by a crate-level lint, as is `unsafe`
code outside the SSE2 permutation.

Run these commands from the workspace root:

```text
cargo test -p tc_aead_cipher --locked
cargo test -p tc_aead_cipher --locked --all-features
cargo clippy -p tc_aead_cipher --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_aead_cipher --check
cargo doc -p tc_aead_cipher --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_aead_cipher --list --locked
cargo publish -p tc_aead_cipher --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

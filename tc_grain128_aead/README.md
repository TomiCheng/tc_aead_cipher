# tc_grain128_aead

[![crates.io](https://img.shields.io/crates/v/tc_grain128_aead.svg)](https://crates.io/crates/tc_grain128_aead)
[![docs.rs](https://docs.rs/tc_grain128_aead/badge.svg)](https://docs.rs/tc_grain128_aead)
[![CI](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Grain-128AEAD authenticated encryption, a finalist of the NIST lightweight
cryptography competition. Both engines implement the `AeadCipher` and
`AeadCipherInit` contracts of
[`tc_aead_cipher`](https://crates.io/crates/tc_aead_cipher). Ported from
Bouncy Castle C#.

The crate is `no_std` and contains no `unsafe` code. It needs no allocator
unless its default-off `alloc` feature is enabled, and depends on
`tc_aead_cipher`, `tc_block_cipher`,
[`tc_constant_time`](https://crates.io/crates/tc_constant_time) and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `FixedGrain128AeadEngine` — holds up to `MAX_AAD_LEN` bytes of associated
  data in a fixed buffer, without the heap.
- `Grain128AeadEngine` (`alloc`) — holds the associated data in a `Vec`.

Grain-128AEAD takes a 16-byte key and a 12-byte nonce and produces an 8-byte
tag; `init` rejects any other tag size. The algorithm encodes the length of
the associated data before the data itself, so both engines hold the
associated data until the message starts, and the fixed engine reports
`AadTooLong` beyond its capacity. `Display` writes `"Grain-128AEAD"`.

## Features

- `alloc` (off by default) — adds `Grain128AeadEngine`; does not require the
  standard library.

## Usage

```toml
[dependencies]
tc_grain128_aead = "0.1.0"
tc_aead_cipher = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_grain128_aead::FixedGrain128AeadEngine;

let (key, nonce) = ([0x42; 16], [0x24; 12]);
let mut grain = FixedGrain128AeadEngine::<64>::new();
grain.init(CipherDirection::Encrypt, &AeadParamsRef::new(&key, &nonce, 8, b"header")).expect("valid sizes");
let mut sealed = [0; 14 + 8];
let written = grain.process_bytes(b"attack at dawn", &mut sealed).expect("initialized");
grain.do_final(&mut sealed[written..]).expect("room for the tag");
```

The type documentation carries an executable example for both engines.

## Security

Never encrypt two messages under one key and nonce. Encryption refuses an
`init` that repeats the previous key and nonce of the same instance, but
nothing tracks nonces across instances or restarts. Decryption may
write plaintext before `do_final` verifies the tag; discard all of it when
`do_final` fails. The 8-byte tag gives at most 64-bit forgery resistance.

Both engines are constant time: the shift registers and the authentication
accumulator are updated with shifts and masks, never with branches on key,
nonce or message bits, and tags are compared in fixed time. Lengths are
public, and the result of a tag check shows in the outcome.

The engines wipe their key, state and buffered associated data on drop.
`Grain128AeadEngine` keeps the associated data in a `Vec`, which is wiped when
cleared, but a `Vec` that grows frees its previous allocation without wiping
it. Wiping does not reach the caller's buffers or copies left in registers and
on the stack.

## Validation

Both engines are tested against the official and Bouncy Castle Grain-128AEAD
vectors. Contract tests cover associated data and messages split across
calls, initial associated data, the fixed engine's capacity, the tag size,
`reset`, nonce-reuse detection, tampering and size errors. A test requires every public API to
document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_grain128_aead --locked
cargo test -p tc_grain128_aead --locked --all-features
cargo clippy -p tc_grain128_aead --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_grain128_aead --check
cargo doc -p tc_grain128_aead --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout, after `tc_aead_cipher` is published:

```text
cargo package -p tc_grain128_aead --list --locked
cargo publish -p tc_grain128_aead --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

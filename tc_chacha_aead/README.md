# tc_chacha_aead

[![crates.io](https://img.shields.io/crates/v/tc_chacha_aead.svg)](https://crates.io/crates/tc_chacha_aead)
[![docs.rs](https://docs.rs/tc_chacha_aead/badge.svg)](https://docs.rs/tc_chacha_aead)
[![CI](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

ChaCha authenticated encryption: ChaCha20-Poly1305 from RFC 8439 and
XChaCha20-Poly1305, its 24-byte-nonce extension. Both engines implement the
`AeadCipher` and `AeadCipherInit` contracts of
[`tc_aead_cipher`](https://crates.io/crates/tc_aead_cipher), over the ChaCha
engines of [`tc_chacha`](https://crates.io/crates/tc_chacha) and the Poly1305
MAC of [`tc_poly1305`](https://crates.io/crates/tc_poly1305). Ported from
Bouncy Castle C#.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
has no features and depends on `tc_aead_cipher`, `tc_block_cipher`,
`tc_chacha`, [`tc_constant_time`](https://crates.io/crates/tc_constant_time),
[`tc_macs`](https://crates.io/crates/tc_macs), `tc_poly1305`,
[`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher) and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `ChaCha20Poly1305Engine` — ChaCha20-Poly1305 from RFC 8439, with 32-byte
  keys, 12-byte nonces and 16-byte tags.
- `XChaCha20Poly1305Engine` — XChaCha20-Poly1305, with 32-byte keys, 24-byte
  nonces and 16-byte tags.

The tag is always 16 bytes, so `init` refuses any other `mac_size`. The
constants `KEY_BYTES`, `NONCE_BYTES`, `XNONCE_BYTES` and `TAG_BYTES` give the
sizes. XChaCha20-Poly1305 derives a subkey with HChaCha20 from the key and the
first 16 bytes of the nonce, and runs ChaCha20-Poly1305 under it, as the XChaCha
draft (draft-irtf-cfrg-xchacha) specifies. A message holds at most 2^32 - 1
blocks of 64 bytes, about 256 GiB. `Display` writes `"ChaCha20-Poly1305"` or
`"XChaCha20-Poly1305"`.

## Usage

```toml
[dependencies]
tc_chacha_aead = "0.1.0"
tc_aead_cipher = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_chacha_aead::{TAG_BYTES, XChaCha20Poly1305Engine};

let (key, nonce) = ([0x42; 32], [0x24; 24]);
let mut cipher = XChaCha20Poly1305Engine::new();
cipher.init(CipherDirection::Encrypt, &AeadParamsRef::new(&key, &nonce, TAG_BYTES, b"header")).expect("valid sizes");
let mut sealed = [0; 14 + TAG_BYTES];
let written = cipher.process_bytes(b"attack at dawn", &mut sealed).expect("initialized");
cipher.do_final(&mut sealed[written..]).expect("room for the tag");
```

The type documentation carries an executable example for both engines.

## Security

Never encrypt two messages under one key and nonce. Encryption refuses an
`init` that repeats the previous key and nonce of the same instance, but
nothing tracks nonces across instances or restarts. A 12-byte nonce is too
short to draw at random for many messages under one key; use
XChaCha20-Poly1305 when nonces are random. Decryption may write plaintext
before `do_final` verifies the tag; discard all of it when `do_final` fails.

Both engines are constant time: ChaCha20 and HChaCha20 are built from
additions, rotations and XORs on 32-bit words, Poly1305 reduces without
branches, and tags are compared in fixed time. Lengths are public, and the
result of a tag check shows in the outcome.

The engines wipe their key, nonce, buffer and tag on drop, and the ChaCha and
Poly1305 engines they hold wipe their own state. Wiping does not reach the
caller's buffers or copies left in registers and on the stack.

## Validation

ChaCha20-Poly1305 is tested against the RFC 8439 vector and
XChaCha20-Poly1305 against the XChaCha draft vector. Contract tests cover
associated data and messages split across calls, initial associated data,
`reset`, nonce-reuse detection, failed `init`, tampering and size errors.
A test requires every public API to document whether it is constant or
variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_chacha_aead --locked
cargo clippy -p tc_chacha_aead --all-targets --locked -- -D warnings
cargo fmt -p tc_chacha_aead --check
cargo doc -p tc_chacha_aead --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_chacha_aead --list --locked
cargo publish -p tc_chacha_aead --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
